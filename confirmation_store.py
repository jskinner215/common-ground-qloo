"""Explicit durable confirmation protocol; no module-import I/O or cloud client.

SQLite is for a private local deployment/tests. It is NOT cross-worker Lambda
storage. A cloud implementation must provide the same atomic CAS transitions.
"""
from contextlib import contextmanager
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
from typing import Protocol

from workflow import WorkflowError

TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
REQUEST = re.compile(r"[A-Za-z0-9_.:-]{8,128}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
MAX_STORED_BYTES = 262144


def session_key(session_id):
    if not isinstance(session_id, str) or not TOKEN.fullmatch(session_id):
        raise WorkflowError("invalid_session", "An explicit valid session token is required.")
    return hashlib.sha256(session_id.encode()).hexdigest()


def request_key(request_id):
    if not isinstance(request_id, str) or not REQUEST.fullmatch(request_id):
        raise WorkflowError("invalid_request_id", "An explicit bounded request ID is required.")
    return request_id


def timestamp(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise WorkflowError("invalid_time", "A finite Unix timestamp is required.")
    return float(value)


def fingerprint(value):
    if not isinstance(value, str) or not HASH.fullmatch(value):
        raise WorkflowError("invalid_fingerprint", "A source-bound request digest is required.")
    return value


def encode(value):
    try:
        text = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(text.encode()) > MAX_STORED_BYTES:
            raise ValueError()
        return text
    except (ValueError, TypeError, RecursionError):
        raise WorkflowError("invalid_confirmation", "Confirmation data exceeds its bounded storage contract.") from None


def decode(value):
    try:
        result = json.loads(value)
        if not isinstance(result, dict):
            raise ValueError()
        return result
    except (ValueError, TypeError, RecursionError):
        raise WorkflowError("confirmation_store_unavailable", "Stored confirmation is unavailable; resolve again.", 503) from None


class ConfirmationStore(Protocol):
    def begin_resolution(self, session_id, request_id, fingerprint, now): ...
    def complete_resolution(self, session_id, generation, request_id, snapshot, expires_at, now): ...
    def current_resolution(self, session_id, now): ...
    def begin_recommendation(self, session_id, generation, resolution_id, request_id, fingerprint, now): ...
    def complete_recommendation(self, session_id, generation, resolution_id, request_id, fingerprint, result, now): ...
    def fail_operation(self, session_id, kind, request_id, now): ...
    def invalidate_resolution(self, session_id, generation, now): ...


class SQLiteConfirmationStore:
    """Caller-selected file, separate connections, atomic generation/idempotency CAS.

    Constructing this class intentionally initializes its explicit local database.
    No path is selected implicitly and no production database is opened on import.
    """
    def __init__(self, path):
        if str(path) == ":memory:":
            raise ValueError("Choose an explicit durable SQLite file.")
        self.path = str(Path(path).resolve())
        with self._transaction() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS confirmations (session TEXT PRIMARY KEY, generation INTEGER NOT NULL, status TEXT NOT NULL, snapshot TEXT, expires_at REAL)")
            connection.execute("CREATE TABLE IF NOT EXISTS operations (session TEXT NOT NULL, kind TEXT NOT NULL, request_id TEXT NOT NULL, fingerprint TEXT NOT NULL, generation INTEGER NOT NULL, status TEXT NOT NULL, result TEXT, PRIMARY KEY(session,kind,request_id))")

    @contextmanager
    def _transaction(self):
        connection = None
        try:
            connection = sqlite3.connect(self.path, timeout=2, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except WorkflowError:
            if connection is not None:
                connection.rollback()
            raise
        except sqlite3.Error:
            if connection is not None:
                connection.rollback()
            raise WorkflowError("confirmation_store_unavailable", "Durable confirmation storage is unavailable; no provider request may start.", 503) from None
        finally:
            if connection is not None:
                connection.close()

    @staticmethod
    def _current(connection, key, now, generation=None, resolution_id=None):
        row = connection.execute("SELECT * FROM confirmations WHERE session=?", (key,)).fetchone()
        if (row is None or row["status"] != "resolved" or row["expires_at"] is None
                or now >= row["expires_at"] or (generation is not None and row["generation"] != generation)):
            raise WorkflowError("stale_resolution", "A newer resolution or expiry requires another explicit identity review.", 409)
        snapshot = decode(row["snapshot"])
        if resolution_id is not None and snapshot.get("resolution_id") != resolution_id:
            raise WorkflowError("stale_resolution", "Resolve and explicitly confirm the current artist pair again.", 409)
        return {"generation": row["generation"], "snapshot": snapshot, "expires_at": row["expires_at"]}

    @staticmethod
    def _operation(connection, key, kind, request_id):
        return connection.execute("SELECT * FROM operations WHERE session=? AND kind=? AND request_id=?", (key, kind, request_id)).fetchone()

    @staticmethod
    def _replay(operation, source_hash):
        if operation["fingerprint"] != source_hash:
            raise WorkflowError("request_conflict", "That request ID is bound to different action data.", 409)
        if operation["status"] == "pending":
            raise WorkflowError("operation_in_progress", "This exact request is already in progress; no duplicate provider request started.", 409)
        if operation["status"] != "done":
            raise WorkflowError("request_uncertain", "The earlier request did not complete. It will not be retried automatically.", 409)

    def begin_resolution(self, session_id, request_id, fingerprint, now):
        key, request_id, source_hash, now = session_key(session_id), request_key(request_id), globals()["fingerprint"](fingerprint), timestamp(now)
        with self._transaction() as connection:
            previous = self._operation(connection, key, "resolve", request_id)
            if previous is not None:
                self._replay(previous, source_hash)
                current = self._current(connection, key, now, previous["generation"])
                return {**current, "replay": True}
            row = connection.execute("SELECT generation FROM confirmations WHERE session=?", (key,)).fetchone()
            generation = 1 if row is None else row["generation"] + 1
            connection.execute("INSERT INTO confirmations(session,generation,status,snapshot,expires_at) VALUES(?,?,'resolving',NULL,NULL) ON CONFLICT(session) DO UPDATE SET generation=excluded.generation,status='resolving',snapshot=NULL,expires_at=NULL", (key, generation))
            connection.execute("INSERT INTO operations VALUES(?,?,?,?,?,'pending',NULL)", (key, "resolve", request_id, source_hash, generation))
            return {"generation": generation, "replay": False, "snapshot": None, "expires_at": None}

    def complete_resolution(self, session_id, generation, request_id, snapshot, expires_at, now):
        key, request_id, now, expires_at = session_key(session_id), request_key(request_id), timestamp(now), timestamp(expires_at)
        if expires_at <= now or snapshot.get("generation") != generation:
            raise WorkflowError("stale_resolution", "The resolution expired before confirmation could be stored.", 409)
        text = encode(snapshot)
        with self._transaction() as connection:
            current = connection.execute("SELECT generation,status FROM confirmations WHERE session=?", (key,)).fetchone()
            operation = self._operation(connection, key, "resolve", request_id)
            if (current is None or current["generation"] != generation or current["status"] != "resolving"
                    or operation is None or operation["generation"] != generation or operation["status"] != "pending"):
                raise WorkflowError("stale_resolution", "A newer resolution superseded this response.", 409)
            connection.execute("UPDATE confirmations SET status='resolved',snapshot=?,expires_at=? WHERE session=? AND generation=?", (text, expires_at, key, generation))
            connection.execute("UPDATE operations SET status='done' WHERE session=? AND kind='resolve' AND request_id=?", (key, request_id))

    def current_resolution(self, session_id, now):
        key, now = session_key(session_id), timestamp(now)
        with self._transaction() as connection:
            return self._current(connection, key, now)

    def begin_recommendation(self, session_id, generation, resolution_id, request_id, fingerprint, now):
        key, request_id, source_hash, now = session_key(session_id), request_key(request_id), globals()["fingerprint"](fingerprint), timestamp(now)
        with self._transaction() as connection:
            self._current(connection, key, now, generation, resolution_id)
            previous = self._operation(connection, key, "recommend", request_id)
            if previous is not None:
                self._replay(previous, source_hash)
                if previous["generation"] != generation:
                    raise WorkflowError("request_conflict", "That request ID belongs to a different confirmation generation.", 409)
                return {"replay": True, "result": decode(previous["result"])}
            connection.execute("INSERT INTO operations VALUES(?,?,?,?,?,'pending',NULL)", (key, "recommend", request_id, source_hash, generation))
            return {"replay": False, "result": None}

    def complete_recommendation(self, session_id, generation, resolution_id, request_id, fingerprint, result, now):
        key, request_id, source_hash, now = session_key(session_id), request_key(request_id), globals()["fingerprint"](fingerprint), timestamp(now)
        text = encode(result)
        with self._transaction() as connection:
            self._current(connection, key, now, generation, resolution_id)
            operation = self._operation(connection, key, "recommend", request_id)
            if (operation is None or operation["fingerprint"] != source_hash
                    or operation["generation"] != generation or operation["status"] != "pending"):
                raise WorkflowError("request_conflict", "The pending recommendation no longer matches this exact request.", 409)
            connection.execute("UPDATE operations SET status='done',result=? WHERE session=? AND kind='recommend' AND request_id=?", (text, key, request_id))

    def fail_operation(self, session_id, kind, request_id, now):
        key, request_id = session_key(session_id), request_key(request_id)
        timestamp(now)
        if kind not in {"resolve", "recommend"}:
            raise ValueError("Unknown operation kind")
        with self._transaction() as connection:
            connection.execute("UPDATE operations SET status='uncertain' WHERE session=? AND kind=? AND request_id=? AND status='pending'", (key, kind, request_id))

    def invalidate_resolution(self, session_id, generation, now):
        key = session_key(session_id)
        timestamp(now)
        with self._transaction() as connection:
            connection.execute("UPDATE confirmations SET status='invalidated',snapshot=NULL,expires_at=NULL WHERE session=? AND generation=?", (key, generation))
