"""Injected DynamoDB confirmation store. Import/constructor perform no I/O.

This is a private source binding, not an AWS deployment or IAM acceptance test.
The caller supplies a low-level client with retries disabled and an explicitly
selected table/retention end. No SDK, environment, credentials or default client
are loaded here. Each mutation is a conditional DynamoDB transaction; no failed
or uncertain transaction is retried by this store.
"""
from copy import deepcopy
import hashlib
import json
import re
import math
import time

from confirmation_store import decode, encode, fingerprint as checked_fingerprint, request_key, session_key, timestamp
from workflow import WorkflowError


MAX_ITEM_BYTES = 327680  # Conservative serialized bound below DynamoDB's 400 KiB.
PARTITION = "qloo"


def unavailable():
    return WorkflowError("confirmation_store_unavailable", "Durable confirmation storage is unavailable; no provider request may start.", 503)


def conflict():
    return WorkflowError("confirmation_conflict", "Another confirmation transition won the version check. Refresh before an explicit new action; no automatic retry occurred.", 409)


class DynamoDBConfirmationStore:
    """Seven-method ConfirmationStore implementation using an injected client.

    PK is always ``qloo``. SK contains only SHA256 session/request identifiers.
    Metadata tombstones remain until the caller's fixed retention end, rather
    than disappearing while an earlier request ID could still be replayed.
    Application expiry remains an explicit UTC check, independent of TTL cleanup.
    """
    def __init__(self, client, *, table_name, retention_until):
        if (client is None or not callable(getattr(client, "get_item", None))
                or not callable(getattr(client, "transact_write_items", None))):
            raise ValueError("An explicit low-level DynamoDB client is required.")
        if not isinstance(table_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name):
            raise ValueError("An explicit bounded table name is required.")
        retention_until = timestamp(retention_until)
        if not retention_until.is_integer():
            raise ValueError("An integer Unix retention timestamp is required for DynamoDB TTL.")
        self.client, self.table_name = client, table_name
        self.retention_until = int(retention_until)

    def _now(self, now):
        now = timestamp(now)
        if now >= self.retention_until:
            raise WorkflowError("stale_resolution", "The store retention window has ended; no provider request may start.", 409)
        return now

    @staticmethod
    def _session_sk(key):
        return "session#" + key

    @staticmethod
    def _operation_sk(key, kind, request_id):
        return "operation#" + key + "#" + kind + "#" + hashlib.sha256(request_id.encode()).hexdigest()

    @staticmethod
    def _key(sk):
        return {"PK": {"S": PARTITION}, "SK": {"S": sk}}

    def _read(self, sk):
        try:
            response = self.client.get_item(TableName=self.table_name, Key=self._key(sk), ConsistentRead=True)
            if not isinstance(response, dict):
                raise ValueError()
            item = response.get("Item")
            if item is None:
                return None
            if (not isinstance(item, dict) or item.get("PK") != {"S": PARTITION}
                    or item.get("SK") != {"S": sk} or set(item) != {"PK", "SK", "revision", "payload", "expireAt"}
                    or not isinstance(item.get("revision"), dict) or set(item["revision"]) != {"N"}
                    or not isinstance(item.get("payload"), dict) or set(item["payload"]) != {"S"}
                    or not isinstance(item.get("expireAt"), dict) or set(item["expireAt"]) != {"N"}):
                raise ValueError()
            revision = int(item["revision"]["N"])
            if revision < 1 or str(revision) != item["revision"]["N"]:
                raise ValueError()
            if timestamp(float(item["expireAt"]["N"])) != self.retention_until:
                raise ValueError()
            # Validate persisted size and finite JSON before returning a fresh copy.
            data = decode(item["payload"]["S"])
            encode(data)
            if type(data.get("generation")) is not int or data["generation"] < 1:
                raise ValueError()
            if sk.startswith("session#"):
                if set(data) != {"generation", "status", "snapshot", "expires_at"} or data["status"] not in {"resolving", "resolved", "invalidated"}:
                    raise ValueError()
                if data["status"] == "resolved":
                    if (not isinstance(data["snapshot"], dict)
                            or data["snapshot"].get("generation") != data["generation"]
                            or timestamp(data["expires_at"]) > self.retention_until):
                        raise ValueError()
                elif data["snapshot"] is not None or data["expires_at"] is not None:
                    raise ValueError()
            else:
                expected = {"fingerprint", "generation", "status", "result"}
                if (set(data) not in (expected, expected | {"started_at"})
                        or data["status"] not in {"pending", "done", "uncertain"}):
                    raise ValueError()
                checked_fingerprint(data["fingerprint"])
                if "started_at" in data and timestamp(data["started_at"]) >= self.retention_until:
                    raise ValueError()
            if len(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_ITEM_BYTES:
                raise ValueError()
            return {"revision": revision, "data": data}
        except WorkflowError:
            raise unavailable() from None
        except Exception:
            raise unavailable() from None

    def _put(self, sk, previous, data):
        revision = 1 if previous is None else previous["revision"] + 1
        item = {**self._key(sk), "revision": {"N": str(revision)}, "payload": {"S": encode(data)},
                "expireAt": {"N": str(self.retention_until)}}
        if len(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_ITEM_BYTES:
            raise WorkflowError("invalid_confirmation", "Confirmation item exceeds its bounded cloud storage contract.")
        condition = "attribute_not_exists(PK)" if previous is None else "#revision = :revision"
        put = {"TableName": self.table_name, "Item": item, "ConditionExpression": condition}
        if previous is not None:
            put.update(ExpressionAttributeNames={"#revision": "revision"},
                       ExpressionAttributeValues={":revision": {"N": str(previous["revision"])}})
        return {"Put": put}

    def _check(self, sk, previous):
        if previous is None:
            raise conflict()
        return {"ConditionCheck": {"TableName": self.table_name, "Key": self._key(sk),
                                   "ConditionExpression": "#revision = :revision",
                                   "ExpressionAttributeNames": {"#revision": "revision"},
                                   "ExpressionAttributeValues": {":revision": {"N": str(previous["revision"])}}}}

    def _commit(self, changes):
        try:
            self.client.transact_write_items(TransactItems=changes)
        except Exception as error:
            # Never expose raw service error text, request IDs, headers or values.
            response = getattr(error, "response", None)
            if isinstance(response, dict):
                code = response.get("Error", {}).get("Code")
                reasons = response.get("CancellationReasons")
                if (code == "TransactionCanceledException" and isinstance(reasons, list)
                        and any(isinstance(reason, dict) and reason.get("Code") == "ConditionalCheckFailed" for reason in reasons)
                        and all(isinstance(reason, dict) and reason.get("Code") in {"None", "ConditionalCheckFailed"} for reason in reasons)):
                    raise conflict() from None
            raise unavailable() from None

    @staticmethod
    def _current(row, now, generation=None, resolution_id=None):
        try:
            data = row["data"] if row else None
            if (not isinstance(data, dict) or data.get("status") != "resolved"
                    or type(data.get("generation")) is not int or data["generation"] < 1
                    or data.get("expires_at") is None or now >= timestamp(data["expires_at"])
                    or (generation is not None and data["generation"] != generation)):
                raise WorkflowError("stale_resolution", "A newer resolution or expiry requires another explicit identity review.", 409)
            snapshot = data.get("snapshot")
            if not isinstance(snapshot, dict) or snapshot.get("generation") != data["generation"]:
                raise unavailable()
            if resolution_id is not None and snapshot.get("resolution_id") != resolution_id:
                raise WorkflowError("stale_resolution", "Resolve and explicitly confirm the current artist pair again.", 409)
            return {"generation": data["generation"], "snapshot": deepcopy(snapshot), "expires_at": data["expires_at"]}
        except (KeyError, TypeError, ValueError):
            raise unavailable() from None

    @staticmethod
    def _replay(row, source_hash, now=None):
        data = row["data"]
        if data.get("fingerprint") != source_hash:
            raise WorkflowError("request_conflict", "That request ID is bound to different action data.", 409)
        if data.get("status") == "pending":
            started = data.get("started_at")
            if (type(started) in (int, float) and type(now) in (int, float)
                    and now >= started and now - started > 8.0):
                raise WorkflowError("operation_overdue_pending", "The original record is still pending after its request budget. Its outcome is unresolved, not permission to resume. This inspection started no new provider work; the barrier is retained.", 409)
            raise WorkflowError("operation_pending_unverified", "The original record is pending. Active execution is not verified, including records with unknown age or a regressed clock. This inspection started no new provider work; the barrier is retained.", 409)
        if data.get("status") != "done":
            raise WorkflowError("request_uncertain", "The earlier request did not complete. It will not be retried automatically.", 409)
        return data

    def _recovery_read(self, sk, deadline):
        if (type(deadline) not in (int, float) or not math.isfinite(deadline)
                or time.monotonic() >= deadline):
            raise WorkflowError("recovery_budget_expired", "Read-only recovery has no trusted remaining budget; no read started.", 504)
        row = self._read(sk)
        if time.monotonic() >= deadline:
            raise WorkflowError("recovery_budget_expired", "Read-only recovery exceeded its cooperative read budget; no next read started.", 504)
        return row

    def inspect_current_resolution(self, session_id, now, *, deadline=None):
        key, now = session_key(session_id), self._now(now)
        return self._current(self._recovery_read(self._session_sk(key), deadline), now)

    def inspect_resolution_operation(self, session_id, request_id, fingerprint, now, *, deadline=None):
        key, request_id = session_key(session_id), request_key(request_id)
        source_hash, now = checked_fingerprint(fingerprint), self._now(now)
        row = self._recovery_read(self._operation_sk(key, "resolve", request_id), deadline)
        if row is None:
            raise WorkflowError("operation_not_recorded", "No stored outcome was found. This read is not permission to create or resume an operation.", 409)
        previous = self._replay(row, source_hash, now)
        current = self._current(self._recovery_read(self._session_sk(key), deadline), now, previous.get("generation"))
        return {**current, "replay": True}

    def inspect_recommendation_operation(self, session_id, generation, resolution_id, request_id, fingerprint, now, *, deadline=None):
        key, request_id = session_key(session_id), request_key(request_id)
        source_hash, now = checked_fingerprint(fingerprint), self._now(now)
        row = self._recovery_read(self._operation_sk(key, "recommend", request_id), deadline)
        if row is None:
            raise WorkflowError("operation_not_recorded", "No stored outcome was found. This read is not permission to create or resume an operation.", 409)
        previous = self._replay(row, source_hash, now)
        if previous.get("generation") != generation:
            raise WorkflowError("request_conflict", "The stored outcome belongs to a different generation.", 409)
        self._current(self._recovery_read(self._session_sk(key), deadline), now, generation, resolution_id)
        if not isinstance(previous.get("result"), dict):
            raise unavailable()
        return {"replay": True, "result": deepcopy(previous["result"])}

    def begin_resolution(self, session_id, request_id, fingerprint, now):
        key, request_id = session_key(session_id), request_key(request_id)
        source_hash, now = checked_fingerprint(fingerprint), self._now(now)
        session_sk, op_sk = self._session_sk(key), self._operation_sk(key, "resolve", request_id)
        operation = self._read(op_sk)
        if operation is not None:
            previous = self._replay(operation, source_hash, now)
            current = self._current(self._read(session_sk), now, previous.get("generation"))
            return {**current, "replay": True}
        current = self._read(session_sk)
        generation = 1 if current is None else current["data"].get("generation", 0) + 1
        if type(generation) is not int or generation < 1:
            raise unavailable()
        session = {"generation": generation, "status": "resolving", "snapshot": None, "expires_at": None}
        operation = {"fingerprint": source_hash, "generation": generation, "status": "pending", "result": None, "started_at": now}
        self._commit([self._put(session_sk, current, session), self._put(op_sk, None, operation)])
        return {"generation": generation, "replay": False, "snapshot": None, "expires_at": None}

    def complete_resolution(self, session_id, generation, request_id, snapshot, expires_at, now):
        key, request_id = session_key(session_id), request_key(request_id)
        now, expires_at = self._now(now), timestamp(expires_at)
        if (not isinstance(snapshot, dict) or expires_at <= now or expires_at > self.retention_until
                or snapshot.get("generation") != generation):
            raise WorkflowError("stale_resolution", "The resolution expired before confirmation could be stored.", 409)
        if (("session_hash" in snapshot and snapshot["session_hash"] != key)
                or ("request_id" in snapshot and snapshot["request_id"] != request_id)):
            raise WorkflowError("invalid_confirmation", "The snapshot is bound to a different session or request.")
        encode(snapshot)
        session_sk, op_sk = self._session_sk(key), self._operation_sk(key, "resolve", request_id)
        current, operation = self._read(session_sk), self._read(op_sk)
        if (current is None or current["data"].get("generation") != generation or current["data"].get("status") != "resolving"
                or operation is None or operation["data"].get("generation") != generation or operation["data"].get("status") != "pending"):
            raise WorkflowError("stale_resolution", "A newer resolution superseded this response.", 409)
        session = {"generation": generation, "status": "resolved", "snapshot": deepcopy(snapshot), "expires_at": expires_at}
        op_data = {**operation["data"], "status": "done"}
        self._commit([self._put(session_sk, current, session), self._put(op_sk, operation, op_data)])

    def current_resolution(self, session_id, now):
        key, now = session_key(session_id), self._now(now)
        return self._current(self._read(self._session_sk(key)), now)

    def begin_recommendation(self, session_id, generation, resolution_id, request_id, fingerprint, now):
        key, request_id = session_key(session_id), request_key(request_id)
        source_hash, now = checked_fingerprint(fingerprint), self._now(now)
        session_sk, op_sk = self._session_sk(key), self._operation_sk(key, "recommend", request_id)
        current = self._read(session_sk)
        self._current(current, now, generation, resolution_id)
        operation = self._read(op_sk)
        if operation is not None:
            previous = self._replay(operation, source_hash, now)
            if previous.get("generation") != generation:
                raise WorkflowError("request_conflict", "That request ID belongs to a different confirmation generation.", 409)
            if not isinstance(previous.get("result"), dict):
                raise unavailable()
            return {"replay": True, "result": deepcopy(previous["result"])}
        data = {"fingerprint": source_hash, "generation": generation, "status": "pending", "result": None, "started_at": now}
        self._commit([self._check(session_sk, current), self._put(op_sk, None, data)])
        return {"replay": False, "result": None}

    def complete_recommendation(self, session_id, generation, resolution_id, request_id, fingerprint, result, now):
        key, request_id = session_key(session_id), request_key(request_id)
        source_hash, now = checked_fingerprint(fingerprint), self._now(now)
        if not isinstance(result, dict):
            raise WorkflowError("invalid_confirmation", "A detached result object is required.")
        encode(result)
        session_sk, op_sk = self._session_sk(key), self._operation_sk(key, "recommend", request_id)
        current, operation = self._read(session_sk), self._read(op_sk)
        self._current(current, now, generation, resolution_id)
        if (operation is None or operation["data"].get("fingerprint") != source_hash
                or operation["data"].get("generation") != generation or operation["data"].get("status") != "pending"):
            raise WorkflowError("request_conflict", "The pending recommendation no longer matches this exact request.", 409)
        self._commit([self._check(session_sk, current), self._put(op_sk, operation, {**operation["data"], "status": "done", "result": result})])

    def fail_operation(self, session_id, kind, request_id, now):
        key, request_id = session_key(session_id), request_key(request_id)
        self._now(now)
        if kind not in {"resolve", "recommend"}:
            raise ValueError("Unknown operation kind")
        op_sk = self._operation_sk(key, kind, request_id)
        operation = self._read(op_sk)
        if operation is not None and operation["data"].get("status") == "pending":
            self._commit([self._put(op_sk, operation, {**operation["data"], "status": "uncertain"})])

    def invalidate_resolution(self, session_id, generation, now):
        key = session_key(session_id)
        self._now(now)
        sk = self._session_sk(key)
        current = self._read(sk)
        if current is not None and current["data"].get("generation") == generation:
            data = {**current["data"], "status": "invalidated", "snapshot": None, "expires_at": None}
            self._commit([self._put(sk, current, data)])
