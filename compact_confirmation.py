"""Lossless native-Binary wrapper for the existing confirmation protocol.

No SDK, credential, network, listener or default client is created. The caller
must inject the same qloo quota mutation gate used for admission. Compressed
records are a new versioned format; legacy/string rows are deliberately refused.
"""
from copy import deepcopy
import base64
import hashlib
import json
import re
import uuid
import zlib

from confirmation_store import MAX_STORED_BYTES, encode
from dynamodb_confirmation_store import DynamoDBConfirmationStore
from workflow import WorkflowError
from global_quota_v2 import flat_item_size


MAX_ITEM_BYTES = 1024
KEY = re.compile(r"(?:session#[0-9a-f]{64}|operation#[0-9a-f]{64}#(?:resolve|recommend)#[0-9a-f]{64})\Z")
MAGIC = b"qz4"
# Versioned, source-pinned schema dictionary. This removes no logical fields:
# the complete canonical payload still has a checked length and SHA256, and
# decompressing with a different dictionary fails those checks.
DICTIONARY = (b'contract archive_sha256 request_hash response_hash correlation_id operation '
    b'evidence_kind execution_verified configured_unverified qualification id sources '
    b'@qloo/qloo-harness@0.1.26/1.0-preview.1 '
    b'95529b2ac520450e5a2c9701a9baa1d2eccf52f15ccd6ef408aec86397d13ed6 '
    b'Configured transport; real Qloo execution, entitlement and quality are unverified. '
    b'Local source-bound wrapper receipt, not a vendor-authenticated receipt. '
    b'session_hash query_hash generation choices candidates state one_candidate ambiguous '
    b'selected selected_ids resolution_id receipt_id result snapshot expires_at request_id '
    b'query label type artist describe recommend interpretation_limit requires_human_confirmation '
    b'One combined aggregate affinity query; no separate per-person support or personal preference prediction is established. '
    b'pending done uncertain needs_input recommendations source rank items fingerprint version')
HEADER_BYTES = len(MAGIC) + 4 + 32


class CompactError(ValueError):
    """Sanitized refusal; no logical payload or service values in the error."""


def _size(item):
    try:
        return flat_item_size(item)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise CompactError("Invalid compact record.") from None


def _shape(item, payload_type="S"):
    if (not isinstance(item, dict) or set(item) != {"PK", "SK", "revision", "payload", "expireAt"}
            or item.get("PK") != {"S": "qloo"}
            or not isinstance(item.get("SK"), dict) or set(item["SK"]) != {"S"}
            or not isinstance(item["SK"]["S"], str) or not KEY.fullmatch(item["SK"]["S"])
            or not isinstance(item.get("payload"), dict) or set(item["payload"]) != {payload_type}
            or not isinstance(item["payload"][payload_type], str if payload_type == "S" else (bytes, bytearray))):
        raise CompactError("Invalid compact record.")
    for field in ("revision", "expireAt"):
        if (not isinstance(item.get(field), dict) or set(item[field]) != {"N"}
                or not isinstance(item[field]["N"], str) or not re.fullmatch(r"[1-9][0-9]{0,9}", item[field]["N"])):
            raise CompactError("Invalid compact record.")


def _key(key):
    return (isinstance(key, dict) and set(key) == {"PK", "SK"} and key["PK"] == {"S": "qloo"}
            and isinstance(key["SK"], dict) and set(key["SK"]) == {"S"}
            and isinstance(key["SK"]["S"], str) and KEY.fullmatch(key["SK"]["S"]) is not None)


def _canonical_payload(text):
    if not isinstance(text, str):
        raise CompactError("Invalid compact payload.")
    try:
        raw = text.encode("utf-8")
        if not 0 < len(raw) <= MAX_STORED_BYTES:
            raise ValueError()
        data = json.loads(text)
        if not isinstance(data, dict) or encode(data) != text:
            raise ValueError()
        return raw
    except (ValueError, TypeError, UnicodeError, RecursionError, WorkflowError):
        raise CompactError("Invalid compact payload.") from None


def _pack_strings(value):
    """Reversible storage encoding only. Canonical logical payload stays intact.

    Hex hashes and UUIDs carry no more information than their binary values;
    bounded base64 tokens avoid paying their JSON hex expansion. Literal token
    prefixes are escaped, so arbitrary user labels cannot impersonate a token.
    """
    if isinstance(value, str):
        if value.startswith("~"):
            return "~s" + value
        if re.fullmatch(r"[0-9a-f]{64}", value):
            return "~h" + base64.b64encode(bytes.fromhex(value)).decode("ascii")
        if re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
            return "~u" + base64.b64encode(uuid.UUID(value).bytes).decode("ascii")
        return value
    if isinstance(value, list):
        return [_pack_strings(v) for v in value]
    if isinstance(value, dict):
        return {k: _pack_strings(v) for k, v in value.items()}
    return value


def _unpack_strings(value):
    if isinstance(value, str) and value.startswith("~"):
        if value.startswith("~s"):
            return value[2:]
        try:
            raw = base64.b64decode(value[2:], validate=True)
            if value.startswith("~h") and len(raw) == 32:
                return raw.hex()
            if value.startswith("~u") and len(raw) == 16:
                return str(uuid.UUID(bytes=raw))
        except (ValueError, UnicodeError):
            pass
        raise CompactError("Invalid compact string token.")
    if isinstance(value, list):
        return [_unpack_strings(v) for v in value]
    if isinstance(value, dict):
        return {k: _unpack_strings(v) for k, v in value.items()}
    return value


def compact_item(item):
    """Lossless new image, bounded by native S/N/B item bytes, not wire JSON."""
    _shape(item)
    raw = _canonical_payload(item["payload"]["S"])
    compressor = zlib.compressobj(level=9, zdict=DICTIONARY)
    encoded = encode(_pack_strings(json.loads(raw))).encode("utf-8")
    compressed = compressor.compress(encoded) + compressor.flush()
    packed = MAGIC + len(raw).to_bytes(4, "big") + hashlib.sha256(raw).digest() + compressed
    wire = {**deepcopy(item), "payload": {"B": packed}}
    if _size(wire) > MAX_ITEM_BYTES:
        raise CompactError("Confirmation data does not fit the explicit compact capacity limit; no data was truncated.")
    return wire


def inflate_item(item):
    """Check bounded flat S/N/B item size, then decompress and validate."""
    _shape(item, "B")
    if _size(item) > MAX_ITEM_BYTES:
        raise CompactError("Stored confirmation exceeds the compact capacity limit.")
    packed = bytes(item["payload"]["B"])
    if len(packed) < HEADER_BYTES + 1 or packed[:len(MAGIC)] != MAGIC:
        raise CompactError("Unknown confirmation storage format.")
    length = int.from_bytes(packed[len(MAGIC):len(MAGIC)+4], "big")
    expected_hash = packed[len(MAGIC)+4:HEADER_BYTES]
    if not 0 < length <= MAX_STORED_BYTES:
        raise CompactError("Invalid compact payload size.")
    try:
        compressed = packed[HEADER_BYTES:]
        decompressor = zlib.decompressobj(zdict=DICTIONARY)
        encoded = decompressor.decompress(compressed, MAX_STORED_BYTES + 1)
        if (len(encoded) > MAX_STORED_BYTES or not decompressor.eof
                or decompressor.unused_data or decompressor.unconsumed_tail):
            raise ValueError()
        encoded_text = encoded.decode("utf-8")
        packed_value = json.loads(encoded_text)
        if encode(packed_value) != encoded_text:
            raise ValueError()
        text = encode(_unpack_strings(packed_value))
        raw = text.encode("utf-8")
        if len(raw) != length or hashlib.sha256(raw).digest() != expected_hash:
            raise ValueError()
        _canonical_payload(text)
    except (ValueError, UnicodeError, zlib.error, CompactError):
        raise CompactError("Stored compact payload failed validation.") from None
    return {**deepcopy(item), "payload": {"S": text}}


class CompactClient:
    """Read raw injected client; mutate only through the shared app gate.

    `waiter`, if supplied, is passed to the gate for its bounded *pre-mutation*
    pacing wait. No default sleep or transaction retry is introduced here.
    """
    def __init__(self, client, *, table_name, mutation_gate, waiter=None):
        if (client is None or not callable(getattr(client, "get_item", None))
                or mutation_gate is None or not callable(getattr(mutation_gate, "guarded_transact", None))
                or getattr(getattr(mutation_gate, "policy", None), "app_id", None) != "qloo"
                or getattr(mutation_gate, "table_name", None) != table_name
                or getattr(mutation_gate, "client", None) is not client
                or not isinstance(table_name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", table_name)
                or (waiter is not None and not callable(waiter))):
            raise ValueError("Inject the explicit raw client and same-table qloo mutation gate.")
        self.client, self.table_name, self.gate, self.waiter = client, table_name, mutation_gate, waiter

    def get_item(self, **kwargs):
        if (set(kwargs) != {"TableName", "Key", "ConsistentRead"} or kwargs["TableName"] != self.table_name
                or kwargs["ConsistentRead"] is not True or not _key(kwargs["Key"])):
            raise CompactError("Use exact strong confirmation reads.")
        response = self.client.get_item(**kwargs)
        if not isinstance(response, dict):
            raise CompactError("Confirmation read unavailable.")
        if response.get("Item") is None:
            return {}
        item = inflate_item(response["Item"])
        if {"PK": item["PK"], "SK": item["SK"]} != kwargs["Key"]:
            raise CompactError("Confirmation read key mismatch.")
        return {"Item": item}

    def transact_write_items(self, **kwargs):
        if set(kwargs) != {"TransactItems"} or not isinstance(kwargs["TransactItems"], list) or not 1 <= len(kwargs["TransactItems"]) <= 2:
            raise CompactError("Use one bounded confirmation transition.")
        # Complete every conversion before the gate is allowed to mutate.
        writes = deepcopy(kwargs["TransactItems"])
        for operation in writes:
            if not isinstance(operation, dict) or len(operation) != 1:
                raise CompactError("Invalid confirmation transition.")
            kind, value = next(iter(operation.items()))
            if kind not in {"Put", "ConditionCheck"} or not isinstance(value, dict) or value.get("TableName") != self.table_name:
                raise CompactError("Invalid confirmation transition.")
            if kind == "Put":
                value["Item"] = compact_item(value["Item"])
            else:
                key = value.get("Key")
                if not _key(key):
                    raise CompactError("Invalid confirmation condition key.")
        return self.gate.guarded_transact(writes, waiter=self.waiter)


class CompactConfirmationStore(DynamoDBConfirmationStore):
    """Existing seven-method CAS/replay semantics, new strict wire format."""
    def __init__(self, client, *, table_name, retention_until, mutation_gate, waiter=None):
        if getattr(getattr(mutation_gate, "policy", None), "retention_until", None) != retention_until:
            raise ValueError("Confirmation and quota retention must match.")
        wrapper = CompactClient(client, table_name=table_name, mutation_gate=mutation_gate, waiter=waiter)
        super().__init__(wrapper, table_name=table_name, retention_until=retention_until)

    def _put(self, sk, previous, data):
        change = super()._put(sk, previous, data)
        try:
            compact_item(change["Put"]["Item"])
        except CompactError:
            raise WorkflowError("confirmation_capacity", "Complete confirmation data exceeds the compact capacity limit. No fields were dropped and no write occurred.", 413) from None
        return change

    def _commit(self, changes):
        try:
            self.client.transact_write_items(TransactItems=changes)
        except Exception as error:
            code = getattr(error, "code", None)
            if code == "qloo_deadline_before_mutation":
                raise WorkflowError("confirmation_deadline", "The operation deadline refused this confirmation transaction before it started. A pending barrier may remain; inspect the original outcome without resending provider work.", 504) from None
            if code == "control_guard_not_executed":
                raise WorkflowError("confirmation_guard_not_executed", "The local history guard refused before the durable client was called. No transaction started.", 503) from None
            if code == "quota_conflict":
                raise WorkflowError("confirmation_conflict", "Another confirmation or admission transition won the shared version check. No retry occurred.", 409) from None
            if code == "quota_paced":
                raise WorkflowError("confirmation_paced", "This app is pacing storage transitions. No transaction started.", 429) from None
            raise WorkflowError("confirmation_store_unavailable", "Durable confirmation storage is unavailable; no provider request may start.", 503) from None
