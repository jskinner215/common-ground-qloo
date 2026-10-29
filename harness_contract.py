"""Narrow Qloo exec 0.1.26 mapping. No process, credential or network transport.

Only an explicitly injected transport is accepted. The brokered composition
binds the pinned direct factory; source receipts do not verify actual service execution.
"""
import asyncio
import hashlib
from copy import deepcopy
import inspect
import json
import math
import re
import time

from workflow import WorkflowError, clean_text, digest, validate_queries
from confirmation_store import session_key, request_key, timestamp

CONTRACT = "@qloo/qloo-harness@0.1.26/1.0-preview.1"
ARCHIVE_SHA256 = "95529b2ac520450e5a2c9701a9baa1d2eccf52f15ccd6ef408aec86397d13ed6"
EVIDENCE_KIND = "configured_unverified"
MAX_BYTES = 131072
LIMIT = 3
MAX_IDENTITY_CANDIDATES = 2
MAX_IDENTITY_LABEL_BYTES = 32
MAX_RECOMMEND_LABEL_BYTES = 32
QUALIFICATION = "Configured transport; real Qloo execution, entitlement and quality are unverified. Local source-bound wrapper receipt, not a vendor-authenticated receipt."
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\Z")
RETRYABLE = {"QLOO_DNS", "QLOO_CONNECT", "QLOO_TIMEOUT", "QLOO_UPSTREAM"}


def refused(message="The normalized harness response failed contract validation."):
    raise WorkflowError("vendor_contract_refused", message, 502)


def entity_id(value):
    if not isinstance(value, str) or not UUID.fullmatch(value):
        refused("A Qloo UUID was required; fixture and unknown IDs are refused.")
    return value.lower()


def artist(value, candidate=False):
    if not isinstance(value, dict):
        refused()
    kind, subtype = value.get("type"), value.get("subtype")
    if (kind not in ("artist", "urn:entity:artist", "urn:entity")
            or (candidate and kind == "urn:entity")
            or (kind == "urn:entity" and subtype != "urn:entity:artist")
            or (subtype is not None and subtype not in ("artist", "urn:entity:artist"))):
        refused("An explicit artist type was required.")
    ident = entity_id(value.get("id" if candidate else "entity_id"))
    try:
        label = clean_text(value.get("name"), 120)
    except WorkflowError:
        refused("An invalid artist label was refused.")
    return {"id": ident, "label": label, "type": "artist"}


def unique_artists(values, candidate=False):
    if not isinstance(values, list) or len(values) > 20:
        refused()
    items = [artist(value, candidate) for value in values]
    if len({item["id"] for item in items}) != len(items):
        refused("Duplicate entity IDs were refused.")
    return items


def strict_json(raw):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        refused("The transport response exceeds the byte budget or is not bytes.")

    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def constant(_value):
        raise ValueError("nonfinite JSON")

    def check(value, depth=0):
        if depth > 16:
            raise ValueError("deep JSON")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("nonfinite number")
        if isinstance(value, (list, dict)):
            if len(value) > 200:
                raise ValueError("wide JSON")
            for item in (value.values() if isinstance(value, dict) else value):
                check(item, depth + 1)

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        check(value)
    except (UnicodeError, ValueError, RecursionError):
        refused("Malformed, duplicate, nonfinite or oversized JSON was refused.")
    if not isinstance(value, dict):
        refused()
    return value


def envelope(value, operation):
    if value.get("operation") != operation:
        refused("The response operation does not match the request.")
    if "error" in value:
        error = value["error"]
        if (not isinstance(error, dict) or set(error) != {"code", "layer", "retryable", "recovery"}
                or not isinstance(error["code"], str) or not isinstance(error["layer"], str)
                or type(error["retryable"]) is not bool or not isinstance(error["recovery"], str)):
            refused()
        code = error["code"]
        failure = WorkflowError("qloo_auth" if code == "QLOO_AUTH" else
                                "qloo_rate_limit" if code == "QLOO_RATE_LIMIT" else "qloo_transport_error",
                                "Qloo access, quota or transport needs review; no endpoint fallback occurred.", 503)
        failure.retryable = code in RETRYABLE and error["retryable"]
        raise failure
    if value.get("schema_version") != "1.0-preview.1":
        refused("Unsupported normalized harness schema version.")
    if value.get("status") not in ("ok", "empty", "needs_input"):
        refused("Partial, degraded or unknown results are not accepted as complete.")
    execution = value.get("execution")
    if (not isinstance(execution, dict)
            or set(execution) != {"transport", "transport_name", "correlation_id", "duration_ms"}
            or execution["transport"] != "direct"
            or not isinstance(execution["duration_ms"], (int, float))
            or isinstance(execution["duration_ms"], bool) or execution["duration_ms"] < 0):
        refused("Unsupported execution transport or metadata.")
    for field in ("transport_name", "correlation_id"):
        try:
            clean_text(execution[field], 160)
        except WorkflowError:
            refused()
    intent = value.get("query_intent")
    if (not isinstance(intent, dict) or intent.get("operation") != operation
            or intent.get("schema_version") != "1.0-preview.1"):
        refused("Missing or mismatched source-bound query intent.")
    results = value.get("results")
    if not isinstance(results, list) or len(results) > 20:
        refused()
    count = value.get("result_count")
    if value["status"] == "needs_input":
        if results:
            refused("Unresolved input cannot carry current recommendations.")
    elif type(count) is not int or count != len(results):
        refused("Result count does not match returned data.")
    return value


def source_receipt(value, request):
    # This is the bridge's ASCII-escaped canonical request, including Unicode
    # names. The logical UTF-8 workflow digest is a different encoding.
    request_hash = hashlib.sha256(json.dumps(request, sort_keys=True, ensure_ascii=True,
        separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    if value["execution"]["correlation_id"] != request_hash:
        refused("The pinned broker correlation digest does not match this exact request.")
    core = {"evidence_kind": EVIDENCE_KIND, "execution_verified": False, "contract": CONTRACT,
            "archive_sha256": ARCHIVE_SHA256, "request_hash": request_hash,
            "response_hash": digest(value), "operation": request["operation"],
            "correlation_id": value["execution"]["correlation_id"]}
    return {**core, "id": digest(core), "qualification": QUALIFICATION}


class QlooHarnessContractAdapter:
    """Adapter for explicit configured transport; not access or live-call authority.

    Transport: async callable(request, *, timeout_seconds, max_response_bytes)
    -> UTF-8 JSON bytes from the normalized `qloo exec` stdout contract. A future
    real process bridge must independently enforce kill/output bounds. No bridge
    or credential lookup is implemented here. Cancellation must be cooperative.
    """
    def __init__(self, transport=None, *, confirmation_store=None,
                 request_timeout=3.0, total_timeout=8.0,
                 resolution_ttl=300.0, clock=time.monotonic, wall_clock=time.time):
        if transport is not None and not (inspect.iscoroutinefunction(transport)
                or inspect.iscoroutinefunction(getattr(transport, "__call__", None))):
            raise ValueError("An explicit asynchronous transport is required.")
        for number, maximum in ((request_timeout, 10), (total_timeout, 20), (resolution_ttl, 600)):
            if type(number) not in (int, float) or not math.isfinite(number) or not 0 < number <= maximum:
                raise ValueError("Invalid time budget.")
        self.transport = transport
        self.request_timeout, self.total_timeout, self.resolution_ttl = request_timeout, total_timeout, resolution_ttl
        self.clock, self.wall_clock, self.store = clock, wall_clock, confirmation_store

    def _store(self):
        if self.transport is None:
            raise WorkflowError("provider_disconnected", "No Qloo transport or credential access is configured.", 503)
        if self.store is None:
            raise WorkflowError("confirmation_store_unconfigured", "An explicitly configured durable session store is required.", 503)
        return self.store

    @staticmethod
    def _snapshot(snapshot, session_id, queries):
        if not isinstance(snapshot, dict):
            refused("Stored confirmation is invalid.")
        core = {key: value for key, value in snapshot.items() if key != "resolution_id"}
        if (snapshot.get("resolution_id") != digest(core)
                or snapshot.get("session_hash") != session_key(session_id)
                or snapshot.get("query_hash") != digest(queries)
                or snapshot.get("contract") != CONTRACT
                or snapshot.get("evidence_kind") != EVIDENCE_KIND
                or type(snapshot.get("generation")) is not int
                or snapshot["generation"] < 1
                or not isinstance(snapshot.get("choices"), list) or len(snapshot["choices"]) != 2):
            raise WorkflowError("stale_resolution", "The stored session, source or artist names changed; resolve again.", 409)
        return deepcopy(snapshot)

    @staticmethod
    def _view(snapshot, queries, expires_at):
        result = deepcopy(snapshot)
        result.pop("session_hash", None)
        result["queries"] = list(queries)
        result["choices"] = [{**choice, "query": query} for choice, query in zip(result["choices"], queries)]
        result.update(expires_at_unix=expires_at, requires_human_confirmation=True, qualification=QUALIFICATION)
        return result

    def _failed(self, session_id, kind, request_id):
        try:
            self.store.fail_operation(session_id, kind, request_id, timestamp(self.wall_clock()))
        except WorkflowError:
            # The existing pending record still prevents an automatic duplicate.
            pass

    async def resolve_pair(self, queries, *, session_id, request_id):
        store = self._store()
        session_key(session_id)
        request_key(request_id)
        if len(request_id) > 32:
            raise WorkflowError("invalid_request_id", "This bounded resolution accepts operation IDs from 8 to 32 characters.")
        try:
            source_hash = digest({"queries": queries})
        except (ValueError, TypeError, RecursionError):
            raise WorkflowError("invalid_queries", "Use a bounded pair of artist names.") from None
        lease = store.begin_resolution(session_id, request_id, source_hash, timestamp(self.wall_clock()))
        try:
            normalized = validate_queries(queries)
            if lease["replay"]:
                snapshot = self._snapshot(lease["snapshot"], session_id, normalized)
                if snapshot["generation"] != lease["generation"]:
                    raise WorkflowError("stale_resolution", "Stored confirmation generation disagrees with its lease.", 409)
                return self._view(snapshot, normalized, lease["expires_at"])
            snapshot = await self._resolve_pair(normalized, session_id, lease["generation"], request_id)
            now = timestamp(self.wall_clock())
            expires_at = now + self.resolution_ttl
            store.complete_resolution(session_id, lease["generation"], request_id, snapshot, expires_at, now)
            return self._view(snapshot, normalized, expires_at)
        except BaseException:
            self._failed(session_id, "resolve", request_id)
            raise

    async def recommend_pair(self, queries, resolution_id, selected_ids, *, session_id, request_id):
        store = self._store()
        queries = validate_queries(queries)
        current = store.current_resolution(session_id, timestamp(self.wall_clock()))
        resolved = self._snapshot(current["snapshot"], session_id, queries)
        if resolved["generation"] != current["generation"]:
            raise WorkflowError("stale_resolution", "Stored confirmation generation disagrees with its lease.", 409)
        if resolution_id != resolved["resolution_id"]:
            raise WorkflowError("stale_resolution", "Resolve and explicitly confirm the current artist pair again.", 409)
        selected = self._selected(resolved, selected_ids)
        selected_ids = [item["id"] for item in selected]
        source_hash = digest({"queries": queries, "resolution_id": resolution_id, "selected_ids": selected_ids})
        lease = store.begin_recommendation(session_id, current["generation"], resolution_id,
                                           request_id, source_hash, timestamp(self.wall_clock()))
        if lease["replay"]:
            return self._cached_recommendation(lease["result"], resolution_id, selected_ids)
        try:
            def authorize_attempt():
                latest = store.current_resolution(session_id, timestamp(self.wall_clock()))
                if (latest["generation"] != current["generation"]
                        or latest["snapshot"].get("resolution_id") != resolution_id):
                    raise WorkflowError("stale_resolution", "A newer resolution requires another identity review.", 409)
            result = await self._recommend_pair(resolved, selected_ids, selected, authorize_attempt)
            store.complete_recommendation(session_id, current["generation"], resolution_id,
                                          request_id, source_hash, result, timestamp(self.wall_clock()))
            return deepcopy(result)
        except BaseException as error:
            if isinstance(error, WorkflowError) and error.code == "confirmation_changed":
                store.invalidate_resolution(session_id, current["generation"], timestamp(self.wall_clock()))
            self._failed(session_id, "recommend", request_id)
            raise

    @staticmethod
    def _cached_recommendation(cached, resolution_id, selected_ids):
        if (not isinstance(cached, dict)
                or cached.get("receipt_id") != digest({key: value for key, value in cached.items() if key != "receipt_id"})
                or cached.get("resolution_id") != resolution_id
                or cached.get("contract") != CONTRACT or cached.get("evidence_kind") != EVIDENCE_KIND
                or not isinstance(cached.get("selected"), list)
                or any(not isinstance(item, dict) for item in cached["selected"])
                or [item.get("id") for item in cached["selected"]] != selected_ids):
            raise WorkflowError("invalid_cached_receipt", "The stored receipt does not match the confirmed pair; no retry started.", 503)
        return deepcopy(cached)

    def recover_known_resolution(self, queries, *, session_id, request_id, deadline=None):
        store = self._store()
        try:
            source_hash = digest({"queries": queries})
        except (ValueError, TypeError, RecursionError):
            raise WorkflowError("invalid_queries", "Use a bounded pair of artist names.") from None
        queries = validate_queries(queries)
        request_key(request_id)
        if len(request_id) > 32:
            raise WorkflowError("invalid_request_id", "Use the original bounded resolve operation ID.")
        inspect = getattr(store, "inspect_resolution_operation", None)
        if not callable(inspect):
            raise WorkflowError("recovery_unavailable", "This store has no qualified read-only recovery operation.", 503)
        result = inspect(session_id, request_id, source_hash, timestamp(self.wall_clock()), deadline=deadline)
        snapshot = self._snapshot(result["snapshot"], session_id, queries)
        if snapshot["generation"] != result["generation"]:
            raise WorkflowError("stale_resolution", "The stored generation changed.", 409)
        return self._view(snapshot, queries, result["expires_at"])

    def recover_known_recommendation(self, queries, resolution_id, selected_ids, *, session_id, request_id, deadline=None):
        store, queries = self._store(), validate_queries(queries)
        current_reader = getattr(store, "inspect_current_resolution", None)
        operation_reader = getattr(store, "inspect_recommendation_operation", None)
        if not callable(current_reader) or not callable(operation_reader):
            raise WorkflowError("recovery_unavailable", "This store has no qualified read-only recovery operation.", 503)
        now = timestamp(self.wall_clock())
        current = current_reader(session_id, now, deadline=deadline)
        resolved = self._snapshot(current["snapshot"], session_id, queries)
        if resolution_id != resolved["resolution_id"] or resolved["generation"] != current["generation"]:
            raise WorkflowError("stale_resolution", "The stored source or generation changed.", 409)
        selected_ids = [item["id"] for item in self._selected(resolved, selected_ids)]
        source_hash = digest({"queries": queries, "resolution_id": resolution_id, "selected_ids": selected_ids})
        result = operation_reader(session_id, current["generation"], resolution_id, request_id, source_hash, now, deadline=deadline)
        return self._cached_recommendation(result["result"], resolution_id, selected_ids)

    async def _request(self, operation, payload, deadline, authorize_attempt=None):
        if self.transport is None:
            raise WorkflowError("provider_disconnected", "No brokered transport is configured.", 503)
        request = {"surface": "qloo exec", "operation": operation, "input": deepcopy(payload)}
        remaining = min(self.request_timeout, deadline - self.clock())
        if remaining <= 0:
            raise WorkflowError("qloo_timeout", "The total request budget expired.", 504)
        if authorize_attempt is not None:
            authorize_attempt()
        try:
            raw = await asyncio.wait_for(self.transport(deepcopy(request), timeout_seconds=remaining,
                max_response_bytes=MAX_BYTES), remaining)
            if self.clock() > deadline:
                raise WorkflowError("qloo_timeout", "A late response was refused.", 504)
            value = envelope(strict_json(raw), operation)
            return value, source_receipt(value, request)
        except TimeoutError:
            raise WorkflowError("qloo_timeout", "The brokered attempt timed out; its outcome may be uncertain. No retry occurred.", 504) from None
        except WorkflowError:
            raise
        except Exception:
            raise WorkflowError("qloo_transport_error", "The brokered attempt failed; its outcome may be uncertain. No fallback or retry occurred.", 503) from None

    async def _resolve_pair(self, queries, session_id, generation, request_id):
        deadline = self.clock() + self.total_timeout
        choices, sources = [], []
        for query in queries:
            value, source = await self._request("describe", {"entity": query, "type": "artist"}, deadline)
            intent = value["query_intent"].get("target")
            if intent != {"type": "artist", "entities": [query]}:
                refused("Describe intent does not match the exact requested name/type.")
            resolution = value.get("resolution")
            if not isinstance(resolution, dict):
                refused("A source resolution report is required.")
            if value["status"] == "needs_input":
                issues = resolution.get("issues")
                if (not isinstance(issues, list) or len(issues) != 1 or not isinstance(issues[0], dict)
                        or issues[0].get("input") != query or issues[0].get("field") != "entity"
                        or issues[0].get("input_kind") != "entity"
                        or issues[0].get("scope") not in ("artist", "urn:entity:artist")
                        or issues[0].get("kind") not in ("ambiguous", "not_found")):
                    refused("Unresolved artist choice was not bound to this name.")
                issue = issues[0]
                candidates = unique_artists(issue.get("candidates", []), candidate=True)
                if (issue["kind"] == "not_found" and candidates) or (issue["kind"] == "ambiguous" and len(candidates) < 2):
                    refused("Ambiguity state conflicts with candidates.")
            else:
                outcomes = resolution.get("outcomes")
                if (value["status"] != "ok" or not isinstance(outcomes, list) or len(outcomes) != 1
                        or not isinstance(outcomes[0], dict) or outcomes[0].get("input") != query
                        or outcomes[0].get("status") != "resolved"
                        or outcomes[0].get("match") not in ("identifier", "exact", "semantic")):
                    refused("Resolved artist identity was not bound to this name.")
                candidates = [artist(outcomes[0].get("selected"), candidate=True)]
                if unique_artists(value["results"]) != candidates:
                    refused("Hydrated artist and resolved identity disagree.")
            # No candidate or label is truncated. Broader identities need a
            # more specific query before any confirmation snapshot is committed.
            if (len(candidates) > MAX_IDENTITY_CANDIDATES
                    or any(len(item["label"].encode("utf-8")) > MAX_IDENTITY_LABEL_BYTES for item in candidates)):
                raise WorkflowError("identity_too_broad", "Use a more specific public artist name. At most two candidates per name and exact labels up to 32 UTF-8 bytes fit this private confirmation limit; no candidates or labels were truncated.", 413)
            choices.append({"query": query, "state": "none" if not candidates else "one_candidate" if len(candidates) == 1 else "ambiguous",
                            "candidates": candidates})
            sources.append(source)
        core = {"query_hash": digest(queries), "choices": [{key: value for key, value in choice.items() if key != "query"} for choice in choices],
                "sources": sources, "contract": CONTRACT, "generation": generation,
                "request_id": request_id, "session_hash": session_key(session_id), "evidence_kind": EVIDENCE_KIND}
        return {**core, "resolution_id": digest(core)}

    @staticmethod
    def _selected(resolved, selected_ids):
        if (not isinstance(selected_ids, list) or len(selected_ids) != 2
                or any(not isinstance(ident, str) for ident in selected_ids)):
            raise WorkflowError("invalid_pair", "Select one reviewed UUID from each name.")
        selected_ids = [entity_id(ident) for ident in selected_ids]
        if len(set(selected_ids)) != 2:
            raise WorkflowError("same_artist", "Confirm two distinct artists.")
        selected = []
        for index, ident in enumerate(selected_ids):
            candidates = resolved["choices"][index]["candidates"]
            if ident not in {candidate["id"] for candidate in candidates}:
                raise WorkflowError("unconfirmed_artist", "The UUID was not in that name's reviewed candidates.")
            selected.append(next(deepcopy(item) for item in candidates if item["id"] == ident))
        return selected

    @staticmethod
    def _same_pair(value, selected_ids):
        return (isinstance(value, dict) and set(value) == {"entities"}
            and isinstance(value["entities"], list)
            and [entity_id(ident) for ident in value["entities"]] == selected_ids)

    async def _recommend_pair(self, resolved, selected_ids, selected, authorize_attempt):
        resolution_id = resolved["resolution_id"]
        request = {"target_type": "artist", "signals": selected_ids, "limit": LIMIT, "explain": False}
        value, source = await self._request("recommend", request, self.clock() + self.total_timeout, authorize_attempt)
        if value["status"] == "needs_input":
            raise WorkflowError("confirmation_changed", "Qloo requires another identity review; prior confirmation was cleared.", 409)
        if value["status"] != "ok":
            refused()
        interpretation, intent = value.get("interpretation"), value["query_intent"]
        if (not isinstance(interpretation, dict) or interpretation.get("target_type") != "urn:entity:artist"
                or intent.get("target") != {"type": "artist"}
                or not self._same_pair(intent.get("signals"), selected_ids)):
            refused("The recommendation intent differs from the confirmed artist pair.")
        signals = interpretation.get("signals")
        if (not isinstance(signals, list) or len(signals) != 2
                or any(not isinstance(item, dict) for item in signals)
                or [entity_id(item.get("entityId")) for item in signals] != selected_ids
                or [entity_id(item.get("input")) for item in signals] != selected_ids):
            refused("Interpreted source IDs differ from the confirmed pair.")
        provenance = value.get("provenance")
        expected_query = {"filter.type": "urn:entity:artist", "take": LIMIT, "signal.interests.entities": selected_ids}
        requests = deepcopy(provenance.get("requests")) if isinstance(provenance, dict) else None
        if (isinstance(requests, list) and len(requests) == 1 and isinstance(requests[0], dict)
                and isinstance(requests[0].get("query"), dict)):
            ids = requests[0]["query"].get("signal.interests.entities")
            if isinstance(ids, list):
                requests[0]["query"]["signal.interests.entities"] = [entity_id(value) for value in ids]
        if (not isinstance(provenance, dict) or provenance.get("source") != "Qloo API"
                or provenance.get("endpoint") != "/v2/insights"
                or provenance.get("transport") != "direct"
                or requests != [{"method": "GET", "path": "/v2/insights", "query": expected_query}]):
            refused("Request provenance differs from the reviewed narrow workflow.")
        items = unique_artists(value["results"])
        if any(len(item["label"].encode("utf-8")) > MAX_RECOMMEND_LABEL_BYTES for item in items):
            raise WorkflowError("recommendation_too_broad", "This bounded receipt accepts exact recommendation labels up to 32 UTF-8 bytes. No result or label was truncated; provider requests already spent remain consumed.", 413)
        if len(items) > LIMIT:
            refused()
        result = {"evidence_kind": EVIDENCE_KIND, "contract": CONTRACT, "resolution_id": resolution_id,
                  "selected": selected, "state": "recommendations" if items else "none",
                  "items": [{**item, "rank": rank} for rank, item in enumerate(items, 1) if item["id"] not in selected_ids],
                  "source": source, "qualification": QUALIFICATION,
                  "interpretation_limit": "One combined aggregate affinity query; no separate per-person support or personal preference prediction is established."}
        if not result["items"]:
            result["state"] = "none"
        result["receipt_id"] = digest(result)
        return result
