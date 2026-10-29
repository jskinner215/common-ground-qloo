"""Pinned official-factory composition. No HTTP, credential or bootstrap code.

An explicitly injected single-HTTP callback is trusted host code. Configured
output is unverified; local source receipts are not authenticated by Qloo.
"""
import asyncio
from contextvars import ContextVar
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import inspect
import math
import re
import time
from urllib.parse import urlsplit

from paid_entitlement import PaidQualificationEntitlement
from public_paid_entitlement import PublicPaidEntitlement

from review_fence import FencedCompactStore, FencedHarnessAdapter
from edge_base import DemoHandler, EdgeConfig, EdgeError, QlooDomain, SECURITY, V2_NOTICE, canonical
from global_quota_v2 import DynamoQuotaStore, RequestPermit
from deadline_quota import DeadlineQuotaStore
from control_guard import ExistingControlClient
from harness_contract import CONTRACT, entity_id
from official_bridge import OfficialFactoryOfflineBridge
from bridge import strict_json as raw_json
from workflow import WorkflowError

HOST = "https://hackathon.api.qloo.com"
NODE_SHA256 = "e237a2839d0cbdc9a9a2adda1a184afc0f5b20306ffbe923af5686550472d8a8"
CHILD_SHA256 = "5cf32da53479b36bf339963a9f80d6c83ff5fa796ff6925d320c5b135adf677c"
LOCK_SHA256 = "71da13c95e3305567173d7a283ff2b41eb13f723913f50706d4f9209c53e6283"
ROUTE_BOUNDS = {"/api/resolve": 4, "/api/shortlist": 3}
_REQUEST = ContextVar("qloo_brokered_composition_request", default=None)


@dataclass(frozen=True)
class TrustedEntitlement:
    """Host assertions, not verification performed by this code or approval.

    Future host must independently verify the terms/caps and call authority.
    Tests use hypothetical synthetic values; actual Qloo allowance is unknown.
    """
    api_host: str
    daily_raw_limit: int
    lifetime_raw_limit: int
    expires_at: int
    evidence_sha256: str
    free_no_automatic_overage_verified: bool = False
    host_explicitly_enabled: bool = False

    def validate(self, config, policy):
        if (self.api_host != HOST or self.free_no_automatic_overage_verified is not True
                or self.host_explicitly_enabled is not True
                or type(self.daily_raw_limit) is not int or self.daily_raw_limit < 4
                or type(self.lifetime_raw_limit) is not int or self.lifetime_raw_limit < 4
                or type(self.expires_at) is not int or self.expires_at < config.expires_at
                or not isinstance(self.evidence_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.evidence_sha256)
                or policy.entitlement_daily != self.daily_raw_limit
                or policy.entitlement_lifetime != self.lifetime_raw_limit):
            raise ValueError("Explicit trusted-host verified free entitlement, exact caps, expiry and evidence are required.")


def validate_host_entitlement(entitlement, config, policy, *, credential_account_ref=None,
                              table_name=None, clock=time.time):
    """Exact type dispatch. Paid facts rechecked before admission and raw I/O."""
    if type(entitlement) is TrustedEntitlement:
        entitlement.validate(config,policy)
    elif type(entitlement) in (PaidQualificationEntitlement, PublicPaidEntitlement):
        now=clock()
        if type(now) not in (int,float) or not math.isfinite(now):
            raise ValueError('A finite trusted paid-account clock is required.')
        entitlement.validate(config,policy,credential_account_ref=credential_account_ref,
                             table_name=table_name,now=int(now))
    else:
        raise ValueError('An exact reviewed free or paid entitlement type is required.')


class BoundQlooDomain(QlooDomain):
    def __init__(self, adapter, mode, *, policy_live_enabled=False):
        # No fictional workflow fallback is initialized or retained.
        self.adapter, self.mode = adapter, mode
        self.live_enabled = adapter is not None and policy_live_enabled is True

    def get(self, path):
        if path == "/api/provider":
            return {"provider": {"name": "Qloo pinned direct factory", "status": self.mode,
                "execution_verified": False}, "mode": self.mode, "contract": CONTRACT,
                "live_enabled": self.live_enabled, "configured_transport_enabled": self.adapter is not None,
                "raw_accounting_offline_qualified": self.adapter is not None,
                "service_execution_qualified": False,
                "qualification": "Configured transport is not a verified service or vendor-authenticated receipt."}
        raise EdgeError("not_found", "No such private composition route.", 404)

    def post(self, path, packet):
        if self.adapter is None or self.mode != "configured_unverified":
            raise EdgeError("provider_disconnected", "No explicitly approved, qualified host binding exists.", 503)
        needed = {"queries", "request_id"} if path == "/api/resolve" else {"queries", "resolution_id", "selected_ids", "request_id"}
        if set(packet) != needed:
            raise EdgeError("invalid_request", "Use only the displayed reviewed-pair fields.")
        binding = _REQUEST.get()
        if not isinstance(binding, dict) or not isinstance(binding.get("permit"), RequestPermit) or not binding.get("session_id"):
            raise EdgeError("session_required", "Use a validated, raw-budgeted composition request.", 403)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            raise EdgeError("async_boundary", "Use the synchronous isolated request boundary.", 503)
        try:
            if path == "/api/resolve":
                operation = self.adapter.resolve_pair(packet["queries"], request_id=packet["request_id"], session_id=binding["session_id"])
            else:
                operation = self.adapter.recommend_pair(packet["queries"], packet["resolution_id"], packet["selected_ids"],
                    request_id=packet["request_id"], session_id=binding["session_id"])
            return asyncio.run(operation)
        except WorkflowError as error:
            raise EdgeError(error.code, error.message, error.status) from None


class QlooComposition(DemoHandler):
    def _check_session(self, cookies, now):
        session = super()._check_session(cookies, now)
        binding = _REQUEST.get()
        if not isinstance(binding, dict):
            raise EdgeError("session_required", "Use a composition request.", 403)
        binding["session_id"] = hashlib.sha256(session.encode("utf-8")).hexdigest()
        return session

    def _validate_packet(self, path, packet):
        if path == "/api/resolve":
            request_id = packet.get("request_id") if isinstance(packet, dict) else None
            if not isinstance(request_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{8,32}", request_id):
                raise EdgeError("invalid_request_id", "Use one resolution operation ID from 8 to 32 characters.")
        if path != "/api/shortlist":
            return
        selected = packet.get("selected_ids") if isinstance(packet, dict) else None
        try:
            if (not isinstance(selected, list) or len(selected) != 2
                    or len({entity_id(ident) for ident in selected}) != 2):
                raise WorkflowError("invalid_pair", "Confirm two distinct vendor-compatible UUIDs.")
        except WorkflowError:
            raise EdgeError("invalid_pair", "Confirm two distinct version 1 to 5 UUIDs with a valid RFC 4122 variant.") from None

    def _recheck_paid(self):
        if type(self.host_entitlement) in (PaidQualificationEntitlement, PublicPaidEntitlement):
            try:
                validate_host_entitlement(self.host_entitlement,self.config,self.host_policy,
                    credential_account_ref=self.credential_account_ref,
                    table_name=self.host_table_name,clock=self.clock)
            except Exception:
                raise EdgeError('paid_entitlement_expired_or_invalid',
                    'The exact paid account, budget and period no longer permit a new attempt.',403) from None

    def _reserve(self, path, request_id, fingerprint):
        if self.domain.adapter is None:
            raise EdgeError("provider_disconnected", "No configured provider action is enabled.", 503)
        binding = _REQUEST.get()
        if not binding or not binding.get("session_id"):
            raise EdgeError("session_required", "Use a validated session.", 403)
        self._recheck_paid()
        permit = self.route_quotas[path].reserve(request_id, fingerprint, use_provider=True)
        if (type(permit) is not RequestPermit or permit.app_id != "qloo"
                or permit.fingerprint != fingerprint or permit.raw_reserved != ROUTE_BOUNDS[path]):
            if callable(getattr(permit, "close", None)):
                permit.close()
            raise EdgeError("reservation_rejected", "The exact route-bound raw reservation is required.", 503)
        binding.update(permit=permit, route=path, fingerprint=fingerprint)

    def _index(self, now):
        response = super()._index(now)
        until = (datetime.fromtimestamp(self.retention_until, timezone.utc).isoformat()
                 if self.retention_until is not None else "no configured store")
        notice = ('<aside class="notice" aria-label="Data and retention notice">'
            'Signal Duet: confirm two artists, then inspect one combined Qloo recommendation. '
            'This configured connection has not been qualified against the service. Requests may send artist names '
            'and confirmed Qloo entity IDs to Qloo after separate host approval. Enter public artist names only; '
            'never enter personal names, emails, private text or client information. Qloo terms allow ongoing use '
            'of anonymized input signals and do not promise their deletion. Private server query, confirmation '
            'and result records expire at '+until+'. Local expiry does not delete provider-held data. '
            'Allowance, actual service behavior and recommendation quality remain unverified. '
            '<a href="https://www.qloo.com/legal/terms" rel="noreferrer">Qloo terms</a> and '
            '<a href="https://www.qloo.com/legal/privacy" rel="noreferrer">privacy policy</a>.</aside>')
        response["body"] = response["body"].replace(V2_NOTICE, notice, 1)
        return response

    def __call__(self, event, context=None):
        token = _REQUEST.set({"deadline": time.monotonic() + 8.0})
        try:
            response = super().__call__(event, context)
            if response["statusCode"] == 200 and _REQUEST.get().get("durable_recovered") is True:
                response = {**response, "headers": {**response.get("headers", {}),
                    "x-qloo-recovery": "read-only-known-durable-result"}}
            if response["statusCode"] == 200 and time.monotonic() > _REQUEST.get()["deadline"]:
                request = event.get("requestContext", {}).get("http", {}) if isinstance(event, dict) else {}
                if request.get("method") == "POST" and event.get("rawPath") in ROUTE_BOUNDS:
                    # A committed/replayed durable result is not an empty timeout.
                    # The explicit marker acknowledges that the fixed budget was missed.
                    return {**response, "headers": {**response.get("headers", {}),
                        "x-qloo-operation-timing": "late-known-durable-result"}}
                return self._response(504, {"error": {"code": "qloo_timeout", "message":
                    "The total operation budget expired; no automatic retry is allowed."}})
            return response
        finally:
            binding = _REQUEST.get()
            if isinstance(binding, dict) and isinstance(binding.get("permit"), RequestPermit):
                binding["permit"].close()
            _REQUEST.reset(token)


def make_qloo_handler(config, *, index_html, signing_key, quota=None,
                      raw_transport=None, mode="disconnected", entitlement=None,
                      node_executable=None, client=None, table_name=None,
                      retention_until=None, waiter=None, clock=time.time,
                      random_bytes=None, forbidden_fragments=(), credential_account_ref=None):
    if not isinstance(config, EdgeConfig) or config.app_id != "qloo":
        raise ValueError("Choose one exact Qloo edge configuration.")
    if mode not in {"disconnected", "configured_unverified"}:
        raise ValueError("Only disconnected or explicitly brokered configured_unverified mode is supported.")
    adapter, route_quotas = None, {}
    if mode == "disconnected":
        if any(value is not None for value in (raw_transport, entitlement, node_executable, client, table_name, retention_until, waiter, credential_account_ref)) or forbidden_fragments:
            raise ValueError("Disconnected mode accepts no provider transport, runtime or storage.")
    else:
        if not (inspect.iscoroutinefunction(raw_transport) or inspect.iscoroutinefunction(getattr(raw_transport, "__call__", None))):
            raise ValueError("Inject an async single-HTTP callback: no internal retry, redirect or credential lookup in this composition.")
        if (not isinstance(quota, DynamoQuotaStore) or quota.client is not client
                or quota.table_name != table_name or quota.policy.app_id != "qloo"
                or quota.policy.expires_at != config.expires_at or quota.policy.retention_until != retention_until
                or quota.policy.max_raw_calls_per_request != 4 or not quota.policy.live_enabled
                or not quota.policy.raw_bound_verified or quota.policy.pacing_ms != 2000):
            raise ValueError("Bind the same-table Qloo quota with exact reviewed raw bound four and explicit host enablement.")
        validate_host_entitlement(entitlement,config,quota.policy,
            credential_account_ref=credential_account_ref,table_name=table_name,clock=clock)
        quota.policy.live_limits()
        # Mandatory app-lane history guard, even without RuntimeSlot.
        client = ExistingControlClient(client, table_name)
        quota = DeadlineQuotaStore(client, table_name=table_name, policy=quota.policy,
            clock_ms=quota.clock, request_binding=_REQUEST.get)
        if not isinstance(node_executable, str) or not node_executable:
            raise ValueError("An explicit pinned runtime path is required; no runtime download is performed.")
        bridge = OfficialFactoryOfflineBridge(node_executable=node_executable, node_sha256=NODE_SHA256,
            child_sha256=CHILD_SHA256, lock_sha256=LOCK_SHA256, forbidden_fragments=forbidden_fragments)
        for path, bound in ROUTE_BOUNDS.items():
            route_quotas[path] = DeadlineQuotaStore(client, table_name=table_name,
                policy=replace(quota.policy, max_raw_calls_per_request=bound), clock_ms=quota.clock, request_binding=_REQUEST.get)

        async def normalized_transport(request, *, timeout_seconds, max_response_bytes):
            binding = _REQUEST.get()
            expected = "/api/resolve" if request.get("operation") == "describe" else "/api/shortlist" if request.get("operation") == "recommend" else None
            if (not isinstance(binding, dict) or binding.get("route") != expected
                    or type(binding.get("permit")) is not RequestPermit
                    or binding["permit"].fingerprint != binding.get("fingerprint")
                    or binding["permit"].raw_reserved != ROUTE_BOUNDS.get(expected)
                    or not binding.get("session_id")):
                raise WorkflowError("raw_binding_required", "No exact source/session/raw lease is bound.", 503)
            remaining = min(timeout_seconds, 10, min(binding["deadline"], binding.get("work_deadline", binding["deadline"])) - time.monotonic())
            if remaining <= 0:
                raise WorkflowError("qloo_timeout", "The total operation budget expired.", 504)

            async def bounded_raw(**kwargs):
                left = min(3.0, kwargs["timeout_seconds"], min(binding["deadline"], binding.get("work_deadline", binding["deadline"])) - time.monotonic())
                if left <= 0:
                    raise TimeoutError()
                # Pacing/reservation may have crossed a paid period boundary.
                # This check precedes actual raw transport entry; the precharged
                # durable reservation remains consumed on refusal or uncertainty.
                validate_host_entitlement(entitlement,config,quota.policy,
                    credential_account_ref=credential_account_ref,table_name=table_name,clock=clock)
                response = await asyncio.wait_for(raw_transport(**{**kwargs, "timeout_seconds": left}), left)
                # The pinned vendor factory itself slices to requested limit.
                # Refuse oversized raw insights BEFORE forwarding to the child,
                # so omitted provider data is never silently called complete.
                if (urlsplit(kwargs["url"]).path == "/v2/insights"
                        and isinstance(response, dict) and type(response.get("status")) is int
                        and 200 <= response["status"] <= 299):
                    body = response.get("body")
                    if not isinstance(body, bytes) or len(body) > kwargs["max_response_bytes"]:
                        raise ValueError("Raw insights body exceeds the explicit byte bound.")
                    value = raw_json(body)
                    entities = value.get("results", {}).get("entities") if isinstance(value, dict) and isinstance(value.get("results"), dict) else None
                    if not isinstance(entities, list) or len(entities) > 3:
                        raise ValueError("Raw insights exceeds the exact requested result bound.")
                return response

            # wait_for includes bridge pin checks, startup and serialized raw
            # callbacks. Cancellation awaits bridge finally (kill/reap) first.
            return await asyncio.wait_for(bridge.run(request, permit=binding["permit"], raw_transport=bounded_raw,
                timeout_seconds=remaining, max_response_bytes=min(max_response_bytes, 131072)), remaining)

        store = FencedCompactStore(client, table_name=table_name, retention_until=retention_until,
            mutation_gate=quota, waiter=waiter)
        adapter = FencedHarnessAdapter(normalized_transport, confirmation_store=store,
            wall_clock=clock, request_timeout=8.0, total_timeout=8.0)
    options = {} if random_bytes is None else {"random_bytes": random_bytes}
    edge = QlooComposition(config, index_html=index_html, domain=BoundQlooDomain(adapter, mode,
        policy_live_enabled=quota.policy.live_enabled if quota is not None else False),
        quota=quota, signing_key=signing_key, clock=clock, **options)
    edge.route_quotas, edge.retention_until = route_quotas, retention_until
    edge.host_entitlement, edge.host_policy = entitlement, (quota.policy if quota else None)
    edge.credential_account_ref, edge.host_table_name = credential_account_ref, table_name
    return edge


def handler(event, context=None):
    """No bootstrap, environment reads, credentials, SDK or provider execution."""
    return {"statusCode": 503, "headers": {**SECURITY, "content-type": "application/json; charset=utf-8"},
        "body": canonical({"error": {"code": "binding_unconfigured", "message":
            "Private Qloo composition is not configured; live providers remain disabled."}}), "isBase64Encoded": False}
