"""Private opt-in binding of the frozen v2 domain to an explicit async host.

Import uses no credentials, client or network. This changes only a caller-owned
handler object after exact source pins match; frozen source files are untouched.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import threading
import time

from async_host import PersistentAsyncHost, HostRefusal, HostTimeout, current_scope
import qloo_composition as frozen
import global_quota_v2 as quotas
import workflow

READ_ONLY_RECOVERY_SECONDS = 0.5

PINS = {
    'global_quota_v2': 'e3411aa54611dc999328b1c8455121118d3be9df65e3d8aa9ed8f4e94c71927f',
    'qloo_composition': 'df5d72f229e573caaa8c86ab4356678fdd1ed1b28212d111f302d95c881c3f07',
    'workflow': '3d4b2b2bc1d415128058e8fb58341310b07f5525049c9bc6b2003243ee3dda8f',
}


def _check_pins():
    for module in (frozen, quotas, workflow):
        if hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() != PINS[module.__name__]:
            raise HostRefusal("The private binding source differs from the reviewed frozen revision.")


def admitted_raw_call():
    """Validate the already-debited active raw permit; never creates a permit."""
    try:
        current_scope()
    except (HostRefusal, HostTimeout):
        return False
    binding = frozen._REQUEST.get()
    if not isinstance(binding, dict):
        return False
    permit = binding.get("permit")
    route = binding.get("route")
    if (type(permit) is not quotas.RequestPermit or permit.app_id != "qloo"
            or not binding.get("session_id") or permit.fingerprint != binding.get("fingerprint")
            or permit.raw_reserved != frozen.ROUTE_BOUNDS.get(route)):
        return False
    # These private fields are used only with the exact source-pinned class.
    with permit._lock:
        return permit._active is True and permit._closed is False


@dataclass(frozen=True)
class _Outcome:
    value: object = None
    error: tuple | None = None


class _PersistentDomain(frozen.BoundQlooDomain):
    def __init__(self, prior, host):
        super().__init__(prior.adapter, prior.mode, policy_live_enabled=prior.live_enabled)
        self._host = host

    def post(self, path, packet):
        if self.adapter is None or self.mode != "configured_unverified":
            raise frozen.EdgeError("provider_disconnected", "No approved host binding exists.", 503)
        if path not in frozen.ROUTE_BOUNDS:
            raise frozen.EdgeError("not_found", "No such private composition route.", 404)
        needed = {"queries", "request_id"} if path == "/api/resolve" else {
            "queries", "resolution_id", "selected_ids", "request_id"}
        if not isinstance(packet, dict) or set(packet) != needed:
            raise frozen.EdgeError("invalid_request", "Use only the reviewed-pair fields.")
        binding = frozen._REQUEST.get()
        if (not isinstance(binding, dict) or type(binding.get("permit")) is not quotas.RequestPermit
                or not binding.get("session_id")):
            raise frozen.EdgeError("session_required", "Use a validated raw-budgeted request.", 403)
        remaining = min(8.0, binding["deadline"] - time.monotonic())
        if remaining <= 0:
            raise frozen.EdgeError("qloo_timeout", "The total operation budget expired.", 504)

        # This reserve is INSIDE the same original eight-second operation.
        # Do not extend deadline in a copied ContextVar when work is draining.
        binding["work_deadline"] = binding["deadline"] - READ_ONLY_RECOVERY_SECONDS
        work_budget = min(remaining - READ_ONLY_RECOVERY_SECONDS,
                          binding["work_deadline"] - time.monotonic())
        if work_budget <= 0:
            raise frozen.EdgeError("qloo_timeout", "No bounded work and read-only recovery budget remains.", 504)

        async def execute():
            try:
                if path == "/api/resolve":
                    value = await self.adapter.resolve_pair(packet["queries"],
                        request_id=packet["request_id"], session_id=binding["session_id"])
                else:
                    value = await self.adapter.recommend_pair(packet["queries"], packet["resolution_id"],
                        packet["selected_ids"], request_id=packet["request_id"], session_id=binding["session_id"])
                return _Outcome(value=value)
            except workflow.WorkflowError as error:
                # Same source-pinned safe error fields as the frozen domain;
                # arbitrary dependency exceptions remain sanitized by the host.
                return _Outcome(error=(error.code, error.message, error.status))
        try:
            result = self._host.run(execute, timeout_seconds=work_budget)
        except HostTimeout:
            host=self._host
            # The host signals done just before its task returns. One bounded
            # non-I/O loop checkpoint distinguishes that tiny completion race
            # from real unfinished work. It queues no async request or retry.
            left=min(0.01,binding["deadline"]-time.monotonic())
            if not host._poisoned and not host._closing and left>0:
                drained=threading.Event()
                try:host._loop.call_soon_threadsafe(drained.set)
                except RuntimeError:pass
                else:drained.wait(left)
            # No new host job, retry, provider call or pending-row reset.
            # A timed-out job must be fully quiescent before read-only recovery.
            if (host._poisoned or host._closing or host._active is not None
                    or host._executor is None or host._executor.pending
                    or any(not task.done() for task in tuple(host._tasks))
                    or time.monotonic() >= binding["deadline"]):
                raise frozen.EdgeError("qloo_timeout_draining",
                    "Timed-out work is still draining or no recovery budget remains; no retry started.", 504) from None
            recovery_deadline=min(binding["deadline"],time.monotonic()+READ_ONLY_RECOVERY_SECONDS)
            try:
                if path == "/api/resolve":
                    recovered=self.adapter.recover_known_resolution(packet["queries"],
                        session_id=binding["session_id"],request_id=packet["request_id"],deadline=recovery_deadline)
                else:
                    recovered=self.adapter.recover_known_recommendation(packet["queries"],packet["resolution_id"],packet["selected_ids"],
                        session_id=binding["session_id"],request_id=packet["request_id"],deadline=recovery_deadline)
            except workflow.WorkflowError as error:
                raise frozen.EdgeError(error.code,error.message,error.status) from None
            if time.monotonic() >= recovery_deadline:
                raise frozen.EdgeError("qloo_recovery_deadline",
                    "Read-only recovery did not return within the original deadline; no action was retried.",504)
            binding["durable_recovered"]=True
            return recovered
        except HostRefusal:
            raise frozen.EdgeError("async_host_unavailable", "Private async host is unavailable or still draining.", 503) from None
        if not isinstance(result, _Outcome):
            raise frozen.EdgeError("invalid_result", "Private async result failed validation.", 503)
        if result.error is not None:
            raise frozen.EdgeError(*result.error)
        return result.value


def bind_private_handler(handler, host):
    """Explicitly replace only a private caller-owned domain; no bootstrap."""
    _check_pins()
    if (type(handler) is not frozen.QlooComposition
            or type(handler.domain) is not frozen.BoundQlooDomain
            or handler.domain.mode != "configured_unverified"
            or type(host) is not PersistentAsyncHost):
        raise HostRefusal("Use one exact frozen private handler and explicit host.")
    handler.domain = _PersistentDomain(handler.domain, host)
    return handler
