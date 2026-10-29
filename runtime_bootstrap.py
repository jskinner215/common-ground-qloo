"""Internal Linux assembly. Import performs no I/O or thread startup.

No SDK, credential loader, configuration-from-event/environment or live default.
RuntimeSlot is an internal trusted factory used by the production entry. Legacy
module configure/handler/lifecycle exports are fenced and own no default slot.
Configured output remains unverified; this module grants no execution authority.
"""
from dataclasses import dataclass
import hashlib
import importlib
import inspect
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parent
OPERATION_SECONDS=8.0
RESPONSE_RESERVE_SECONDS=1.0
FUNCTION_SECONDS=25.0
NODE_SHA='e237a2839d0cbdc9a9a2adda1a184afc0f5b20306ffbe923af5686550472d8a8'
MODULE_PINS = {
    'async_host': 'b6063f3a5f0a26c07139fd43ab67a756cd1f50d04fdfc8fd3973e5998f79a9fd',
    'deadline_quota': '357189dcf86be34855caaac5df94079ed1e5c6246e2e879008cac556f24e6082',
    'global_quota_v2': 'e3411aa54611dc999328b1c8455121118d3be9df65e3d8aa9ed8f4e94c71927f',
    'paid_entitlement': '252207edc99f57b7204f193f2e7a600c5d4eb75435216295d6d18346e97d001d',
    'public_paid_entitlement': '6221f6a01146202c08d94603ed1c15174977bbd8e3232e7910f3062dd716ad76',
    'qloo_composition': 'df5d72f229e573caaa8c86ab4356678fdd1ed1b28212d111f302d95c881c3f07',
    'qloo_http': '4cbb38d19a54adb5262769ce8632c04199fd7f4d5362d2aa659a5cbeaeeb5e70',
    'v2_binding': 'e0c5d4012f1332c66902c56a8e155241b6b4f70a97ee4ede7dafdd69763d8968',
}
DEPENDENCIES={'aiohttp','aiohappyeyeballs','aiosignal','attr','attrs','frozenlist','multidict','propcache','yarl','idna','typing_extensions'}


class RuntimeRefusal(RuntimeError):
    pass


@dataclass(frozen=True)
class Inputs:
    config: object
    policy: object
    entitlement: object
    table_name: str
    client_provider: object
    signing_key_provider: object
    raw_transport: object
    clock_ms: object
    clock: object
    waiter: object
    random_bytes: object = None
    credential_account_ref: str | None = None


@dataclass(frozen=True)
class CloseResult:
    stopped: bool
    pending_executor_jobs: int
    pending_operation: bool


def _closed(code='runtime_unconfigured',status=503):
    return {'statusCode':status,'headers':{'content-type':'application/json; charset=utf-8','cache-control':'no-store',
        'x-content-type-options':'nosniff','content-security-policy':"default-src 'none'"},
        'body':json.dumps({'error':{'code':code,'message':'Private runtime is unavailable; no new action may start.'}},separators=(',',':')),
        'isBase64Encoded':False}


def _digest(path):
    value=hashlib.sha256()
    with path.open('rb') as source:
        while data:=source.read(65536): value.update(data)
    return value.hexdigest()


def _remaining(context):
    method=getattr(context,'get_remaining_time_in_millis',None)
    if not callable(method): raise RuntimeRefusal('A trusted invocation deadline is required.')
    value=method()
    if type(value) not in (int,float) or not math.isfinite(value) or value<=0:
        raise RuntimeRefusal('A valid invocation deadline is required.')
    return min(FUNCTION_SECONDS,value/1000)


def _verify_package():
    lock=json.loads((ROOT/'RUNTIME_LOCK.json').read_bytes())
    mapping=lock.get('files')
    if not isinstance(mapping,dict) or lock.get('nodeSha256')!=NODE_SHA:
        raise RuntimeRefusal('The fixed package lock is invalid.')
    revision=hashlib.sha256(json.dumps(mapping,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if lock.get('sourceRevision')!=revision:
        raise RuntimeRefusal('The package revision does not bind its exact canonical file map.')
    observed=set()
    for path in ROOT.rglob('*'):
        if path.is_symlink(): raise RuntimeRefusal('Package links are refused.')
        if path.is_file(): observed.add(path.relative_to(ROOT).as_posix())
    if observed!=set(mapping)|{'RUNTIME_LOCK.json'}:
        raise RuntimeRefusal('Unexpected or missing package files.')
    for name,proof in mapping.items():
        path=ROOT/name
        if ('\\' in name or ':' in name or any(p in {'','..','.'} for p in name.split('/'))
                or not path.resolve().is_relative_to(ROOT) or not stat.S_ISREG(path.stat().st_mode)
                or path.stat().st_size!=proof['bytes'] or _digest(path)!=proof['sha256']):
            raise RuntimeRefusal('Package source/runtime pin differs.')
    node=ROOT/'runtime/node'
    if _digest(node)!=NODE_SHA or not os.access(node,os.X_OK) or stat.S_IMODE(node.stat().st_mode)!=0o755:
        raise RuntimeRefusal('The exact executable permission/pin is required.')
    version=subprocess.run([str(node),'--version'],env={},stdin=subprocess.DEVNULL,capture_output=True,timeout=2)
    if version.returncode or version.stdout!=b'v24.14.0\n' or len(version.stderr)>1024:
        raise RuntimeRefusal('Pinned executable version could not be established.')
    return lock


def _loaded_origins(lock):
    authored={name[:-3]:proof for name,proof in lock['files'].items() if name.endswith('.py') and '/' not in name}
    for name,proof in authored.items():
        module=sys.modules.get(name)
        if module is not None and (not getattr(module,'__file__',None)
                or Path(module.__file__).resolve()!=ROOT/(name+'.py') or _digest(Path(module.__file__))!=proof['sha256']):
            raise RuntimeRefusal('A preloaded application module is outside the fixed package.')
    for name,module in list(sys.modules.items()):
        if name.split('.')[0] in DEPENDENCIES and getattr(module,'__file__',None):
            if not Path(module.__file__).resolve().is_relative_to(ROOT/'deps'):
                raise RuntimeRefusal('An existing foreign dependency cannot be replaced silently.')


def _modules(lock):
    sys.dont_write_bytecode=True
    for path in (ROOT/'deps',ROOT):
        if str(path) not in sys.path: sys.path.insert(0,str(path))
    modules={}
    _loaded_origins(lock)
    for name,pin in MODULE_PINS.items():
        module=importlib.import_module(name)
        if Path(module.__file__).resolve()!=ROOT/(name+'.py') or _digest(Path(module.__file__))!=pin:
            raise RuntimeRefusal('An unexpected loaded module was refused.')
        modules[name]=module
    _loaded_origins(lock)
    return modules


class RuntimeSlot:
    """One non-queuing, non-replaceable lifecycle with explicit bounded close."""
    def __init__(self):
        self._gate=threading.Lock(); self._closing=threading.Event()
        self._state='unconfigured'; self._host=None; self._edge=None; self._last_close=None

    def configure(self,inputs,context):
        if not self._gate.acquire(blocking=False): raise RuntimeRefusal('Configuration is busy.')
        began_configuration=False
        try:
            if self._state!='unconfigured' or self._closing.is_set(): raise RuntimeRefusal('Runtime cannot be replaced or restarted.')
            began_configuration=True
            self._state='preparing'
            invocation_deadline=time.monotonic()+_remaining(context)
            if invocation_deadline-time.monotonic()<OPERATION_SECONDS+RESPONSE_RESERVE_SECONDS: raise RuntimeRefusal('Insufficient readiness/admission budget.')
            if not isinstance(inputs,Inputs) or not all(callable(value) for value in
                    (inputs.client_provider,inputs.signing_key_provider,inputs.raw_transport,inputs.clock_ms,inputs.clock,inputs.waiter)):
                raise RuntimeRefusal('Explicit trusted injected providers are required.')
            lock=_verify_package(); modules=_modules(lock)
            if (not isinstance(inputs.config,modules['qloo_composition'].EdgeConfig) or inputs.config.app_id!='qloo'
                    or inputs.config.source_revision!=lock['sourceRevision']):
                raise RuntimeRefusal('Configuration must bind the exact packaged revision.')
            if (not isinstance(inputs.policy,modules['global_quota_v2'].QuotaPolicy)
                    or inputs.policy.app_id!='qloo' or inputs.policy.expires_at!=inputs.config.expires_at
                    or inputs.policy.pacing_ms!=2000 or inputs.policy.max_raw_calls_per_request!=4
                    or not inputs.policy.live_enabled or not inputs.policy.raw_bound_verified
                    or type(inputs.entitlement) not in (modules['qloo_composition'].TrustedEntitlement,modules['paid_entitlement'].PaidQualificationEntitlement,modules['public_paid_entitlement'].PublicPaidEntitlement)
                    or not (inspect.iscoroutinefunction(inputs.raw_transport) or inspect.iscoroutinefunction(getattr(inputs.raw_transport,'__call__',None)))):
                raise RuntimeRefusal('Exact source-pinned policy/entitlement/async transport required.')
            modules['qloo_composition'].validate_host_entitlement(inputs.entitlement,inputs.config,inputs.policy,
                credential_account_ref=inputs.credential_account_ref,table_name=inputs.table_name,clock=inputs.clock)
            inputs.policy.live_limits()
            if not isinstance(inputs.table_name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',inputs.table_name):
                raise RuntimeRefusal('An exact valid table name is required.')
            if inputs.random_bytes is not None and not callable(inputs.random_bytes):
                raise RuntimeRefusal('A supplied nonce provider must be callable.')
            from control_guard import ExistingControlClient
            guard_module=sys.modules['control_guard']
            if Path(guard_module.__file__).resolve()!=ROOT/'control_guard.py' or _digest(Path(guard_module.__file__))!=lock['files']['control_guard.py']['sha256']:
                raise RuntimeRefusal('An unexpected control guard was refused.')
            client=ExistingControlClient(inputs.client_provider(),inputs.table_name)
            quota=modules['global_quota_v2'].DynamoQuotaStore(client,table_name=inputs.table_name,
                policy=inputs.policy,clock_ms=inputs.clock_ms)
            # Exact source-pinned validator; missing/invalid control is never a
            # fresh namespace, including on every later guarded strong read.
            quota._read('quota#v2#control',control=True)
            signing_key=inputs.signing_key_provider()
            if not isinstance(signing_key,bytes) or len(signing_key)!=32: raise RuntimeRefusal('Explicit32byte signing material required.')
            host=modules['async_host'].PersistentAsyncHost(); self._host=host
            edge=modules['qloo_composition'].make_qloo_handler(inputs.config,index_html=(ROOT/'index.html').read_bytes(),
                signing_key=signing_key,quota=quota,raw_transport=inputs.raw_transport,mode='configured_unverified',
                entitlement=inputs.entitlement,node_executable=str(ROOT/'runtime/node'),client=client,table_name=inputs.table_name,
                retention_until=inputs.policy.retention_until,waiter=inputs.waiter,clock=inputs.clock,random_bytes=inputs.random_bytes,credential_account_ref=inputs.credential_account_ref)
            edge=modules['v2_binding'].bind_private_handler(edge,host)
            host.start()  # Validation/build precede thread startup.
            async def readiness():
                async with modules['qloo_http']._new_session(1): pass
            host.run(readiness,timeout_seconds=3)
            _loaded_origins(lock)
            if self._closing.is_set() or min(_remaining(context),invocation_deadline-time.monotonic())<OPERATION_SECONDS+RESPONSE_RESERVE_SECONDS:
                raise RuntimeRefusal('Readiness did not leave the original operation budget.')
            self._edge=edge; self._state='ready'
            return self
        except Exception:
            if not began_configuration:
                raise RuntimeRefusal('Runtime cannot be replaced or restarted.') from None
            self._state='failed'
            if self._host is not None: self._last_close=self._host.close(timeout_seconds=0.5)
            raise RuntimeRefusal('Private runtime configuration refused; no automatic retry or replacement.') from None
        finally: self._gate.release()

    def handle(self,event,context=None):
        if self._closing.is_set() or not self._gate.acquire(blocking=False): return _closed('runtime_busy')
        try:
            if self._state!='ready' or self._host is None: return _closed()
            host=self._host
            if (host._closing or host._poisoned or host._executor is None or host._executor.pending
                    or host._active is not None or any(not task.done() for task in tuple(host._tasks))
                    or not host._thread.is_alive()):
                return _closed('runtime_draining')
            try: remaining=_remaining(context)
            except RuntimeRefusal: return _closed('invocation_deadline_required')
            if remaining<OPERATION_SECONDS+RESPONSE_RESERVE_SECONDS: return _closed('insufficient_invocation_budget')
            began=time.monotonic()
            response=self._edge(event,context)
            elapsed=time.monotonic()-began
            if elapsed>remaining-RESPONSE_RESERVE_SECONDS:
                request=event.get('requestContext',{}).get('http',{}) if isinstance(event,dict) else {}
                known=(isinstance(response,dict) and response.get('statusCode')==200
                    and request.get('method')=='POST' and event.get('rawPath') in ('/api/resolve','/api/shortlist'))
                if known and elapsed<remaining:
                    # Preserve the exact source-bound durable result when only
                    # the response reserve was crossed, without extending the
                    # actual invocation deadline or claiming on-time delivery.
                    return {**response,'headers':{**response.get('headers',{}),
                        'x-qloo-invocation-timing':'response-reserve-crossed',
                        'x-qloo-invocation-remaining-ms':str(max(0,int((remaining-elapsed)*1000)))}}
                if known:
                    return {**_closed('invocation_deadline_exhausted_known_result',504),
                        'headers':{**_closed()['headers'],'x-qloo-invocation-timing':'actual-deadline-crossed',
                            'x-qloo-recovery':'check-original-action-id-read-only'}}
                return _closed('invocation_budget_exhausted',504)
            return response
        except Exception: return _closed('runtime_unavailable')
        finally:
            if self._closing.is_set() and self._host is not None: self._last_close=self._host.close(timeout_seconds=0)
            self._gate.release()

    def close(self,*,timeout_seconds=0.5):
        if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 0<=timeout_seconds<=2:
            raise RuntimeRefusal('Use the existing bounded close limit.')
        self._closing.set()
        if not self._gate.acquire(blocking=False):
            jobs=self._host._executor.pending if self._host and self._host._executor else 0
            return CloseResult(False,jobs,True)
        try:
            self._state='closing'
            if self._host is None: return CloseResult(True,0,False)
            result=self._host.close(timeout_seconds=timeout_seconds); self._last_close=result
            return CloseResult(result.stopped,result.pending_executor_jobs,result.pending_operation)
        finally: self._gate.release()


def configure_runtime(inputs,context):
    """Legacy activation is fenced; use the reviewed production entry."""
    raise RuntimeRefusal('Legacy runtime activation is disabled; use configure_production explicitly.')


def handler(event,context=None): return _closed('legacy_runtime_export_disabled')


def close_runtime(*,timeout_seconds=0.5):
    raise RuntimeRefusal('Legacy runtime lifecycle is disabled; use close_production explicitly.')
