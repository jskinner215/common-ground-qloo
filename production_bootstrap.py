"""Explicit trusted-host composition. Import and default handler stay inert.

No event/env configuration, SDK construction, secret storage, control creation,
credential discovery, retries or fallbacks. Operator facts are assertions that
must be independently established. Tests use fictitious facts and providers.
"""
from dataclasses import dataclass
import hashlib
import math
import re
import threading
import time

import runtime_bootstrap as runtime

HOST = 'https://hackathon.api.qloo.com'
WCM_TARGET = 'jskinner.biz/CommonGround/QlooAgenticHackathon2026'
SHA = re.compile(r'[0-9a-f]{64}')


class BootstrapRefusal(ValueError):
    def __init__(self, message, *, cleanup=None, cleanup_uncertain=False):
        super().__init__(message)
        self.cleanup = cleanup
        self.cleanup_uncertain = cleanup_uncertain


def digest(value):
    if not isinstance(value, str) or not SHA.fullmatch(value):
        raise BootstrapRefusal('An exact nonsecret evidence SHA256 is required.')
    return value


@dataclass(frozen=True)
class OperatorContract:
    source_revision: str
    account_ref: str
    api_host: str
    origin: str
    table_name: str
    region: str
    starts_at: int
    expires_at: int
    retention_until: int
    approval_evidence_sha256: str
    maximum_cost_evidence_sha256: str
    usd_ceiling_microusd: int
    maximum_charge_per_raw_microusd: int
    daily_raw_limit: int
    lifetime_raw_limit: int
    post_daily: int
    post_lifetime: int
    purpose: str
    credential_kind: str
    credential_location_ref: str
    credential_configuration_approval_sha256: str
    signing_configuration_approval_sha256: str
    deployment_approval_sha256: str
    approved_quota_namespace_sha256: str
    enabled: bool = False

    def validate(self, *, revision, now):
        if self.enabled is not True:
            raise BootstrapRefusal('Explicit host activation is disabled.')
        if (self.api_host != HOST or self.region != 'us-east-2'
                or self.source_revision != revision
                or self.purpose not in {'qualification', 'public-demo'}):
            raise BootstrapRefusal('Exact source, host, region and purpose required.')
        for name in ('source_revision', 'account_ref', 'approval_evidence_sha256',
                     'maximum_cost_evidence_sha256', 'credential_configuration_approval_sha256',
                     'signing_configuration_approval_sha256', 'deployment_approval_sha256',
                     'approved_quota_namespace_sha256'):
            digest(getattr(self, name))
        if (not isinstance(self.table_name, str)
                or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}', self.table_name)
                or not isinstance(self.credential_location_ref, str)
                or not 1 <= len(self.credential_location_ref) <= 512):
            raise BootstrapRefusal('Exact table and nonsecret credential locator required.')
        from paid_entitlement import namespace_ref
        if self.approved_quota_namespace_sha256 != namespace_ref(self.account_ref, self.table_name):
            raise BootstrapRefusal('Account/table differs from the independently supplied approved quota namespace.')
        if (type(now) not in (int, float) or not math.isfinite(now)
                or type(self.starts_at) is not int or type(self.expires_at) is not int
                or type(self.retention_until) is not int
                or not self.starts_at <= now < self.expires_at < self.retention_until):
            raise BootstrapRefusal('Exact active approval and retention period required.')
        if self.purpose == 'qualification':
            if (self.credential_kind != 'owner-wcm'
                    or self.credential_location_ref != WCM_TARGET
                    or (self.daily_raw_limit, self.lifetime_raw_limit, self.post_daily, self.post_lifetime) != (8, 8, 2, 2)):
                raise BootstrapRefusal('Qualification is only the existing Owner WCM two-POST scope.')
        elif (self.credential_kind != 'approved-cloud-secret'
                or self.credential_location_ref.casefold() == WCM_TARGET.casefold()):
            raise BootstrapRefusal('Public hosting requires separate cloud credential approval.')


@dataclass(frozen=True)
class Providers:
    account_ref: str
    credential_kind: str
    credential_location_ref: str
    client_provider: object
    signing_key_provider: object
    credential_provider: object
    clock_ms: object
    clock: object
    waiter: object
    random_bytes: object = None


def _validate_client(client, contract):
    from sdk_guard import validate_client
    validate_client(client)
    # Exact supported SDK configuration is an injected host fact. No SDK or
    # credential-chain initialization happens here. A slow SDK can still exceed
    # its timeout through DNS/platform behavior; quota code reports uncertainty.
    meta = getattr(client, 'meta', None)
    config = getattr(meta, 'config', None)
    endpoint = getattr(client, '_endpoint', None)
    http = getattr(endpoint, 'http_session', None)
    timeout = getattr(http, '_timeout', None)
    if (getattr(meta, 'region_name', None) != contract.region
            or getattr(meta, 'endpoint_url', None) != 'https://dynamodb.us-east-2.amazonaws.com'
            or getattr(config, 'retries', None) != {'total_max_attempts': 1, 'mode': 'standard'}
            or getattr(config, 'connect_timeout', None) != 0.05
            or getattr(config, 'read_timeout', None) != 0.10
            or getattr(config, 'max_pool_connections', None) != 1
            or getattr(config, 'proxies', None) != {}
            or getattr(config, 'signature_version', None) != 'v4'
            or getattr(config, 'use_fips_endpoint', None) not in (None, False)
            or getattr(config, 'use_dualstack_endpoint', None) not in (None, False)
            or getattr(config, 'endpoint_discovery_enabled', None) not in (None, False)
            or getattr(http, '_verify', None) is not True
            or getattr(http, '_max_pool_connections', None) != 1
            or getattr(timeout, 'connect_timeout', None) != 0.05
            or getattr(timeout, 'read_timeout', None) != 0.10
            or getattr(getattr(http, '_proxy_config', None), '_proxies', None) != {}
            or not all(callable(getattr(client, n, None)) for n in ('get_item', 'transact_write_items'))):
        raise BootstrapRefusal('Explicit no-retry bounded fixed-region durable client required.')
    return client


class ProductionEntry:
    def __init__(self):
        self._lock = threading.Lock()
        self._closing = threading.Event()
        self._attempted = False
        self._slot = None
        self._last_close = None
        self._cleanup_uncertain = False

    @property
    def last_close(self):
        return self._last_close

    @property
    def cleanup_uncertain(self):
        return self._cleanup_uncertain

    def _open(self):
        if self._closing.is_set():
            raise BootstrapRefusal('Shutdown is terminal; no new configuration or action.')

    def configure(self, contract, providers, context):
        if not self._lock.acquire(blocking=False):
            raise BootstrapRefusal('Configuration is busy.')
        began = False
        try:
            self._open()
            if self._attempted:
                raise BootstrapRefusal('No replacement, restart or retry configuration.')
            self._attempted = True
            began = True
            if type(contract) is not OperatorContract or type(providers) is not Providers:
                raise BootstrapRefusal('Exact immutable operator and provider descriptors required.')
            # Pure failure before package checks, SDK or secret providers.
            if contract.enabled is not True:
                raise BootstrapRefusal('Host activation is disabled.')
            for name in ('client_provider', 'signing_key_provider', 'credential_provider',
                         'clock_ms', 'clock', 'waiter'):
                if not callable(getattr(providers, name)):
                    raise BootstrapRefusal('Explicit trusted providers required.')
            lock = runtime._verify_package()
            self._open()
            contract.validate(revision=lock['sourceRevision'], now=providers.clock())
            if (providers.account_ref != contract.account_ref
                    or providers.credential_kind != contract.credential_kind
                    or providers.credential_location_ref != contract.credential_location_ref):
                raise BootstrapRefusal('Provider binding differs from approved account and locator.')
            modules = runtime._modules(lock)
            from paid_entitlement import PaidQualificationEntitlement, namespace_ref
            from public_paid_entitlement import PublicPaidEntitlement
            config = modules['qloo_composition'].EdgeConfig('qloo', contract.origin,
                lock['sourceRevision'], contract.expires_at)
            policy = modules['global_quota_v2'].QuotaPolicy('qloo', contract.expires_at,
                contract.retention_until, post_daily=contract.post_daily,
                post_lifetime=contract.post_lifetime, provider_daily=contract.daily_raw_limit,
                provider_lifetime=contract.lifetime_raw_limit,
                entitlement_daily=contract.daily_raw_limit, entitlement_lifetime=contract.lifetime_raw_limit,
                max_raw_calls_per_request=4, live_enabled=True, raw_bound_verified=True)
            values = dict(api_host=HOST, account_ref=contract.account_ref,
                approval_evidence_sha256=contract.approval_evidence_sha256,
                maximum_cost_evidence_sha256=contract.maximum_cost_evidence_sha256,
                usd_ceiling_microusd=contract.usd_ceiling_microusd,
                maximum_charge_per_raw_microusd=contract.maximum_charge_per_raw_microusd,
                starts_at=contract.starts_at, expires_at=contract.expires_at,
                quota_namespace_sha256=contract.approved_quota_namespace_sha256,
                host_explicitly_enabled=True)
            if contract.purpose == 'qualification':
                entitlement = PaidQualificationEntitlement(**values)
            else:
                entitlement = PublicPaidEntitlement(**values, daily_raw_limit=contract.daily_raw_limit,
                    lifetime_raw_limit=contract.lifetime_raw_limit, post_daily=contract.post_daily,
                    post_lifetime=contract.post_lifetime)
            entitlement.validate(config, policy, credential_account_ref=providers.account_ref,
                table_name=contract.table_name, now=int(providers.clock()))
            self._open()
            # No credential read until an admitted raw call. The callback itself
            # must implement the separately approved loader; never receives data
            # from events or request configuration.
            raw = modules['qloo_http'].make_raw_get_transport(
                credential_provider=providers.credential_provider,
                admission_check=modules['v2_binding'].admitted_raw_call,
                network_enabled=True)
            # Verify exact public installed SDK source BEFORE a client provider
            # can initialize an approved credential source. No SDK discovery or
            # client/credential initialization is performed by this guard.
            from sdk_guard import verify_sdk
            verify_sdk()
            self._open()
            client = _validate_client(providers.client_provider(), contract)
            self._open()
            inputs = runtime.Inputs(config, policy, entitlement, contract.table_name,
                lambda: client, providers.signing_key_provider, raw, providers.clock_ms,
                providers.clock, providers.waiter, providers.random_bytes,
                credential_account_ref=providers.account_ref)
            slot = runtime.RuntimeSlot()
            self._slot = slot
            self._open()
            slot.configure(inputs, context)
            self._open()
            return self
        except Exception:
            if began and self._slot is not None:
                try:
                    self._last_close = self._slot.close(timeout_seconds=0.5)
                    self._cleanup_uncertain = False
                except Exception:
                    self._cleanup_uncertain = True
            raise BootstrapRefusal('Production configuration refused; no automatic retry.',
                cleanup=self._last_close, cleanup_uncertain=self._cleanup_uncertain) from None
        finally:
            self._lock.release()

    def handle(self, event, context=None):
        if self._closing.is_set():
            return runtime._closed('runtime_draining')
        slot = self._slot
        return runtime._closed() if slot is None else slot.handle(event, context)

    def close(self, *, timeout_seconds=0.5):
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 <= timeout_seconds <= 2):
            raise BootstrapRefusal('Use the existing bounded shutdown limit.')
        self._closing.set()
        if not self._lock.acquire(blocking=False):
            slot = self._slot
            try:
                result = slot.close(timeout_seconds=0) if slot else None
            except Exception:
                self._cleanup_uncertain = True
                raise BootstrapRefusal('Shutdown completion is uncertain.',
                    cleanup=self._last_close, cleanup_uncertain=True) from None
            # The outer configuration/provider callback may still be running.
            # This never says stopped while that work owns the configuration gate.
            self._last_close = runtime.CloseResult(False, result.pending_executor_jobs if result else 0, True)
            self._cleanup_uncertain = False
            return self._last_close
        try:
            self._last_close = self._slot.close(timeout_seconds=timeout_seconds) if self._slot else runtime.CloseResult(True, 0, False)
            self._cleanup_uncertain = False
            return self._last_close
        except Exception:
            self._cleanup_uncertain = True
            raise BootstrapRefusal('Shutdown completion is uncertain.',
                cleanup=self._last_close, cleanup_uncertain=True) from None
        finally:
            self._lock.release()


_DEFAULT = ProductionEntry()


def configure_production(contract, providers, context):
    """Trusted in-process injection only. A contract is not user authorization."""
    return _DEFAULT.configure(contract, providers, context)


def handler(event, context=None):
    return _DEFAULT.handle(event, context)


def close_production(*, timeout_seconds=0.5):
    return _DEFAULT.close(timeout_seconds=timeout_seconds)
