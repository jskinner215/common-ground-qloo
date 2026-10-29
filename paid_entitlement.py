"""Proposed paid qualification contract. Pure validation; no execution authority.

This NEW module is not imported by the frozen app/runtime. The accompanying
unapplied delta describes required binding and pin updates. No price is assumed.
"""
from dataclasses import dataclass
import re
import hashlib
import json

HOST = 'https://hackathon.api.qloo.com'
SHA = re.compile(r'[0-9a-f]{64}')
SLOTS = 8  # two existing POST admissions at bound four; actual raw <= seven


class PaidRefusal(ValueError): pass


def _integer(value): return type(value) is int and value > 0


@dataclass(frozen=True)
class PaidQualificationEntitlement:
    api_host: str
    account_ref: str
    approval_evidence_sha256: str
    maximum_cost_evidence_sha256: str
    usd_ceiling_microusd: int
    maximum_charge_per_raw_microusd: int
    starts_at: int
    expires_at: int
    quota_namespace_sha256: str
    daily_raw_limit: int = SLOTS
    lifetime_raw_limit: int = SLOTS
    host_explicitly_enabled: bool = False
    scope: str = 'one-local-qloo-qualification-v1'

    @property
    def free_no_automatic_overage_verified(self): return False

    def validate(self, config, policy, *, credential_account_ref, table_name, now):
        # These values are trusted host facts. Merely constructing this class
        # neither proves approval nor verifies pricing, identity or credentials.
        if self.host_explicitly_enabled is not True: raise PaidRefusal('paid_not_enabled')
        if (self.api_host != HOST or self.scope != 'one-local-qloo-qualification-v1'
                or not isinstance(self.account_ref, str) or not SHA.fullmatch(self.account_ref)
                or self.account_ref != credential_account_ref):
            raise PaidRefusal('paid_scope_mismatch')
        if self.quota_namespace_sha256 != namespace_ref(self.account_ref, table_name):
            raise PaidRefusal('paid_namespace_mismatch')
        if any(not isinstance(value, str) or not SHA.fullmatch(value) for value in
               (self.approval_evidence_sha256, self.maximum_cost_evidence_sha256)):
            raise PaidRefusal('paid_evidence_missing')
        if (not _integer(self.usd_ceiling_microusd) or not _integer(self.maximum_charge_per_raw_microusd)
                or self.maximum_charge_per_raw_microusd * SLOTS > self.usd_ceiling_microusd):
            raise PaidRefusal('paid_cost_bound_invalid')
        if (not _integer(self.starts_at) or not _integer(self.expires_at) or type(now) is not int
                or not self.starts_at <= now < self.expires_at
                or not self.starts_at < self.expires_at
                or type(config.expires_at) is not int or not now < config.expires_at <= self.expires_at):
            raise PaidRefusal('paid_period_invalid')
        if (type(self.daily_raw_limit) is not int or self.daily_raw_limit != SLOTS
                or type(self.lifetime_raw_limit) is not int or self.lifetime_raw_limit != SLOTS
                or policy.entitlement_daily != SLOTS or policy.entitlement_lifetime != SLOTS
                or type(policy.provider_daily) is not int or not 0 < policy.provider_daily <= SLOTS
                or type(policy.provider_lifetime) is not int or not 0 < policy.provider_lifetime <= SLOTS
                or policy.max_raw_calls_per_request != 4 or policy.app_id != 'qloo'
                or policy.post_daily != 2 or policy.post_lifetime != 2
                or policy.expires_at != config.expires_at or not policy.live_enabled or not policy.raw_bound_verified):
            raise PaidRefusal('paid_raw_policy_invalid')
        return {'allowance_slots': SLOTS,
                'conservative_maximum_microusd': SLOTS * self.maximum_charge_per_raw_microusd,
                'dollar_scope': 'this exact account/table/app/control namespace only; other credential consumers excluded'}


def namespace_ref(account_ref, table_name):
    if (not isinstance(account_ref,str) or not SHA.fullmatch(account_ref)
            or not isinstance(table_name,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{3,255}',table_name)):
        raise PaidRefusal('paid_namespace_invalid')
    value={'account_ref':account_ref,'table':table_name,'app_id':'qloo',
           'control_key':'quota#v2#control','control_version':2}
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
