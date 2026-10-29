"""Host-supplied public-demo allowance; no authority, pricing or credit inferred.

The durable namespace consumes route reservations before HTTP. Other programs
using the same provider key are outside this namespace and financial bound.
"""
from dataclasses import dataclass
from paid_entitlement import HOST, SHA, namespace_ref, PaidRefusal


def positive(value):
    return type(value) is int and value > 0


@dataclass(frozen=True)
class PublicPaidEntitlement:
    api_host: str
    account_ref: str
    approval_evidence_sha256: str
    maximum_cost_evidence_sha256: str
    usd_ceiling_microusd: int
    maximum_charge_per_raw_microusd: int
    starts_at: int
    expires_at: int
    quota_namespace_sha256: str
    daily_raw_limit: int
    lifetime_raw_limit: int
    post_daily: int
    post_lifetime: int
    host_explicitly_enabled: bool = False
    scope: str = 'one-public-qloo-demo-v1'

    @property
    def free_no_automatic_overage_verified(self):
        return False

    def validate(self, config, policy, *, credential_account_ref, table_name, now):
        if self.host_explicitly_enabled is not True:
            raise PaidRefusal('public_paid_not_enabled')
        if (self.api_host != HOST or self.scope != 'one-public-qloo-demo-v1'
                or not isinstance(self.account_ref, str) or not SHA.fullmatch(self.account_ref)
                or self.account_ref != credential_account_ref
                or self.quota_namespace_sha256 != namespace_ref(self.account_ref, table_name)):
            raise PaidRefusal('public_paid_scope_mismatch')
        if any(not isinstance(v, str) or not SHA.fullmatch(v) for v in
               (self.approval_evidence_sha256, self.maximum_cost_evidence_sha256)):
            raise PaidRefusal('public_paid_evidence_missing')
        integers = (self.usd_ceiling_microusd, self.maximum_charge_per_raw_microusd,
                    self.starts_at, self.expires_at, self.daily_raw_limit,
                    self.lifetime_raw_limit, self.post_daily, self.post_lifetime)
        if not all(positive(v) for v in integers):
            raise PaidRefusal('public_paid_bound_invalid')
        if (not 4 <= self.daily_raw_limit <= min(300, self.lifetime_raw_limit)
                or self.lifetime_raw_limit > 2500
                or not 1 <= self.post_daily <= min(100, self.post_lifetime)
                or self.post_lifetime > 2000
                or self.maximum_charge_per_raw_microusd * self.lifetime_raw_limit > self.usd_ceiling_microusd):
            raise PaidRefusal('public_paid_cost_bound_invalid')
        if (type(now) is not int or not self.starts_at <= now < self.expires_at
                or type(config.expires_at) is not int
                or not now < config.expires_at <= self.expires_at):
            raise PaidRefusal('public_paid_period_invalid')
        if (policy.app_id != 'qloo' or policy.max_raw_calls_per_request != 4
                or policy.expires_at != config.expires_at
                or policy.entitlement_daily != self.daily_raw_limit
                or policy.entitlement_lifetime != self.lifetime_raw_limit
                or policy.provider_daily != self.daily_raw_limit
                or policy.provider_lifetime != self.lifetime_raw_limit
                or policy.post_daily != self.post_daily or policy.post_lifetime != self.post_lifetime
                or policy.live_enabled is not True or policy.raw_bound_verified is not True):
            raise PaidRefusal('public_paid_policy_invalid')
        return {'allowance_slots': self.lifetime_raw_limit,
                'conservative_maximum_microusd': self.lifetime_raw_limit * self.maximum_charge_per_raw_microusd,
                'scope': 'exact account/table/control only; other key consumers excluded'}
