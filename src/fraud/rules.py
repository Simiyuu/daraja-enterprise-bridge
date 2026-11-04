"""Composite risk scoring and dynamic decision engine for transaction authorization."""

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional

from src.fraud.device import DeviceAnomalyDecision
from src.fraud.velocity import VelocityEvaluation
from src.fraud.watchlist import WatchlistEngine, WatchlistEntityType, WatchlistType
from src.models.enums import RiskTier


class FraudAction(str, Enum):
    """Actionable decision dictated by risk evaluation."""
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class RiskFactor:
    """Individual triggered risk rule contributing to the composite score."""
    rule_name: str
    weight: int
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RiskAssessment:
    """Final composite decision payload for an in-flight transaction."""
    composite_score: int  # Clamped to [0, 100]
    risk_tier: RiskTier
    action: FraudAction
    factors: List[RiskFactor] = field(default_factory=list)

    @property
    def is_blocked(self) -> bool:
        return self.action == FraudAction.BLOCK

    @property
    def is_allowed(self) -> bool:
        return self.action in (FraudAction.ALLOW, FraudAction.FLAG)


class RiskEngine:
    """Aggregates multi-vector fraud signals into an explainable composite risk score."""

    def __init__(
        self,
        watchlist_engine: Optional[WatchlistEngine] = None,
        low_threshold: int = 30,
        medium_threshold: int = 60,
        high_threshold: int = 85,
    ):
        self.watchlist_engine = watchlist_engine or WatchlistEngine()
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold

    def evaluate_transaction(
        self,
        msisdn: str,
        amount: Decimal,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        velocity_eval: Optional[VelocityEvaluation] = None,
        device_eval: Optional[DeviceAnomalyDecision] = None,
        hour_of_day: Optional[int] = None,
    ) -> RiskAssessment:
        """
        Compute composite risk score across watchlist, velocity, device, and behavioral vectors.
        """
        factors: List[RiskFactor] = []
        score = 0

        # 1. Watchlist Screenings
        # MSISDN
        msisdn_match = self.watchlist_engine.screen(msisdn, WatchlistEntityType.MSISDN)
        if msisdn_match.matched and msisdn_match.list_type == WatchlistType.BLACKLIST:
            factors.append(
                RiskFactor(
                    rule_name="BLACKLISTED_MSISDN",
                    weight=100,
                    description=f"MSISDN '{msisdn}' matches active blacklist",
                )
            )
            score += 100
        elif msisdn_match.matched and msisdn_match.list_type == WatchlistType.GREYLIST:
            factors.append(
                RiskFactor(
                    rule_name="GREYLISTED_MSISDN",
                    weight=35,
                    description=f"MSISDN '{msisdn}' matches greylist review",
                )
            )
            score += 35

        # IP Address
        if ip_address:
            ip_match = self.watchlist_engine.screen(ip_address, WatchlistEntityType.IP_ADDRESS)
            if ip_match.matched and ip_match.list_type == WatchlistType.BLACKLIST:
                factors.append(
                    RiskFactor(
                        rule_name="BLACKLISTED_IP",
                        weight=100,
                        description=f"IP '{ip_address}' matches blacklist",
                    )
                )
                score += 100

        # Device ID
        if device_id:
            dev_match = self.watchlist_engine.screen(device_id, WatchlistEntityType.DEVICE_ID)
            if dev_match.matched and dev_match.list_type == WatchlistType.BLACKLIST:
                factors.append(
                    RiskFactor(
                        rule_name="BLACKLISTED_DEVICE",
                        weight=100,
                        description=f"Device '{device_id}' matches blacklist",
                    )
                )
                score += 100

        # 2. Velocity Violations
        if velocity_eval and not velocity_eval.is_allowed:
            count_violations = [v for v in velocity_eval.violations if v.metric == "COUNT"]
            vol_violations = [v for v in velocity_eval.violations if v.metric == "VOLUME"]

            if count_violations:
                factors.append(
                    RiskFactor(
                        rule_name="VELOCITY_RATE_BREACH",
                        weight=30,
                        description=f"Exceeded transaction frequency limit ({len(count_violations)} windows breached)",
                    )
                )
                score += 30

            if vol_violations:
                factors.append(
                    RiskFactor(
                        rule_name="VELOCITY_VOLUME_BREACH",
                        weight=40,
                        description=f"Exceeded monetary volume limit ({len(vol_violations)} windows breached)",
                    )
                )
                score += 40

        # 3. Geo-IP and Device Multiplexing
        if device_eval:
            if device_eval.impossible_travel:
                factors.append(
                    RiskFactor(
                        rule_name="IMPOSSIBLE_TRAVEL_SPEED",
                        weight=50,
                        description="Geographic relocation speed violates physical bounds",
                    )
                )
                score += 50

            if device_eval.device_multiplexing:
                factors.append(
                    RiskFactor(
                        rule_name="DEVICE_SIM_MULTIPLEXING",
                        weight=40,
                        description=f"Device associated with {device_eval.associated_msisdns_count} accounts",
                    )
                )
                score += 40

        # 4. Transaction Value Outlier
        if amount >= Decimal("150000.00"):
            factors.append(
                RiskFactor(
                    rule_name="HIGH_VALUE_TRANSACTION",
                    weight=35,
                    description="Transaction amount reaches high-value tier (>= KES 150,000)",
                )
            )
            score += 35
        elif amount >= Decimal("70000.00"):
            factors.append(
                RiskFactor(
                    rule_name="ELEVATED_VALUE_TRANSACTION",
                    weight=20,
                    description="Transaction amount reaches elevated tier (>= KES 70,000)",
                )
            )
            score += 20

        # 5. Off-Hours / Nocturnal Anomaly (e.g. 01:00 to 04:59 local time)
        if hour_of_day is not None and (1 <= hour_of_day <= 4) and amount >= Decimal("20000.00"):
            factors.append(
                RiskFactor(
                    rule_name="NOCTURNAL_HIGH_VALUE_ANOMALY",
                    weight=15,
                    description="High-value transaction initiated during nocturnal window (01:00-04:59)",
                )
            )
            score += 15

        # 6. Whitelist Override (if explicit whitelist match exists on MSISDN, reduce score by 50)
        if msisdn_match.matched and msisdn_match.list_type == WatchlistType.WHITELIST:
            score = max(0, score - 50)
            factors.append(
                RiskFactor(
                    rule_name="WHITELIST_TRUST_CREDIT",
                    weight=-50,
                    description="Entity is registered on trusted whitelist; applying risk credit",
                )
            )

        # Clamp composite score to [0, 100]
        clamped_score = max(0, min(100, score))

        # Map to 3-tier RiskTier taxonomy and 4-tier FraudAction policy
        if clamped_score < self.low_threshold:
            tier = RiskTier.LOW
            action = FraudAction.ALLOW
        elif clamped_score < self.high_threshold:
            tier = RiskTier.ELEVATED
            action = (
                FraudAction.CHALLENGE
                if clamped_score >= self.medium_threshold
                else FraudAction.FLAG
            )
        else:
            tier = RiskTier.CRITICAL_INTERCEPT
            action = FraudAction.BLOCK

        return RiskAssessment(
            composite_score=clamped_score,
            risk_tier=tier,
            action=action,
            factors=factors,
        )
    