"""Unified Telco Fraud Interception Switch coordinating fraud detection subsystems."""

from dataclasses import dataclass
from decimal import Decimal
import time
from typing import Optional

from src.fraud.device import DeviceAnomalyDecision, DeviceSecurityEngine, GeoCoordinate
from src.fraud.rules import FraudAction, RiskAssessment, RiskEngine
from src.fraud.velocity import VelocityEvaluation, VelocityProfiler
from src.fraud.watchlist import WatchlistEngine
from src.models.enums import RiskTier


class FraudInterceptionError(Exception):
    """Raised when an in-flight transaction is blocked by the fraud switch."""

    def __init__(self, message: str, assessment: RiskAssessment):
        super().__init__(message)
        self.assessment = assessment


@dataclass(frozen=True)
class InterceptionDecision:
    """Actionable decision payload returned by the interceptor switch."""
    is_cleared: bool
    action: FraudAction
    risk_assessment: RiskAssessment
    reason: Optional[str] = None

    @property
    def is_blocked(self) -> bool:
        return self.action == FraudAction.BLOCK

    @property
    def requires_challenge(self) -> bool:
        return self.action == FraudAction.CHALLENGE


class FraudInterceptor:
    """Central fraud interception switch orchestrating velocity, watchlist, and device telemetry."""

    def __init__(
        self,
        risk_engine: Optional[RiskEngine] = None,
        velocity_profiler: Optional[VelocityProfiler] = None,
        device_security_engine: Optional[DeviceSecurityEngine] = None,
        watchlist_engine: Optional[WatchlistEngine] = None,
    ):
        self.watchlist_engine = watchlist_engine or WatchlistEngine()
        self.velocity_profiler = velocity_profiler or VelocityProfiler()
        self.device_security_engine = device_security_engine or DeviceSecurityEngine()
        self.risk_engine = risk_engine or RiskEngine(watchlist_engine=self.watchlist_engine)

    def inspect_transaction(
        self,
        msisdn: str,
        amount: Decimal,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        geo_coord: Optional[GeoCoordinate] = None,
        timestamp: Optional[float] = None,
        hour_of_day: Optional[int] = None,
        record_state: bool = True,
    ) -> InterceptionDecision:
        """
        Execute pre-flight multi-vector fraud evaluation.

        If record_state is True and the transaction is not blocked, records the
        transaction event in the velocity and device tracking stores.
        """
        now = timestamp if timestamp is not None else time.time()

        # 1. Sliding-Window Velocity Profiling
        velocity_eval: VelocityEvaluation = self.velocity_profiler.evaluate(
            key=msisdn,
            amount=amount,
            timestamp=now,
        )

        # 2. Device Fingerprint & Geo-Velocity Telemetry
        if record_state:
            device_eval = self.device_security_engine.inspect_and_record(
                msisdn=msisdn,
                device_id=device_id,
                geo_coord=geo_coord,
                current_time=now,
            )
        else:
            geo_alert = (
                self.device_security_engine.evaluate_geo_velocity(msisdn, geo_coord, current_time=now)
                if geo_coord
                else None
            )
            multiplexing_violation = False
            msisdn_count = 1
            if device_id and device_id.strip():
                multiplexing_violation, msisdn_count = (
                    self.device_security_engine.evaluate_device_multiplexing(
                        device_id, msisdn, current_time=now
                    )
                )

            impossible_travel = geo_alert is not None
            reasons = []
            if impossible_travel and geo_alert:
                reasons.append(
                    f"Impossible travel detected: {geo_alert.distance_km:.1f} km in "
                    f"{geo_alert.time_elapsed_hours:.2f} hrs ({geo_alert.calculated_speed_kmh:.1f} km/h)"
                )
            if multiplexing_violation:
                reasons.append(
                    f"Device SIM multiplexing detected: {msisdn_count} accounts on device within window"
                )

            device_eval = DeviceAnomalyDecision(
                is_allowed=not (impossible_travel or multiplexing_violation),
                impossible_travel=impossible_travel,
                device_multiplexing=multiplexing_violation,
                geo_alert=geo_alert,
                associated_msisdns_count=msisdn_count,
                reason="; ".join(reasons) if reasons else None,
            )

        # 3. Composite Risk Evaluation
        assessment = self.risk_engine.evaluate_transaction(
            msisdn=msisdn,
            amount=amount,
            ip_address=ip_address,
            device_id=device_id,
            velocity_eval=velocity_eval,
            device_eval=device_eval,
            hour_of_day=hour_of_day,
        )

        is_cleared = assessment.action in (FraudAction.ALLOW, FraudAction.FLAG)

        # 4. State Commitment on Clearance
        if record_state and is_cleared:
            self.velocity_profiler.record_event(msisdn, amount, timestamp=now)

        summary_reason = (
            "; ".join(f"{f.rule_name}: {f.description}" for f in assessment.factors)
            if assessment.factors
            else None
        )

        return InterceptionDecision(
            is_cleared=is_cleared,
            action=assessment.action,
            risk_assessment=assessment,
            reason=summary_reason,
        )

    def enforce_clearance(
        self,
        msisdn: str,
        amount: Decimal,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        geo_coord: Optional[GeoCoordinate] = None,
        timestamp: Optional[float] = None,
        hour_of_day: Optional[int] = None,
    ) -> InterceptionDecision:
        """
        Evaluate transaction clearance and assert approval.

        Raises:
            FraudInterceptionError: If the transaction risk action is BLOCK.
        """
        decision = self.inspect_transaction(
            msisdn=msisdn,
            amount=amount,
            ip_address=ip_address,
            device_id=device_id,
            geo_coord=geo_coord,
            timestamp=timestamp,
            hour_of_day=hour_of_day,
            record_state=True,
        )

        if decision.is_blocked:
            msg = f"Transaction for MSISDN '{msisdn}' blocked by fraud interceptor: {decision.reason}"
            raise FraudInterceptionError(msg, assessment=decision.risk_assessment)

        return decision
    