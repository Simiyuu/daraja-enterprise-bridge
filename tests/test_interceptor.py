"""Tests for the unified telco fraud interception switch."""

from decimal import Decimal
import pytest

from src.fraud.device import GeoCoordinate
from src.fraud.interceptor import FraudInterceptor, FraudInterceptionError
from src.fraud.rules import FraudAction
from src.fraud.velocity import VelocityWindow
from src.fraud.watchlist import WatchlistEntityType, WatchlistType
from src.models.enums import RiskTier


@pytest.fixture
def interceptor():
    return FraudInterceptor()


def test_clean_transaction_cleared_and_recorded(interceptor):
    msisdn = "0712345678"
    amount = Decimal("2500.00")

    decision = interceptor.inspect_transaction(
        msisdn=msisdn,
        amount=amount,
        hour_of_day=14,
    )

    assert decision.is_cleared is True
    assert decision.action == FraudAction.ALLOW
    assert decision.is_blocked is False
    assert decision.requires_challenge is False
    assert decision.risk_assessment.risk_tier == RiskTier.LOW

    # Verify transaction was recorded in velocity history
    events = interceptor.velocity_profiler._events.get("0712345678", [])
    assert len(events) == 1
    assert events[0][1] == amount


def test_blacklisted_entity_blocked_and_enforce_raises(interceptor):
    msisdn = "0799000000"
    interceptor.watchlist_engine.add_entry(
        entity_value=msisdn,
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.BLACKLIST,
        reason="Reported fraud syndicate",
    )

    decision = interceptor.inspect_transaction(
        msisdn=msisdn,
        amount=Decimal("1000.00"),
    )

    assert decision.is_cleared is False
    assert decision.is_blocked is True
    assert decision.action == FraudAction.BLOCK
    assert decision.risk_assessment.risk_tier == RiskTier.CRITICAL_INTERCEPT

    # Enforce clearance must raise FraudInterceptionError
    with pytest.raises(FraudInterceptionError, match="blocked by fraud interceptor") as exc_info:
        interceptor.enforce_clearance(
            msisdn=msisdn,
            amount=Decimal("1000.00"),
        )
    assert exc_info.value.assessment.action == FraudAction.BLOCK


def test_impossible_travel_intercept(interceptor):
    msisdn = "0722111111"
    nairobi = GeoCoordinate(latitude=-1.286389, longitude=36.817223, city="Nairobi")
    london = GeoCoordinate(latitude=51.5074, longitude=-0.1278, city="London")

    t0 = 10000.0
    # First valid transaction in Nairobi
    dec1 = interceptor.inspect_transaction(
        msisdn=msisdn,
        amount=Decimal("5000.00"),
        geo_coord=nairobi,
        timestamp=t0,
    )
    assert dec1.is_cleared is True

    # 10 minutes later from London with elevated value (KES 75,000)
    # Impossible travel (+50) + Elevated value (+20) = 70 points -> CHALLENGE action
    dec2 = interceptor.inspect_transaction(
        msisdn=msisdn,
        amount=Decimal("75000.00"),
        geo_coord=london,
        timestamp=t0 + 600.0,
    )

    assert dec2.is_cleared is False
    assert dec2.requires_challenge is True
    assert dec2.action == FraudAction.CHALLENGE
    assert "IMPOSSIBLE_TRAVEL_SPEED" in (dec2.reason or "")
    assert any(f.rule_name == "IMPOSSIBLE_TRAVEL_SPEED" for f in dec2.risk_assessment.factors)


def test_dry_run_does_not_mutate_state(interceptor):
    msisdn = "0788333333"
    amount = Decimal("1000.00")

    decision = interceptor.inspect_transaction(
        msisdn=msisdn,
        amount=amount,
        record_state=False,  # Dry run
    )

    assert decision.is_cleared is True
    # Ensure nothing was committed to memory stores
    assert "0788333333" not in interceptor.velocity_profiler._events


def test_velocity_limit_breach_intercept(interceptor):
    # Configure tight velocity window: max 2 transactions
    interceptor.velocity_profiler.default_windows = [
        VelocityWindow(window_seconds=60, max_count=2)
    ]
    msisdn = "0711999999"

    # Transaction 1 & 2 succeed
    interceptor.inspect_transaction(msisdn=msisdn, amount=Decimal("1000.00"), record_state=True)
    interceptor.inspect_transaction(msisdn=msisdn, amount=Decimal("1000.00"), record_state=True)

    # Transaction 3 breaches rate limit (+30) -> Elevated tier -> FLAG
    dec3 = interceptor.inspect_transaction(msisdn=msisdn, amount=Decimal("1000.00"), record_state=True)
    assert dec3.action == FraudAction.FLAG
    assert "VELOCITY_RATE_BREACH" in (dec3.reason or "")
    assert any(f.rule_name == "VELOCITY_RATE_BREACH" for f in dec3.risk_assessment.factors)
    