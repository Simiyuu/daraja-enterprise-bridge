"""Tests for composite risk scoring, factor explanations, and policy actions."""

from decimal import Decimal
import pytest

from src.fraud.device import DeviceAnomalyDecision
from src.fraud.rules import FraudAction, RiskEngine
from src.fraud.velocity import VelocityEvaluation, VelocityViolation
from src.fraud.watchlist import WatchlistEngine, WatchlistEntityType, WatchlistType
from src.models.enums import RiskTier


@pytest.fixture
def risk_engine():
    watchlist = WatchlistEngine()
    # Pre-populate sample sanctions
    watchlist.add_entry(
        entity_value="0711000000",
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.BLACKLIST,
        reason="Known SIM box fraudster",
    )
    watchlist.add_entry(
        entity_value="0722000000",
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.GREYLIST,
        reason="Rapid SIM replacement under investigation",
    )
    watchlist.add_entry(
        entity_value="0733000000",
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.WHITELIST,
        reason="Verified VIP Corporate Partner",
    )
    return RiskEngine(watchlist_engine=watchlist)


def test_clean_low_risk_transaction_allowed(risk_engine):
    assessment = risk_engine.evaluate_transaction(
        msisdn="0712345678",
        amount=Decimal("1500.00"),
        hour_of_day=14,  # 2 PM
    )

    assert assessment.composite_score == 0
    assert assessment.risk_tier == RiskTier.LOW
    assert assessment.action == FraudAction.ALLOW
    assert assessment.is_allowed is True
    assert assessment.is_blocked is False
    assert len(assessment.factors) == 0


def test_blacklisted_msisdn_immediate_block(risk_engine):
    assessment = risk_engine.evaluate_transaction(
        msisdn="0711000000",
        amount=Decimal("500.00"),
    )

    assert assessment.composite_score == 100
    assert assessment.risk_tier == RiskTier.CRITICAL_INTERCEPT
    assert assessment.action == FraudAction.BLOCK
    assert assessment.is_blocked is True
    assert any(f.rule_name == "BLACKLISTED_MSISDN" for f in assessment.factors)


def test_greylisted_msisdn_triggers_flag(risk_engine):
    assessment = risk_engine.evaluate_transaction(
        msisdn="0722000000",
        amount=Decimal("2000.00"),
    )

    # Greylist contributes 35 points -> ELEVATED tier (30-84) with FLAG action (<60)
    assert assessment.composite_score == 35
    assert assessment.risk_tier == RiskTier.ELEVATED
    assert assessment.action == FraudAction.FLAG
    assert assessment.is_allowed is True


def test_elevated_and_high_value_brackets(risk_engine):
    # Elevated tier: KES 80,000 -> 20 points -> LOW tier (<30)
    res_elevated = risk_engine.evaluate_transaction(
        msisdn="0799111111",
        amount=Decimal("80000.00"),
    )
    assert res_elevated.composite_score == 20
    assert res_elevated.action == FraudAction.ALLOW

    # High value tier: KES 160,000 -> 35 points -> ELEVATED tier -> FLAG
    res_high = risk_engine.evaluate_transaction(
        msisdn="0799111111",
        amount=Decimal("160000.00"),
    )
    assert res_high.composite_score == 35
    assert res_high.risk_tier == RiskTier.ELEVATED
    assert res_high.action == FraudAction.FLAG


def test_combined_signals_escalate_to_challenge(risk_engine):
    # Velocity volume breach (+40) + Elevated transaction (+20) = 60 points -> ELEVATED tier -> CHALLENGE (>=60)
    mock_velocity = VelocityEvaluation(
        key="0799222222",
        is_allowed=False,
        violations=[
            VelocityViolation(
                window_seconds=3600,
                metric="VOLUME",
                limit=Decimal("100000.00"),
                observed=Decimal("150000.00"),
            )
        ],
    )

    assessment = risk_engine.evaluate_transaction(
        msisdn="0799222222",
        amount=Decimal("75000.00"),
        velocity_eval=mock_velocity,
    )

    assert assessment.composite_score == 60
    assert assessment.risk_tier == RiskTier.ELEVATED
    assert assessment.action == FraudAction.CHALLENGE


def test_impossible_travel_and_device_multiplexing_block(risk_engine):
    # Impossible travel (+50) + Device multiplexing (+40) = 90 points -> CRITICAL_INTERCEPT -> BLOCK (>=85)
    mock_device = DeviceAnomalyDecision(
        is_allowed=False,
        impossible_travel=True,
        device_multiplexing=True,
        associated_msisdns_count=5,
    )

    assessment = risk_engine.evaluate_transaction(
        msisdn="0799333333",
        amount=Decimal("5000.00"),
        device_eval=mock_device,
    )

    assert assessment.composite_score == 90
    assert assessment.risk_tier == RiskTier.CRITICAL_INTERCEPT
    assert assessment.action == FraudAction.BLOCK
    assert assessment.is_blocked is True


def test_nocturnal_anomaly_weighting(risk_engine):
    # 3 AM transaction with KES 75,000: Nocturnal (+15) + Elevated Value (+20) = 35 -> ELEVATED (FLAG)
    assessment = risk_engine.evaluate_transaction(
        msisdn="0799444444",
        amount=Decimal("75000.00"),
        hour_of_day=3,
    )

    assert assessment.composite_score == 35
    assert assessment.action == FraudAction.FLAG
    assert any(f.rule_name == "NOCTURNAL_HIGH_VALUE_ANOMALY" for f in assessment.factors)


def test_whitelist_trust_credit_mitigation(risk_engine):
    # High value transaction (+35) on Whitelisted VIP (-50 credit) clamped to 0
    assessment = risk_engine.evaluate_transaction(
        msisdn="0733000000",
        amount=Decimal("160000.00"),
    )

    assert assessment.composite_score == 0
    assert assessment.action == FraudAction.ALLOW
    assert any(f.rule_name == "WHITELIST_TRUST_CREDIT" for f in assessment.factors)
    