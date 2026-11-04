"""Tests for Great Circle Haversine distance, geo-velocity impossible travel, and device multiplexing."""

import pytest

from src.fraud.device import (
    DeviceSecurityEngine,
    GeoCoordinate,
    haversine_distance_km,
)


def test_geocoordinate_range_validation():
    # Valid Nairobi coordinates
    coord = GeoCoordinate(latitude=-1.286389, longitude=36.817223, city="Nairobi", country_code="KE")
    assert coord.latitude == -1.286389

    with pytest.raises(ValueError, match="Latitude '-95.0' out of valid range"):
        GeoCoordinate(latitude=-95.0, longitude=36.0)

    with pytest.raises(ValueError, match="Longitude '190.0' out of valid range"):
        GeoCoordinate(latitude=0.0, longitude=190.0)


def test_haversine_distance_nairobi_to_mombasa():
    # Nairobi: -1.286389, 36.817223
    # Mombasa: -4.043477, 39.668206
    # Great circle distance is ~440-450 km
    dist = haversine_distance_km(-1.286389, 36.817223, -4.043477, 39.668206)
    assert 435.0 <= dist <= 455.0


def test_haversine_identical_coordinates():
    dist = haversine_distance_km(-1.286389, 36.817223, -1.286389, 36.817223)
    assert dist == 0.0


def test_reasonable_ground_travel_allowed():
    engine = DeviceSecurityEngine(max_speed_kmh=900.0)
    msisdn = "254712345678"

    nairobi = GeoCoordinate(latitude=-1.286389, longitude=36.817223, city="Nairobi")
    thika = GeoCoordinate(latitude=-1.03326, longitude=37.06933, city="Thika")  # ~40 km away

    t0 = 10000.0
    # Initial event in Nairobi at t0
    dec1 = engine.inspect_and_record(msisdn=msisdn, geo_coord=nairobi, current_time=t0)
    assert dec1.is_allowed is True

    # 1 hour later (3600s), event in Thika (speed ~ 40 km/h)
    dec2 = engine.inspect_and_record(msisdn=msisdn, geo_coord=thika, current_time=t0 + 3600.0)
    assert dec2.is_allowed is True
    assert dec2.impossible_travel is False


def test_impossible_travel_triggers_alert():
    engine = DeviceSecurityEngine(max_speed_kmh=900.0)
    msisdn = "254722000000"

    nairobi = GeoCoordinate(latitude=-1.286389, longitude=36.817223, city="Nairobi")
    london = GeoCoordinate(latitude=51.5074, longitude=-0.1278, city="London")  # ~6,800 km away

    t0 = 20000.0
    # First checkout in Nairobi
    engine.inspect_and_record(msisdn=msisdn, geo_coord=nairobi, current_time=t0)

    # 10 minutes later (600s), second checkout originating in London
    # Speed = 6800 km / 0.1667 hrs = ~40,800 km/h (impossible)
    decision = engine.inspect_and_record(msisdn=msisdn, geo_coord=london, current_time=t0 + 600.0)

    assert decision.is_allowed is False
    assert decision.impossible_travel is True
    assert decision.geo_alert is not None
    assert decision.geo_alert.calculated_speed_kmh > 30000.0
    assert "Impossible travel detected" in (decision.reason or "")


def test_device_sim_multiplexing_detection():
    # Max 3 MSISDNs per device within 1 hour window
    engine = DeviceSecurityEngine(max_msisdns_per_device=3, device_window_seconds=3600)
    device_id = "IMEI-864209041234567"
    t0 = 30000.0

    # Associate 3 distinct MSISDNs on same device -> allowed
    for i in range(1, 4):
        phone = f"25470000000{i}"
        dec = engine.inspect_and_record(msisdn=phone, device_id=device_id, current_time=t0 + (i * 10))
        assert dec.is_allowed is True
        assert dec.device_multiplexing is False

    # 4th MSISDN within same hour -> triggers multiplexing breach
    dec4 = engine.inspect_and_record(
        msisdn="254700000004", device_id=device_id, current_time=t0 + 60.0
    )
    assert dec4.is_allowed is False
    assert dec4.device_multiplexing is True
    assert dec4.associated_msisdns_count == 4
    assert "Device SIM multiplexing detected" in (dec4.reason or "")
    