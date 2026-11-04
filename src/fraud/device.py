"""Geo-IP velocity anomaly detection and device multiplexing analysis."""

from dataclasses import dataclass, field
import math
import threading
import time
from typing import Dict, List, Optional, Set, Tuple


# Earth radius in kilometers for Great Circle spherical calculations
EARTH_RADIUS_KM = 6371.0


def haversine_distance_km(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """Calculate the Great Circle distance between two coordinates in kilometers."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_KM * c


@dataclass(frozen=True)
class GeoCoordinate:
    latitude: float
    longitude: float
    city: Optional[str] = None
    country_code: Optional[str] = None

    def __post_init__(self):
        if not (-90.0 <= self.latitude <= 90.0):
            raise ValueError(f"Latitude '{self.latitude}' out of valid range [-90, 90].")
        if not (-180.0 <= self.longitude <= 180.0):
            raise ValueError(f"Longitude '{self.longitude}' out of valid range [-180, 180].")


@dataclass(frozen=True)
class GeoVelocityAlert:
    distance_km: float
    time_elapsed_hours: float
    calculated_speed_kmh: float
    max_allowable_speed_kmh: float
    origin: GeoCoordinate
    destination: GeoCoordinate


@dataclass(frozen=True)
class DeviceAnomalyDecision:
    is_allowed: bool
    impossible_travel: bool = False
    device_multiplexing: bool = False
    geo_alert: Optional[GeoVelocityAlert] = None
    associated_msisdns_count: int = 1
    reason: Optional[str] = None


class DeviceSecurityEngine:
    """Thread-safe engine monitoring geo-velocity impossible travel and device-to-SIM multiplexing."""

    def __init__(
        self,
        max_speed_kmh: float = 900.0,
        max_msisdns_per_device: int = 3,
        device_window_seconds: int = 3600,
    ):
        self.max_speed_kmh = max_speed_kmh
        self.max_msisdns_per_device = max_msisdns_per_device
        self.device_window_seconds = device_window_seconds

        # In-memory tracking:
        # {msisdn: (GeoCoordinate, timestamp)}
        self._user_geo_history: Dict[str, Tuple[GeoCoordinate, float]] = {}
        # {device_id: [(msisdn, timestamp)]}
        self._device_associations: Dict[str, List[Tuple[str, float]]] = {}
        self._lock = threading.RLock()

    def evaluate_geo_velocity(
        self,
        msisdn: str,
        current_geo: GeoCoordinate,
        current_time: Optional[float] = None,
    ) -> Optional[GeoVelocityAlert]:
        """
        Evaluate if user location change implies impossible travel speed.

        Returns GeoVelocityAlert if speed exceeds max_speed_kmh, otherwise None.
        """
        now = current_time if current_time is not None else time.time()
        clean_msisdn = msisdn.strip()

        with self._lock:
            last_record = self._user_geo_history.get(clean_msisdn)
            if not last_record:
                return None

            prev_geo, prev_time = last_record
            time_delta_seconds = now - prev_time

            # If timestamps are identical or negative, allow zero distance; flag non-zero
            if time_delta_seconds <= 0:
                dist = haversine_distance_km(
                    prev_geo.latitude, prev_geo.longitude,
                    current_geo.latitude, current_geo.longitude,
                )
                if dist > 1.0:
                    return GeoVelocityAlert(
                        distance_km=dist,
                        time_elapsed_hours=0.0,
                        calculated_speed_kmh=float("inf"),
                        max_allowable_speed_kmh=self.max_speed_kmh,
                        origin=prev_geo,
                        destination=current_geo,
                    )
                return None

            time_elapsed_hours = time_delta_seconds / 3600.0
            dist_km = haversine_distance_km(
                prev_geo.latitude, prev_geo.longitude,
                current_geo.latitude, current_geo.longitude,
            )
            speed_kmh = dist_km / time_elapsed_hours

            if speed_kmh > self.max_speed_kmh:
                return GeoVelocityAlert(
                    distance_km=dist_km,
                    time_elapsed_hours=time_elapsed_hours,
                    calculated_speed_kmh=speed_kmh,
                    max_allowable_speed_kmh=self.max_speed_kmh,
                    origin=prev_geo,
                    destination=current_geo,
                )

        return None

    def evaluate_device_multiplexing(
        self,
        device_id: str,
        msisdn: str,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, int]:
        """
        Evaluate if device is cycling an abnormal count of MSISDNs within the configured window.

        Returns: (is_multiplexing_violation, unique_msisdns_count)
        """
        now = current_time if current_time is not None else time.time()
        clean_dev = device_id.strip().upper()
        clean_msisdn = msisdn.strip()
        cutoff = now - self.device_window_seconds

        with self._lock:
            history = self._device_associations.get(clean_dev, [])
            valid_entries = [e for e in history if e[1] >= cutoff]

            unique_msisdns = {e[0] for e in valid_entries}
            unique_msisdns.add(clean_msisdn)
            count = len(unique_msisdns)

            is_violation = count > self.max_msisdns_per_device
            return is_violation, count

    def inspect_and_record(
        self,
        msisdn: str,
        device_id: Optional[str] = None,
        geo_coord: Optional[GeoCoordinate] = None,
        current_time: Optional[float] = None,
    ) -> DeviceAnomalyDecision:
        """
        Atomically inspect both geo-velocity and device multiplexing rules, recording the session.
        """
        now = current_time if current_time is not None else time.time()
        clean_msisdn = msisdn.strip()

        with self._lock:
            geo_alert = None
            if geo_coord is not None:
                geo_alert = self.evaluate_geo_velocity(clean_msisdn, geo_coord, current_time=now)

            multiplexing_violation = False
            msisdn_count = 1
            if device_id is not None and device_id.strip():
                clean_dev = device_id.strip().upper()
                multiplexing_violation, msisdn_count = self.evaluate_device_multiplexing(
                    clean_dev, clean_msisdn, current_time=now
                )

            # Determine final decision
            impossible_travel = geo_alert is not None
            is_allowed = not (impossible_travel or multiplexing_violation)

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

            decision = DeviceAnomalyDecision(
                is_allowed=is_allowed,
                impossible_travel=impossible_travel,
                device_multiplexing=multiplexing_violation,
                geo_alert=geo_alert,
                associated_msisdns_count=msisdn_count,
                reason="; ".join(reasons) if reasons else None,
            )

            # Record state if compliant or for continued tracking
            if geo_coord is not None:
                self._user_geo_history[clean_msisdn] = (geo_coord, now)

            if device_id is not None and device_id.strip():
                clean_dev = device_id.strip().upper()
                if clean_dev not in self._device_associations:
                    self._device_associations[clean_dev] = []
                self._device_associations[clean_dev].append((clean_msisdn, now))

            return decision
            