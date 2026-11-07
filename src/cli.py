"""Operational CLI and diagnostic probe interface for the Daraja Enterprise Bridge."""

import argparse
from decimal import Decimal
import json
import sys
from typing import List, Optional

from src.bridge import DarajaEnterpriseBridge
from src.config import BridgeConfig
from src.fraud.watchlist import WatchlistEntityType, WatchlistType


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="daraja-bridge",
        description="Operational command-line utility and diagnostic probe for Daraja Enterprise Bridge.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. Probe command
    probe_parser = subparsers.add_parser("probe", help="Run environment diagnostic probe and connectivity checks.")
    probe_parser.add_argument("--json", action="store_true", help="Output diagnostic report in JSON format.")

    # 2. Audit command
    audit_parser = subparsers.add_parser("audit", help="Execute trial balance and ledger equilibrium audit.")
    audit_parser.add_argument("--json", action="store_true", help="Output audit report in JSON format.")

    # 3. Screen command
    screen_parser = subparsers.add_parser("screen", help="Screen an entity against fraud watchlists and risk rules.")
    screen_parser.add_argument("--msisdn", type=str, help="Phone number to screen (e.g., 0712345678).")
    screen_parser.add_argument("--ip", type=str, help="IP address to screen (e.g., 196.201.214.200).")
    screen_parser.add_argument("--device", type=str, help="Device ID / IMEI to screen.")
    screen_parser.add_argument("--amount", type=str, default="1000.00", help="Transaction amount to simulate (default: 1000.00).")
    screen_parser.add_argument("--json", action="store_true", help="Output screening evaluation in JSON format.")

    return parser


def handle_probe(args: argparse.Namespace) -> int:
    report = {
        "status": "HEALTHY",
        "environment": None,
        "checks": {},
        "errors": [],
    }

    try:
        cfg = BridgeConfig.from_env()
        report["environment"] = cfg.environment.value
        report["checks"]["config_loaded"] = True
        report["checks"]["shortcode"] = cfg.shortcode
        report["checks"]["base_url"] = cfg.base_url
        report["checks"]["callback_url"] = cfg.callback_url
        report["checks"]["ip_whitelist_enforced"] = cfg.enforce_ip_whitelist
    except Exception as exc:
        report["status"] = "UNHEALTHY"
        report["checks"]["config_loaded"] = False
        report["errors"].append(f"Configuration error: {str(exc)}")

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Bridge Diagnostics: [{report['status']}]")
        for k, v in report["checks"].items():
            print(f"  - {k}: {v}")
        if report["errors"]:
            print("  Errors:")
            for err in report["errors"]:
                print(f"    * {err}")

    return 0 if report["status"] == "HEALTHY" else 1


def handle_audit(args: argparse.Namespace) -> int:
    try:
        cfg = BridgeConfig.from_env()
    except Exception:
        # Fallback configuration for isolated audit inspection
        cfg = BridgeConfig(
            consumer_key="probe_key_12345",
            consumer_secret="probe_secret_12345",
            passkey="probe_passkey_0123456789abcdef",
            shortcode="174379",
            callback_url="https://example.com/callback",
        )

    bridge = DarajaEnterpriseBridge(config=cfg)
    tb = bridge.get_trial_balance()
    integrity = bridge.verify_ledger_integrity()

    total_journals = getattr(
        integrity,
        "total_journals",
        getattr(
            integrity,
            "journals_checked",
            getattr(
                integrity,
                "total_checked",
                getattr(
                    integrity,
                    "journals_audited",
                    len(getattr(bridge.ledger_engine, "_journals", {})),
                ),
            ),
        ),
    )

    corrupt_items = getattr(
        integrity,
        "corrupted_journals",
        getattr(integrity, "corrupt_journals", []),
    )
    corrupt_count = len(corrupt_items) if isinstance(corrupt_items, (list, tuple, set)) else int(corrupt_items)

    report = {
        "is_balanced": tb.is_balanced,
        "total_debits": str(tb.total_debits),
        "total_credits": str(tb.total_credits),
        "discrepancy": str(tb.discrepancy),
        "is_sound": integrity.is_sound,
        "total_journals": total_journals,
        "corrupt_journals_count": corrupt_count,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        status_text = "PASSED" if (tb.is_balanced and integrity.is_sound) else "FAILED"
        print(f"Ledger Audit: [{status_text}]")
        print(f"  - Balanced: {tb.is_balanced} (Debits: {tb.total_debits}, Credits: {tb.total_credits})")
        print(f"  - Integrity: {'SOUND' if integrity.is_sound else 'COMPROMISED'} ({total_journals} journals verified)")

    return 0 if (tb.is_balanced and integrity.is_sound) else 1


def handle_screen(args: argparse.Namespace) -> int:
    if not (args.msisdn or args.ip or args.device):
        sys.stderr.write("Error: At least one of --msisdn, --ip, or --device must be provided for screening.\n")
        return 2

    try:
        cfg = BridgeConfig.from_env()
    except Exception:
        cfg = BridgeConfig(
            consumer_key="probe_key_12345",
            consumer_secret="probe_secret_12345",
            passkey="probe_passkey_0123456789abcdef",
            shortcode="174379",
            callback_url="https://example.com/callback",
        )

    bridge = DarajaEnterpriseBridge(config=cfg)
    amount = Decimal(args.amount)

    phone = args.msisdn or "254700000000"
    decision = bridge.inspect_risk(
        phone_number=phone,
        amount=amount,
        ip_address=args.ip,
        device_id=args.device,
    )

    report = {
        "is_cleared": decision.is_cleared,
        "action": decision.action.value,
        "risk_tier": decision.risk_assessment.risk_tier.value,
        "composite_score": decision.risk_assessment.composite_score,
        "reason": decision.reason,
        "factors": [
            {"rule": f.rule_name, "weight": f.weight, "desc": f.description}
            for f in decision.risk_assessment.factors
        ],
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Risk Screening Result: [{decision.action.value}] (Score: {decision.risk_assessment.composite_score})")
        print(f"  - Cleared: {decision.is_cleared}")
        print(f"  - Tier: {decision.risk_assessment.risk_tier.value}")
        if decision.reason:
            print(f"  - Reason: {decision.reason}")

    return 0 if decision.is_cleared else 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "probe":
        return handle_probe(args)
    elif args.command == "audit":
        return handle_audit(args)
    elif args.command == "screen":
        return handle_screen(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
    