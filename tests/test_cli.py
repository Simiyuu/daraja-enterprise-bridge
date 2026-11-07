"""Tests for operational CLI diagnostic probe, ledger audit, and risk screening."""

import json
from unittest.mock import patch
import pytest

from src.cli import main


@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("DARAJA_ENVIRONMENT", "SANDBOX")
    monkeypatch.setenv("DARAJA_CONSUMER_KEY", "cli_test_consumer_key")
    monkeypatch.setenv("DARAJA_CONSUMER_SECRET", "cli_test_consumer_secret")
    monkeypatch.setenv("DARAJA_PASSKEY", "cli_test_passkey_0123456789abcdef")
    monkeypatch.setenv("DARAJA_SHORTCODE", "174379")
    monkeypatch.setenv("DARAJA_CALLBACK_URL", "https://example.com/callback")


def test_cli_probe_success(mock_env, capsys):
    exit_code = main(["probe", "--json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["status"] == "HEALTHY"
    assert report["environment"] == "sandbox"
    assert report["checks"]["config_loaded"] is True
    assert report["checks"]["shortcode"] == "174379"


def test_cli_probe_unhealthy_on_missing_env(monkeypatch, capsys):
    # Clear critical env vars to induce configuration error
    monkeypatch.delenv("DARAJA_CONSUMER_KEY", raising=False)
    monkeypatch.delenv("DARAJA_CONSUMER_SECRET", raising=False)
    monkeypatch.delenv("DARAJA_PASSKEY", raising=False)
    monkeypatch.delenv("DARAJA_SHORTCODE", raising=False)
    monkeypatch.delenv("DARAJA_CALLBACK_URL", raising=False)

    exit_code = main(["probe", "--json"])
    assert exit_code == 1

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["status"] == "UNHEALTHY"
    assert report["checks"]["config_loaded"] is False
    assert len(report["errors"]) > 0


def test_cli_audit_command(capsys):
    exit_code = main(["audit", "--json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["is_balanced"] is True
    assert report["is_sound"] is True
    assert report["discrepancy"] == "0.00"


def test_cli_screen_clean_transaction(capsys):
    exit_code = main(["screen", "--msisdn", "0712345678", "--amount", "2500.00", "--json"])
    assert exit_code == 0

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["is_cleared"] is True
    assert report["action"] == "ALLOW"
    assert report["composite_score"] == 0


def test_cli_screen_missing_arguments(capsys):
    exit_code = main(["screen"])
    assert exit_code == 2

    captured = capsys.readouterr()
    assert "At least one of --msisdn, --ip, or --device must be provided" in captured.err


def test_cli_human_readable_output(capsys):
    exit_code = main(["audit"])
    assert exit_code == 0

    captured = capsys.readouterr()
    assert "Ledger Audit: [PASSED]" in captured.out
    assert "Balanced: True" in captured.out
    