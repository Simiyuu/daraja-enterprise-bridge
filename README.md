# Daraja Enterprise Bridge

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/architecture-hybrid--fintech-orange.svg)](#architecture)
[![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#testing)

An enterprise-grade payment gateway and fraud mitigation switch bridging merchant applications, Safaricom's M-Pesa Daraja network, and AWS hybrid cloud infrastructure. Built with atomic double-entry accounting, replay-resistant webhook ingestion, and real-time telco fraud interception rules.

---

## Architecture Overview

```text
  [ Merchant / Client App ]
             |
             v
+-------------------------------------------------------------+
|               DARAJA ENTERPRISE BRIDGE                      |
|                                                             |
|  1. Daraja API Core                                         |
|     - OAuth 2.0 Token Authority (Thread-Safe In-Memory Cache)|
|     - Dynamic Base64 Password Generator (UTC Timestamped)   |
|     - STK Push (Lipa Na M-Pesa Online) Dispatcher           |
|                                                             |
|  2. Webhook Ingress & Idempotency Layer                     |
|     - SHA-256 Request Signature & Replay Protection         |
|     - Safaricom Ingress CIDR IP Validation                  |
|     - Asynchronous Result Callback Normalizer               |
|                                                             |
|  3. Telco Security & Fraud Interceptors                     |
|     - SIM-Swap Timing Correlation Engine (48hr Window)      |
|     - Velocity Thresholding (Rapid Dispersed Cash-Out)      |
|                                                             |
|  4. Financial Settlement Core                               |
|     - Thread-Safe Double-Entry Ledger (ACID Compliant)      |
|     - Paired Debit/Credit Journal Mutation                  |
+-------------------------------------------------------------+
             |                                    |
             v                                    v
   [ Safaricom M-Pesa Core ]              [ AWS Hybrid Cloud ]
   - C2B / B2C Rails                     - Secrets Manager (Passkeys)
   - USSD / STK SIM Prompts              - Lambda Webhook Handlers
   - Real-time Balance Inquiries         - CloudWatch Audit Trail
```

---

## Core Capabilities

1. **Daraja API & Dynamic Cryptography:**
   - Thread-safe OAuth token caching with automated pre-expiry refresh.
   - Dynamic Base64 transaction credential synthesis (`Shortcode + Passkey + Timestamp`).
   - Resilient STK Push dispatching with exponential backoff and jitter.

2. **Idempotent Webhook Processing:**
   - Deterministic SHA-256 payload hashing preventing duplicate credits during network callback retries.
   - Strict CIDR-based source verification enforcing Safaricom IP whitelisting.

3. **Atomic Double-Entry Ledger:**
   - Zero-sum paired journal entries for every completed, reversed, or failed transaction.
   - Prevents race conditions during concurrent account settlements.

4. **Telco Fraud Interception:**
   - Correlates incoming transaction requests with telco subscriber metadata.
   - Blocks high-value cash-outs on SIM identities swapped within a high-risk velocity window.

5. **AWS Enterprise Security:**
   - Decoupled credential management via AWS Secrets Manager using `boto3`.
   - Serverless event adapter designed for AWS Lambda and Amazon API Gateway.

---

## Repository Structure

```text
daraja-enterprise-bridge/
├── src/
│   ├── __init__.py
│   ├── aws/               # AWS Secrets Manager & CloudWatch adapters
│   ├── core/              # Atomic double-entry ledger & transaction journals
│   ├── daraja/            # OAuth token manager, password compiler & STK client
│   ├── fraud/             # SIM-swap and velocity interceptor engines
│   ├── models/            # Pydantic data contracts, schemas & enums
│   └── webhook/           # Idempotent callback handler & IP ingress filtering
├── tests/
│   ├── __init__.py
│   ├── test_daraja_client.py
│   ├── test_fraud_interceptors.py
│   ├── test_idempotent_webhook.py
│   └── test_ledger_atomic.py
├── .gitignore
├── pytest.ini
├── requirements.txt
└── README.md
```

---

## Getting Started

### Prerequisites
- Python 3.10+
- Virtualenv (`python -m venv venv`)

### Installation
```bash
git clone [https://github.com/Simiyuu/daraja-enterprise-bridge.git](https://github.com/Simiyuu/daraja-enterprise-bridge.git)
cd daraja-enterprise-bridge
python -m venv venv

# Windows:
.\venv\Scripts\Activate.ps1
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### Running Tests
```bash
python -m pytest -v
```
