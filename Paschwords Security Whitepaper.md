# Paschwords Security Whitepaper

## Introduction
Paschwords is a PowerShell-based password management tool engineered for secure enterprise environments. Designed with zero-trust principles and SOC 2 compliance alignment, Paschwords offers robust mechanisms for secure storage, access control, auditing, and operational integrity.

---

## Design Principles

- **Zero-Trust Foundation**: Assumes no inherent trust in users or systems; all access must be explicitly granted and verified.
- **Defense-in-Depth**: Implements multiple layers of security, including encryption, HMAC validation, secure memory handling, and RBAC.
- **Auditor-Ready Logging**: Full activity and authentication logs with chained HMACs enable forensic-grade verification of system behavior.

---

## Authentication & Credential Handling

### User Passwords
- Derived using PBKDF2 with unique per-user salts
- Hashed using SHA-256
- Encoded in Base64 for registry storage
- One-way authentication only (never decrypted)

### Master Password
- PBKDF2 + Salt + SHA-256
- Separate validation mechanism, fully isolated from standard users
- Enforces brute-force delay and lockout

---

## Encryption & Data Protection

### Entry-Level Protection
- Each password is AES-256-CBC encrypted with a unique, random IV
- Base64-encoded after encryption
- Appended with a per-entry HMAC for tamper detection

### File-Level Protection
- Full databases and user registry files are AES-256-CBC encrypted
- GZIP compression is applied to databases before encryption (v4.5+)
- HMAC validation applied after encryption to detect file tampering

---

## Memory & Module Hardening

- Module content is GZIP-compressed, then encrypted
- Decrypted only in memory via a secure loader script
- Ensures secrets and logic are never written to disk unencrypted

---

## Logging and Auditability

- Logs use a visually distinct separator-based structure
- Every entry is timestamped, and includes user, event, and HMAC
- Chained HMAC structure (v4.6+) allows detection of midstream tampering
- Log verification tool validates original vs. calculated HMACs

---

## Role-Based Access Control (RBAC)

- Three-tier privilege model:
  1. Standard User – Limited access
  2. Admin – Can manage entries and view logs
  3. Superuser – Full access, including registry and key initialization
- Enforces least privilege access

---

## Anti-Brute Force Measures

- Incremental delays after failed attempts
- Tracking of all failed login reasons and counts
- Account lockouts after repeated failures
- Fully logged authentication attempts for auditing

---

## Compliance Alignment

Paschwords was developed with alignment to SOC 2 Trust Services Criteria. Key controls include:
- Encryption and HMAC integrity at all levels
- Role and identity management
- Secure configuration and execution
- Tamper-evident logging
- Time-synchronized log entries (NTP)
- Clean key and memory lifecycle

---

## Limitations and Responsibility Boundaries

While Paschwords is designed for compliance, actual certification requires proper:
- Deployment practices (e.g., restricted permissions, patching)
- Environmental controls (e.g., NTP enforcement, OS hardening)
- Monitoring and alerting (external systems)
- Backup and disaster recovery planning

---

## Conclusion

Paschwords v4.6 is a mature, security-hardened tool built to support SOC 2-compliant deployments. It provides layered encryption, authentication, and logging mechanisms with zero-trust foundations. Designed for enterprise-grade security in PowerShell environments, Paschwords empowers organizations to manage passwords safely, verify integrity, and withstand scrutiny from auditors or attackers alike.
