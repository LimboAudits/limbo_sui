<p align="center">
  <img src="https://github.com/user-attachments/assets/4ad1f0e8-c629-4294-9c2b-326d533984d6" alt="limbo" width="300" />
</p>

<h3 align="center">Your Move contract won't leave the same.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/limbo__sui-v0.2.0-red" />
  <img src="https://img.shields.io/badge/network-Sui-blue" />
  <img src="https://img.shields.io/badge/language-Move-purple" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
  <img src="https://img.shields.io/badge/built%20for-Sui%20Overflow%202026-orange" />
</p>

---

**limbo_sui** is an open-source CLI security auditor for Sui Move smart contracts. Point it at any GitHub repo, local directory, or `.move` file — it runs a 4-layer analysis pipeline and generates a professional `limbo.report.md` in seconds.

No Docker. No Python. No templates. No config. Zero setup.

---

## Install

```bash
git clone https://github.com/LimboAudits/limbo_sui
cd limbo_sui
chmod +x install.sh && ./install.sh
```

One command installs everything including the Sui binary.

## Setup

```bash
cp .env.example .env
# Add your free Gemini API key from aistudio.google.com
```

Layers 1-3 work without an API key. Layer 4 (AI report) requires it.

## Usage

```bash
# Audit any GitHub repo
limbo_sui audit https://github.com/user/sui-project

# Audit a local project
limbo_sui audit ./my-sui-contract

# Audit a single file
limbo_sui audit ./sources/vault.move

# Skip exploit verification (faster)
limbo_sui audit ./contract --no-exploit
```

---

## Architecture

```
limbo_sui audit <target>
        │
        ▼
  ◆ Resolve target
    Clone GitHub URL / read local path / scan file
        │
        ▼
  ◆ Layer 1 — RECON ENGINE
    Maps entire codebase:
    → All entry points + visibility
    → All capability types
    → All math operations + operand types
    → All transfer calls + ownership context
        │
        ▼
  ◆ Layer 3 — DEEP PATTERN SCANNER
    Based on real Move hacks and CVE research:
    → Cetus-pattern bit shift overflow ($223M hack)
    → Unchecked integer arithmetic on financial values
    → Missing access control on privileged functions
    → Capability leakage via public returns
    → Unchecked object ownership on transfers
    → DeFi price/tick manipulation patterns
    → Missing abort on conditional logic
        │
        ▼
  ◆ Layer 2 — EXPLOIT ENGINE
    For each candidate finding:
    → Generates a Move test that TRIGGERS the bug
    → Injects it into the contract temporarily
    → Runs sui move test
    → PASS = bug mathematically confirmed
    → FAIL = false positive, filtered out
        │
        ▼
  ◆ Layer 4 — AI EXPLAINER
    Receives ONLY confirmed findings
    → Zero hallucinations (explaining real bugs)
    → Professional limbo.report.md
    → Exploit scenarios + code fixes
```

---

## Detected Vulnerability Classes

| Pattern | Severity | Based On |
|---|---|---|
| Cetus Bit Shift Overflow | CRITICAL | $223M Cetus hack, May 2025 |
| Unchecked Integer Arithmetic | HIGH | MWC taxonomy, MoveScan research |
| Missing Access Control | CRITICAL | Most common DeFi exploit |
| Capability Leakage | HIGH | Move capability model misuse |
| Unchecked Object Ownership | HIGH | Sui object model violation |
| DeFi Price Manipulation | CRITICAL | AMM/CLMM exploit patterns |
| Missing Abort on Error | MEDIUM | Logic error class |

---

## Demo

```bash
limbo_sui audit ./demo
```

Scans `VulnerableVault` — intentionally built with 5 real vulnerability classes:

| # | Vulnerability | Line | Pattern |
|---|---|---|---|
| 1 | Integer overflow in deposit | 52 | Unchecked u64 arithmetic |
| 2 | Missing access control | 34 | Public fun, no auth |
| 3 | Unchecked ownership on withdraw | 58 | transfer without owner check |
| 4 | Capability leakage | 71 | Public fun returns AdminCap |
| 5 | Missing abort | 76 | if without assert/abort |

---

## Why limbo_sui

The Sui Move ecosystem lost $223M in May 2025 (Cetus hack) to a vulnerability that existing tools couldn't catch. limbo_sui is built specifically to detect these Move-native attack patterns.

```
limbo_evm  →  Ethereum (Slither + Mythril + Echidna + Halmos)
limbo_sui  →  Sui Move (native, zero-config, exploit-verified)
```

Every finding is either:
- **Mathematically confirmed** by a generated exploit test, or
- **High confidence** pattern match with exact file + line + code snippet

No hallucinations. No guesses.

---

> *Your contract has been to Limbo.*
> Powered by [Limbo](https://github.com/LimboAudits) — Astrophel
> Built for Sui Overflow 2026
