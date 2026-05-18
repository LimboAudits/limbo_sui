<p align="center">
  <img src="https://github.com/user-attachments/assets/4ad1f0e8-c629-4294-9c2b-326d533984d6" alt="limbo" width="300" />
</p>

### Your Move contract won't leave the same.

![limbo_sui](https://img.shields.io/badge/limbo__sui-v0.1.0-red)
![Sui](https://img.shields.io/badge/network-Sui-blue)
![Language](https://img.shields.io/badge/language-Move-purple)
![License](https://img.shields.io/badge/license-MIT-green)

**limbo_sui** is an open-source CLI security auditor for Sui Move smart contracts. Point it at any GitHub repo, local directory, or `.move` file — it runs a 4-layer analysis pipeline and generates a professional `limbo.report.md` in seconds.

---

## Install

```bash
# Clone
git clone https://github.com/astrophel/limbo_sui
cd limbo_sui

# Build
cargo build --release

# Add to PATH
cp target/release/limbo_sui /usr/local/bin/
```

## Setup

```bash
cp .env.example .env
# Add your Gemini API key (free at aistudio.google.com)
```

## Usage

```bash
# Audit a GitHub repo
limbo_sui audit https://github.com/user/sui-project

# Audit a local project
limbo_sui audit ./my-sui-contract

# Audit a single file
limbo_sui audit ./sources/vault.move

# Specify output directory
limbo_sui audit https://github.com/user/repo --output ./reports
```

## How It Works

```
limbo_sui audit <target>
        │
        ▼
Layer 1: sui move build     → compiler errors + type violations
Layer 2: sui move test      → test failures + runtime aborts
        │
        ▼  cross-reference
        │
Layer 3: pattern scanner    → 6 Move-specific vulnerability patterns
         classifier         → maps errors → vulnerability types
        │
        ├── CONFIRMED   (L1/L2 + L3 agree)    → HIGH severity
        ├── POTENTIAL   (L3 only, strong)      → MEDIUM severity  
        └── SINGLE TOOL (one layer only)       → flagged for review
        │
        ▼
Layer 4: Gemini 2.5 Flash   → professional limbo.report.md
```

## Detected Vulnerability Classes

| Pattern | Severity | Detection Method |
|---|---|---|
| Integer Overflow | HIGH | Arithmetic without overflow checks |
| Missing Access Control | CRITICAL | Entry functions without auth |
| Capability Leakage | HIGH | Capabilities in public returns |
| Unchecked Ownership | HIGH | Transfer without owner validation |
| Unsafe Public Transfer | MEDIUM | public_transfer without sender check |
| Missing Abort on Error | MEDIUM | Conditionals without assert/abort |

## Demo

```bash
limbo_sui audit ./demo
```

Audits the included `VulnerableVault` contract — intentionally flawed with 5 vulnerabilities across all detection classes.

---

> *Your contract has been to Limbo.*  
> Powered by Limbo — Astrophel  
> Built for Sui Overflow 2026
