<p align="center">
  <img src="https://github.com/user-attachments/assets/4ad1f0e8-c629-4294-9c2b-326d533984d6" alt="limbo" width="300" />
</p>

<p align="center">
  <strong>Your Move contract won't leave the same.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/limbo__sui-v0.1.0-red" />
  <img src="https://img.shields.io/badge/network-Sui-blue" />
  <img src="https://img.shields.io/badge/language-Move-purple" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

---

**limbo_sui** is an open-source CLI security auditor for Sui Move smart contracts. Point it at any GitHub repo, local directory, or `.move` file — it runs a 4-layer analysis pipeline and generates a professional `limbo.report.md` in seconds.

---

## Requirements

Before installing, make sure you have the following:

- [Rust & Cargo](https://rustup.rs) — stable toolchain
- [Sui CLI](https://docs.sui.io/guides/developer/getting-started/sui-install) — required for Layers 1 & 2
- A free [Gemini API key](https://aistudio.google.com) — required for the AI report (Layer 4)

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/astrophel/limbo_sui
cd limbo_sui

# 2. (Optional) Auto-install the Sui binary if you don't have it
bash install.sh

# 3. Build the release binary
cargo build --release

# 4. Add to PATH
cp target/release/limbo_sui /usr/local/bin/
```

---

## Setup

limbo_sui uses Gemini 2.5 Flash to generate the final audit report. You need to provide your API key once.

```bash
# Copy the example env file
cp .env.example .env
```

Then open `.env` and fill in your key:

```env
GEMINI_API_KEY=your_key_here
```

Get a free key at [aistudio.google.com](https://aistudio.google.com). No billing required.

---

## Usage

```bash
# Audit a GitHub repository
limbo_sui audit https://github.com/user/sui-project

# Audit a local project directory
limbo_sui audit ./my-sui-contract

# Audit a single .move file
limbo_sui audit ./sources/vault.move

# Specify where the report should be saved
limbo_sui audit https://github.com/user/repo --output ./reports
```

After the audit completes, a `limbo.report.md` file is written to the output directory (current directory by default).

---

## How It Works

limbo_sui runs a 4-layer pipeline — each layer cross-referencing the last.

```
limbo_sui audit <target>
        │
        ▼
Layer 1 ── sui move build
           Catches compiler errors and type violations

Layer 2 ── sui move test
           Catches test failures and runtime aborts
        │
        ▼  (cross-referenced)
        │
Layer 3 ── Pattern scanner
           6 Move-specific vulnerability patterns
           Classifier maps L1/L2 errors → vulnerability types

           ├── CONFIRMED   (L1/L2 + L3 agree)    → HIGH severity
           ├── POTENTIAL   (L3 only, strong)      → MEDIUM severity
           └── SINGLE TOOL (one layer only)       → flagged for review
        │
        ▼
Layer 4 ── Gemini 2.5 Flash
           Synthesizes all findings into a professional limbo.report.md
```

---

## Detected Vulnerabilities

| Vulnerability | Severity | How It's Detected |
|---|---|---|
| Integer Overflow | HIGH | Arithmetic without overflow checks |
| Missing Access Control | CRITICAL | Entry functions without auth |
| Capability Leakage | HIGH | Capabilities in public return values |
| Unchecked Ownership | HIGH | Transfer without owner validation |
| Unsafe Public Transfer | MEDIUM | `public_transfer` without sender check |
| Missing Abort on Error | MEDIUM | Conditionals without `assert` / `abort` |

---

## Demo

The repo ships with `VulnerableVault` — a contract intentionally written with 5 vulnerabilities spanning all detection classes.

```bash
limbo_sui audit ./demo
```

Run it to see a full end-to-end audit and inspect the generated `limbo.report.md`.

---

## Project Structure

```
limbo_sui/
├── src/
│   ├── main.rs          # CLI entrypoint
│   ├── audit.rs         # Pipeline orchestrator
│   ├── git.rs           # Target resolver (GitHub URL / local path / .move file)
│   ├── layer1.rs        # sui move build
│   ├── layer2.rs        # sui move test
│   ├── layer3.rs        # Pattern scanner
│   ├── classifier.rs    # Error → vulnerability mapper
│   ├── layer4.rs        # Gemini report generator
│   ├── report.rs        # Report writer
│   └── types.rs         # Shared types
├── demo/
│   └── sources/
│       └── vulnerable_vault.move
├── install.sh           # Sui binary installer
├── Cargo.toml
└── .env.example
```

---

## License

MIT — see [LICENSE](LICENSE)

---

<p align="center">
  <em>Your contract has been to Limbo.</em><br/>
  Powered by Limbo — Astrophel<br/>
  Built for Sui Overflow 2026
</p>
