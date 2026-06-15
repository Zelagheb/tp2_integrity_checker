# TP2 – File Integrity Checker and IOC Matcher

![Rust](https://img.shields.io/badge/language-Rust-orange)
![Tests](https://img.shields.io/badge/tests-11%20passed-brightgreen)
![Clippy](https://img.shields.io/badge/clippy-0%20warnings-brightgreen)

A command-line security tool written in Rust that scans files and directories,
computes SHA-256 cryptographic hashes, compares them against a list of known
Indicators of Compromise (IOCs), and generates structured reports.

Built as part of **Module 7.1 – Programming with Rust** (2025–2026).

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Usage](#usage)
- [Arguments](#arguments)
- [Output Formats](#output-formats)
- [IOC File Format](#ioc-file-format)
- [Running Tests](#running-tests)
- [Bonus Features](#bonus-features)

---

## Overview

This tool is designed for defensive security workflows. Given a target path and
an IOC list, it:

1. Walks the target file or directory recursively
2. Computes the SHA-256 hash of each file
3. Compares each hash against the IOC list
4. Outputs a summary to the terminal
5. Writes a detailed CSV or JSON report

The objective is to practice secure systems programming in Rust using a realistic
defensive-security workflow: reading files safely, walking directories, computing
cryptographic hashes, and producing reproducible reports.

---

## Features

- SHA-256 file hashing using the `sha2` crate
- Recursive directory scanning
- IOC file parsing with graceful handling of invalid lines
- CSV and JSON report generation
- `--only-matches` filter for focused reporting
- Clean error messages for missing files or directories
- No `unwrap()` or `unsafe` in the main execution path
- 11 unit and integration tests
- Zero clippy warnings

---

## Project Structure

```
tp2_integrity_checker/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs       # Entry point and CLI argument parsing
│   ├── hashing.rs    # SHA-256 hash computation and validation
│   ├── ioc.rs        # IOC file loading and parsing
│   ├── scanner.rs    # File and directory scanning
│   └── report.rs     # CSV and JSON report generation
├── samples/
│   ├── files/
│   │   ├── clean_readme.txt
│   │   ├── suspicious_dropper.txt
│   │   └── notes.txt
│   └── iocs.txt
└── reports/
    └── scan_report.csv
```

---

## Requirements

- Rust toolchain (rustc, cargo)
- Docker Compose environment (provided for the lab)

Start the environment:

```bash
docker compose up -d --build
docker compose exec rustlab bash
cd /workspace/tp2_integrity_checker
```

Check the Rust toolchain:

```bash
rustc --version
cargo --version
cargo fmt --version
cargo clippy --version
```

---

## Usage

### Basic scan (CSV output)

```bash
cargo run -- \
  --target samples/files \
  --ioc samples/iocs.txt \
  --report reports/scan_report.csv
```

### JSON output

```bash
cargo run -- \
  --target samples/files \
  --ioc samples/iocs.txt \
  --report reports/scan_report.json \
  --json
```

### Show only matched files

```bash
cargo run -- \
  --target samples/files \
  --ioc samples/iocs.txt \
  --report reports/matches.csv \
  --only-matches
```

### Scan a single file

```bash
cargo run -- \
  --target samples/files/suspicious_dropper.txt \
  --ioc samples/iocs.txt \
  --report reports/single.csv
```

---

## Arguments

| Argument | Required | Description |
|---|---|---|
| `--target` | ✅ | File or directory to scan |
| `--ioc` | ✅ | Path to the IOC file |
| `--report` | ✅ | Output report file path |
| `--json` | ❌ | Write JSON instead of CSV |
| `--only-matches` | ❌ | Only include matched files in report |

If any required argument is missing, the program prints:

```
Usage:
  tp2_integrity_checker --target <FILE_OR_DIR> --ioc <IOC_FILE> --report <REPORT_FILE> [--json] [--only-matches]
```

---

## Output Formats

### Terminal summary

```
TP2 File Integrity Checker and IOC Matcher
Target:   samples/files
IOC file: samples/iocs.txt
Report:   reports/scan_report.csv

Summary:
  * Files scanned:      3
  * IOC entries loaded: 2
  * Invalid IOC lines:  1
  * Matches found:      1
  * Errors:             0

Matches:
  [ALERT] samples/files/suspicious_dropper.txt
  SHA-256: 44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b
  IOC label: Demo suspicious test sample

CSV report written to reports/scan_report.csv
```

### CSV report

```
path,sha256,status,label
samples/files/clean_readme.txt,70bbeaa0f2d408a45827aa9d5bd58209564a5bd7b61d6c069267c9e9e35f97cd,CLEAN,
samples/files/notes.txt,1888673b4c962129e57b54b81fda2f967c52f87c28e9d7908e5fba0dfed097e3,CLEAN,
samples/files/suspicious_dropper.txt,44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b,MATCH,Demo suspicious test sample
```

### JSON report

```json
[
  {"path": "samples/files/clean_readme.txt", "sha256": "70bbeaa0...", "status": "CLEAN", "label": ""},
  {"path": "samples/files/notes.txt", "sha256": "1888673b...", "status": "CLEAN", "label": ""},
  {"path": "samples/files/suspicious_dropper.txt", "sha256": "44ea92be...", "status": "MATCH", "label": "Demo suspicious test sample"}
]
```

---

## IOC File Format

```
# hash,label
44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b,Demo suspicious test sample
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,Fake known malware hash
INVALID_LINE_IS_IGNORED
```

Rules:
- Lines starting with `#` are treated as comments and skipped
- Empty lines are skipped
- Lines with an invalid hash (not 64 lowercase hex characters) are counted but do not stop execution
- Format per valid line: `sha256_hash,label`

---

## Running Tests

```bash
# Run all 11 tests
cargo test

# Format code
cargo fmt

# Run linter with zero warnings enforced
cargo clippy -- -D warnings
```

Expected test output:

```
running 11 tests
test hashing::tests::test_is_valid_sha256_ok ... ok
test hashing::tests::test_is_valid_sha256_too_short ... ok
test hashing::tests::test_is_valid_sha256_invalid_chars ... ok
test hashing::tests::test_hash_file_sha256_known_value ... ok
test ioc::tests::test_load_iocs_valid ... ok
test ioc::tests::test_load_iocs_invalid_line ... ok
test scanner::tests::test_scan_clean_file ... ok
test scanner::tests::test_scan_match_file ... ok
test scanner::integration_tests::test_scan_directory_finds_all_files ... ok
test scanner::integration_tests::test_scan_directory_detects_match ... ok
test scanner::integration_tests::test_scan_missing_target_returns_error ... ok
test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

---

## Bonus Features

| Feature | Flag | Description |
|---|---|---|
| Recursive scanning | (default) | Scans subdirectories automatically |
| JSON output | `--json` | Generates a JSON report instead of CSV |
| Filter matches | `--only-matches` | Report contains only matched files |
| Integration tests | (automatic) | 3 tests run against real `samples/` files |

---
