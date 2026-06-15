# TP2 – File Integrity Checker and IOC Matcher

A command-line tool written in Rust that scans files or directories,
computes SHA-256 hashes, compares them against an IOC list, and generates a CSV report.

## Usage

```bash
cargo run -- --target samples/files --ioc samples/iocs.txt --report reports/scan_report.csv
```

## Run tests

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt
```
