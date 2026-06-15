mod hashing;
mod ioc;
mod report;
mod scanner;

use ioc::load_iocs;
use report::{print_summary, write_csv_report, write_json_report};
use scanner::scan_target;
use std::path::Path;
use std::process;

fn parse_args(args: &[String]) -> Option<(String, String, String, bool, bool)> {
    let mut target = None;
    let mut ioc = None;
    let mut rep = None;
    let mut json = false;
    let mut only_matches = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => { i += 1; target = args.get(i).cloned(); }
            "--ioc"    => { i += 1; ioc = args.get(i).cloned(); }
            "--report" => { i += 1; rep = args.get(i).cloned(); }
            "--json"         => { json = true; }
            "--only-matches" => { only_matches = true; }
            _ => {}
        }
        i += 1;
    }

    match (target, ioc, rep) {
        (Some(t), Some(i), Some(r)) => Some((t, i, r, json, only_matches)),
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let (target_str, ioc_str, report_str, use_json, only_matches) = match parse_args(&args) {
        Some(v) => v,
        None => {
            eprintln!(
                "Usage:\n  tp2_integrity_checker --target <FILE_OR_DIR> --ioc <IOC_FILE> --report <REPORT_FILE> [--json] [--only-matches]"
            );
            process::exit(1);
        }
    };

    let ioc_path = Path::new(&ioc_str);
    if !ioc_path.exists() {
        eprintln!("Error: IOC file not found: {}", ioc_str);
        process::exit(1);
    }

    let ioc_load = match load_iocs(ioc_path) {
        Ok(r) => r,
        Err(e) => { eprintln!("Error loading IOC file: {}", e); process::exit(1); }
    };

    let target_path = Path::new(&target_str);
    if !target_path.exists() {
        eprintln!("Error: Target not found: {}", target_str);
        process::exit(1);
    }

    let mut results = scan_target(target_path, &ioc_load.entries);

    if only_matches {
        results.retain(|r| matches!(r.status, scanner::ScanStatus::Match(_)));
    }

    let report_path = Path::new(&report_str);

    if use_json {
        if let Err(e) = write_json_report(&results, report_path) {
            eprintln!("Error writing JSON report: {}", e);
            process::exit(1);
        }
    } else {
        if let Err(e) = write_csv_report(&results, report_path) {
            eprintln!("Error writing CSV report: {}", e);
            process::exit(1);
        }
    }

    print_summary(
        &results,
        ioc_load.entries.len(),
        ioc_load.invalid_count,
        &target_str,
        &ioc_str,
        &report_str,
        use_json,
        only_matches,
    );
}
