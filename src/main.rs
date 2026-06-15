mod hashing;
mod ioc;
mod report;
mod scanner;

use ioc::load_iocs;
use report::{print_summary, write_csv_report};
use scanner::scan_target;
use std::path::Path;
use std::process;

fn parse_args(args: &[String]) -> Option<(String, String, String)> {
    let mut target = None;
    let mut ioc = None;
    let mut rep = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--target" => {
                i += 1;
                target = args.get(i).cloned();
            }
            "--ioc" => {
                i += 1;
                ioc = args.get(i).cloned();
            }
            "--report" => {
                i += 1;
                rep = args.get(i).cloned();
            }
            _ => {}
        }
        i += 1;
    }

    match (target, ioc, rep) {
        (Some(t), Some(i), Some(r)) => Some((t, i, r)),
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let (target_str, ioc_str, report_str) = match parse_args(&args) {
        Some(v) => v,
        None => {
            eprintln!(
                "Usage:\n  tp2_integrity_checker --target <FILE_OR_DIR> --ioc <IOC_FILE> --report <REPORT_FILE>"
            );
            process::exit(1);
        }
    };

    // Charger les IOCs
    let ioc_path = Path::new(&ioc_str);
    if !ioc_path.exists() {
        eprintln!("Error: IOC file not found: {}", ioc_str);
        process::exit(1);
    }

    let ioc_load = match load_iocs(ioc_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error loading IOC file: {}", e);
            process::exit(1);
        }
    };

    // Vérifier la cible
    let target_path = Path::new(&target_str);
    if !target_path.exists() {
        eprintln!("Error: Target not found: {}", target_str);
        process::exit(1);
    }

    // Scanner
    let results = scan_target(target_path, &ioc_load.entries);

    // Rapport CSV
    let report_path = Path::new(&report_str);
    if let Err(e) = write_csv_report(&results, report_path) {
        eprintln!("Error writing CSV report: {}", e);
        process::exit(1);
    }

    // Affichage terminal
    print_summary(
        &results,
        ioc_load.entries.len(),
        ioc_load.invalid_count,
        &target_str,
        &ioc_str,
        &report_str,
    );
}
