use crate::scanner::{ScanResult, ScanStatus};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

pub fn write_csv_report(results: &[ScanResult], output_path: &Path) -> Result<(), io::Error> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(output_path)?;
    writeln!(file, "path,sha256,status,label")?;
    for result in results {
        let sha256 = result.sha256.as_deref().unwrap_or("");
        let (status_str, label) = match &result.status {
            ScanStatus::Clean => ("CLEAN", String::new()),
            ScanStatus::Match(label) => ("MATCH", label.clone()),
            ScanStatus::Error(msg) => ("ERROR", msg.clone()),
        };
        writeln!(file, "{},{},{},{}", result.path, sha256, status_str, label)?;
    }
    Ok(())
}

pub fn write_json_report(results: &[ScanResult], output_path: &Path) -> Result<(), io::Error> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(output_path)?;
    writeln!(file, "[")?;
    let last = results.len().saturating_sub(1);
    for (i, result) in results.iter().enumerate() {
        let sha256 = result.sha256.as_deref().unwrap_or("");
        let (status_str, label) = match &result.status {
            ScanStatus::Clean => ("CLEAN", String::new()),
            ScanStatus::Match(label) => ("MATCH", label.clone()),
            ScanStatus::Error(msg) => ("ERROR", msg.clone()),
        };
        let comma = if i < last { "," } else { "" };
        writeln!(
            file,
            "  {{\"path\": \"{}\", \"sha256\": \"{}\", \"status\": \"{}\", \"label\": \"{}\"}}{}", 
            result.path, sha256, status_str, label, comma
        )?;
    }
    writeln!(file, "]")?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn print_summary(
    results: &[ScanResult],
    ioc_count: usize,
    invalid_ioc_count: usize,
    target: &str,
    ioc_file: &str,
    report_file: &str,
    use_json: bool,
    only_matches: bool,
) {
    let files_scanned = results
        .iter()
        .filter(|r| !matches!(r.status, ScanStatus::Error(_)))
        .count();
    let matches: Vec<&ScanResult> = results
        .iter()
        .filter(|r| matches!(r.status, ScanStatus::Match(_)))
        .collect();
    let errors = results
        .iter()
        .filter(|r| matches!(r.status, ScanStatus::Error(_)))
        .count();
    println!("TP2 File Integrity Checker and IOC Matcher");
    println!("Target:   {}", target);
    println!("IOC file: {}", ioc_file);
    println!("Report:   {}", report_file);
    if use_json {
        println!("Mode:     JSON output");
    }
    if only_matches {
        println!("Filter:   only matches");
    }
    println!();
    println!("Summary:");
    println!("  * Files scanned:      {}", files_scanned);
    println!("  * IOC entries loaded: {}", ioc_count);
    println!("  * Invalid IOC lines:  {}", invalid_ioc_count);
    println!("  * Matches found:      {}", matches.len());
    println!("  * Errors:             {}", errors);
    if !matches.is_empty() {
        println!();
        println!("Matches:");
        for r in &matches {
            if let ScanStatus::Match(label) = &r.status {
                println!("  [ALERT] {}", r.path);
                println!("  SHA-256: {}", r.sha256.as_deref().unwrap_or("N/A"));
                println!("  IOC label: {}", label);
            }
        }
    }
    println!();
    let fmt = if use_json { "JSON" } else { "CSV" };
    println!("{} report written to {}", fmt, report_file);
}