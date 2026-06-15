use crate::hashing::hash_file_sha256;
use crate::ioc::IocEntry;
use std::fs;
use std::path::Path;

/// Statut d'un fichier après scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Clean,
    Match(String), // label de l'IOC correspondant
    Error(String),
}

/// Résultat du scan d'un fichier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanResult {
    pub path: String,
    pub sha256: Option<String>,
    pub status: ScanStatus,
}

/// Scanne un fichier ou tous les fichiers réguliers d'un répertoire (récursif).
pub fn scan_target(target: &Path, iocs: &[IocEntry]) -> Vec<ScanResult> {
    let mut results = Vec::new();

    if target.is_file() {
        results.push(scan_file(target, iocs));
    } else if target.is_dir() {
        scan_dir_recursive(target, iocs, &mut results);
    } else {
        results.push(ScanResult {
            path: target.display().to_string(),
            sha256: None,
            status: ScanStatus::Error("Path is not a file or directory".to_string()),
        });
    }

    results
}

fn scan_dir_recursive(dir: &Path, iocs: &[IocEntry], results: &mut Vec<ScanResult>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            results.push(ScanResult {
                path: dir.display().to_string(),
                sha256: None,
                status: ScanStatus::Error(err.to_string()),
            });
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            results.push(scan_file(&path, iocs));
        } else if path.is_dir() {
            scan_dir_recursive(&path, iocs, results);
        }
    }
}

fn scan_file(path: &Path, iocs: &[IocEntry]) -> ScanResult {
    match hash_file_sha256(path) {
        Ok(hash) => {
            let status = match iocs.iter().find(|ioc| ioc.hash == hash) {
                Some(ioc) => ScanStatus::Match(ioc.label.clone()),
                None => ScanStatus::Clean,
            };
            ScanResult {
                path: path.display().to_string(),
                sha256: Some(hash),
                status,
            }
        }
        Err(err) => ScanResult {
            path: path.display().to_string(),
            sha256: None,
            status: ScanStatus::Error(err.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocEntry;
    use std::fs;

    #[test]
    fn test_scan_clean_file() {
        let path = std::path::Path::new("/tmp/test_scan_clean.txt");
        fs::write(path, "Welcome to TP2 Rust integrity lab.\n").unwrap();
        let iocs = vec![];
        let results = scan_target(path, &iocs);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].status, ScanStatus::Clean);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_scan_match_file() {
        let path = std::path::Path::new("/tmp/test_scan_match.txt");
        fs::write(path, "MALWARE-TEST-SAMPLE-TP2\n").unwrap();
        let iocs = vec![IocEntry {
            hash: "44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b".to_string(),
            label: "Demo suspicious test sample".to_string(),
        }];
        let results = scan_target(path, &iocs);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].status,
            ScanStatus::Match("Demo suspicious test sample".to_string())
        );
        fs::remove_file(path).ok();
    }
}
