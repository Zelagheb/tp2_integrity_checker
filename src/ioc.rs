use crate::hashing::is_valid_sha256;
use std::fs;
use std::io;
use std::path::Path;

/// Représente une entrée IOC valide (hash + label).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocEntry {
    pub hash: String,
    pub label: String,
}

/// Résultat du chargement des IOCs.
pub struct IocLoadResult {
    pub entries: Vec<IocEntry>,
    pub invalid_count: usize,
}

/// Charge et parse le fichier IOC.
/// Les lignes vides et les commentaires (#) sont ignorés.
/// Les lignes invalides sont comptées mais ne font pas planter le programme.
pub fn load_iocs(path: &Path) -> Result<IocLoadResult, io::Error> {
    let content = fs::read_to_string(path)?;
    let mut entries = Vec::new();
    let mut invalid_count = 0;

    for line in content.lines() {
        let line = line.trim();

        // Ignorer les lignes vides et les commentaires
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Parser "hash,label"
        let parts: Vec<&str> = line.splitn(2, ',').collect();
        if parts.len() < 2 {
            invalid_count += 1;
            continue;
        }

        let hash = parts[0].trim().to_lowercase();
        let label = parts[1].trim().to_string();

        if !is_valid_sha256(&hash) {
            invalid_count += 1;
            continue;
        }

        entries.push(IocEntry { hash, label });
    }

    Ok(IocLoadResult {
        entries,
        invalid_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_iocs_valid() {
        let path = std::path::Path::new("/tmp/test_iocs_valid.txt");
        fs::write(
            path,
            "# comment\n44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b,Malware\n",
        )
        .unwrap();
        let result = load_iocs(path).unwrap();
        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].label, "Malware");
        assert_eq!(result.invalid_count, 0);
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_load_iocs_invalid_line() {
        let path = std::path::Path::new("/tmp/test_iocs_invalid.txt");
        fs::write(path, "INVALID_HASH_LINE_SHOULD_BE_IGNORED\n").unwrap();
        let result = load_iocs(path).unwrap();
        assert_eq!(result.entries.len(), 0);
        assert_eq!(result.invalid_count, 1);
        fs::remove_file(path).ok();
    }
}
