use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Calcule le hash SHA-256 d'un fichier et le retourne en hexadécimal minuscule.
pub fn hash_file_sha256(path: &Path) -> Result<String, io::Error> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// Vérifie qu'une chaîne est un hash SHA-256 valide (64 caractères hexadécimaux).
pub fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_sha256_ok() {
        let valid = "44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b";
        assert!(is_valid_sha256(valid));
    }

    #[test]
    fn test_is_valid_sha256_too_short() {
        assert!(!is_valid_sha256("abc123"));
    }

    #[test]
    fn test_is_valid_sha256_invalid_chars() {
        let invalid = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
        assert!(!is_valid_sha256(invalid));
    }

    #[test]
    fn test_hash_file_sha256_known_value() {
        // Crée un fichier temporaire avec un contenu connu
        use std::fs;
        let path = std::path::Path::new("/tmp/test_hash_tp2.txt");
        fs::write(path, "MALWARE-TEST-SAMPLE-TP2\n").unwrap();
        let hash = hash_file_sha256(path).unwrap();
        assert_eq!(
            hash,
            "44ea92bec1f9e8aa690d8aceddf1294e9fb4a71d39769d6f383e3915ac76bb3b"
        );
        fs::remove_file(path).ok();
    }
}
