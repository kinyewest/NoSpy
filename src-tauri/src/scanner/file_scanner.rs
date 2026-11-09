use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use sha2::{Sha256, Digest};
use chrono::Utc;
use uuid::Uuid;
use super::types::{Threat, ThreatCategory, ThreatSeverity};

pub struct FileScanner;

impl FileScanner {
    pub fn scan_threat_directories(max_files: usize) -> (usize, Vec<Threat>) {
        let mut target_dirs: Vec<PathBuf> = Vec::new();

        if let Ok(temp) = std::env::var("TEMP") {
            target_dirs.push(PathBuf::from(temp));
        }
        if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
            let temp2 = PathBuf::from(&localappdata).join("Temp");
            if !target_dirs.contains(&temp2) {
                target_dirs.push(temp2);
            }
            target_dirs.push(PathBuf::from(localappdata).join("Microsoft").join("Windows").join("INetCache"));
        }

        let mut scanned_count = 0;
        let mut threats = Vec::new();

        let dangerous_extensions = [
            ".scr", ".pif", ".hta", ".vbs", ".wsf", ".jar",
        ];

        let double_extensions = [
            ".pdf.exe", ".jpg.exe", ".png.exe", ".docx.exe", ".xlsx.exe", ".txt.exe", ".zip.exe",
        ];

        let stealer_dump_names = [
            "passwords.txt",
            "browser_passwords.txt",
            "tokens.txt",
            "wallets.zip",
            "discord_backup.txt",
            "cookies.sqlite.dump",
        ];

        for dir in target_dirs {
            if !dir.exists() {
                continue;
            }

            for entry in WalkDir::new(dir)
                .max_depth(3)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if scanned_count >= max_files {
                    break;
                }

                if entry.file_type().is_file() {
                    scanned_count += 1;
                    let path = entry.path();
                    let file_name = entry.file_name().to_string_lossy();
                    let file_name_lower = file_name.to_lowercase();
                    let path_str = path.to_string_lossy().to_string();

                    // 1. Check double extensions
                    for dext in &double_extensions {
                        if file_name_lower.ends_with(dext) {
                            threats.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("Disguised Dropper Payload: {}", file_name),
                                category: ThreatCategory::SuspiciousDropper,
                                severity: ThreatSeverity::Critical,
                                description: format!("Executable disguised as document/media with double extension: {}", path_str),
                                file_path: Some(path_str.clone()),
                                pid: None,
                                registry_key: None,
                                remote_addr: None,
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Quarantine file immediately to prevent accidental launch".to_string(),
                            });
                            break;
                        }
                    }

                    // 2. Check dangerous standalone script droppers in temp
                    for ext in &dangerous_extensions {
                        if file_name_lower.ends_with(ext) {
                            threats.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("High-Risk Dropper Script: {}", file_name),
                                category: ThreatCategory::SuspiciousDropper,
                                severity: ThreatSeverity::High,
                                description: format!("Dangerous executable script dropped in user temp: {}", path_str),
                                file_path: Some(path_str.clone()),
                                pid: None,
                                registry_key: None,
                                remote_addr: None,
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Quarantine and inspect script contents".to_string(),
                            });
                            break;
                        }
                    }

                    // 3. Check InfoStealer staging/dump files
                    for dump_name in &stealer_dump_names {
                        if file_name_lower == *dump_name {
                            threats.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("Stealer Credential Dump: {}", file_name),
                                category: ThreatCategory::InfoStealer,
                                severity: ThreatSeverity::Critical,
                                description: format!("Staged credential or token archive discovered in temp directory: {}", path_str),
                                file_path: Some(path_str.clone()),
                                pid: None,
                                registry_key: None,
                                remote_addr: None,
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Examine immediately and rotate stored credentials and browser sessions".to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }

        (scanned_count, threats)
    }

    pub fn calculate_file_sha256(path: &Path) -> Option<String> {
        let bytes = std::fs::read(path).ok()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Some(format!("{:x}", hasher.finalize()))
    }
}
