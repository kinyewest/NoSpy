use std::fs;
use std::path::{Path, PathBuf};
use chrono::Utc;
use sha2::{Digest, Sha256};
use sysinfo::System;
use uuid::Uuid;
use walkdir::WalkDir;

use super::types::{
    ProtectedFolderStatus, RansomwareStatus, Threat, ThreatCategory, ThreatSeverity,
};

const CANARY_FILENAME: &str = ".nospy_canary_trap.txt";
const CANARY_PAYLOAD: &str = "NOSPY-ANTI-RANSOMWARE-CANARY-DO-NOT-MODIFY-OR-ENCRYPT-V1";

pub struct RansomwareGuard;

impl RansomwareGuard {
    fn expected_canary_hash() -> String {
        let mut hasher = Sha256::new();
        hasher.update(CANARY_PAYLOAD.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn get_protected_directories() -> Vec<(String, PathBuf)> {
        let mut dirs = Vec::new();
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let base = PathBuf::from(profile);
            dirs.push(("Documents".to_string(), base.join("Documents")));
            dirs.push(("Desktop".to_string(), base.join("Desktop")));
            dirs.push(("Pictures".to_string(), base.join("Pictures")));
            dirs.push(("Downloads".to_string(), base.join("Downloads")));
        }
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            let vault_dir = PathBuf::from(local).join("NoSpy").join("CanaryVault");
            let _ = fs::create_dir_all(&vault_dir);
            dirs.push(("NoSpy Canary Vault".to_string(), vault_dir));
        }
        dirs
    }

    pub fn deploy_canaries() -> usize {
        let mut deployed = 0;
        for (_, dir) in Self::get_protected_directories() {
            if dir.exists() {
                let canary_path = dir.join(CANARY_FILENAME);
                if fs::write(&canary_path, CANARY_PAYLOAD).is_ok() {
                    deployed += 1;
                }
            }
        }
        deployed
    }

    pub fn check_status(shield_enabled: bool) -> RansomwareStatus {
        let expected_hash = Self::expected_canary_hash();
        let mut folder_statuses = Vec::new();
        let mut alerts = Vec::new();

        let ransomware_exts = [
            ".locked",
            ".encrypted",
            ".crypted",
            ".wannacry",
            ".wcry",
            ".ryuk",
            ".lockbit",
            ".blackcat",
            ".akira",
            ".phobos",
            ".cerber",
        ];

        let ransom_notes = [
            "readme_to_decrypt",
            "how_to_decrypt",
            "restore_my_files",
            "decrypt_instructions",
            "_readme.txt",
        ];

        for (label, dir) in Self::get_protected_directories() {
            let exists = dir.exists();
            let canary_path = dir.join(CANARY_FILENAME);
            let mut canary_intact = false;

            if exists {
                if !canary_path.exists() {
                    let _ = fs::write(&canary_path, CANARY_PAYLOAD);
                }
                if let Ok(bytes) = fs::read(&canary_path) {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let actual_hash = format!("{:x}", hasher.finalize());
                    canary_intact = actual_hash == expected_hash;

                    if !canary_intact {
                        alerts.push(Threat {
                            id: Uuid::new_v4().to_string(),
                            name: format!("Ransomware Canary Tampered ({})", label),
                            category: ThreatCategory::RansomwareBehavior,
                            severity: ThreatSeverity::Critical,
                            description: format!(
                                "Decoy canary trap file was modified or encrypted in {}: {}",
                                label,
                                canary_path.to_string_lossy()
                            ),
                            file_path: Some(canary_path.to_string_lossy().to_string()),
                            pid: None,
                            registry_key: None,
                            remote_addr: None,
                            detected_at: Utc::now().to_rfc3339(),
                            status: "Active".to_string(),
                            recommendation: "Isolate system network and inspect active processes immediately".to_string(),
                        });
                    }
                }
            }

            let mut suspicious_files_found = 0;
            if exists {
                for entry in WalkDir::new(&dir)
                    .max_depth(2)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .take(250)
                {
                    if entry.file_type().is_file() {
                        let fname = entry.file_name().to_string_lossy().to_lowercase();
                        let fpath = entry.path().to_string_lossy().to_string();

                        if ransomware_exts.iter().any(|ext| fname.ends_with(ext)) {
                            suspicious_files_found += 1;
                            alerts.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("Encrypted Ransomware File Indicator: {}", fname),
                                category: ThreatCategory::RansomwareBehavior,
                                severity: ThreatSeverity::Critical,
                                description: format!(
                                    "File with known ransomware extension detected in {}: {}",
                                    label, fpath
                                ),
                                file_path: Some(fpath),
                                pid: None,
                                registry_key: None,
                                remote_addr: None,
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Check for active encryption process and terminate immediately".to_string(),
                            });
                        } else if ransom_notes.iter().any(|note| fname.contains(note)) {
                            suspicious_files_found += 1;
                            alerts.push(Threat {
                                id: Uuid::new_v4().to_string(),
                                name: format!("Suspected Ransom Note Detected: {}", fname),
                                category: ThreatCategory::RansomwareBehavior,
                                severity: ThreatSeverity::High,
                                description: format!("Potential ransom note found in {}: {}", label, fpath),
                                file_path: Some(fpath),
                                pid: None,
                                registry_key: None,
                                remote_addr: None,
                                detected_at: Utc::now().to_rfc3339(),
                                status: "Active".to_string(),
                                recommendation: "Inspect file and verify backup integrity".to_string(),
                            });
                        }
                    }
                }
            }

            folder_statuses.push(ProtectedFolderStatus {
                path: dir.to_string_lossy().to_string(),
                label,
                exists,
                canary_intact,
                canary_path: canary_path.to_string_lossy().to_string(),
                suspicious_files_found,
            });
        }

        // Check running processes for VSS shadow copy tampering
        let mut sys = System::new_all();
        sys.refresh_all();
        for (pid, process) in sys.processes() {
            let name = process.name().to_string_lossy().to_lowercase();
            let cmd_joined = process
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy().to_lowercase())
                .collect::<Vec<_>>()
                .join(" ");

            if (name.contains("vssadmin") && cmd_joined.contains("delete"))
                || (name.contains("wmic") && cmd_joined.contains("shadowcopy"))
                || (name.contains("wbadmin") && cmd_joined.contains("delete"))
                || (name.contains("bcdedit") && cmd_joined.contains("recoveryenabled"))
            {
                alerts.push(Threat {
                    id: Uuid::new_v4().to_string(),
                    name: format!("Shadow Copy / Recovery Tampering ({})", name),
                    category: ThreatCategory::RansomwareBehavior,
                    severity: ThreatSeverity::Critical,
                    description: format!(
                        "Process PID {} attempted to inhibit system recovery or delete shadow copies: {}",
                        pid.as_u32(),
                        cmd_joined
                    ),
                    file_path: process.exe().map(|p: &Path| p.to_string_lossy().to_string()),
                    pid: Some(pid.as_u32()),
                    registry_key: None,
                    remote_addr: None,
                    detected_at: Utc::now().to_rfc3339(),
                    status: "Active".to_string(),
                    recommendation: "Terminate process immediately to protect Volume Shadow Copies".to_string(),
                });
            }
        }

        RansomwareStatus {
            shield_enabled,
            canary_guard_active: true,
            vss_shadow_guard_active: true,
            protected_folders: folder_statuses,
            alerts,
            last_checked: Utc::now().to_rfc3339(),
        }
    }
}
