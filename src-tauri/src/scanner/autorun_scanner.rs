use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;
use chrono::Utc;
use uuid::Uuid;
use super::types::{AutorunEntry, Threat, ThreatCategory, ThreatSeverity};

pub struct AutorunScanner;

impl AutorunScanner {
    pub fn scan_autoruns() -> (Vec<AutorunEntry>, Vec<Threat>) {
        let mut entries = Vec::new();
        let mut threats = Vec::new();

        // 1. HKCU Run
        Self::scan_registry_key(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            &mut entries,
            &mut threats,
        );

        // 2. HKCU RunOnce
        Self::scan_registry_key(
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            &mut entries,
            &mut threats,
        );

        // 3. HKLM Run
        Self::scan_registry_key(
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            &mut entries,
            &mut threats,
        );

        // 4. HKLM RunOnce
        Self::scan_registry_key(
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            &mut entries,
            &mut threats,
        );

        // 5. User Startup Folder
        if let Ok(appdata) = std::env::var("APPDATA") {
            let startup_path = format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", appdata);
            Self::scan_folder(&startup_path, "User Startup Folder", &mut entries, &mut threats);
        }

        // 6. Common Startup Folder
        if let Ok(progdata) = std::env::var("PROGRAMDATA") {
            let startup_path = format!(r"{}\Microsoft\Windows\Start Menu\Programs\Startup", progdata);
            Self::scan_folder(&startup_path, "System Startup Folder", &mut entries, &mut threats);
        }

        (entries, threats)
    }

    fn scan_registry_key(
        root: winreg::HKEY,
        subpath: &str,
        display_location: &str,
        entries: &mut Vec<AutorunEntry>,
        threats: &mut Vec<Threat>,
    ) {
        let reg = RegKey::predef(root);
        if let Ok(key) = reg.open_subkey_with_flags(subpath, KEY_READ) {
            for val in key.enum_values().flatten() {
                let (name, value) = val;
                let cmd = value.to_string();
                let cmd_lower = cmd.to_lowercase();

                let mut is_suspicious = false;
                let mut reason = None;

                // Heuristics:
                if cmd_lower.contains("powershell") && (cmd_lower.contains("-enc") || cmd_lower.contains("-w hidden") || cmd_lower.contains("bypass")) {
                    is_suspicious = true;
                    reason = Some("Obfuscated hidden PowerShell execution in autorun registry".to_string());
                } else if cmd_lower.contains("\\appdata\\local\\temp\\") || cmd_lower.contains("c:\\users\\public\\") {
                    is_suspicious = true;
                    reason = Some("Autorun executes binary from temporary or public user directory".to_string());
                } else if cmd_lower.ends_with(".vbs") || cmd_lower.ends_with(".bat") || cmd_lower.ends_with(".cmd") || cmd_lower.ends_with(".js") {
                    is_suspicious = true;
                    reason = Some("Script file (.vbs/.bat/.js) set to execute automatically at Windows logon".to_string());
                } else if cmd_lower.contains("wscript") || cmd_lower.contains("cscript") {
                    is_suspicious = true;
                    reason = Some("Windows Script Host invocation configured for startup persistence".to_string());
                }

                if is_suspicious {
                    threats.push(Threat {
                        id: Uuid::new_v4().to_string(),
                        name: format!("Suspicious Autorun: {}", name),
                        category: ThreatCategory::SpywarePersistence,
                        severity: ThreatSeverity::High,
                        description: reason.clone().unwrap_or_default(),
                        file_path: None,
                        pid: None,
                        registry_key: Some(format!("{}\\{}", display_location, name)),
                        remote_addr: None,
                        detected_at: Utc::now().to_rfc3339(),
                        status: "Active".to_string(),
                        recommendation: "Remove persistence registry entry to prevent automatic startup".to_string(),
                    });
                }

                entries.push(AutorunEntry {
                    id: Uuid::new_v4().to_string(),
                    name,
                    source: "Registry".to_string(),
                    location: display_location.to_string(),
                    command: cmd,
                    is_suspicious,
                    reason,
                });
            }
        }
    }

    fn scan_folder(
        folder: &str,
        source: &str,
        entries: &mut Vec<AutorunEntry>,
        threats: &mut Vec<Threat>,
    ) {
        let p = Path::new(folder);
        if p.exists() && p.is_dir() {
            if let Ok(dir_entries) = std::fs::read_dir(p) {
                for entry_res in dir_entries.flatten() {
                    let path = entry_res.path();
                    let name = entry_res.file_name().to_string_lossy().to_string();
                    let path_str = path.to_string_lossy().to_string();
                    let path_lower = path_str.to_lowercase();

                    if name.eq_ignore_ascii_case("desktop.ini") {
                        continue;
                    }

                    let mut is_suspicious = false;
                    let mut reason = None;

                    if path_lower.ends_with(".vbs") || path_lower.ends_with(".bat") || path_lower.ends_with(".ps1") {
                        is_suspicious = true;
                        reason = Some("Unsafe executable script dropped into Windows Startup folder".to_string());
                    } else if path_lower.ends_with(".exe") && !path_lower.contains("shortcut") {
                        is_suspicious = true;
                        reason = Some("Direct executable binary in Startup directory (non-shortcut)".to_string());
                    }

                    if is_suspicious {
                        threats.push(Threat {
                            id: Uuid::new_v4().to_string(),
                            name: format!("Startup Folder Threat: {}", name),
                            category: ThreatCategory::SpywarePersistence,
                            severity: ThreatSeverity::High,
                            description: reason.clone().unwrap_or_default(),
                            file_path: Some(path_str.clone()),
                            pid: None,
                            registry_key: None,
                            remote_addr: None,
                            detected_at: Utc::now().to_rfc3339(),
                            status: "Active".to_string(),
                            recommendation: "Remove or quarantine file from Startup directory".to_string(),
                        });
                    }

                    entries.push(AutorunEntry {
                        id: Uuid::new_v4().to_string(),
                        name,
                        source: source.to_string(),
                        location: folder.to_string(),
                        command: path_str,
                        is_suspicious,
                        reason,
                    });
                }
            }
        }
    }

    pub fn remove_autorun(location: &str, name: &str) -> Result<(), String> {
        if location.starts_with("HKCU\\") {
            let subkey = location.trim_start_matches("HKCU\\");
            let reg = RegKey::predef(HKEY_CURRENT_USER);
            let (key, _) = reg.create_subkey(subkey).map_err(|e| e.to_string())?;
            key.delete_value(name).map_err(|e| e.to_string())?;
            Ok(())
        } else if location.starts_with("HKLM\\") {
            let subkey = location.trim_start_matches("HKLM\\");
            let reg = RegKey::predef(HKEY_LOCAL_MACHINE);
            let (key, _) = reg.create_subkey(subkey).map_err(|e| e.to_string())?;
            key.delete_value(name).map_err(|e| e.to_string())?;
            Ok(())
        } else {
            // Folder path
            let full_path = Path::new(location).join(name);
            if full_path.exists() {
                std::fs::remove_file(full_path).map_err(|e| e.to_string())?;
                Ok(())
            } else {
                Err("File not found in startup directory".to_string())
            }
        }
    }
}
