use std::path::{Path, PathBuf};
use std::fs;
use chrono::Utc;
use uuid::Uuid;
use super::file_scanner::FileScanner;
use super::types::QuarantineItem;

pub struct QuarantineManager;

impl QuarantineManager {
    fn get_quarantine_dir() -> PathBuf {
        let base = std::env::var("LOCALAPPDATA")
            .unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let q_dir = PathBuf::from(base).join("NoSpy").join("Quarantine");
        let _ = fs::create_dir_all(&q_dir);
        q_dir
    }

    fn get_manifest_path() -> PathBuf {
        Self::get_quarantine_dir().join("quarantine_manifest.json")
    }

    pub fn list_quarantined() -> Vec<QuarantineItem> {
        let manifest_path = Self::get_manifest_path();
        if let Ok(data) = fs::read_to_string(&manifest_path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            Vec::new()
        }
    }

    fn save_manifest(items: &[QuarantineItem]) -> Result<(), String> {
        let manifest_path = Self::get_manifest_path();
        let json = serde_json::to_string_pretty(items).map_err(|e| e.to_string())?;
        fs::write(manifest_path, json).map_err(|e| e.to_string())
    }

    pub fn quarantine_file(file_path: &str, threat_name: &str) -> Result<QuarantineItem, String> {
        let orig_path = Path::new(file_path);
        if !orig_path.exists() {
            return Err("Target file does not exist".to_string());
        }

        let file_size = fs::metadata(orig_path).map(|m| m.len()).unwrap_or(0);
        let sha256_hash = FileScanner::calculate_file_sha256(orig_path).unwrap_or_default();
        let item_id = Uuid::new_v4().to_string();

        let q_dir = Self::get_quarantine_dir();
        let vault_filename = format!("{}.nospy_vault", item_id);
        let vault_path = q_dir.join(vault_filename);

        // Move or copy + delete original
        fs::rename(orig_path, &vault_path).or_else(|_| {
            fs::copy(orig_path, &vault_path).and_then(|_| fs::remove_file(orig_path))
        }).map_err(|e| format!("Failed to quarantine file: {}", e))?;

        let item = QuarantineItem {
            id: item_id,
            original_path: file_path.to_string(),
            quarantine_path: vault_path.to_string_lossy().to_string(),
            threat_name: threat_name.to_string(),
            file_size_bytes: file_size,
            sha256_hash,
            quarantined_at: Utc::now().to_rfc3339(),
        };

        let mut current_items = Self::list_quarantined();
        current_items.push(item.clone());
        Self::save_manifest(&current_items)?;

        Ok(item)
    }

    pub fn restore_file(id: &str) -> Result<(), String> {
        let mut items = Self::list_quarantined();
        if let Some(pos) = items.iter().position(|i| i.id == id) {
            let item = items.remove(pos);
            let vault_path = Path::new(&item.quarantine_path);
            let orig_path = Path::new(&item.original_path);

            if let Some(parent) = orig_path.parent() {
                let _ = fs::create_dir_all(parent);
            }

            fs::rename(vault_path, orig_path).or_else(|_| {
                fs::copy(vault_path, orig_path).and_then(|_| fs::remove_file(vault_path))
            }).map_err(|e| format!("Failed to restore file: {}", e))?;

            Self::save_manifest(&items)?;
            Ok(())
        } else {
            Err("Quarantine item not found".to_string())
        }
    }

    pub fn delete_permanently(id: &str) -> Result<(), String> {
        let mut items = Self::list_quarantined();
        if let Some(pos) = items.iter().position(|i| i.id == id) {
            let item = items.remove(pos);
            let vault_path = Path::new(&item.quarantine_path);
            if vault_path.exists() {
                let _ = fs::remove_file(vault_path);
            }
            Self::save_manifest(&items)?;
            Ok(())
        } else {
            Err("Quarantine item not found".to_string())
        }
    }
}
