use std::fs;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use serde_json::{json, Value};

use super::types::{SourceInspectionReport, Threat};

const CREATE_NO_WINDOW: u32 = 0x08000000;

pub struct GroqAnalyzer;

impl GroqAnalyzer {
    fn key_file_path() -> PathBuf {
        let base = std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("C:\\ProgramData"));
        let dir = base.join("NoSpy");
        let _ = fs::create_dir_all(&dir);
        dir.join("groq_api_key.dat")
    }

    pub fn save_api_key(key: &str) -> Result<bool, String> {
        let trimmed = key.trim();
        let path = Self::key_file_path();
        if trimmed.is_empty() {
            let _ = fs::remove_file(path);
            return Ok(false);
        }
        fs::write(path, trimmed).map_err(|e| e.to_string())?;
        Ok(true)
    }

    pub fn load_api_key() -> Option<String> {
        let path = Self::key_file_path();
        let content = fs::read_to_string(path).ok()?;
        let trimmed = content.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    }

    pub fn is_configured() -> bool {
        Self::load_api_key().is_some()
    }

    pub fn analyze_source_report(report: &SourceInspectionReport) -> Result<String, String> {
        let api_key = Self::load_api_key()
            .ok_or_else(|| "Groq API key is not configured. Click 'Groq AI' to enter your key.".to_string())?;

        let snippet: String = report.desourced_preview.chars().take(1800).collect();
        let prompt = format!(
            "You are NoSpy AI Antivirus & De-Source Analyst. Analyze this de-sourced binary/script inspection report and provide a concise, high-signal security verdict (3-5 bullet points max, no markdown headers):\n\
            File: {} ({})\n\
            SHA-256: {}\n\
            Entropy: {:.2} bits/byte (Risk Score: {}/100)\n\
            Flagged APIs: {:?}\n\
            Extracted URLs: {:?}\n\
            De-sourced Excerpt:\n{}",
            report.file_name,
            report.file_format,
            report.sha256,
            report.entropy,
            report.risk_score,
            report.suspicious_apis,
            report.extracted_urls_and_ips,
            snippet
        );

        Self::query_groq(&api_key, &prompt)
    }

    pub fn analyze_scan_threats(threats: &[Threat], total_scanned: usize, desourced_count: usize) -> Option<String> {
        let api_key = Self::load_api_key()?;

        let threat_summary = if threats.is_empty() {
            "0 threats detected. All processes, autorun keys, network sockets, and de-sourced binaries passed heuristic checks.".to_string()
        } else {
            threats
                .iter()
                .take(10)
                .map(|t| format!("- [{}] {:?}: {} ({})", t.name, t.severity, t.description, t.file_path.clone().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join("\n")
        };

        let prompt = format!(
            "You are NoSpy AI Security Analyst. Summarize this Windows system antivirus & de-source scan in 2-3 concise sentences for the user, including actionable advice if threats were found:\n\
            Total items scanned: {}\n\
            Binaries/Scripts De-sourced: {}\n\
            Findings:\n{}",
            total_scanned, desourced_count, threat_summary
        );

        Self::query_groq(&api_key, &prompt).ok()
    }

    pub fn query_groq(api_key: &str, user_prompt: &str) -> Result<String, String> {
        let payload = json!({
            "model": "llama-3.3-70b-versatile",
            "temperature": 0.2,
            "max_tokens": 360,
            "messages": [
                {
                    "role": "system",
                    "content": "You are a precise, technical cybersecurity and reverse-engineering antivirus engine built into NoSpy. Be direct, clear, and concise."
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        });

        let temp_dir = std::env::temp_dir();
        let req_path = temp_dir.join("nospy_groq_payload.json");
        fs::write(&req_path, payload.to_string()).map_err(|e| e.to_string())?;

        let auth_header = format!("Authorization: Bearer {}", api_key.trim());
        let data_arg = format!("@{}", req_path.to_string_lossy());

        let output = Command::new("curl.exe")
            .args([
                "-s",
                "-S",
                "--max-time",
                "12",
                "-X",
                "POST",
                "https://api.groq.com/openai/v1/chat/completions",
                "-H",
                "Content-Type: application/json",
                "-H",
                &auth_header,
                "--data-binary",
                &data_arg,
            ])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("Failed to invoke curl: {}", e))?;

        let _ = fs::remove_file(&req_path);

        if !output.status.success() {
            return Err(format!(
                "Groq request failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let resp_str = String::from_utf8_lossy(&output.stdout);
        let parsed: Value = serde_json::from_str(&resp_str)
            .map_err(|e| format!("Invalid Groq response JSON: {}", e))?;

        if let Some(err_msg) = parsed.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str()) {
            return Err(format!("Groq API Error: {}", err_msg));
        }

        parsed["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.trim().to_string())
            .ok_or_else(|| "Empty response from Groq AI".to_string())
    }
}
