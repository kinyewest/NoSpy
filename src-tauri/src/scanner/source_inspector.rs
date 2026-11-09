use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::Path;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::process_scanner::ProcessScanner;
use super::types::{SourceInspectionReport, Threat, ThreatCategory, ThreatSeverity};

pub struct SourceInspector;

impl SourceInspector {
    pub fn inspect_file(path_str: &str) -> Result<SourceInspectionReport, String> {
        let cleaned_path = path_str.trim().trim_matches('"');
        let path = Path::new(cleaned_path);
        if !path.exists() || !path.is_file() {
            return Err(format!("File not found or inaccessible: {}", cleaned_path));
        }

        let metadata = fs::metadata(path).map_err(|e| e.to_string())?;
        let file_size_bytes = metadata.len();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| cleaned_path.to_string());

        // Read up to 2 MB for fast deep source/binary inspection
        let max_read = 2 * 1024 * 1024;
        let file = fs::File::open(path).map_err(|e| e.to_string())?;
        let mut buffer = Vec::with_capacity(std::cmp::min(file_size_bytes as usize, max_read));
        file.take(max_read as u64)
            .read_to_end(&mut buffer)
            .map_err(|e| e.to_string())?;

        // Calculate SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&buffer);
        let sha256 = format!("{:x}", hasher.finalize());

        // Calculate Shannon Entropy
        let entropy = Self::calculate_entropy(&buffer);

        // Determine file format
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        let is_pe = buffer.len() >= 2 && buffer[0] == b'M' && buffer[1] == b'Z';
        let file_format = if is_pe {
            "PE32/PE64 Windows Executable (MZ)".to_string()
        } else {
            match ext.as_str() {
                "ps1" => "PowerShell Script (.ps1)".to_string(),
                "bat" | "cmd" => "Windows Batch Script (.bat/.cmd)".to_string(),
                "vbs" | "vbe" | "wsf" => "VBScript / Windows Script Host".to_string(),
                "js" | "jse" => "JScript / JavaScript Source".to_string(),
                "hta" => "HTML Application (.hta)".to_string(),
                "py" => "Python Script (.py)".to_string(),
                "dll" => "Dynamic Link Library (.dll)".to_string(),
                "sys" => "Windows Kernel/System Driver (.sys)".to_string(),
                _ => format!("Binary / Source File (.{})", if ext.is_empty() { "bin" } else { &ext }),
            }
        };

        let is_script = matches!(
            ext.as_str(),
            "ps1" | "bat" | "cmd" | "vbs" | "vbe" | "wsf" | "js" | "jse" | "hta" | "py" | "txt" | "xml" | "json"
        );

        let extracted_strings = if is_script {
            String::from_utf8_lossy(&buffer).to_string()
        } else {
            Self::extract_binary_strings(&buffer, 5)
        };

        // Detect suspicious APIs & capabilities
        let api_signatures = [
            ("VirtualAllocEx", "Remote process memory allocation (Process Injection)"),
            ("WriteProcessMemory", "Remote process memory write (Code Injection)"),
            ("CreateRemoteThread", "Remote thread creation (DLL/Shellcode Injection)"),
            ("NtUnmapViewOfSection", "Process hollowing indicator"),
            ("SetWindowsHookEx", "Global keyboard/mouse hook (Keylogger)"),
            ("GetAsyncKeyState", "Keystroke polling API (Keylogger)"),
            ("GetForegroundWindow", "Active window title tracking (Spyware)"),
            ("GetClipboardData", "Clipboard harvesting / crypto address swapper"),
            ("BitBlt", "Screen capture / desktop screenshot API"),
            ("CryptUnprotectData", "DPAPI browser password/cookie decryption (InfoStealer)"),
            ("BCryptEncrypt", "Cryptographic file encryption API"),
            ("CryptEncrypt", "CryptoAPI encryption routine"),
            ("vssadmin", "Volume Shadow Copy manipulation (Ransomware)"),
            ("wmic shadowcopy", "Shadow copy deletion command (Ransomware)"),
            ("bcdedit", "Boot recovery configuration tampering"),
            ("FromBase64String", "Base64 payload decoding"),
            ("-EncodedCommand", "Obfuscated PowerShell command execution"),
            ("Invoke-Expression", "Dynamic script evaluation (IEX)"),
            ("Net.WebClient", "Remote payload download cradle"),
            ("IsDebuggerPresent", "Anti-debugging evasion check"),
        ];

        let mut suspicious_apis = Vec::new();
        let lower_content = extracted_strings.to_lowercase();
        for (sig, desc) in &api_signatures {
            if lower_content.contains(&sig.to_lowercase()) {
                suspicious_apis.push(format!("{} — {}", sig, desc));
            }
        }

        // Extract embedded URLs, webhooks, and IP indicators
        let extracted_urls_and_ips = Self::extract_urls_and_ips(&extracted_strings);

        // Attempt to decode embedded Base64 blobs in scripts
        let decoded_payloads = Self::extract_and_decode_base64(&extracted_strings);

        // Compute heuristic risk score
        let is_packed_or_encrypted = entropy > 7.25 && is_pe;
        let mut risk_score: u32 = 0;
        if is_packed_or_encrypted {
            risk_score += 30;
        }
        risk_score += (suspicious_apis.len() as u32) * 15;
        if !decoded_payloads.is_empty() {
            risk_score += 25;
        }
        if extracted_urls_and_ips.iter().any(|u| {
            u.contains("discord.com/api/webhooks")
                || u.contains("api.telegram.org")
                || u.contains("pastebin.com")
                || u.contains("raw.githubusercontent.com")
        }) {
            risk_score += 40;
        }
        let lower_path = cleaned_path.to_lowercase();
        if (lower_path.contains("\\appdata\\local\\temp") || lower_path.contains("\\appdata\\roaming"))
            && (is_pe || is_script)
        {
            risk_score += 20;
        }
        risk_score = risk_score.min(100);

        let verdict = if risk_score >= 65 {
            "Malicious / High Risk".to_string()
        } else if risk_score >= 35 {
            "Suspicious / Review Recommended".to_string()
        } else {
            "Clean / Normal Structure".to_string()
        };

        // Build de-sourced preview
        let desourced_preview = Self::build_desourced_view(
            &file_name,
            &file_format,
            &sha256,
            entropy,
            is_script,
            &suspicious_apis,
            &extracted_urls_and_ips,
            &decoded_payloads,
            &extracted_strings,
        );

        Ok(SourceInspectionReport {
            file_path: cleaned_path.to_string(),
            file_name,
            file_size_bytes,
            sha256,
            file_format,
            entropy,
            is_packed_or_encrypted,
            risk_score,
            verdict,
            suspicious_apis,
            extracted_urls_and_ips,
            decoded_payloads,
            desourced_preview,
            groq_analysis: None,
        })
    }

    pub fn scan_all_active_sources(max_targets: usize) -> (usize, Vec<SourceInspectionReport>, Vec<Threat>) {
        let (procs, _) = ProcessScanner::scan_processes();
        let mut seen_paths = HashSet::new();
        let mut reports = Vec::new();
        let mut threats = Vec::new();

        for proc in procs {
            if reports.len() >= max_targets {
                break;
            }
            if proc.exe_path.is_empty() {
                continue;
            }
            let lower = proc.exe_path.to_lowercase();
            // Prioritize non-Windows-system binaries and any flagged process
            if lower.starts_with("c:\\windows\\system32\\") && !proc.is_suspicious {
                continue;
            }
            if seen_paths.insert(proc.exe_path.clone()) {
                if let Ok(report) = Self::inspect_file(&proc.exe_path) {
                    if report.risk_score >= 55 {
                        threats.push(Threat {
                            id: Uuid::new_v4().to_string(),
                            name: format!("De-Sourced Binary Anomaly: {}", report.file_name),
                            category: ThreatCategory::ObfuscatedSource,
                            severity: if report.risk_score >= 75 {
                                ThreatSeverity::Critical
                            } else {
                                ThreatSeverity::High
                            },
                            description: format!(
                                "Source inspection flagged {} (Entropy: {:.2}, Risk: {}/100, Indicators: {})",
                                report.file_name,
                                report.entropy,
                                report.risk_score,
                                report.suspicious_apis.len()
                            ),
                            file_path: Some(report.file_path.clone()),
                            pid: Some(proc.pid),
                            registry_key: None,
                            remote_addr: None,
                            detected_at: Utc::now().to_rfc3339(),
                            status: "Active".to_string(),
                            recommendation: "Inspect de-sourced strings and quarantine if unauthorized".to_string(),
                        });
                    }
                    reports.push(report);
                }
            }
        }

        reports.sort_by(|a, b| b.risk_score.cmp(&a.risk_score));
        let count = reports.len();
        (count, reports, threats)
    }

    fn calculate_entropy(bytes: &[u8]) -> f32 {
        if bytes.is_empty() {
            return 0.0;
        }
        let mut counts = [0usize; 256];
        for &b in bytes {
            counts[b as usize] += 1;
        }
        let len = bytes.len() as f32;
        let mut entropy = 0.0f32;
        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    fn extract_binary_strings(bytes: &[u8], min_len: usize) -> String {
        let mut results = Vec::new();
        let mut current = Vec::new();

        for &b in bytes {
            if (0x20..=0x7E).contains(&b) {
                current.push(b);
            } else {
                if current.len() >= min_len {
                    if let Ok(s) = std::str::from_utf8(&current) {
                        results.push(s.to_string());
                    }
                }
                current.clear();
            }
            if results.len() >= 600 {
                break;
            }
        }

        // Also scan UTF-16LE strings common in Windows PE binaries
        let mut u16_curr = Vec::new();
        let mut i = 0;
        while i + 1 < bytes.len() && results.len() < 900 {
            let lo = bytes[i];
            let hi = bytes[i + 1];
            if (0x20..=0x7E).contains(&lo) && hi == 0 {
                u16_curr.push(lo);
            } else {
                if u16_curr.len() >= min_len {
                    if let Ok(s) = std::str::from_utf8(&u16_curr) {
                        results.push(s.to_string());
                    }
                }
                u16_curr.clear();
            }
            i += 2;
        }

        results.join("\n")
    }

    fn extract_urls_and_ips(text: &str) -> Vec<String> {
        let mut found = Vec::new();
        let mut seen = HashSet::new();

        for token in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '<' || c == '>' || c == '(' || c == ')') {
            let trimmed = token.trim();
            if (trimmed.starts_with("http://") || trimmed.starts_with("https://") || trimmed.starts_with("wss://"))
                && trimmed.len() > 10
            {
                if seen.insert(trimmed.to_string()) {
                    found.push(trimmed.to_string());
                }
            }
            if found.len() >= 25 {
                break;
            }
        }
        found
    }

    fn extract_and_decode_base64(text: &str) -> Vec<String> {
        let mut decoded = Vec::new();
        for word in text.split_whitespace() {
            let clean = word.trim_matches(|c: char| c == '"' || c == '\'' || c == ';');
            if clean.len() >= 28
                && clean.len() % 4 == 0
                && clean.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
            {
                if let Some(dec) = Self::simple_base64_decode(clean) {
                    if dec.len() >= 8 && dec.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).count() * 10 >= dec.len() * 8 {
                        decoded.push(dec);
                        if decoded.len() >= 5 {
                            break;
                        }
                    }
                }
            }
        }
        decoded
    }

    fn simple_base64_decode(input: &str) -> Option<String> {
        const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = Vec::new();
        let mut buf = 0u32;
        let mut bits = 0u32;

        for b in input.bytes() {
            if b == b'=' {
                break;
            }
            let val = TABLE.iter().position(|&c| c == b)? as u32;
            buf = (buf << 6) | val;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buf >> bits) & 0xFF) as u8);
            }
        }

        // Handle UTF-16LE PowerShell Base64 or UTF-8
        if out.len() >= 4 && out[1] == 0 && out[3] == 0 {
            let filtered: Vec<u8> = out.into_iter().filter(|&b| b != 0).collect();
            String::from_utf8(filtered).ok()
        } else {
            String::from_utf8(out).ok()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_desourced_view(
        file_name: &str,
        file_format: &str,
        sha256: &str,
        entropy: f32,
        is_script: bool,
        suspicious_apis: &[String],
        urls: &[String],
        decoded: &[String],
        raw_strings: &str,
    ) -> String {
        let mut out = String::new();
        out.push_str(&format!("// ============================================================\n"));
        out.push_str(&format!("// NOSPY DE-SOURCE & STATIC ANTIVIRUS ANALYSIS\n"));
        out.push_str(&format!("// Target   : {}\n", file_name));
        out.push_str(&format!("// Format   : {}\n", file_format));
        out.push_str(&format!("// SHA-256  : {}\n", sha256));
        out.push_str(&format!("// Entropy  : {:.3} bits/byte {}\n", entropy, if entropy > 7.25 { "[PACKED / HIGH ENTROPY]" } else { "[NORMAL]" }));
        out.push_str(&format!("// ============================================================\n\n"));

        if !suspicious_apis.is_empty() {
            out.push_str("// [!] FLAGGED CAPABILITIES & IMPORTS:\n");
            for api in suspicious_apis {
                out.push_str(&format!("  import {}\n", api));
            }
            out.push('\n');
        }

        if !urls.is_empty() {
            out.push_str("// [!] EMBEDDED ENDPOINTS / URLS:\n");
            for u in urls {
                out.push_str(&format!("  endpoint \"{}\"\n", u));
            }
            out.push('\n');
        }

        if !decoded.is_empty() {
            out.push_str("// [!] DEOBFUSCATED BASE64 PAYLOADS:\n");
            for (idx, d) in decoded.iter().enumerate() {
                out.push_str(&format!("  decoded_block_{} = {:?}\n", idx + 1, d));
            }
            out.push('\n');
        }

        out.push_str(if is_script {
            "// --- EXTRACTED SCRIPT SOURCE ---\n"
        } else {
            "// --- DE-SOURCED BINARY STRINGS & SYMBOLS ---\n"
        });

        let preview_lines: Vec<&str> = raw_strings
            .lines()
            .filter(|l| !l.trim().is_empty())
            .take(140)
            .collect();
        out.push_str(&preview_lines.join("\n"));
        out
    }
}
