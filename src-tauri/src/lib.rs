pub mod scanner;

use std::sync::Mutex;
use sysinfo::System;
use tauri::{State, Window};
use scanner::{
    autorun_scanner::AutorunScanner,
    groq_analyzer::GroqAnalyzer,
    network_scanner::NetworkScanner,
    process_scanner::ProcessScanner,
    quarantine_manager::QuarantineManager,
    ransomware_guard::RansomwareGuard,
    realtime_monitor::RealtimeMonitorState,
    source_inspector::SourceInspector,
    types::{
        AutorunEntry, MonitoredProcess, NetworkSocketEntry, QuarantineItem, RansomwareStatus,
        RealtimeStatus, ScanResult, SourceInspectionReport, SystemResourceStats, SystemSummary,
    },
    ScannerEngine,
};

pub struct AppState {
    pub realtime_shield_enabled: Mutex<bool>,
    pub ransomware_shield_enabled: Mutex<bool>,
    pub system_monitor: Mutex<System>,
    pub realtime_state: Mutex<RealtimeMonitorState>,
}

#[tauri::command]
fn get_system_summary(state: State<'_, AppState>) -> SystemSummary {
    let shield = *state.realtime_shield_enabled.lock().unwrap();
    let r_shield = *state.ransomware_shield_enabled.lock().unwrap();
    ScannerEngine::get_summary(shield, r_shield)
}

#[tauri::command]
fn get_resource_stats(state: State<'_, AppState>) -> SystemResourceStats {
    let mut sys = state.system_monitor.lock().unwrap();
    ProcessScanner::collect_resource_stats(&mut sys)
}

#[tauri::command]
fn run_quick_scan() -> ScanResult {
    ScannerEngine::quick_scan()
}

#[tauri::command]
fn run_deep_scan() -> ScanResult {
    ScannerEngine::deep_scan()
}

#[tauri::command]
fn get_all_processes() -> Vec<MonitoredProcess> {
    let (procs, _) = ProcessScanner::scan_processes();
    procs
}

#[tauri::command]
fn terminate_process(pid: u32) -> Result<(), String> {
    ProcessScanner::terminate_process(pid)
}

#[tauri::command]
fn get_all_autoruns() -> Vec<AutorunEntry> {
    let (autoruns, _) = AutorunScanner::scan_autoruns();
    autoruns
}

#[tauri::command]
fn remove_autorun(location: String, name: String) -> Result<(), String> {
    AutorunScanner::remove_autorun(&location, &name)
}

#[tauri::command]
fn get_all_network_sockets() -> Vec<NetworkSocketEntry> {
    let (sockets, _) = NetworkScanner::scan_network_sockets();
    sockets
}

#[tauri::command]
fn quarantine_file(path: String, threat_name: String) -> Result<QuarantineItem, String> {
    QuarantineManager::quarantine_file(&path, &threat_name)
}

#[tauri::command]
fn list_quarantine() -> Vec<QuarantineItem> {
    QuarantineManager::list_quarantined()
}

#[tauri::command]
fn restore_quarantined_file(id: String) -> Result<(), String> {
    QuarantineManager::restore_file(&id)
}

#[tauri::command]
fn delete_quarantined_file(id: String) -> Result<(), String> {
    QuarantineManager::delete_permanently(&id)
}

#[tauri::command]
fn toggle_realtime_shield(state: State<'_, AppState>) -> bool {
    let mut shield = state.realtime_shield_enabled.lock().unwrap();
    *shield = !*shield;
    let mut rt = state.realtime_state.lock().unwrap();
    rt.enabled = *shield;
    *shield
}

#[tauri::command]
fn poll_realtime_monitor(state: State<'_, AppState>) -> RealtimeStatus {
    let mut rt = state.realtime_state.lock().unwrap();
    rt.poll_tick()
}

#[tauri::command]
fn inspect_file_source(path: String, use_groq: bool) -> Result<SourceInspectionReport, String> {
    let mut report = SourceInspector::inspect_file(&path)?;
    if use_groq && GroqAnalyzer::is_configured() {
        if let Ok(analysis) = GroqAnalyzer::analyze_source_report(&report) {
            report.groq_analysis = Some(analysis);
        }
    }
    Ok(report)
}

#[tauri::command]
fn scan_all_sources() -> Vec<SourceInspectionReport> {
    let (_, reports, _) = SourceInspector::scan_all_active_sources(35);
    reports
}

#[tauri::command]
fn analyze_source_with_groq(path: String) -> Result<String, String> {
    let report = SourceInspector::inspect_file(&path)?;
    GroqAnalyzer::analyze_source_report(&report)
}

#[tauri::command]
fn save_groq_api_key(key: String) -> Result<bool, String> {
    GroqAnalyzer::save_api_key(&key)
}

#[tauri::command]
fn get_groq_status() -> bool {
    GroqAnalyzer::is_configured()
}

#[tauri::command]
fn get_ransomware_status(state: State<'_, AppState>) -> RansomwareStatus {
    let enabled = *state.ransomware_shield_enabled.lock().unwrap();
    RansomwareGuard::check_status(enabled)
}

#[tauri::command]
fn deploy_ransomware_canaries() -> usize {
    RansomwareGuard::deploy_canaries()
}

#[tauri::command]
fn toggle_ransomware_shield(state: State<'_, AppState>) -> bool {
    let mut r = state.ransomware_shield_enabled.lock().unwrap();
    *r = !*r;
    *r
}

#[tauri::command]
fn window_minimize(window: Window) {
    let _ = window.minimize();
}

#[tauri::command]
fn window_toggle_maximize(window: Window) {
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    } else {
        let _ = window.maximize();
    }
}

#[tauri::command]
fn window_close(window: Window) {
    let _ = window.close();
}

#[tauri::command]
fn window_start_dragging(window: Window) {
    let _ = window.start_dragging();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let mut initial_sys = System::new_all();
    initial_sys.refresh_cpu_all();
    initial_sys.refresh_memory();

    // Ensure ransomware canary traps exist on startup
    let _ = RansomwareGuard::deploy_canaries();

    tauri::Builder::default()
        .manage(AppState {
            realtime_shield_enabled: Mutex::new(true),
            ransomware_shield_enabled: Mutex::new(true),
            system_monitor: Mutex::new(initial_sys),
            realtime_state: Mutex::new(RealtimeMonitorState::new()),
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_system_summary,
            get_resource_stats,
            run_quick_scan,
            run_deep_scan,
            get_all_processes,
            terminate_process,
            get_all_autoruns,
            remove_autorun,
            get_all_network_sockets,
            quarantine_file,
            list_quarantine,
            restore_quarantined_file,
            delete_quarantined_file,
            toggle_realtime_shield,
            poll_realtime_monitor,
            inspect_file_source,
            scan_all_sources,
            analyze_source_with_groq,
            save_groq_api_key,
            get_groq_status,
            get_ransomware_status,
            deploy_ransomware_canaries,
            toggle_ransomware_shield,
            window_minimize,
            window_toggle_maximize,
            window_close,
            window_start_dragging,
        ])
        .run(tauri::generate_context!())
        .expect("error while running NoSpy AntiSpyware application");
}
