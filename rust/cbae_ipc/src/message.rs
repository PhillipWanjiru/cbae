//! IPC message types — command path (GUI→Daemon) and status path (Daemon→GUI).
use serde::{Deserialize, Serialize};

/// Commands sent from the GUI to the daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum GuiMsg {
    ScanRequest,
    InstallRequest  { driver_id: String, target_os: String },
    RollbackRequest { transaction_id: i64 },
    StatusQuery,
    BatchSubmit     { path: String, priority: i32 },
}

/// Status updates sent from the daemon to the GUI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DaemonMsg {
    ScanProgress    { percent: u8, current: String },
    InstallProgress { phase: String, health_score: f32 },
    HealthUpdate    { score: f32, rollback_ready: bool },
    RollbackProgress{ percent: u8 },
    BatchProgress   { job_id: i64, stage: String },
    Error           { code: i32, message: String },
}

impl DaemonMsg {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

impl GuiMsg {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}
