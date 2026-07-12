//! Job record definition.
use serde::{Deserialize, Serialize};

pub type JobId = i64;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStage {
    Pending,
    Loading,
    Disassembling,
    Analysing,
    Decompiling,
    DnaExtraction,
    Translating,
    Complete,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id:        JobId,
    pub binary_id: i64,
    pub binary_path: String,
    pub stage:     JobStage,
    pub priority:  i32,
    pub error_msg: Option<String>,
}

impl Job {
    pub fn new(id: JobId, binary_id: i64, path: impl Into<String>) -> Self {
        Self {
            id,
            binary_id,
            binary_path: path.into(),
            stage: JobStage::Pending,
            priority: 0,
            error_msg: None,
        }
    }
}
