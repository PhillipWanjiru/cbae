//! Worker thread — pulls jobs from the queue and executes them.
use crate::job::{Job, JobStage};
use crate::queue::JobQueue;
use std::sync::Arc;

/// Execute one job.
/// In Phase 3+ this will call back into the C analysis pipeline via FFI.
/// For Phase 2 it validates that the binary file exists.
pub fn execute_job(job: &mut Job) {
    log::info!("Worker: executing job {} — {}", job.id, job.binary_path);
    if std::path::Path::new(&job.binary_path).exists() {
        job.stage = JobStage::Complete;
        log::info!("Job {} complete", job.id);
    } else {
        job.stage = JobStage::Failed;
        job.error_msg = Some(format!("File not found: {}", job.binary_path));
        log::warn!("Job {} failed: file not found", job.id);
    }
}

/// Spawn a worker thread that pulls from the queue indefinitely.
pub fn spawn_worker(queue: Arc<JobQueue>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        loop {
            match queue.rx.recv() {
                Ok(mut job) => {
                    execute_job(&mut job);
                    match job.stage {
                        JobStage::Complete => { let _ = queue.mark_complete(job.id); }
                        JobStage::Failed   => {
                            let msg = job.error_msg.as_deref().unwrap_or("unknown");
                            let _ = queue.mark_failed(job.id, msg);
                        }
                        _ => {}
                    }
                }
                Err(_) => break, // channel closed — shut down
            }
        }
    })
}
