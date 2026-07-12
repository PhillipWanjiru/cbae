//! Scheduler — manages the worker pool and job dispatch.
use crate::queue::JobQueue;
use crate::worker::spawn_worker;
use std::sync::Arc;

pub struct Scheduler {
    queue:   Arc<JobQueue>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl Scheduler {
    /// Create a scheduler with `num_workers` parallel worker threads.
    pub fn new(db_path: &str, num_workers: usize)
        -> rusqlite::Result<Self>
    {
        let queue = Arc::new(JobQueue::open(db_path)?);
        let mut workers = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            workers.push(spawn_worker(Arc::clone(&queue)));
        }
        log::info!("Scheduler started with {} workers", num_workers);
        Ok(Self { queue, workers })
    }

    pub fn submit(&self, binary_id: i64, path: &str, priority: i32)
        -> rusqlite::Result<i64>
    {
        self.queue.enqueue(binary_id, path, priority)
    }

    pub fn shutdown(self) {
        // Drop the queue to close the channel, workers will exit
        drop(self.queue);
        for w in self.workers { let _ = w.join(); }
        log::info!("Scheduler shutdown complete");
    }
}
