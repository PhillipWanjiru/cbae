//! SQLite-backed persistent job queue with in-memory crossbeam channel.
use crate::job::{Job, JobId, JobStage};
use crossbeam_channel::{unbounded, Receiver, Sender};
use rusqlite::{Connection, Result};
use std::sync::{Arc, Mutex};

pub struct JobQueue {
    db:    Arc<Mutex<Connection>>,
    tx:    Sender<Job>,
    pub rx: Receiver<Job>,
}

impl JobQueue {
    pub fn open(db_path: &str) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS batch_jobs (
                id         INTEGER PRIMARY KEY,
                binary_id  INTEGER NOT NULL,
                binary_path TEXT NOT NULL,
                stage      TEXT NOT NULL DEFAULT 'Pending',
                priority   INTEGER NOT NULL DEFAULT 0,
                error_msg  TEXT
            );"
        )?;
        let (tx, rx) = unbounded();
        // Reload pending jobs from DB on startup (crash recovery)
        {
            let mut stmt = conn.prepare(
                "SELECT id, binary_id, binary_path, priority
                 FROM batch_jobs WHERE stage='Pending'
                 ORDER BY priority DESC"
            )?;
            let jobs: Vec<Job> = stmt.query_map([], |row| {
                Ok(Job::new(row.get(0)?, row.get(1)?, row.get::<_,String>(2)?))
            })?.filter_map(|j| j.ok()).collect();
            for job in jobs { let _ = tx.send(job); }
        }
        Ok(Self { db: Arc::new(Mutex::new(conn)), tx, rx })
    }

    pub fn enqueue(&self, binary_id: i64, path: &str, priority: i32)
        -> Result<JobId>
    {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO batch_jobs(binary_id, binary_path, priority) VALUES(?1,?2,?3)",
            rusqlite::params![binary_id, path, priority],
        )?;
        let id = db.last_insert_rowid();
        let job = Job::new(id, binary_id, path);
        let _ = self.tx.send(job);
        Ok(id)
    }

    pub fn mark_complete(&self, id: JobId) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("UPDATE batch_jobs SET stage='Complete' WHERE id=?1",
                   rusqlite::params![id])?;
        Ok(())
    }

    pub fn mark_failed(&self, id: JobId, msg: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("UPDATE batch_jobs SET stage='Failed', error_msg=?1 WHERE id=?2",
                   rusqlite::params![msg, id])?;
        Ok(())
    }
}
