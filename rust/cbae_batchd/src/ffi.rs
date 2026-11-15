//! C-compatible FFI surface for cbae_batchd.
//! The CMake build uses cbindgen to generate include/rust/cbae_batchd.h
//! from these #[no_mangle] extern "C" functions.

use crate::scheduler::Scheduler;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// Opaque handle exposed to C as cbae_scheduler_t*.
pub struct CScheduler(Scheduler);

/// Create a new scheduler.
/// Returns NULL on failure.
#[no_mangle]
pub extern "C" fn cbae_scheduler_create(
    db_path: *const c_char,
    num_workers: u32,
) -> *mut CScheduler {
    if db_path.is_null() { return ptr::null_mut(); }
    let path = unsafe { CStr::from_ptr(db_path) }.to_string_lossy();
    match Scheduler::new(path.as_ref(), num_workers as usize) {
        Ok(s)  => Box::into_raw(Box::new(CScheduler(s))),
        Err(e) => { log::error!("scheduler_create failed: {}", e); ptr::null_mut() }
    }
}

/// Submit a job. Returns job_id >= 0 on success, -1 on failure.
#[no_mangle]
pub extern "C" fn cbae_scheduler_submit(
    sched:     *mut CScheduler,
    binary_id: i64,
    path:      *const c_char,
    priority:  i32,
) -> i64 {
    if sched.is_null() || path.is_null() { return -1; }
    let s    = unsafe { &*sched };
    let p    = unsafe { CStr::from_ptr(path) }.to_string_lossy();
    match s.0.submit(binary_id, p.as_ref(), priority) {
        Ok(id) => id,
        Err(e) => { log::error!("submit failed: {}", e); -1 }
    }
}

/// Shut down the scheduler and free memory.
#[no_mangle]
pub extern "C" fn cbae_scheduler_destroy(sched: *mut CScheduler) {
    if sched.is_null() { return; }
    let boxed = unsafe { Box::from_raw(sched) };
    boxed.0.shutdown();
}
