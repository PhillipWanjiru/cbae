//! C FFI surface for cbae_ipc.
//! cbindgen generates include/rust/cbae_ipc.h from these exports.
use crate::message::{DaemonMsg, GuiMsg};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// Serialise a DaemonMsg::Error to JSON.  Caller must free with cbae_ipc_free_string().
#[no_mangle]
pub extern "C" fn cbae_ipc_error_msg(code: i32, message: *const c_char) -> *mut c_char {
    if message.is_null() { return ptr::null_mut(); }
    let msg_str = unsafe { CStr::from_ptr(message) }.to_string_lossy();
    let dm      = DaemonMsg::Error { code, message: msg_str.into_owned() };
    match CString::new(dm.to_json()) {
        Ok(s)  => s.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Parse a GuiMsg from a JSON C-string.
/// Returns 1 if parsing succeeds, 0 otherwise.
#[no_mangle]
pub extern "C" fn cbae_ipc_parse_gui_msg(json: *const c_char) -> i32 {
    if json.is_null() { return 0; }
    let s = unsafe { CStr::from_ptr(json) }.to_string_lossy();
    match GuiMsg::from_json(s.as_ref()) {
        Ok(_)  => 1,
        Err(e) => { log::warn!("parse_gui_msg failed: {}", e); 0 }
    }
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn cbae_ipc_free_string(s: *mut c_char) {
    if !s.is_null() { unsafe { drop(CString::from_raw(s)) }; }
}
