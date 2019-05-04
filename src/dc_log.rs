use libc;

use crate::constants::Event;
use crate::dc_context::dc_context_t;
use crate::dc_tools::*;
use crate::types::*;
use crate::x::*;

pub unsafe extern "C" fn dc_log_event(
    mut context: &dc_context_t,
    mut event_code: Event,
    mut data1: libc::c_int,
    mut msg: *const libc::c_char,
    mut va: ...
) {
    log_vprintf(context, event_code, data1, msg, va);
}

/* Asynchronous "Thread-errors" are reported by the dc_log_error()
function.  These errors must be shown to the user by a bubble or so.

"Normal" errors are usually returned by a special value (null or so) and are
usually not reported using dc_log_error() - its up to the caller to
decide, what should be reported or done.  However, these "Normal" errors
are usually logged by dc_log_warning(). */
unsafe fn log_vprintf(
    mut context: &dc_context_t,
    mut event: Event,
    mut data1: libc::c_int,
    mut msg_format: *const libc::c_char,
    mut va_0: ::std::ffi::VaList,
) {
    let mut msg: *mut libc::c_char;
    if !msg_format.is_null() {
        let mut tempbuf: [libc::c_char; 1025] = [0; 1025];
        vsnprintf(
            tempbuf.as_mut_ptr(),
            1024i32 as libc::c_ulong,
            msg_format,
            va_0,
        );
        msg = dc_strdup(tempbuf.as_mut_ptr())
    } else {
        msg = dc_mprintf(
            b"event #%i\x00" as *const u8 as *const libc::c_char,
            event as libc::c_int,
        )
    }
    ((*context).cb)(context, event, data1 as uintptr_t, msg as uintptr_t);
    free(msg as *mut libc::c_void);
}

pub unsafe extern "C" fn dc_log_event_seq(
    mut context: &dc_context_t,
    mut event_code: Event,
    mut sequence_start: *mut libc::c_int,
    mut msg: *const libc::c_char,
    mut va_0: ...
) {
    if sequence_start.is_null() {
        return;
    }
    log_vprintf(context, event_code, *sequence_start, msg, va_0);
    *sequence_start = 0i32;
}

pub unsafe extern "C" fn dc_log_error(
    mut context: &dc_context_t,
    mut data1: libc::c_int,
    mut msg: *const libc::c_char,
    mut va_1: ...
) {
    log_vprintf(context, Event::ERROR, data1, msg, va_1);
}

pub unsafe extern "C" fn dc_log_warning(
    mut context: &dc_context_t,
    mut data1: libc::c_int,
    mut msg: *const libc::c_char,
    mut va_2: ...
) {
    log_vprintf(context, Event::WARNING, data1, msg, va_2);
}

pub unsafe extern "C" fn dc_log_info(
    mut context: &dc_context_t,
    mut data1: libc::c_int,
    mut msg: *const libc::c_char,
    mut va_3: ...
) {
    log_vprintf(context, Event::INFO, data1, msg, va_3);
}
