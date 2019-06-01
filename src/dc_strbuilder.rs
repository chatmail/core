use crate::x::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct dc_strbuilder_t {
    pub buf: *mut libc::c_char,
    pub allocated: libc::c_int,
    pub free: libc::c_int,
    pub eos: *mut libc::c_char,
}

pub unsafe fn dc_strbuilder_init(mut strbuilder: *mut dc_strbuilder_t, init_bytes: libc::c_int) {
    if strbuilder.is_null() {
        return;
    }
    (*strbuilder).allocated = if init_bytes > 128i32 {
        init_bytes
    } else {
        128i32
    };
    (*strbuilder).buf = malloc((*strbuilder).allocated as usize) as *mut libc::c_char;
    assert!(!(*strbuilder).buf.is_null());
    *(*strbuilder).buf.offset(0isize) = 0i32 as libc::c_char;
    (*strbuilder).free = (*strbuilder).allocated - 1i32;
    (*strbuilder).eos = (*strbuilder).buf;
}
pub unsafe fn dc_strbuilder_cat(
    mut strbuilder: *mut dc_strbuilder_t,
    text: *const libc::c_char,
) -> *mut libc::c_char {
    if strbuilder.is_null() || text.is_null() {
        return 0 as *mut libc::c_char;
    }
    let len: libc::c_int = strlen(text) as libc::c_int;
    if len > (*strbuilder).free {
        let add_bytes: libc::c_int = if len > (*strbuilder).allocated {
            len
        } else {
            (*strbuilder).allocated
        };
        let old_offset: libc::c_int =
            (*strbuilder).eos.wrapping_offset_from((*strbuilder).buf) as libc::c_int;
        (*strbuilder).allocated = (*strbuilder).allocated + add_bytes;
        (*strbuilder).buf = realloc(
            (*strbuilder).buf as *mut libc::c_void,
            ((*strbuilder).allocated + add_bytes) as usize,
        ) as *mut libc::c_char;
        assert!(!(*strbuilder).buf.is_null());
        (*strbuilder).free = (*strbuilder).free + add_bytes;
        (*strbuilder).eos = (*strbuilder).buf.offset(old_offset as isize)
    }
    let ret: *mut libc::c_char = (*strbuilder).eos;
    strcpy((*strbuilder).eos, text);
    (*strbuilder).eos = (*strbuilder).eos.offset(len as isize);
    (*strbuilder).free -= len;
    return ret;
}
pub unsafe fn dc_strbuilder_empty(mut strbuilder: *mut dc_strbuilder_t) {
    *(*strbuilder).buf.offset(0isize) = 0i32 as libc::c_char;
    (*strbuilder).free = (*strbuilder).allocated - 1i32;
    (*strbuilder).eos = (*strbuilder).buf;
}
