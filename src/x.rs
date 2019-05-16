use crate::dc_strbuilder::dc_strbuilder_t;
use crate::types::*;

pub use libc::{
    atoi, calloc, close, closedir, exit, fclose, fgets, fopen, fread, free, fseek, ftell, fwrite,
    gmtime, gmtime_r, localtime, localtime_r, malloc, memcmp, memcpy, memmove, memset, mkdir, open,
    opendir, printf, read, readdir, realloc, remove, sprintf, sscanf, strcat, strchr, strcmp,
    strcpy, strcspn, strlen, strncmp, strncpy, strrchr, strspn, strstr, strtol, system, time,
    tolower, write,
};

pub unsafe fn strdup(s: *const libc::c_char) -> *mut libc::c_char {
    let slen = libc::strlen(s);
    let result = libc::malloc(slen + 1);
    if result.is_null() {
        return std::ptr::null_mut();
    }

    libc::memcpy(result, s as *const _, slen + 1);
    result as *mut _
}

extern "C" {
    pub fn clock() -> libc::clock_t;
    pub fn qsort(
        __base: *mut libc::c_void,
        __nel: size_t,
        __width: size_t,
        __compar: Option<
            unsafe extern "C" fn(_: *const libc::c_void, _: *const libc::c_void) -> libc::c_int,
        >,
    );
    pub fn pow(_: libc::c_double, _: libc::c_double) -> libc::c_double;
    pub fn strndup(_: *const libc::c_char, _: libc::c_ulong) -> *mut libc::c_char;
    pub fn strftime(
        _: *mut libc::c_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const tm,
    ) -> size_t;
    pub fn atol(_: *const libc::c_char) -> libc::c_long;
    pub fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::std::ffi::VaList,
    ) -> libc::c_int;

    #[cfg(target_os = "macos")]
    pub fn __assert_rtn(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *const libc::c_char,
    ) -> !;
    #[cfg(not(target_os = "macos"))]
    fn __assert(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *const libc::c_char,
    ) -> !;

    #[cfg(windows)]
    pub(crate) fn snprintf(
        s: *mut libc::c_char,
        n: libc::size_t,
        format: *const libc::c_char,
        _: ...
    ) -> libc::c_int;

    // -- DC Methods

    pub fn dc_strbuilder_catf(_: *mut dc_strbuilder_t, format: *const libc::c_char, _: ...);
    pub fn dc_mprintf(format: *const libc::c_char, _: ...) -> *mut libc::c_char;
}

#[cfg(not(windows))]
pub(crate) use libc::snprintf;

#[cfg(not(target_os = "macos"))]
pub unsafe extern "C" fn __assert_rtn(
    a: *const libc::c_char,
    b: *const libc::c_char,
    c: libc::c_int,
    d: *const libc::c_char,
) -> ! {
    __assert(a, b, c, d)
}

#[cfg(not(target_os = "android"))]
pub use libc::atof;

#[cfg(target_os = "android")]
pub unsafe fn atof(nptr: *mut libc::c_char) -> libc::c_double {
    libc::strtod(nptr, std::ptr::null_mut())
}

pub(crate) unsafe fn strcasecmp(s1: *const libc::c_char, s2: *const libc::c_char) -> libc::c_int {
    let s1 = std::ffi::CStr::from_ptr(s1)
        .to_string_lossy()
        .to_lowercase();
    let s2 = std::ffi::CStr::from_ptr(s2)
        .to_string_lossy()
        .to_lowercase();
    if s1 == s2 {
        0
    } else {
        1
    }
}

pub(crate) unsafe fn strncasecmp(
    s1: *const libc::c_char,
    s2: *const libc::c_char,
    n: libc::size_t,
) -> libc::c_int {
    let s1 = std::ffi::CStr::from_ptr(s1)
        .to_string_lossy()
        .to_lowercase();
    let s2 = std::ffi::CStr::from_ptr(s2)
        .to_string_lossy()
        .to_lowercase();
    let m1 = std::cmp::min(n, s1.len());
    let m2 = std::cmp::min(n, s2.len());

    if s1[..m1] == s2[..m2] {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_atox() {
        unsafe {
            assert_eq!(atol(b"\x00" as *const u8 as *const libc::c_char), 0);
            assert_eq!(atoi(b"\x00" as *const u8 as *const libc::c_char), 0);
        }
    }
}
