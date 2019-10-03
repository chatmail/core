use std::ptr;

use libc::free;
use quick_xml;
use quick_xml::events::{BytesEnd, BytesStart, BytesText};

use crate::constants::*;
use crate::context::Context;
use crate::dc_tools::*;
use crate::login_param::LoginParam;

use super::read_autoconf_file;
/* ******************************************************************************
 * Outlook's Autodiscover
 ******************************************************************************/
#[repr(C)]
struct outlk_autodiscover_t<'a> {
    pub in_0: &'a LoginParam,
    pub out: LoginParam,
    pub out_imap_set: libc::c_int,
    pub out_smtp_set: libc::c_int,
    pub tag_config: libc::c_int,
    pub config: [*mut libc::c_char; 6],
}

pub unsafe fn outlk_autodiscover(
    context: &Context,
    url__: &str,
    param_in: &LoginParam,
) -> Option<LoginParam> {
    let mut xml_raw: *mut libc::c_char = ptr::null_mut();
    let mut url = url__.strdup();
    let mut outlk_ad = outlk_autodiscover_t {
        in_0: param_in,
        out: LoginParam::new(),
        out_imap_set: 0,
        out_smtp_set: 0,
        tag_config: 0,
        config: [ptr::null_mut(); 6],
    };
    let ok_to_continue;
    let mut i = 0;
    loop {
        if i >= 10 {
            ok_to_continue = true;
            break;
        }
        libc::memset(
            &mut outlk_ad as *mut outlk_autodiscover_t as *mut libc::c_void,
            0,
            ::std::mem::size_of::<outlk_autodiscover_t>(),
        );
        xml_raw = read_autoconf_file(context, as_str(url));
        if xml_raw.is_null() {
            ok_to_continue = false;
            break;
        }

        let mut reader = quick_xml::Reader::from_str(as_str(xml_raw));
        reader.trim_text(true);

        let mut buf = Vec::new();

        loop {
            match reader.read_event(&mut buf) {
                Ok(quick_xml::events::Event::Start(ref e)) => {
                    outlk_autodiscover_starttag_cb(e, &mut outlk_ad)
                }
                Ok(quick_xml::events::Event::End(ref e)) => {
                    outlk_autodiscover_endtag_cb(e, &mut outlk_ad)
                }
                Ok(quick_xml::events::Event::Text(ref e)) => {
                    outlk_autodiscover_text_cb(e, &mut outlk_ad, &reader)
                }
                Err(e) => {
                    error!(
                        context,
                        "Configure xml: Error at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    );
                }
                Ok(quick_xml::events::Event::Eof) => break,
                _ => (),
            }
            buf.clear();
        }

        if !(!outlk_ad.config[5].is_null()
            && 0 != *outlk_ad.config[5usize].offset(0isize) as libc::c_int)
        {
            ok_to_continue = true;
            break;
        }
        free(url as *mut libc::c_void);
        url = dc_strdup(outlk_ad.config[5usize]);

        outlk_clean_config(&mut outlk_ad);
        free(xml_raw as *mut libc::c_void);
        xml_raw = ptr::null_mut();
        i += 1;
    }

    if ok_to_continue {
        if outlk_ad.out.mail_server.is_empty()
            || outlk_ad.out.mail_port == 0
            || outlk_ad.out.send_server.is_empty()
            || outlk_ad.out.send_port == 0
        {
            let r = outlk_ad.out.to_string();
            warn!(context, "Bad or incomplete autoconfig: {}", r,);
            free(url as *mut libc::c_void);
            free(xml_raw as *mut libc::c_void);
            outlk_clean_config(&mut outlk_ad);

            return None;
        }
    }
    free(url as *mut libc::c_void);
    free(xml_raw as *mut libc::c_void);
    outlk_clean_config(&mut outlk_ad);
    Some(outlk_ad.out)
}

unsafe fn outlk_clean_config(mut outlk_ad: *mut outlk_autodiscover_t) {
    for i in 0..6 {
        free((*outlk_ad).config[i] as *mut libc::c_void);
        (*outlk_ad).config[i] = ptr::null_mut();
    }
}

fn outlk_autodiscover_text_cb<B: std::io::BufRead>(
    event: &BytesText,
    outlk_ad: &mut outlk_autodiscover_t,
    reader: &quick_xml::Reader<B>,
) {
    let val = event.unescape_and_decode(reader).unwrap_or_default();

    unsafe {
        free(outlk_ad.config[outlk_ad.tag_config as usize].cast());
        outlk_ad.config[outlk_ad.tag_config as usize] = val.trim().strdup();
    }
}

unsafe fn outlk_autodiscover_endtag_cb(event: &BytesEnd, outlk_ad: &mut outlk_autodiscover_t) {
    let tag = String::from_utf8_lossy(event.name()).trim().to_lowercase();

    if tag == "protocol" {
        if !outlk_ad.config[1].is_null() {
            let port = dc_atoi_null_is_0(outlk_ad.config[3]);
            let ssl_on = (!outlk_ad.config[4].is_null()
                && strcasecmp(
                    outlk_ad.config[4],
                    b"on\x00" as *const u8 as *const libc::c_char,
                ) == 0) as libc::c_int;
            let ssl_off = (!outlk_ad.config[4].is_null()
                && strcasecmp(
                    outlk_ad.config[4],
                    b"off\x00" as *const u8 as *const libc::c_char,
                ) == 0) as libc::c_int;
            if strcasecmp(
                outlk_ad.config[1],
                b"imap\x00" as *const u8 as *const libc::c_char,
            ) == 0
                && outlk_ad.out_imap_set == 0
            {
                outlk_ad.out.mail_server = to_string(outlk_ad.config[2]);
                outlk_ad.out.mail_port = port;
                if 0 != ssl_on {
                    outlk_ad.out.server_flags |= DC_LP_IMAP_SOCKET_SSL as i32
                } else if 0 != ssl_off {
                    outlk_ad.out.server_flags |= DC_LP_IMAP_SOCKET_PLAIN as i32
                }
                outlk_ad.out_imap_set = 1
            } else if strcasecmp(
                outlk_ad.config[1usize],
                b"smtp\x00" as *const u8 as *const libc::c_char,
            ) == 0
                && outlk_ad.out_smtp_set == 0
            {
                outlk_ad.out.send_server = to_string(outlk_ad.config[2]);
                outlk_ad.out.send_port = port;
                if 0 != ssl_on {
                    outlk_ad.out.server_flags |= DC_LP_SMTP_SOCKET_SSL as i32
                } else if 0 != ssl_off {
                    outlk_ad.out.server_flags |= DC_LP_SMTP_SOCKET_PLAIN as i32
                }
                outlk_ad.out_smtp_set = 1
            }
        }
        outlk_clean_config(outlk_ad);
    }
    outlk_ad.tag_config = 0;
}

fn outlk_autodiscover_starttag_cb(event: &BytesStart, outlk_ad: &mut outlk_autodiscover_t) {
    let tag = String::from_utf8_lossy(event.name()).trim().to_lowercase();

    if tag == "protocol" {
        unsafe { outlk_clean_config(outlk_ad) };
    } else if tag == "type" {
        outlk_ad.tag_config = 1
    } else if tag == "server" {
        outlk_ad.tag_config = 2
    } else if tag == "port" {
        outlk_ad.tag_config = 3
    } else if tag == "ssl" {
        outlk_ad.tag_config = 4
    } else if tag == "redirecturl" {
        outlk_ad.tag_config = 5
    };
}
