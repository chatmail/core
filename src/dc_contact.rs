use libc;

use crate::constants::Event;
use crate::dc_apeerstate::*;
use crate::dc_array::*;
use crate::dc_context::dc_context_t;
use crate::dc_context::*;
use crate::dc_e2ee::*;
use crate::dc_key::*;
use crate::dc_log::*;
use crate::dc_loginparam::*;
use crate::dc_sqlite3::*;
use crate::dc_stock::*;
use crate::dc_strbuilder::*;
use crate::dc_tools::*;
use crate::types::*;
use crate::x::*;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct dc_contact_t<'a> {
    pub magic: uint32_t,
    pub context: &'a dc_context_t,
    pub id: uint32_t,
    pub name: *mut libc::c_char,
    pub authname: *mut libc::c_char,
    pub addr: *mut libc::c_char,
    pub blocked: libc::c_int,
    pub origin: libc::c_int,
}

pub unsafe fn dc_marknoticed_contact(context: &dc_context_t, contact_id: uint32_t) {
    let mut stmt: *mut sqlite3_stmt = dc_sqlite3_prepare(
        context,
        &context.sql.clone().read().unwrap(),
        b"UPDATE msgs SET state=13 WHERE from_id=? AND state=10;\x00" as *const u8
            as *const libc::c_char,
    );
    sqlite3_bind_int(stmt, 1i32, contact_id as libc::c_int);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    ((*context).cb)(
        context,
        Event::MSGS_CHANGED,
        0i32 as uintptr_t,
        0i32 as uintptr_t,
    );
}

// handle contacts
// TODO should return bool /rtn
pub unsafe extern "C" fn dc_may_be_valid_addr(mut addr: *const libc::c_char) -> libc::c_int {
    if addr.is_null() {
        return 0i32;
    }
    let mut at: *const libc::c_char = strchr(addr, '@' as i32);
    if at.is_null() || (at.wrapping_offset_from(addr) as libc::c_long) < 1i32 as libc::c_long {
        return 0i32;
    }
    let mut dot: *const libc::c_char = strchr(at, '.' as i32);
    if dot.is_null()
        || (dot.wrapping_offset_from(at) as libc::c_long) < 2i32 as libc::c_long
        || *dot.offset(1isize) as libc::c_int == 0i32
        || *dot.offset(2isize) as libc::c_int == 0i32
    {
        return 0i32;
    }

    1
}

pub unsafe fn dc_lookup_contact_id_by_addr(
    mut context: &dc_context_t,
    mut addr: *const libc::c_char,
) -> uint32_t {
    let mut contact_id: libc::c_int = 0i32;
    let mut addr_normalized: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut addr_self: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    if !(addr.is_null() || *addr.offset(0isize) as libc::c_int == 0i32) {
        addr_normalized = dc_addr_normalize(addr);
        addr_self = dc_sqlite3_get_config(
            context,
            &context.sql.clone().read().unwrap(),
            b"configured_addr\x00" as *const u8 as *const libc::c_char,
            b"\x00" as *const u8 as *const libc::c_char,
        );
        if strcasecmp(addr_normalized, addr_self) == 0i32 {
            contact_id = 1i32
        } else {
            stmt =
                dc_sqlite3_prepare(
                    context,&context.sql.clone().read().unwrap(),
                                   b"SELECT id FROM contacts WHERE addr=?1 COLLATE NOCASE AND id>?2 AND origin>=?3 AND blocked=0;\x00"
                                       as *const u8 as *const libc::c_char);
            sqlite3_bind_text(
                stmt,
                1i32,
                addr_normalized as *const libc::c_char,
                -1i32,
                None,
            );
            sqlite3_bind_int(stmt, 2i32, 9i32);
            sqlite3_bind_int(stmt, 3i32, 0x100i32);
            if sqlite3_step(stmt) == 100i32 {
                contact_id = sqlite3_column_int(stmt, 0i32)
            }
        }
    }
    sqlite3_finalize(stmt);
    free(addr_normalized as *mut libc::c_void);
    free(addr_self as *mut libc::c_void);

    contact_id as uint32_t
}

pub unsafe fn dc_addr_normalize(mut addr: *const libc::c_char) -> *mut libc::c_char {
    let mut addr_normalized: *mut libc::c_char = dc_strdup(addr);
    dc_trim(addr_normalized);
    if strncmp(
        addr_normalized,
        b"mailto:\x00" as *const u8 as *const libc::c_char,
        7,
    ) == 0i32
    {
        let mut old: *mut libc::c_char = addr_normalized;
        addr_normalized = dc_strdup(&mut *old.offset(7isize));
        free(old as *mut libc::c_void);
        dc_trim(addr_normalized);
    }

    addr_normalized
}

pub unsafe fn dc_create_contact(
    mut context: &dc_context_t,
    mut name: *const libc::c_char,
    mut addr: *const libc::c_char,
) -> uint32_t {
    let mut contact_id: uint32_t = 0i32 as uint32_t;
    let mut sth_modified: libc::c_int = 0i32;
    let mut blocked: libc::c_int;
    if !(addr.is_null() || *addr.offset(0isize) as libc::c_int == 0i32) {
        contact_id = dc_add_or_lookup_contact(context, name, addr, 0x4000000i32, &mut sth_modified);
        blocked = dc_is_contact_blocked(context, contact_id);
        ((*context).cb)(
            context,
            Event::CONTACTS_CHANGED,
            (if sth_modified == 2i32 {
                contact_id
            } else {
                0i32 as libc::c_uint
            }) as uintptr_t,
            0i32 as uintptr_t,
        );
        if 0 != blocked {
            dc_block_contact(context, contact_id, 0i32);
        }
    }

    contact_id
}

pub unsafe fn dc_block_contact(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
    mut new_blocking: libc::c_int,
) {
    let mut current_block: u64;
    let mut send_event: libc::c_int = 0i32;
    let mut contact: *mut dc_contact_t = dc_contact_new(context);
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    if !(contact_id <= 9i32 as libc::c_uint) {
        if 0 != dc_contact_load_from_db(contact, &context.sql.clone().read().unwrap(), contact_id)
            && (*contact).blocked != new_blocking
        {
            stmt = dc_sqlite3_prepare(
                context,
                &context.sql.clone().read().unwrap(),
                b"UPDATE contacts SET blocked=? WHERE id=?;\x00" as *const u8
                    as *const libc::c_char,
            );
            sqlite3_bind_int(stmt, 1i32, new_blocking);
            sqlite3_bind_int(stmt, 2i32, contact_id as libc::c_int);
            if sqlite3_step(stmt) != 101i32 {
                current_block = 5249903830285462583;
            } else {
                sqlite3_finalize(stmt);
                stmt =
                    dc_sqlite3_prepare(
                        context,&context.sql.clone().read().unwrap(),
                                       b"UPDATE chats SET blocked=? WHERE type=? AND id IN (SELECT chat_id FROM chats_contacts WHERE contact_id=?);\x00"
                                           as *const u8 as
                                           *const libc::c_char);
                sqlite3_bind_int(stmt, 1i32, new_blocking);
                sqlite3_bind_int(stmt, 2i32, 100i32);
                sqlite3_bind_int(stmt, 3i32, contact_id as libc::c_int);
                if sqlite3_step(stmt) != 101i32 {
                    current_block = 5249903830285462583;
                } else {
                    dc_marknoticed_contact(context, contact_id);
                    send_event = 1i32;
                    current_block = 15652330335145281839;
                }
            }
        } else {
            current_block = 15652330335145281839;
        }
        match current_block {
            5249903830285462583 => {}
            _ => {
                if 0 != send_event {
                    ((*context).cb)(
                        context,
                        Event::CONTACTS_CHANGED,
                        0i32 as uintptr_t,
                        0i32 as uintptr_t,
                    );
                }
            }
        }
    }
    sqlite3_finalize(stmt);
    dc_contact_unref(contact);
}

/**
 * @class dc_contact_t
 *
 * An object representing a single contact in memory.
 * The contact object is not updated.
 * If you want an update, you have to recreate the object.
 *
 * The library makes sure
 * only to use names _authorized_ by the contact in `To:` or `Cc:`.
 * _Given-names _as "Daddy" or "Honey" are not used there.
 * For this purpose, internally, two names are tracked -
 * authorized-name and given-name.
 * By default, these names are equal,
 * but functions working with contact names
 * (eg. dc_contact_get_name(), dc_contact_get_display_name(),
 * dc_contact_get_name_n_addr(), dc_contact_get_first_name(),
 * dc_create_contact() or dc_add_address_book())
 * only affect the given-name.
 */
pub unsafe fn dc_contact_new<'a>(context: &'a dc_context_t) -> *mut dc_contact_t<'a> {
    let mut contact: *mut dc_contact_t;
    contact = calloc(1, ::std::mem::size_of::<dc_contact_t>()) as *mut dc_contact_t;
    if contact.is_null() {
        exit(19i32);
    }
    (*contact).magic = 0xc047ac7i32 as uint32_t;
    (*contact).context = context;

    contact
}

pub unsafe fn dc_contact_unref(contact: *mut dc_contact_t) {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return;
    }
    dc_contact_empty(contact);
    (*contact).magic = 0i32 as uint32_t;
    free(contact as *mut libc::c_void);
}

pub unsafe fn dc_contact_empty(mut contact: *mut dc_contact_t) {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return;
    }
    (*contact).id = 0i32 as uint32_t;
    free((*contact).name as *mut libc::c_void);
    (*contact).name = 0 as *mut libc::c_char;
    free((*contact).authname as *mut libc::c_void);
    (*contact).authname = 0 as *mut libc::c_char;
    free((*contact).addr as *mut libc::c_void);
    (*contact).addr = 0 as *mut libc::c_char;
    (*contact).origin = 0i32;
    (*contact).blocked = 0i32;
}

/* From: of incoming messages of unknown sender */
/* Cc: of incoming messages of unknown sender */
/* To: of incoming messages of unknown sender */
/* address scanned but not verified */
/* Reply-To: of incoming message of known sender */
/* Cc: of incoming message of known sender */
/* additional To:'s of incoming message of known sender */
/* a chat was manually created for this user, but no message yet sent */
/* message sent by us */
/* message sent by us */
/* message sent by us */
/* internal use */
/* address is in our address book */
/* set on Alice's side for contacts like Bob that have scanned the QR code offered by her. Only means the contact has once been established using the "securejoin" procedure in the past, getting the current key verification status requires calling dc_contact_is_verified() ! */
/* set on Bob's side for contacts scanned and verified from a QR code. Only means the contact has once been established using the "securejoin" procedure in the past, getting the current key verification status requires calling dc_contact_is_verified() ! */
/* contact added mannually by dc_create_contact(), this should be the largets origin as otherwise the user cannot modify the names */
/* contacts with at least this origin value are shown in the contact list */
/* contacts with at least this origin value are verified and known not to be spam */
/* contacts with at least this origin value start a new "normal" chat, defaults to off */
// TODO should return bool /rtn
pub unsafe fn dc_contact_load_from_db(
    contact: *mut dc_contact_t,
    sql: &dc_sqlite3_t,
    contact_id: uint32_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut success: libc::c_int = 0i32;
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    if !(contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint) {
        dc_contact_empty(contact);
        if contact_id == 1i32 as libc::c_uint {
            (*contact).id = contact_id;
            (*contact).name = dc_stock_str((*contact).context, 2i32);
            (*contact).addr = dc_sqlite3_get_config(
                (*contact).context,
                sql,
                b"configured_addr\x00" as *const u8 as *const libc::c_char,
                b"\x00" as *const u8 as *const libc::c_char,
            );
            current_block = 5143058163439228106;
        } else {
            stmt =
                dc_sqlite3_prepare(
                    (*contact).context,sql,
                                   b"SELECT c.name, c.addr, c.origin, c.blocked, c.authname  FROM contacts c  WHERE c.id=?;\x00"
                                       as *const u8 as *const libc::c_char);
            sqlite3_bind_int(stmt, 1i32, contact_id as libc::c_int);
            if sqlite3_step(stmt) != 100i32 {
                current_block = 12908855840294526070;
            } else {
                (*contact).id = contact_id;
                (*contact).name = dc_strdup(sqlite3_column_text(stmt, 0i32) as *mut libc::c_char);
                (*contact).addr = dc_strdup(sqlite3_column_text(stmt, 1i32) as *mut libc::c_char);
                (*contact).origin = sqlite3_column_int(stmt, 2i32);
                (*contact).blocked = sqlite3_column_int(stmt, 3i32);
                (*contact).authname =
                    dc_strdup(sqlite3_column_text(stmt, 4i32) as *mut libc::c_char);
                current_block = 5143058163439228106;
            }
        }
        match current_block {
            12908855840294526070 => {}
            _ => success = 1i32,
        }
    }
    sqlite3_finalize(stmt);

    success
}

// TODO should return bool /rtn
pub unsafe fn dc_is_contact_blocked(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
) -> libc::c_int {
    let mut is_blocked: libc::c_int = 0i32;
    let mut contact: *mut dc_contact_t = dc_contact_new(context);
    if 0 != dc_contact_load_from_db(contact, &context.sql.clone().read().unwrap(), contact_id) {
        if 0 != (*contact).blocked {
            is_blocked = 1i32
        }
    }
    dc_contact_unref(contact);

    is_blocked
}

/*can be NULL*/
pub unsafe fn dc_add_or_lookup_contact(
    mut context: &dc_context_t,
    mut name: *const libc::c_char,
    mut addr__: *const libc::c_char,
    mut origin: libc::c_int,
    mut sth_modified: *mut libc::c_int,
) -> uint32_t {
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    let mut row_id: uint32_t = 0i32 as uint32_t;
    let mut dummy: libc::c_int = 0i32;
    let mut addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut addr_self: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut row_name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut row_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut row_authname: *mut libc::c_char = 0 as *mut libc::c_char;
    if sth_modified.is_null() {
        sth_modified = &mut dummy
    }
    *sth_modified = 0i32;
    if !(addr__.is_null() || origin <= 0i32) {
        addr = dc_addr_normalize(addr__);
        addr_self = dc_sqlite3_get_config(
            context,
            &context.sql.clone().read().unwrap(),
            b"configured_addr\x00" as *const u8 as *const libc::c_char,
            b"\x00" as *const u8 as *const libc::c_char,
        );
        if strcasecmp(addr, addr_self) == 0i32 {
            row_id = 1i32 as uint32_t
        } else if 0 == dc_may_be_valid_addr(addr) {
            dc_log_warning(
                context,
                0i32,
                b"Bad address \"%s\" for contact \"%s\".\x00" as *const u8 as *const libc::c_char,
                addr,
                if !name.is_null() {
                    name
                } else {
                    b"<unset>\x00" as *const u8 as *const libc::c_char
                },
            );
        } else {
            stmt =
                dc_sqlite3_prepare(
                    context,&context.sql.clone().read().unwrap(),
                                   b"SELECT id, name, addr, origin, authname FROM contacts WHERE addr=? COLLATE NOCASE;\x00"
                                       as *const u8 as *const libc::c_char);
            sqlite3_bind_text(stmt, 1i32, addr as *const libc::c_char, -1i32, None);
            if sqlite3_step(stmt) == 100i32 {
                let mut row_origin: libc::c_int;
                let mut update_addr: libc::c_int = 0i32;
                let mut update_name: libc::c_int = 0i32;
                let mut update_authname: libc::c_int = 0i32;
                row_id = sqlite3_column_int(stmt, 0i32) as uint32_t;
                row_name = dc_strdup(sqlite3_column_text(stmt, 1i32) as *mut libc::c_char);
                row_addr = dc_strdup(sqlite3_column_text(stmt, 2i32) as *mut libc::c_char);
                row_origin = sqlite3_column_int(stmt, 3i32);
                row_authname = dc_strdup(sqlite3_column_text(stmt, 4i32) as *mut libc::c_char);
                sqlite3_finalize(stmt);
                stmt = 0 as *mut sqlite3_stmt;
                if !name.is_null() && 0 != *name.offset(0isize) as libc::c_int {
                    if 0 != *row_name.offset(0isize) {
                        if origin >= row_origin && strcmp(name, row_name) != 0i32 {
                            update_name = 1i32
                        }
                    } else {
                        update_name = 1i32
                    }
                    if origin == 0x10i32 && strcmp(name, row_authname) != 0i32 {
                        update_authname = 1i32
                    }
                }
                if origin >= row_origin && strcmp(addr, row_addr) != 0i32 {
                    update_addr = 1i32
                }
                if 0 != update_name
                    || 0 != update_authname
                    || 0 != update_addr
                    || origin > row_origin
                {
                    stmt = dc_sqlite3_prepare(
                        context,
                        &context.sql.clone().read().unwrap(),
                        b"UPDATE contacts SET name=?, addr=?, origin=?, authname=? WHERE id=?;\x00"
                            as *const u8 as *const libc::c_char,
                    );
                    sqlite3_bind_text(
                        stmt,
                        1i32,
                        if 0 != update_name { name } else { row_name },
                        -1i32,
                        None,
                    );
                    sqlite3_bind_text(
                        stmt,
                        2i32,
                        if 0 != update_addr { addr } else { row_addr },
                        -1i32,
                        None,
                    );
                    sqlite3_bind_int(
                        stmt,
                        3i32,
                        if origin > row_origin {
                            origin
                        } else {
                            row_origin
                        },
                    );
                    sqlite3_bind_text(
                        stmt,
                        4i32,
                        if 0 != update_authname {
                            name
                        } else {
                            row_authname
                        },
                        -1i32,
                        None,
                    );
                    sqlite3_bind_int(stmt, 5i32, row_id as libc::c_int);
                    sqlite3_step(stmt);
                    sqlite3_finalize(stmt);
                    stmt = 0 as *mut sqlite3_stmt;
                    if 0 != update_name {
                        stmt =
                            dc_sqlite3_prepare(
                                context,&context.sql.clone().read().unwrap(),
                                               b"UPDATE chats SET name=? WHERE type=? AND id IN(SELECT chat_id FROM chats_contacts WHERE contact_id=?);\x00"
                                                   as *const u8 as
                                                   *const libc::c_char);
                        sqlite3_bind_text(stmt, 1i32, name, -1i32, None);
                        sqlite3_bind_int(stmt, 2i32, 100i32);
                        sqlite3_bind_int(stmt, 3i32, row_id as libc::c_int);
                        sqlite3_step(stmt);
                    }
                    *sth_modified = 1i32
                }
            } else {
                sqlite3_finalize(stmt);
                stmt = dc_sqlite3_prepare(
                    context,
                    &context.sql.clone().read().unwrap(),
                    b"INSERT INTO contacts (name, addr, origin) VALUES(?, ?, ?);\x00" as *const u8
                        as *const libc::c_char,
                );
                sqlite3_bind_text(
                    stmt,
                    1i32,
                    if !name.is_null() {
                        name
                    } else {
                        b"\x00" as *const u8 as *const libc::c_char
                    },
                    -1i32,
                    None,
                );
                sqlite3_bind_text(stmt, 2i32, addr, -1i32, None);
                sqlite3_bind_int(stmt, 3i32, origin);
                if sqlite3_step(stmt) == 101i32 {
                    row_id = dc_sqlite3_get_rowid(
                        context,
                        &context.sql.clone().read().unwrap(),
                        b"contacts\x00" as *const u8 as *const libc::c_char,
                        b"addr\x00" as *const u8 as *const libc::c_char,
                        addr,
                    );
                    *sth_modified = 2i32
                } else {
                    dc_log_error(
                        context,
                        0i32,
                        b"Cannot add contact.\x00" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
    }
    free(addr as *mut libc::c_void);
    free(addr_self as *mut libc::c_void);
    free(row_addr as *mut libc::c_void);
    free(row_name as *mut libc::c_void);
    free(row_authname as *mut libc::c_void);
    sqlite3_finalize(stmt);

    row_id
}

pub unsafe fn dc_add_address_book(
    mut context: &dc_context_t,
    mut adr_book: *const libc::c_char,
) -> libc::c_int {
    let mut lines: *mut carray = 0 as *mut carray;
    let mut i: size_t;
    let mut iCnt: size_t;
    let mut sth_modified: libc::c_int = 0i32;
    let mut modify_cnt: libc::c_int = 0i32;
    if !(adr_book.is_null()) {
        lines = dc_split_into_lines(adr_book);
        if !lines.is_null() {
            iCnt = carray_count(lines) as size_t;
            i = 0i32 as size_t;
            while i.wrapping_add(1) < iCnt {
                let mut name: *mut libc::c_char =
                    carray_get(lines, i as libc::c_uint) as *mut libc::c_char;
                let mut addr: *mut libc::c_char =
                    carray_get(lines, i.wrapping_add(1) as libc::c_uint) as *mut libc::c_char;
                dc_normalize_name(name);
                dc_add_or_lookup_contact(context, name, addr, 0x80000i32, &mut sth_modified);
                if 0 != sth_modified {
                    modify_cnt += 1
                }
                i = (i as libc::c_ulong).wrapping_add(2i32 as libc::c_ulong) as size_t as size_t
            }
            if 0 != modify_cnt {
                ((*context).cb)(
                    context,
                    Event::CONTACTS_CHANGED,
                    0i32 as uintptr_t,
                    0i32 as uintptr_t,
                );
            }
        }
    }
    dc_free_splitted_lines(lines);

    modify_cnt
}

// Working with names
pub unsafe fn dc_normalize_name(mut full_name: *mut libc::c_char) {
    if full_name.is_null() {
        return;
    }
    dc_trim(full_name);
    let mut len: libc::c_int = strlen(full_name) as libc::c_int;
    if len > 0i32 {
        let mut firstchar: libc::c_char = *full_name.offset(0isize);
        let mut lastchar: libc::c_char = *full_name.offset((len - 1i32) as isize);
        if firstchar as libc::c_int == '\'' as i32 && lastchar as libc::c_int == '\'' as i32
            || firstchar as libc::c_int == '\"' as i32 && lastchar as libc::c_int == '\"' as i32
            || firstchar as libc::c_int == '<' as i32 && lastchar as libc::c_int == '>' as i32
        {
            *full_name.offset(0isize) = ' ' as i32 as libc::c_char;
            *full_name.offset((len - 1i32) as isize) = ' ' as i32 as libc::c_char
        }
    }
    let mut p1: *mut libc::c_char = strchr(full_name, ',' as i32);
    if !p1.is_null() {
        *p1 = 0i32 as libc::c_char;
        let mut last_name: *mut libc::c_char = dc_strdup(full_name);
        let mut first_name: *mut libc::c_char = dc_strdup(p1.offset(1isize));
        dc_trim(last_name);
        dc_trim(first_name);
        strcpy(full_name, first_name);
        strcat(full_name, b" \x00" as *const u8 as *const libc::c_char);
        strcat(full_name, last_name);
        free(last_name as *mut libc::c_void);
        free(first_name as *mut libc::c_void);
    } else {
        dc_trim(full_name);
    };
}

pub unsafe fn dc_get_contacts(
    mut context: &dc_context_t,
    mut listflags: uint32_t,
    mut query: *const libc::c_char,
) -> *mut dc_array_t {
    let mut current_block: u64;
    let mut self_addr: *mut libc::c_char;
    let mut self_name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut self_name2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut add_self: libc::c_int = 0i32;
    let mut ret: *mut dc_array_t = dc_array_new(100i32 as size_t);
    let mut s3strLikeCmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;

    self_addr = dc_sqlite3_get_config(
        context,
        &context.sql.clone().read().unwrap(),
        b"configured_addr\x00" as *const u8 as *const libc::c_char,
        b"\x00" as *const u8 as *const libc::c_char,
    );
    if 0 != listflags & 0x1i32 as libc::c_uint || !query.is_null() {
        s3strLikeCmd = sqlite3_mprintf(
            b"%%%s%%\x00" as *const u8 as *const libc::c_char,
            if !query.is_null() {
                query
            } else {
                b"\x00" as *const u8 as *const libc::c_char
            },
        );
        if s3strLikeCmd.is_null() {
            current_block = 7597307149762829253;
        } else {
            stmt =
                dc_sqlite3_prepare(
                    context,&context.sql.clone().read().unwrap(),
                                       b"SELECT c.id FROM contacts c LEFT JOIN acpeerstates ps ON c.addr=ps.addr  WHERE c.addr!=?1 AND c.id>?2 AND c.origin>=?3 AND c.blocked=0 AND (c.name LIKE ?4 OR c.addr LIKE ?5) AND (1=?6 OR LENGTH(ps.verified_key_fingerprint)!=0)  ORDER BY LOWER(c.name||c.addr),c.id;\x00"
                                           as *const u8 as
                                           *const libc::c_char);
            sqlite3_bind_text(stmt, 1i32, self_addr, -1i32, None);
            sqlite3_bind_int(stmt, 2i32, 9i32);
            sqlite3_bind_int(stmt, 3i32, 0x100i32);
            sqlite3_bind_text(stmt, 4i32, s3strLikeCmd, -1i32, None);
            sqlite3_bind_text(stmt, 5i32, s3strLikeCmd, -1i32, None);
            sqlite3_bind_int(
                stmt,
                6i32,
                if 0 != listflags & 0x1i32 as libc::c_uint {
                    0i32
                } else {
                    1i32
                },
            );
            self_name = dc_sqlite3_get_config(
                context,
                &context.sql.clone().read().unwrap(),
                b"displayname\x00" as *const u8 as *const libc::c_char,
                b"\x00" as *const u8 as *const libc::c_char,
            );
            self_name2 = dc_stock_str(context, 2i32);
            if query.is_null()
                || 0 != dc_str_contains(self_addr, query)
                || 0 != dc_str_contains(self_name, query)
                || 0 != dc_str_contains(self_name2, query)
            {
                add_self = 1i32
            }
            current_block = 15768484401365413375;
        }
    } else {
        stmt =
            dc_sqlite3_prepare(
                context,&context.sql.clone().read().unwrap(),
                                   b"SELECT id FROM contacts WHERE addr!=?1 AND id>?2 AND origin>=?3 AND blocked=0 ORDER BY LOWER(name||addr),id;\x00"
                                       as *const u8 as *const libc::c_char);
        sqlite3_bind_text(stmt, 1i32, self_addr, -1i32, None);
        sqlite3_bind_int(stmt, 2i32, 9i32);
        sqlite3_bind_int(stmt, 3i32, 0x100i32);
        add_self = 1i32;
        current_block = 15768484401365413375;
    }
    match current_block {
        7597307149762829253 => {}
        _ => {
            while sqlite3_step(stmt) == 100i32 {
                dc_array_add_id(ret, sqlite3_column_int(stmt, 0i32) as uint32_t);
            }
            if 0 != listflags & 0x2i32 as libc::c_uint && 0 != add_self {
                dc_array_add_id(ret, 1i32 as uint32_t);
            }
        }
    }

    sqlite3_finalize(stmt);
    sqlite3_free(s3strLikeCmd as *mut libc::c_void);
    free(self_addr as *mut libc::c_void);
    free(self_name as *mut libc::c_void);
    free(self_name2 as *mut libc::c_void);

    ret
}

pub unsafe fn dc_get_blocked_cnt(context: &dc_context_t) -> libc::c_int {
    let mut ret: libc::c_int = 0i32;
    let mut stmt: *mut sqlite3_stmt;

    stmt = dc_sqlite3_prepare(
        context,
        &context.sql.clone().read().unwrap(),
        b"SELECT COUNT(*) FROM contacts WHERE id>? AND blocked!=0\x00" as *const u8
            as *const libc::c_char,
    );
    sqlite3_bind_int(stmt, 1i32, 9i32);
    if !(sqlite3_step(stmt) != 100i32) {
        ret = sqlite3_column_int(stmt, 0i32)
    }

    sqlite3_finalize(stmt);
    ret
}

pub unsafe fn dc_get_blocked_contacts(mut context: &dc_context_t) -> *mut dc_array_t {
    let mut ret: *mut dc_array_t = dc_array_new(100i32 as size_t);
    let mut stmt: *mut sqlite3_stmt;

    stmt = dc_sqlite3_prepare(
        context,
        &context.sql.clone().read().unwrap(),
        b"SELECT id FROM contacts WHERE id>? AND blocked!=0 ORDER BY LOWER(name||addr),id;\x00"
            as *const u8 as *const libc::c_char,
    );
    sqlite3_bind_int(stmt, 1i32, 9i32);
    while sqlite3_step(stmt) == 100i32 {
        dc_array_add_id(ret, sqlite3_column_int(stmt, 0i32) as uint32_t);
    }

    sqlite3_finalize(stmt);
    ret
}

pub unsafe fn dc_get_contact_encrinfo(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
) -> *mut libc::c_char {
    let mut ret: dc_strbuilder_t;
    let mut loginparam: *mut dc_loginparam_t = dc_loginparam_new();
    let mut contact: *mut dc_contact_t = dc_contact_new(context);
    let mut peerstate: *mut dc_apeerstate_t = dc_apeerstate_new(context);
    let mut self_key: *mut dc_key_t = dc_key_new();
    let mut fingerprint_self: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fingerprint_other_verified: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fingerprint_other_unverified: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char;

    ret = dc_strbuilder_t {
        buf: 0 as *mut libc::c_char,
        allocated: 0,
        free: 0,
        eos: 0 as *mut libc::c_char,
    };
    dc_strbuilder_init(&mut ret, 0i32);
    if !(0 == dc_contact_load_from_db(contact, &context.sql.clone().read().unwrap(), contact_id)) {
        dc_apeerstate_load_by_addr(
            peerstate,
            &context.sql.clone().read().unwrap(),
            (*contact).addr,
        );
        dc_loginparam_read(
            context,
            loginparam,
            &context.sql.clone().read().unwrap(),
            b"configured_\x00" as *const u8 as *const libc::c_char,
        );
        dc_key_load_self_public(
            context,
            self_key,
            (*loginparam).addr,
            &context.sql.clone().read().unwrap(),
        );
        if !dc_apeerstate_peek_key(peerstate, 0i32).is_null() {
            p = dc_stock_str(
                context,
                if (*peerstate).prefer_encrypt == 1i32 {
                    34i32
                } else {
                    25i32
                },
            );
            dc_strbuilder_cat(&mut ret, p);
            free(p as *mut libc::c_void);
            if (*self_key).binary.is_null() {
                dc_ensure_secret_key_exists(context);
                dc_key_load_self_public(
                    context,
                    self_key,
                    (*loginparam).addr,
                    &context.sql.clone().read().unwrap(),
                );
            }
            dc_strbuilder_cat(&mut ret, b" \x00" as *const u8 as *const libc::c_char);
            p = dc_stock_str(context, 30i32);
            dc_strbuilder_cat(&mut ret, p);
            free(p as *mut libc::c_void);
            dc_strbuilder_cat(&mut ret, b":\x00" as *const u8 as *const libc::c_char);
            fingerprint_self = dc_key_get_formatted_fingerprint(context, self_key);
            fingerprint_other_verified =
                dc_key_get_formatted_fingerprint(context, dc_apeerstate_peek_key(peerstate, 2i32));
            fingerprint_other_unverified =
                dc_key_get_formatted_fingerprint(context, dc_apeerstate_peek_key(peerstate, 0i32));
            if strcmp((*loginparam).addr, (*peerstate).addr) < 0i32 {
                cat_fingerprint(
                    &mut ret,
                    (*loginparam).addr,
                    fingerprint_self,
                    0 as *const libc::c_char,
                );
                cat_fingerprint(
                    &mut ret,
                    (*peerstate).addr,
                    fingerprint_other_verified,
                    fingerprint_other_unverified,
                );
            } else {
                cat_fingerprint(
                    &mut ret,
                    (*peerstate).addr,
                    fingerprint_other_verified,
                    fingerprint_other_unverified,
                );
                cat_fingerprint(
                    &mut ret,
                    (*loginparam).addr,
                    fingerprint_self,
                    0 as *const libc::c_char,
                );
            }
        } else if 0 == (*loginparam).server_flags & 0x400i32
            && 0 == (*loginparam).server_flags & 0x40000i32
        {
            p = dc_stock_str(context, 27i32);
            dc_strbuilder_cat(&mut ret, p);
            free(p as *mut libc::c_void);
        } else {
            p = dc_stock_str(context, 28i32);
            dc_strbuilder_cat(&mut ret, p);
            free(p as *mut libc::c_void);
        }
    }

    dc_apeerstate_unref(peerstate);
    dc_contact_unref(contact);
    dc_loginparam_unref(loginparam);
    dc_key_unref(self_key);
    free(fingerprint_self as *mut libc::c_void);
    free(fingerprint_other_verified as *mut libc::c_void);
    free(fingerprint_other_unverified as *mut libc::c_void);

    ret.buf
}

unsafe fn cat_fingerprint(
    mut ret: *mut dc_strbuilder_t,
    mut addr: *const libc::c_char,
    mut fingerprint_verified: *const libc::c_char,
    mut fingerprint_unverified: *const libc::c_char,
) {
    dc_strbuilder_cat(ret, b"\n\n\x00" as *const u8 as *const libc::c_char);
    dc_strbuilder_cat(ret, addr);
    dc_strbuilder_cat(ret, b":\n\x00" as *const u8 as *const libc::c_char);
    dc_strbuilder_cat(
        ret,
        if !fingerprint_verified.is_null()
            && 0 != *fingerprint_verified.offset(0isize) as libc::c_int
        {
            fingerprint_verified
        } else {
            fingerprint_unverified
        },
    );
    if !fingerprint_verified.is_null()
        && 0 != *fingerprint_verified.offset(0isize) as libc::c_int
        && !fingerprint_unverified.is_null()
        && 0 != *fingerprint_unverified.offset(0isize) as libc::c_int
        && strcmp(fingerprint_verified, fingerprint_unverified) != 0i32
    {
        dc_strbuilder_cat(ret, b"\n\n\x00" as *const u8 as *const libc::c_char);
        dc_strbuilder_cat(ret, addr);
        dc_strbuilder_cat(
            ret,
            b" (alternative):\n\x00" as *const u8 as *const libc::c_char,
        );
        dc_strbuilder_cat(ret, fingerprint_unverified);
    };
}

// TODO should return bool /rtn
pub unsafe fn dc_delete_contact(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
) -> libc::c_int {
    let mut success: libc::c_int = 0i32;
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    if !contact_id <= 9i32 as libc::c_uint {
        stmt = dc_sqlite3_prepare(
            context,
            &context.sql.clone().read().unwrap(),
            b"SELECT COUNT(*) FROM chats_contacts WHERE contact_id=?;\x00" as *const u8
                as *const libc::c_char,
        );
        sqlite3_bind_int(stmt, 1i32, contact_id as libc::c_int);
        if !(sqlite3_step(stmt) != 100i32 || sqlite3_column_int(stmt, 0i32) >= 1i32) {
            sqlite3_finalize(stmt);
            stmt = dc_sqlite3_prepare(
                context,
                &context.sql.clone().read().unwrap(),
                b"SELECT COUNT(*) FROM msgs WHERE from_id=? OR to_id=?;\x00" as *const u8
                    as *const libc::c_char,
            );
            sqlite3_bind_int(stmt, 1i32, contact_id as libc::c_int);
            sqlite3_bind_int(stmt, 2i32, contact_id as libc::c_int);
            if !(sqlite3_step(stmt) != 100i32 || sqlite3_column_int(stmt, 0i32) >= 1i32) {
                sqlite3_finalize(stmt);
                stmt = dc_sqlite3_prepare(
                    context,
                    &context.sql.clone().read().unwrap(),
                    b"DELETE FROM contacts WHERE id=?;\x00" as *const u8 as *const libc::c_char,
                );
                sqlite3_bind_int(stmt, 1i32, contact_id as libc::c_int);
                if !(sqlite3_step(stmt) != 101i32) {
                    ((*context).cb)(
                        context,
                        Event::CONTACTS_CHANGED,
                        0i32 as uintptr_t,
                        0i32 as uintptr_t,
                    );
                    success = 1i32
                }
            }
        }
    }
    sqlite3_finalize(stmt);

    success
}

pub unsafe fn dc_get_contact(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
) -> *mut dc_contact_t {
    let mut ret: *mut dc_contact_t = dc_contact_new(context);
    if 0 == dc_contact_load_from_db(ret, &context.sql.clone().read().unwrap(), contact_id) {
        dc_contact_unref(ret);
        ret = 0 as *mut dc_contact_t
    }
    ret
}

pub unsafe fn dc_contact_get_id(mut contact: *const dc_contact_t) -> uint32_t {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return 0i32 as uint32_t;
    }
    (*contact).id
}

pub unsafe fn dc_contact_get_addr(mut contact: *const dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return dc_strdup(0 as *const libc::c_char);
    }
    dc_strdup((*contact).addr)
}

pub unsafe fn dc_contact_get_name(mut contact: *const dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return dc_strdup(0 as *const libc::c_char);
    }
    dc_strdup((*contact).name)
}

pub unsafe fn dc_contact_get_display_name(mut contact: *const dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return dc_strdup(0 as *const libc::c_char);
    }
    if !(*contact).name.is_null() && 0 != *(*contact).name.offset(0isize) as libc::c_int {
        return dc_strdup((*contact).name);
    }
    dc_strdup((*contact).addr)
}

pub unsafe fn dc_contact_get_name_n_addr(mut contact: *const dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return dc_strdup(0 as *const libc::c_char);
    }
    if !(*contact).name.is_null() && 0 != *(*contact).name.offset(0isize) as libc::c_int {
        return dc_mprintf(
            b"%s (%s)\x00" as *const u8 as *const libc::c_char,
            (*contact).name,
            (*contact).addr,
        );
    }
    dc_strdup((*contact).addr)
}

pub unsafe fn dc_contact_get_first_name(mut contact: *const dc_contact_t) -> *mut libc::c_char {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return dc_strdup(0 as *const libc::c_char);
    }
    if !(*contact).name.is_null() && 0 != *(*contact).name.offset(0isize) as libc::c_int {
        return dc_get_first_name((*contact).name);
    }
    dc_strdup((*contact).addr)
}

pub unsafe fn dc_get_first_name(mut full_name: *const libc::c_char) -> *mut libc::c_char {
    let mut first_name: *mut libc::c_char = dc_strdup(full_name);
    let mut p1: *mut libc::c_char = strchr(first_name, ' ' as i32);
    if !p1.is_null() {
        *p1 = 0i32 as libc::c_char;
        dc_rtrim(first_name);
        if *first_name.offset(0isize) as libc::c_int == 0i32 {
            free(first_name as *mut libc::c_void);
            first_name = dc_strdup(full_name)
        }
    }
    first_name
}

pub unsafe fn dc_contact_get_profile_image(mut contact: *const dc_contact_t) -> *mut libc::c_char {
    let mut selfavatar: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut image_abs: *mut libc::c_char = 0 as *mut libc::c_char;
    if !(contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint) {
        if (*contact).id == 1i32 as libc::c_uint {
            selfavatar = dc_get_config(
                (*contact).context,
                b"selfavatar\x00" as *const u8 as *const libc::c_char,
            );
            if !selfavatar.is_null() && 0 != *selfavatar.offset(0isize) as libc::c_int {
                image_abs = dc_strdup(selfavatar)
            }
        }
    }
    // TODO: else get image_abs from contact param
    free(selfavatar as *mut libc::c_void);
    image_abs
}

pub unsafe fn dc_contact_get_color(mut contact: *const dc_contact_t) -> uint32_t {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return 0i32 as uint32_t;
    }
    dc_str_to_color((*contact).addr) as uint32_t
}

pub unsafe fn dc_contact_is_blocked(mut contact: *const dc_contact_t) -> libc::c_int {
    if contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint {
        return 0i32;
    }
    (*contact).blocked
}

pub unsafe fn dc_contact_is_verified(mut contact: *mut dc_contact_t) -> libc::c_int {
    dc_contact_is_verified_ex(contact, 0 as *mut dc_apeerstate_t)
}

pub unsafe fn dc_contact_is_verified_ex<'a>(
    contact: *mut dc_contact_t<'a>,
    mut peerstate: *mut dc_apeerstate_t<'a>,
) -> libc::c_int {
    let mut current_block: u64;
    let mut contact_verified: libc::c_int = 0i32;
    let mut peerstate_to_delete: *mut dc_apeerstate_t = 0 as *mut dc_apeerstate_t;
    if !(contact.is_null() || (*contact).magic != 0xc047ac7i32 as libc::c_uint) {
        if (*contact).id == 1i32 as libc::c_uint {
            contact_verified = 2i32
        } else {
            // we're always sort of secured-verified as we could verify the key on this device any time with the key on this device
            if peerstate.is_null() {
                peerstate_to_delete = dc_apeerstate_new((*contact).context);
                if 0 == dc_apeerstate_load_by_addr(
                    peerstate_to_delete,
                    &mut (*contact).context.sql.clone().read().unwrap(),
                    (*contact).addr,
                ) {
                    current_block = 8667923638376902112;
                } else {
                    peerstate = peerstate_to_delete;
                    current_block = 13109137661213826276;
                }
            } else {
                current_block = 13109137661213826276;
            }
            match current_block {
                8667923638376902112 => {}
                _ => {
                    contact_verified = if !(*peerstate).verified_key.is_null() {
                        2i32
                    } else {
                        0i32
                    }
                }
            }
        }
    }
    dc_apeerstate_unref(peerstate_to_delete);
    contact_verified
}

// Working with e-mail-addresses
pub unsafe fn dc_addr_cmp(
    mut addr1: *const libc::c_char,
    mut addr2: *const libc::c_char,
) -> libc::c_int {
    let mut norm1: *mut libc::c_char = dc_addr_normalize(addr1);
    let mut norm2: *mut libc::c_char = dc_addr_normalize(addr2);
    let mut ret: libc::c_int = strcasecmp(addr1, addr2);
    free(norm1 as *mut libc::c_void);
    free(norm2 as *mut libc::c_void);
    ret
}

pub unsafe fn dc_addr_equals_self(
    mut context: &dc_context_t,
    mut addr: *const libc::c_char,
) -> libc::c_int {
    let mut ret: libc::c_int = 0i32;
    let mut normalized_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut self_addr: *mut libc::c_char = 0 as *mut libc::c_char;
    if !addr.is_null() {
        normalized_addr = dc_addr_normalize(addr);
        self_addr = dc_sqlite3_get_config(
            context,
            &context.sql.clone().read().unwrap(),
            b"configured_addr\x00" as *const u8 as *const libc::c_char,
            0 as *const libc::c_char,
        );
        if !self_addr.is_null() {
            ret = if strcasecmp(normalized_addr, self_addr) == 0i32 {
                1i32
            } else {
                0i32
            }
        }
    }
    free(self_addr as *mut libc::c_void);
    free(normalized_addr as *mut libc::c_void);
    ret
}

// TODO should return bool /rtn
pub unsafe fn dc_addr_equals_contact(
    mut context: &dc_context_t,
    mut addr: *const libc::c_char,
    mut contact_id: uint32_t,
) -> libc::c_int {
    let mut addr_are_equal: libc::c_int = 0i32;
    if !addr.is_null() {
        let mut contact: *mut dc_contact_t = dc_contact_new(context);
        if 0 != dc_contact_load_from_db(contact, &context.sql.clone().read().unwrap(), contact_id) {
            if !(*contact).addr.is_null() {
                let mut normalized_addr: *mut libc::c_char = dc_addr_normalize(addr);
                if strcasecmp((*contact).addr, normalized_addr) == 0i32 {
                    addr_are_equal = 1i32
                }
                free(normalized_addr as *mut libc::c_void);
            }
        }
        dc_contact_unref(contact);
    }
    addr_are_equal
}

// Context functions to work with contacts
pub unsafe fn dc_get_real_contact_cnt(mut context: &dc_context_t) -> size_t {
    let mut ret: size_t = 0i32 as size_t;
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    if !context.sql.clone().read().unwrap().cobj.is_null() {
        stmt = dc_sqlite3_prepare(
            context,
            &context.sql.clone().read().unwrap(),
            b"SELECT COUNT(*) FROM contacts WHERE id>?;\x00" as *const u8 as *const libc::c_char,
        );
        sqlite3_bind_int(stmt, 1i32, 9i32);
        if !(sqlite3_step(stmt) != 100i32) {
            ret = sqlite3_column_int(stmt, 0i32) as size_t
        }
    }
    sqlite3_finalize(stmt);
    ret
}

pub unsafe fn dc_get_contact_origin(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
    mut ret_blocked: *mut libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0i32;
    let mut dummy: libc::c_int = 0i32;
    if ret_blocked.is_null() {
        ret_blocked = &mut dummy
    }
    let mut contact: *mut dc_contact_t = dc_contact_new(context);
    *ret_blocked = 0i32;
    if !(0 == dc_contact_load_from_db(contact, &context.sql.clone().read().unwrap(), contact_id)) {
        /* we could optimize this by loading only the needed fields */
        if 0 != (*contact).blocked {
            *ret_blocked = 1i32
        } else {
            ret = (*contact).origin
        }
    }
    dc_contact_unref(contact);
    ret
}

// TODO should return bool /rtn
pub unsafe fn dc_real_contact_exists(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
) -> libc::c_int {
    let mut stmt: *mut sqlite3_stmt = 0 as *mut sqlite3_stmt;
    let mut ret: libc::c_int = 0i32;
    if !(context.sql.clone().read().unwrap().cobj.is_null() || contact_id <= 9i32 as libc::c_uint) {
        stmt = dc_sqlite3_prepare(
            context,
            &context.sql.clone().read().unwrap(),
            b"SELECT id FROM contacts WHERE id=?;\x00" as *const u8 as *const libc::c_char,
        );
        sqlite3_bind_int(stmt, 1i32, contact_id as libc::c_int);
        if sqlite3_step(stmt) == 100i32 {
            ret = 1i32
        }
    }
    sqlite3_finalize(stmt);
    ret
}

pub unsafe fn dc_scaleup_contact_origin(
    mut context: &dc_context_t,
    mut contact_id: uint32_t,
    mut origin: libc::c_int,
) {
    let mut stmt: *mut sqlite3_stmt = dc_sqlite3_prepare(
        context,
        &context.sql.clone().read().unwrap(),
        b"UPDATE contacts SET origin=? WHERE id=? AND origin<?;\x00" as *const u8
            as *const libc::c_char,
    );
    sqlite3_bind_int(stmt, 1i32, origin);
    sqlite3_bind_int(stmt, 2i32, contact_id as libc::c_int);
    sqlite3_bind_int(stmt, 3i32, origin);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}
