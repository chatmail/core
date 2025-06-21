use chrono::TimeZone as _;

use super::*;

#[test]
fn test_vcard_thunderbird() {
    let contacts = parse_vcard(
        "BEGIN:VCARD
VERSION:4.0
FN:'Alice Mueller'
EMAIL;PREF=1:alice.mueller@posteo.de
UID:a8083264-ca47-4be7-98a8-8ec3db1447ca
END:VCARD
BEGIN:VCARD
VERSION:4.0
FN:'bobzzz@freenet.de'
EMAIL;PREF=1:bobzzz@freenet.de
UID:cac4fef4-6351-4854-bbe4-9b6df857eaed
END:VCARD
",
    );

    assert_eq!(contacts[0].addr, "alice.mueller@posteo.de".to_string());
    assert_eq!(contacts[0].authname, "Alice Mueller".to_string());
    assert_eq!(contacts[0].key, None);
    assert_eq!(contacts[0].profile_image, None);
    assert!(contacts[0].timestamp.is_err());

    assert_eq!(contacts[1].addr, "bobzzz@freenet.de".to_string());
    assert_eq!(contacts[1].authname, "".to_string());
    assert_eq!(contacts[1].key, None);
    assert_eq!(contacts[1].profile_image, None);
    assert!(contacts[1].timestamp.is_err());

    assert_eq!(contacts.len(), 2);
}

#[test]
fn test_vcard_simple_example() {
    let contacts = parse_vcard(
        "BEGIN:VCARD
VERSION:4.0
FN:Alice Wonderland
N:Wonderland;Alice;;;Ms.
GENDER:W
EMAIL;TYPE=work:alice@example.com
KEY;TYPE=PGP;ENCODING=b:[base64-data]
REV:20240418T184242Z

END:VCARD",
    );

    assert_eq!(contacts[0].addr, "alice@example.com".to_string());
    assert_eq!(contacts[0].authname, "Alice Wonderland".to_string());
    assert_eq!(contacts[0].key, Some("[base64-data]".to_string()));
    assert_eq!(contacts[0].profile_image, None);
    assert_eq!(*contacts[0].timestamp.as_ref().unwrap(), 1713465762);

    assert_eq!(contacts.len(), 1);
}

#[test]
fn test_vcard_with_trailing_newline() {
    let contacts = parse_vcard(
        "BEGIN:VCARD\r
VERSION:4.0\r
FN:Alice Wonderland\r
N:Wonderland;Alice;;;Ms.\r
GENDER:W\r
EMAIL;TYPE=work:alice@example.com\r
KEY;TYPE=PGP;ENCODING=b:[base64-data]\r
REV:20240418T184242Z\r
END:VCARD\r
\r",
    );

    assert_eq!(contacts[0].addr, "alice@example.com".to_string());
    assert_eq!(contacts[0].authname, "Alice Wonderland".to_string());
    assert_eq!(contacts[0].key, Some("[base64-data]".to_string()));
    assert_eq!(contacts[0].profile_image, None);
    assert_eq!(*contacts[0].timestamp.as_ref().unwrap(), 1713465762);

    assert_eq!(contacts.len(), 1);
}

#[test]
fn test_make_and_parse_vcard() {
    let contacts = [
        VcardContact {
            addr: "alice@example.org".to_string(),
            authname: "Alice Wonderland".to_string(),
            key: Some("[base64-data]".to_string()),
            profile_image: Some("image in Base64".to_string()),
            biography: Some("Hi, I'm Alice".to_string()),
            timestamp: Ok(1713465762),
        },
        VcardContact {
            addr: "bob@example.com".to_string(),
            authname: "".to_string(),
            key: None,
            profile_image: None,
            biography: None,
            timestamp: Ok(0),
        },
    ];
    let items = [
        "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:alice@example.org\r\n\
             FN:Alice Wonderland\r\n\
             KEY:data:application/pgp-keys;base64\\,[base64-data]\r\n\
             PHOTO:data:image/jpeg;base64\\,image in Base64\r\n\
             NOTE:Hi\\, I'm Alice\r\n\
             REV:20240418T184242Z\r\n\
             END:VCARD\r\n",
        "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:bob@example.com\r\n\
             FN:bob@example.com\r\n\
             REV:19700101T000000Z\r\n\
             END:VCARD\r\n",
    ];
    let mut expected = "".to_string();
    for len in 0..=contacts.len() {
        let contacts = &contacts[0..len];
        let vcard = make_vcard(contacts);
        if len > 0 {
            expected += items[len - 1];
        }
        assert_eq!(vcard, expected);
        let parsed = parse_vcard(&vcard);
        assert_eq!(parsed.len(), contacts.len());
        for i in 0..parsed.len() {
            assert_eq!(parsed[i].addr, contacts[i].addr);
            assert_eq!(parsed[i].authname, contacts[i].authname);
            assert_eq!(parsed[i].key, contacts[i].key);
            assert_eq!(parsed[i].profile_image, contacts[i].profile_image);
            assert_eq!(
                parsed[i].timestamp.as_ref().unwrap(),
                contacts[i].timestamp.as_ref().unwrap()
            );
        }
    }
}

#[test]
fn test_vcard_android() {
    let contacts = parse_vcard(
        "BEGIN:VCARD
VERSION:2.1
N:;Bob;;;
FN:Bob
TEL;CELL:+1-234-567-890
EMAIL;HOME:bob@example.org
END:VCARD
BEGIN:VCARD
VERSION:2.1
N:;Alice;;;
FN:Alice
EMAIL;HOME:alice@example.org
END:VCARD
",
    );

    assert_eq!(contacts[0].addr, "bob@example.org".to_string());
    assert_eq!(contacts[0].authname, "Bob".to_string());
    assert_eq!(contacts[0].key, None);
    assert_eq!(contacts[0].profile_image, None);

    assert_eq!(contacts[1].addr, "alice@example.org".to_string());
    assert_eq!(contacts[1].authname, "Alice".to_string());
    assert_eq!(contacts[1].key, None);
    assert_eq!(contacts[1].profile_image, None);

    assert_eq!(contacts.len(), 2);
}

#[test]
fn test_vcard_local_datetime() {
    let contacts = parse_vcard(
        "BEGIN:VCARD\n\
             VERSION:4.0\n\
             FN:Alice Wonderland\n\
             EMAIL;TYPE=work:alice@example.org\n\
             REV:20240418T184242\n\
             END:VCARD",
    );
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].addr, "alice@example.org".to_string());
    assert_eq!(contacts[0].authname, "Alice Wonderland".to_string());
    assert_eq!(
        *contacts[0].timestamp.as_ref().unwrap(),
        chrono::offset::Local
            .with_ymd_and_hms(2024, 4, 18, 18, 42, 42)
            .unwrap()
            .timestamp()
    );
}

#[test]
fn test_vcard_with_base64_avatar() {
    // This is not an actual base64-encoded avatar, it's just to test the parsing.
    // This one is Android-like.
    let vcard0 = "BEGIN:VCARD
VERSION:2.1
N:;Bob;;;
FN:Bob
EMAIL;HOME:bob@example.org
PHOTO;ENCODING=BASE64;JPEG:/9j/4AAQSkZJRgABAQAAAQABAAD/4gIoSUNDX1BST0ZJTEU
 AAQEAAAIYAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAA
 L8bRuAJYoZUYrI4ZY3VWwxw4Ay28AAGBISScmf/2Q==

END:VCARD
";
    // This one is DOS-like.
    let vcard1 = vcard0.replace('\n', "\r\n");
    for vcard in [vcard0, vcard1.as_str()] {
        let contacts = parse_vcard(vcard);
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].addr, "bob@example.org".to_string());
        assert_eq!(contacts[0].authname, "Bob".to_string());
        assert_eq!(contacts[0].key, None);
        assert_eq!(contacts[0].profile_image.as_deref().unwrap(), "/9j/4AAQSkZJRgABAQAAAQABAAD/4gIoSUNDX1BST0ZJTEUAAQEAAAIYAAAAAAQwAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAL8bRuAJYoZUYrI4ZY3VWwxw4Ay28AAGBISScmf/2Q==");
    }
}

#[test]
fn test_protonmail_vcard() {
    let contacts = parse_vcard(
        "BEGIN:VCARD
VERSION:4.0
FN;PREF=1:Alice Wonderland
UID:proton-web-03747582-328d-38dc-5ddd-000000000000
ITEM1.EMAIL;PREF=1:alice@example.org
ITEM1.KEY;PREF=1:data:application/pgp-keys;base64,aaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
ITEM1.KEY;PREF=2:data:application/pgp-keys;base64,bbbbbbbbbbbbbbbbbbbbbbbbb
 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ITEM1.X-PM-ENCRYPT:true
ITEM1.X-PM-SIGN:true
END:VCARD",
    );

    assert_eq!(contacts.len(), 1);
    assert_eq!(&contacts[0].addr, "alice@example.org");
    assert_eq!(&contacts[0].authname, "Alice Wonderland");
    assert_eq!(contacts[0].key.as_ref().unwrap(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(contacts[0].timestamp.is_err());
    assert_eq!(contacts[0].profile_image, None);
}

/// Proton at some point slightly changed the format of their vcards.
/// This also tests unescaped commas in PHOTO and KEY (old Delta Chat format).
#[test]
fn test_protonmail_vcard2() {
    let contacts = parse_vcard(
        r"BEGIN:VCARD
VERSION:4.0
FN;PREF=1:Alice
PHOTO;PREF=1:data:image/jpeg;base64,/9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Z
REV:Invalid Date
ITEM1.EMAIL;PREF=1:alice@example.org
KEY;PREF=1:data:application/pgp-keys;base64,xsaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==
UID:proton-web-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
END:VCARD",
    );

    assert_eq!(contacts.len(), 1);
    assert_eq!(&contacts[0].addr, "alice@example.org");
    assert_eq!(&contacts[0].authname, "Alice");
    assert_eq!(contacts[0].key.as_ref().unwrap(), "xsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==");
    assert!(contacts[0].timestamp.is_err());
    assert_eq!(contacts[0].profile_image.as_ref().unwrap(), "/9aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/Z");
}
