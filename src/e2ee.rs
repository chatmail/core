//! End-to-end encryption support.

#[cfg(test)]
mod tests {
    #[test]
    fn test_mailmime_parse() {
        let plain = b"Chat-Disposition-Notification-To: hello@world.de
Chat-Group-ID: CovhGgau8M-
Chat-Group-Name: Delta Chat Dev
Subject: =?utf-8?Q?Chat=3A?= Delta Chat =?utf-8?Q?Dev=3A?= sidenote for
 =?utf-8?Q?all=3A?= rust core master ...
Content-Type: text/plain; charset=\"utf-8\"; protected-headers=\"v1\"
Content-Transfer-Encoding: quoted-printable

sidenote for all: things are trick atm recomm=
end not to try to run with desktop or ios unless you are ready to hunt bugs

-- =20
Sent with my Delta Chat Messenger: https://delta.chat";
        let mail = mailparse::parse_mail(plain).expect("failed to parse valid message");

        assert_eq!(mail.headers.len(), 6);
        assert!(
            mail.get_body().unwrap().starts_with(
                "sidenote for all: things are trick atm recommend not to try to run with desktop or ios unless you are ready to hunt bugs")
        );
    }
}
