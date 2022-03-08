# Standards used in Delta Chat

Some of the standards Delta Chat is based on:

Tasks                            | Standards
---------------------------------|---------------------------------------------
Transport                        | IMAP v4 ([RFC 3501](https://tools.ietf.org/html/rfc3501)), SMTP ([RFC 5321](https://tools.ietf.org/html/rfc5321)) and Internet Message Format (IMF, [RFC 5322](https://tools.ietf.org/html/rfc5322))
Proxy                            | SOCKS5 ([RFC 1928](https://tools.ietf.org/html/rfc1928))
Embedded media                   | MIME Document Series ([RFC 2045](https://tools.ietf.org/html/rfc2045), [RFC 2046](https://tools.ietf.org/html/rfc2046)), Content-Disposition Header ([RFC 2183](https://tools.ietf.org/html/rfc2183)), Multipart/Related ([RFC 2387](https://tools.ietf.org/html/rfc2387))
Text and Quote encoding          | Fixed, Flowed ([RFC 3676](https://tools.ietf.org/html/rfc3676))
Filename encoding                | Encoded Words ([RFC 2047](https://tools.ietf.org/html/rfc2047)), Encoded Word Extensions ([RFC 2231](https://tools.ietf.org/html/rfc2231))
Identify server folders          | IMAP LIST Extension ([RFC 6154](https://tools.ietf.org/html/rfc6154))
Push                             | IMAP IDLE ([RFC 2177](https://tools.ietf.org/html/rfc2177))
Quota                            | IMAP QUOTA extension ([RFC 2087](https://tools.ietf.org/html/rfc2087))
Seen status synchronization      | IMAP CONDSTORE extension ([RFC 7162](https://tools.ietf.org/html/rfc7162))
Authorization                    | OAuth2 ([RFC 6749](https://tools.ietf.org/html/rfc6749))
End-to-end encryption            | [Autocrypt Level 1](https://autocrypt.org/level1.html), OpenPGP ([RFC 4880](https://tools.ietf.org/html/rfc4880)), Security Multiparts for MIME ([RFC 1847](https://tools.ietf.org/html/rfc1847)) and [“Mixed Up” Encryption repairing](https://tools.ietf.org/id/draft-dkg-openpgp-pgpmime-message-mangling-00.html)
Header encryption                | [Protected Headers for Cryptographic E-mail](https://datatracker.ietf.org/doc/draft-autocrypt-lamps-protected-headers/)
Configuration assistance         | [Autoconfigure](https://web.archive.org/web/20210402044801/https://developer.mozilla.org/en-US/docs/Mozilla/Thunderbird/Autoconfiguration) and [Autodiscover](https://technet.microsoft.com/library/bb124251(v=exchg.150).aspx)
Messenger functions              | [Chat-over-Email](https://github.com/deltachat/deltachat-core-rust/blob/master/spec.md#chat-mail-specification)
Detect mailing list              | List-Id ([RFC 2919](https://tools.ietf.org/html/rfc2919)) and Precedence ([RFC 3834](https://tools.ietf.org/html/rfc3834))
User and chat colors             | [XEP-0392](https://xmpp.org/extensions/xep-0392.html): Consistent Color Generation
Send and receive system messages | Multipart/Report Media Type ([RFC 6522](https://tools.ietf.org/html/rfc6522))
Return receipts                  | Message Disposition Notification (MDN, [RFC 8098](https://tools.ietf.org/html/rfc8098), [RFC 3503](https://tools.ietf.org/html/rfc3503)) using the Chat-Disposition-Notification-To header
Locations                        | KML ([Open Geospatial Consortium](http://www.opengeospatial.org/standards/kml/), [Google Dev](https://developers.google.com/kml/))

