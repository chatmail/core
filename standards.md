# Standards used in chatmail core

Some of the standards chatmail is based on:

Tasks                            | Standards
-------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Transport                        | IMAP v4 ([RFC 3501][]), SMTP ([RFC 5321][]) and Internet Message Format (IMF, [RFC 5322][])
Proxy                            | SOCKS5 ([RFC 1928][])
Embedded media                   | MIME Document Series ([RFC 2045][], [RFC 2046][]), Content-Disposition Header ([RFC 2183][]), Multipart/Related ([RFC 2387][])
Text and Quote encoding          | Fixed, Flowed ([RFC 3676][])
Reactions                        | Reaction: Indicating Summary Reaction to a Message ([RFC 9078][])
Filename encoding                | Encoded Words ([RFC 2047][]), Encoded Word Extensions ([RFC 2231][])
Identify server folders          | IMAP LIST Extension ([RFC 6154][])
Push                             | IMAP IDLE ([RFC 2177][])
Quota                            | IMAP QUOTA extension ([RFC 2087][])
Seen status synchronization      | IMAP CONDSTORE extension ([RFC 7162][])
Client/server identification     | IMAP ID extension ([RFC 2971][])
Authorization                    | OAuth2 ([RFC 6749][])
End-to-end encryption            | [Autocrypt Level 1][], OpenPGP ([RFC 4880][]), Security Multiparts for MIME ([RFC 1847][]) and [“Mixed Up” Encryption repairing](https://tools.ietf.org/id/draft-dkg-openpgp-pgpmime-message-mangling-00.html)
Detect/prevent active attacks    | [securejoin][] protocols
Compare public keys              | [openpgp4fpr][] URI Scheme
Metadata minimization            | Header Protection for Cryptographically Protected Email ([RFC 9788][])
Configuration assistance         | [Autoconfigure](https://web.archive.org/web/20210402044801/https://developer.mozilla.org/en-US/docs/Mozilla/Thunderbird/Autoconfiguration) and [Autodiscover][]
Messenger functions              | [Chat-over-Email](https://github.com/chatmail/core/blob/main/spec.md#chat-mail-specification)
Detect mailing list              | List-Id ([RFC 2919][]) and Precedence ([RFC 3834][])
User and chat colors             | [XEP-0392][]: Consistent Color Generation
Send and receive system messages | Multipart/Report Media Type ([RFC 6522][])
Send and receive contact files   | vCard ([RFC 6350][])
Return receipts                  | Message Disposition Notification (MDN, [RFC 8098][]) using the Chat-Disposition-Notification-To header
Locations                        | KML ([Open Geospatial Consortium](http://www.opengeospatial.org/standards/kml/), [Google Dev](https://developers.google.com/kml/))

[Autocrypt Level 1]: https://autocrypt.org/level1.html
[securejoin]: https://securejoin.delta.chat/
[openpgp4fpr]: https://metacode.biz/openpgp/openpgp4fpr
[Autodiscover]: https://learn.microsoft.com/en-us/exchange/autodiscover-service-for-exchange-2013
[XEP-0392]: https://xmpp.org/extensions/xep-0392.html
[RFC 1847]: https://tools.ietf.org/html/rfc1847
[RFC 1928]: https://tools.ietf.org/html/rfc1928
[RFC 2045]: https://tools.ietf.org/html/rfc2045
[RFC 2046]: https://tools.ietf.org/html/rfc2046
[RFC 2047]: https://tools.ietf.org/html/rfc2047
[RFC 2087]: https://tools.ietf.org/html/rfc2087
[RFC 2177]: https://tools.ietf.org/html/rfc2177
[RFC 2183]: https://tools.ietf.org/html/rfc2183
[RFC 2231]: https://tools.ietf.org/html/rfc2231
[RFC 2387]: https://tools.ietf.org/html/rfc2387
[RFC 2919]: https://tools.ietf.org/html/rfc2919
[RFC 2971]: https://tools.ietf.org/html/rfc2971
[RFC 3501]: https://tools.ietf.org/html/rfc3501
[RFC 3676]: https://tools.ietf.org/html/rfc3676
[RFC 3834]: https://tools.ietf.org/html/rfc3834
[RFC 4880]: https://tools.ietf.org/html/rfc4880
[RFC 5321]: https://tools.ietf.org/html/rfc5321
[RFC 5322]: https://tools.ietf.org/html/rfc5322
[RFC 6154]: https://tools.ietf.org/html/rfc6154
[RFC 6350]: https://tools.ietf.org/html/rfc6350
[RFC 6522]: https://tools.ietf.org/html/rfc6522
[RFC 6749]: https://tools.ietf.org/html/rfc6749
[RFC 7162]: https://tools.ietf.org/html/rfc7162
[RFC 8098]: https://tools.ietf.org/html/rfc8098
[RFC 9078]: https://tools.ietf.org/html/rfc9078
[RFC 9788]: https://tools.ietf.org/html/rfc9788
