# Tests that were left untouched; to be removed once unencrypted is removed

These tests tested behavior that was specific to unencrypted mail,
and there was no point in migrating them.
I will remove them once we remove support for unencrypted.

- `message::message_tests::test_unencrypted_quote_encrypted_message`
- `contact::contact_tests::test_contact_freshness_address_contact`
- `contact::contact_tests::test_lookup_id_by_addr_recent`
- `contact::contact_tests::test_lookup_id_by_addr_recent_accepted`
- `mimeparser::mimeparser_tests::test_ms_exchange_mdn`
- `mimeparser::mimeparser_tests::test_receive_signed_only`
- `e2ee::tests::test_cannot_send_unencrypted_by_default`
- `e2ee::tests::test_chatmail_can_send_unencrypted`
- `tests::pre_messages::sending::test_unencrypted_gets_no_pre_message`
