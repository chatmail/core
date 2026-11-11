# Tests that were left untouched; to be removed once unencrypted is removed

These tests tested behavior that was specific to unencrypted mail,
and there was no point in migrating them.
I will remove them once we remove support for unencrypted.

- `message::message_tests::test_unencrypted_quote_encrypted_message`
- `contact::contact_tests::test_contact_freshness_address_contact`
- `contact::contact_tests::test_lookup_id_by_addr_recent`
- `contact::contact_tests::test_lookup_id_by_addr_recent_accepted`
