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
- `tests::verified_chats::test_outgoing_mua_msg`
- `tests::verified_chats::test_reply`

## Securejoin tests that still depend on unencrypted messages; to be decided

- `securejoin::securejoin_tests::test_vc_request_encrypted_at_rest`: without `allow_unencrypted()`, the vc-request is trashed ("Fetched unencrypted message, ignoring").

# Tests migrated to encrypted ad-hoc groups

These tests used to receive unencrypted ad-hoc group messages. They now receive an encrypted message without a group ID, sent to multiple recipients, as an encrypting MUA would send it.

In the future, we may just assign these messages to the 1:1 chat with the sender, but whatever we do, we'll need tests for core's behavior for these messages.

- `events::chatlist_events::test_chatlist_events::test_adhoc_group`
- `securejoin::securejoin_tests::test_adhoc_group_no_qr`
