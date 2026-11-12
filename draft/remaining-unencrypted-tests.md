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
- `chat::chat_tests::test_forward_encrypted_to_unencrypted`
- `chat::chat_tests::test_send_delete_request_no_encryption`
- `chat::chat_tests::test_no_key_contacts_in_adhoc_chats`
- `chat::chat_tests::test_create_unencrypted_group_chat`
- `chat::chat_tests::test_no_avatar_in_adhoc_chats`
- `chat::chat_tests::test_classic_email_chat`
- `receive_imf::receive_imf_tests::test_dont_show_noreply_in_contacts_list`
- `receive_imf::receive_imf_tests::test_dont_show_tokens_in_contacts_list`
- `receive_imf::receive_imf_tests::test_dont_show_all_outgoing_msgs_in_self_chat` (This was a regression test for server-added `Bcc: <self>` header. But unencrypted headers are anyways ignored for encrypted messages, so the test passes even with the fix reverted)
- `mimefactory::mimefactory_tests::test_mdn_create_unencrypted`
- `mimefactory::mimefactory_tests::test_no_unencrypted_selfavatar`
- `mimefactory::mimefactory_tests::test_no_empty_to_header` (in encrypted messages, the outer To: header is always set to hidden-recipients, so this test wouldn't really test anything with encrypted messages)
- `mimefactory::mimefactory_tests::test_render_unencrypted_msg_basic`
- `mimefactory::mimefactory_tests::test_render_unencrypted_msg_with_attachment`

## Tests to adapt once unencrypted is removed

These receive an encrypted message whose signature can't be verified, which core treats like an unencrypted message. Once unencrypted messages are removed, they should check that such messages are ignored.

- `receive_imf::receive_imf_tests::test_forged_from_and_no_valid_signatures`
- `receive_imf::receive_imf_tests::test_wrong_from_name_and_no_valid_signatures`

## Securejoin tests that still depend on unencrypted messages; to be decided

- `securejoin::securejoin_tests::test_vc_request_encrypted_at_rest`: without `allow_unencrypted()`, the vc-request is trashed ("Fetched unencrypted message, ignoring").
- All other tests for legacy securejoin

# Tests migrated to encrypted ad-hoc groups

These tests used to receive unencrypted ad-hoc group messages. They now receive an encrypted message without a group ID, sent to multiple recipients, as an encrypting MUA would send it. But right now, these groups still have address-contacts as members, which we will remove.

In the future, we may just assign these messages to the 1:1 chat with the sender, but whatever we do, we'll need tests for core's behavior for these messages.

- `events::chatlist_events::test_chatlist_events::test_adhoc_group`
- `securejoin::securejoin_tests::test_adhoc_group_no_qr`
- `chat::chat_tests::test_sync_adhoc_grp`
- `receive_imf::receive_imf_tests::test_escaped_recipients`
- `receive_imf::receive_imf_tests::test_cc_to_contact`
- `receive_imf::receive_imf_tests::test_auto_accept_group_for_bots`
- `receive_imf::receive_imf_tests::test_adhoc_group_is_shown`
- `receive_imf::receive_imf_tests::test_adhoc_group_show_accepted_contact_accepted`
- `receive_imf::receive_imf_tests::test_adhoc_group_show_all`
