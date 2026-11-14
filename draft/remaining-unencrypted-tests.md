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
- `receive_imf::receive_imf_tests::test_outgoing_classic_mail_creates_chat`
- `receive_imf::receive_imf_tests::test_bcc_not_a_group` (This was a regression test receiving a message where the `To` addr is the same as `From`, but we don't really look at `To` if the message is encrypted, so that this test passes even with the fix reverted)
- `receive_imf::receive_imf_tests::test_outgoing_undecryptable` (undecryptable messages are trashed, so the "multiple devices" device message and the other `decryption_error` code paths in `receive_imf.rs` are unreachable with `force_encryption`)
- `receive_imf::receive_imf_tests::test_unencrypted_doesnt_goto_self_chat`
- `receive_imf::receive_imf_tests::test_unencrypted_group_id_no_recipients`
- `receive_imf::receive_imf_tests::test_small_unencrypted_group`
- `receive_imf::receive_imf_tests::test_outgoing_unencrypted_chat_assignment`
- `receive_imf::receive_imf_tests::test_thunderbird_autocrypt_unencrypted`
- `receive_imf::receive_imf_tests::test_thunderbird_unsigned_with_unencrypted_subject`
- `receive_imf::receive_imf_tests::test_mua_user_adds_member`
- `receive_imf::receive_imf_tests::test_mua_user_adds_recipient_to_single_chat`
- `receive_imf::receive_imf_tests::test_mua_cant_remove`
- `receive_imf::receive_imf_tests::test_mua_can_add`
- `receive_imf::receive_imf_tests::test_mua_can_readd`
- `receive_imf::receive_imf_tests::test_github_mailing_list`
- `receive_imf::receive_imf_tests::test_classic_mailing_list`
- `receive_imf::receive_imf_tests::test_other_device_writes_to_mailinglist`
- `receive_imf::receive_imf_tests::test_block_mailing_list`
- `receive_imf::receive_imf_tests::test_mailing_list_decide_block_then_unblock`
- `receive_imf::receive_imf_tests::test_mailing_list_decide_not_now`
- `receive_imf::receive_imf_tests::test_mailing_list_decide_accept`
- `receive_imf::receive_imf_tests::test_mailing_list_multiple_names_in_subject`
- `receive_imf::receive_imf_tests::test_majordomo_mailing_list`
- `receive_imf::receive_imf_tests::test_mailchimp_mailing_list`
- `receive_imf::receive_imf_tests::test_dhl_mailing_list`
- `receive_imf::receive_imf_tests::test_dpd_mailing_list`
- `receive_imf::receive_imf_tests::test_xt_local_mailing_list`
- `receive_imf::receive_imf_tests::test_xing_mailing_list`
- `receive_imf::receive_imf_tests::test_ttline_mailing_list`
- `receive_imf::receive_imf_tests::test_mailing_list_with_mimepart_footer`
- `receive_imf::receive_imf_tests::test_mailing_list_with_mimepart_footer_signed`
- `receive_imf::receive_imf_tests::test_apply_mailinglist_changes_assigned_by_reply`
- `receive_imf::receive_imf_tests::test_mailing_list_chat_message`
- `receive_imf::receive_imf_tests::test_mailing_list_bot`
- `receive_imf::receive_imf_tests::test_ignore_footer_status_from_mailinglist`
- `receive_imf::receive_imf_tests::test_list_from`

## Tests to adapt once unencrypted is removed

These receive an encrypted message whose signature can't be verified, which core treats like an unencrypted message. Once unencrypted messages are removed, they should check that such messages are ignored.

TODO: Actually, these tests can be adapted now already by removing the allow_unencrypted() call and checking that these messages are ignored.

- `receive_imf::receive_imf_tests::test_forged_from_and_no_valid_signatures`
- `receive_imf::receive_imf_tests::test_wrong_from_name_and_no_valid_signatures`

## NDN tests; to be decided

Servers never encrypt NDNs (bounces), so these tests still receive unencrypted messages.

- `receive_imf::receive_imf_tests::test_parse_ndn_tiscali`
- `receive_imf::receive_imf_tests::test_parse_ndn_testrun`
- `receive_imf::receive_imf_tests::test_parse_ndn_testrun_2`
- `receive_imf::receive_imf_tests::test_parse_ndn_yahoo`
- `receive_imf::receive_imf_tests::test_parse_ndn_gmail`
- `receive_imf::receive_imf_tests::test_parse_ndn_gmx`
- `receive_imf::receive_imf_tests::test_parse_ndn_posteo`
- `receive_imf::receive_imf_tests::test_parse_ndn_with_attachment`
- `receive_imf::receive_imf_tests::test_parse_ndn_group_msg`
- `receive_imf::receive_imf_tests::test_concat_multiple_ndns`
- `receive_imf::receive_imf_tests::test_resend_after_ndn`
- `receive_imf::receive_imf_tests::test_parse_dsn_relayed`

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
