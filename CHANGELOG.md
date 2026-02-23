# Changelog

## [2.43.0] - 2026-02-17

### Features / Changes

- Group and broadcast channel descriptions ([#7829](https://github.com/chatmail/core/pull/7829)).

### Fixes

- Assign iroh gossip topic to pre-message when post-message is received.

### Miscellaneous Tasks

- Update fast-socks5 to version 1.0.
- cargo: Update keccak from 0.1.5 to 0.1.6.
- deps: Bump astral-sh/setup-uv from 7.1.6 to 7.3.0.

### Performance

- Use recv_direct() instead of recv() on the event channel.

### Refactor

- Enable `clippy::manual_is_variant_and`.

### Tests

- Fix flaky `test_transport_synchronization` ([#7850](https://github.com/chatmail/core/pull/7850)).

## [2.42.0] - 2026-02-10

### Fixes

- Set `mvbox_move` to '0' explicitly for existing chatmail profiles.
  It's needed to prevent device message about deprecated `mvbox_move` option from appearing in chatmail profiles.

### Features / Changes

- Do not scan not watched folders.

### Miscellaneous Tasks

- Update rPGP from 0.18.0 to 0.19.0.
- cargo: Bump quick-xml from 0.38.4 to 0.39.0.

### Tests

- Remove test_dont_show_emails.

### Other

- Fix typo in CHANGELOG for marknoticed_all_chats.

## [2.41.0] - 2026-02-06

### Features / Changes

- Do not require `ShowEmails` to be set to `All` for adding second relay.
- Use different strings for audio and video calls.

### Fixes

- Don't set download state to Failure if message is available on another Session's transport ([#7684](https://github.com/chatmail/core/pull/7684)).
- Make use of call stock strings.

### Miscellaneous Tasks

- cargo: Bump `time` from 0.3.37 to 0.3.47.

## [2.40.0] - 2026-02-04

### Features / Changes

- Receive_imf: Log reasoning for chat assignment.
- Use more fitting encryption info message.
- Send Intended Recipient Fingerprint subpackets.
- Trash messages with intended recipient fingerprints, but w/o our one included.
- Do not collect email addresses from messages after configuration.
- Add device message about legacy `mvbox_move`.
- Never create IMAP folders.
- Make summary for pre-messages look like summary for fully downloaded messages ([#7775](https://github.com/chatmail/core/pull/7775)).
- Don't call `BlobObject::create_and_deduplicate()` when forwarding message to the same account.
- Allow clients to specify whether a call has video initially or not ([#7740](https://github.com/chatmail/core/pull/7740)).
- Do not load more than one own key from the keychain.

### Fixes

- Cross-account forwarding of a message which `has_html()` ([#7791](https://github.com/chatmail/core/pull/7791)).
- Make self-contact a key-contact even if key isn't generated yet.
- `apply_group_changes()`: Check whether From is key-contact.
- Don't add SELF to unencrypted chat created from encrypted message ([#7661](https://github.com/chatmail/core/pull/7661)).
- Don't upscale images and test that image resolution isn't changed unnecessarily ([#7769](https://github.com/chatmail/core/pull/7769)).
- Restart i/o when there are new transports in a sync message ([#7640](https://github.com/chatmail/core/pull/7640)).
- `add_or_lookup_key_contacts*()`: Advance fingerprint_iter on invalid address.
- `receive_imf`: Look up key contact by intended recipient fingerprint ([#7661](https://github.com/chatmail/core/pull/7661)).
- Remove `Config::DeleteToTrash` and `Config::ConfiguredTrashFolder`.

### API-Changes

- jsonrpc(python): Process events forever by default.

### CI

- Make scripts/deny.sh test the locked version of dependencies.

### Refactor

- Remove unneeded dbg! statements ([#7776](https://github.com/chatmail/core/pull/7776)).
- Remove unused Context.is_inbox().
- Rename lookup_key_contacts_by_address_list() to lookup_key_contacts_fallback_to_chat().
- Mark `ProviderOptions` as `non_exhaustive`.

### Miscellaneous Tasks

- Update provider database.
- cargo: Update `bytes` from 1.11.0 to 1.11.1.
- cargo: Bump tokio from 1.48.0 to 1.49.0.
- cargo: Bump tokio-util from 0.7.17 to 0.7.18.
- cargo: Bump libc from 0.2.178 to 0.2.180.
- cargo: Bump quote from 1.0.42 to 1.0.44.
- cargo: Bump syn from 2.0.111 to 2.0.114.
- cargo: Bump human-panic from 2.0.4 to 2.0.6.
- cargo: Bump chrono from 0.4.42 to 0.4.43.
- cargo: Bump data-encoding from 2.9.0 to 2.10.0.
- cargo: Bump colorutils-rs from 0.7.5 to 0.7.6.
- Update provider database.
- cargo: Bump thiserror from 2.0.17 to 2.0.18.
- deps: Bump EmbarkStudios/cargo-deny-action from 2.0.14 to 2.0.15.
- Remove RUSTSEC-2026-0002 exception from deny.toml.
- cargo: Bump tokio-stream from 0.1.17 to 0.1.18.
- cargo: Bump toml from 0.9.10+spec-1.1.0 to 0.9.11+spec-1.1.0.
- cargo: Bump serde_json from 1.0.148 to 1.0.149.
- cargo: Bump uuid from 1.19.0 to 1.20.0.
- cargo: Bump rustls-pki-types from 1.13.2 to 1.14.0.
- cargo: Bump tracing-subscriber from 0.3.20 to 0.3.22.

### Tests

- 2nd device receives message via new primary transport.
- Make `test_dont_move_sync_msgs` less flaky.
- Encrypted incoming message goes to encrypted 1:1 chat even if references messages in ad-hoc group.
- Message in blocked chat arrives as InSeen.
- Set `mvbox_move` to 0 for test rust accounts.

## [2.39.0] - 2026-01-23

### CI

- Update Rust to 1.93.0.

### Documentation

- RELEASE.md: Push preparation commit to the main branch before tagging.
- RELEASE.md: Add section about dealing with failed releases.

### Fixes

- Forward message with file ([#7755](https://github.com/chatmail/core/pull/7755)).
- Do not additionally reduce the resolution of images that fit into the resolution-limit and are larger than the file-size-limit ([#7760](https://github.com/chatmail/core/pull/7760)).

### Miscellaneous Tasks

- Merge v2.38.0 into main branch.
- Cleanup deprecated functions/defines ([#7763](https://github.com/chatmail/core/pull/7763)).

## [2.38.0] - 2026-01-22

### API-Changes

- [**breaking**] Jsonrpc: remove `contacts` from `FullChat`. To migrate load contacts on demand via `get_contacts_by_ids` using `FullChat.contactIds` ([#7282](https://github.com/chatmail/core/pull/7282)).
- jsonrpc: Add run_until parameter for bots ([#7688](https://github.com/chatmail/core/pull/7688)).
- rust, jsonrpc: Add `get_message_read_receipt_count` method ([#7732](https://github.com/chatmail/core/pull/7732)).
- rust and jsonrpc: Marknoticed_all_chats method to mark all chats as noticed, including muted ones. ([#7709](https://github.com/chatmail/core/pull/7709)).
- Public re-export of Connectivity ([#7737](https://github.com/chatmail/core/pull/7737)).

### Documentation

- Fix chat types.
- Set_config_from_qr() configures context for "DCACCOUNT:" and "DCLOGIN:" QRs ([#7450](https://github.com/chatmail/core/pull/7450)).
- Fix formatting of `indoc!` link.

### Features / Changes

- Pre-messages / next version of download on demand ([#7371](https://github.com/chatmail/core/pull/7371)).
- Connectivity view: move quota up and combine with IMAP state. ([#7653](https://github.com/chatmail/core/pull/7653)).
- Execute sync message before checking for primary transport update.
- Disable partial search by contact address.
- Don't put text into post-message ([#7714](https://github.com/chatmail/core/pull/7714)).
- Don't scale up Origin of multiple and broadcast recipients when sending a message.
- pgp: Use preferred hash algorithm for signing instead of hardcoded SHA256.
- In teamprofiles, don't mark chat as read on outgoing message ([#7717](https://github.com/chatmail/core/pull/7717)).
- Send and apply MDNs to self ([#7005](https://github.com/chatmail/core/pull/7005))

### Fixes

- Do not show contact address in message info ([#7695](https://github.com/chatmail/core/pull/7695)).
- Take transport_id into account when marking messages with \Seen flags.
- Send bcc-self messages to all own relays ([#7656](https://github.com/chatmail/core/pull/7656)).
- Only emit TransportsModified if transports are really modified.
- Logging errors in deltachat-rpc-server during startup ([#7707](https://github.com/chatmail/core/pull/7707)).
- Use only lowercase letters for stats id ([#7700](https://github.com/chatmail/core/pull/7700)).
- Hide incoming broadcasts in `DC_GCL_FOR_FORWARDING` ([#7726](https://github.com/chatmail/core/pull/7726)).
- Do not resolve ICE server hostnames during IMAP loop.
- More reliable parsing of `dclogin:` links with ip address as host ([#7734](https://github.com/chatmail/core/pull/7734)).
- Don't remember old channel members in the database ([#7716](https://github.com/chatmail/core/pull/7716)).
- Make it possible to leave and immediately delete a chat ([#7744](https://github.com/chatmail/core/pull/7744)).
- Emit MsgsChanged instead of MsgsNoticed on self-MDN if chat still has fresh messages.
- Prevent possible infinite loop with invalid `smtp` row ([#7746](https://github.com/chatmail/core/pull/7746)).
- Sync broadcast subscribers list ([#7578](https://github.com/chatmail/core/pull/7578))

### Refactor

- Don't use `concat!` in sql statements ([#7720](https://github.com/chatmail/core/pull/7720)).

### Tests

- Port test_dont_move_sync_msgs to JSON-RPC ([#7676](https://github.com/chatmail/core/pull/7676)).
- rpc-client: Replace remaining print()s with `logging` ([#6082](https://github.com/chatmail/core/pull/6082)).

## [2.37.0] - 2026-01-08

### API-Changes

- JSON-RPC API `get_all_ui_config_keys` to get all "ui.*" config keys ([#7579](https://github.com/chatmail/core/pull/7579)).
- Add `who_can_call_me` config option.
- cffi api to create account manager with existing events channel to see events emitted during startup. `dc_event_channel_new`, `dc_event_channel_unref`, `dc_event_channel_get_event_emitter` and `dc_accounts_new_with_event_channel` ([#7609](https://github.com/chatmail/core/pull/7609)).

### Features / Changes

- Config option to skip seen synchronization ([#7694](https://github.com/chatmail/core/pull/7694)).
- More text instead of sender in channel summary.

### Fixes

- Do not rely on Secure-Join header to detect {vc,vg}-request.

### Documentation

- Update instructions to UI where to display the address.

### Miscellaneous Tasks

- cargo: bump rsa from 0.9.9 to 0.9.10.
- Update lru 0.12.3 to 0.12.5 and add RUSTSEC-2026-0002 exception.

### Refactor

- ffi: Replace implicit drop in cffi with explicit `drop(Arc::from_raw(var))` ([#7664](https://github.com/chatmail/core/pull/7664)).

### Tests

- Regression test for vc-request encrypted by the server.
- Test that channel summary does not have sender name.

## [2.36.0] - 2026-01-03

### CI

- Pin GitHub Action references.

### API-Changes

- Add transports event to FFI.

### Features / Changes

- Add core version to `receive_imf` failure message.
- Connectivity view: quota for all transports ([#7630](https://github.com/chatmail/core/pull/7630)).
- Send sync messages over SMTP and do not move them to mvbox.

### Fixes

- When accepting group, add members with `Origin::IncomingTo` and sort them down in the contact list (7592).
- Update fallback welcome message.
- `inner_configure`: Check Config::OnlyFetchMvbox before MvboxMove for multi-transport ([#7637](https://github.com/chatmail/core/pull/7637)).
- Reset options not available for chatmail on chatmail profiles.
- Don't send webxdc notification for `notify: "*"` when chat is muted ([#7658](https://github.com/chatmail/core/pull/7658)).

### Documentation

- `delete_chat()`: don't lie that messages aren't deleted from server.
- Remove references to removed `sentbox_watch` config.
- Update documentation for `TransportsModified` event.

### Tests

- Contact list after accepting group with unknown contacts ([#7592](https://github.com/chatmail/core/pull/7592)).
- Port test_import_export_online_all to JSON-RPC ([#7411](https://github.com/chatmail/core/pull/7411)).

### Refactor

- Turn `DC_VERSION_STR` into `&str`.
- ffi: Remove one pointer indirection for `dc_accounts_t`.

### Miscellaneous Tasks

- deps: Bump actions/download-artifact from 6 to 7.
- deps: Bump actions/upload-artifact from 5 to 6.
- deps: Bump astral-sh/setup-uv from 7.1.4 to 7.1.6.
- deps: Bump cachix/install-nix-action from 31.8.4 to 31.9.0.
- cargo: Bump serde_json from 1.0.145 to 1.0.147.
- cargo: Bump uuid from 1.18.1 to 1.19.0.
- cargo: Bump toml from 0.9.8 to 0.9.10+spec-1.1.0.
- cargo: Bump tempfile from 3.23.0 to 3.24.0.
- cargo: Bump libc from 0.2.177 to 0.2.178.
- cargo: Bump tracing from 0.1.41 to 0.1.44.
- cargo: Bump hyper-util from 0.1.18 to 0.1.19.
- cargo: Bump log from 0.4.28 to 0.4.29.
- cargo: Bump rustls-pki-types from 1.13.0 to 1.13.2.
- cargo: Bump criterion from 0.7.0 to 0.8.1.

## [2.35.0] - 2025-12-16

### API-Changes

- Add blob dir size to storage info ([#7605](https://github.com/chatmail/core/pull/7605)).

### Features / Changes

- Use `turn.delta.chat` as fallback TURN server ([#7382](https://github.com/chatmail/core/pull/7382)).
- Add ip addresses of known public chatmail relays from https://chatmail.at/relays to DNS cache ([#7607](https://github.com/chatmail/core/pull/7607)).
- Improve error messages on adding relays.
- Add transport addresses to IMAP URLs in message info.
- `lookup_host_with_cache()`: Don't return empty address list ([#7596](https://github.com/chatmail/core/pull/7596)).

### Fixes

- `get_chat_msgs_ex()`: Don't match on "S=" (Cmd) in param payload.
- Remove `SecurejoinWait` info message when received Alice's key ([#7585](https://github.com/chatmail/core/pull/7585)).
- Do not set normalized name for existing chats and contacts in a migration.
- Remove now redundant "used_account_settings" and "entered_account_settings" from `Context.get_info()` ([#7587](https://github.com/chatmail/core/pull/7587)).
- Don't use fallback servers if got TURN servers from IMAP METADATA.
- Use fallback ICE servers if server can't IMAP METADATA ([#7382](https://github.com/chatmail/core/pull/7382)).
- Add explicit limit for adding relays (5 at the moment) ([#7611](https://github.com/chatmail/core/pull/7611)).
- Take `transport_id` into account when using `imap` table.

### CI

- Update Rust to 1.92.0.

### Miscellaneous Tasks

- Apply Rust 1.92.0 clippy suggestions.

### Other

- Log entered login params and actual used params on configuration failure ([#7610](https://github.com/chatmail/core/pull/7610)).

## [2.34.0] - 2025-12-11

### API-Changes

- rpc-client: Accept `Account` for `Chat.{add,remove}_contact()`.
- rpc-client: Add `Chat.num_contacts()`.
- Forwarding messages to another profile ([#7491](https://github.com/chatmail/core/pull/7491)).

### Features / Changes

- Double ringing time to 120 seconds.
- Better logging for failing securejoin messages ([#7593](https://github.com/chatmail/core/pull/7593)).
- Add multi-transport information to `Context.get_info` ([#7583](https://github.com/chatmail/core/pull/7583))

### Fixes

- Multi-transport: all transports were shown as "inbox" in connectivity view, now they are shown by their hostname ([#7582](https://github.com/chatmail/core/pull/7582)).
- Multi-transport: Synchronize primary transport immediately after changing it.
- Use u64 instead of usize to calculate storage usage.
- Use u64 to represent the number of bytes in backup files.
- Use u64 to count the number of bytes sent/received over the network.
- Use logging macros instead of emitting event directly, so that it is also logged by tracing ([#7459](https://github.com/chatmail/core/pull/7459)).
- Let securejoin succeed even if the chat was deleted in the meantime ([#7594](https://github.com/chatmail/core/pull/7594)).

### Miscellaneous Tasks

- Add RUSTSEC-2025-0134 exception to deny.toml.

### Refactor

- Use u16 instead of usize to represent progress bar.
- Remove EncryptHelper.prefer_encrypt.
- Add params when forwarding message instead of removing unneeded ones.

### Tests

- Port test_synchronize_member_list_on_group_rejoin to JSON-RPC.
- Test setting up second device between core versions.

## [2.33.0] - 2025-12-05

### Features / Changes

- Case-insensitive search for non-ASCII chat and contact names ([#7477](https://github.com/chatmail/core/pull/7477)).

### Fixes

- Recognize all transport addresses as own addresses.

## [2.32.0] - 2025-12-04

Version bump to trigger publishing of npm prebuilds
that failed to be published for 2.31.0 due to not configured "trusted publishers".

### Features / Changes

- `lookup_or_create_adhoc_group()`: Add context to SQL errors ([#7554](https://github.com/chatmail/core/pull/7554)).

## [2.31.0] - 2025-12-04

### CI

- Update npm before publishing packages.

### Features / Changes

- Use v2 SEIPD when sending messages to self.

## [2.30.0] - 2025-12-04

### Features / Changes

- Disable SNI for STARTTLS ([#7499](https://github.com/chatmail/core/pull/7499)).
- Introduce cross-core testing along with improvements to test frameworking.
- Synchronize transports via sync messages.

### Fixes

- Fix shutdown shortly after call.

### API-Changes

- Add `TransportsModified` event (for tests).

### CI

- Use "trusted publishing" for NPM packages.

### Miscellaneous Tasks

- deps: Bump actions/checkout from 5 to 6.
- cargo: Bump syn from 2.0.110 to 2.0.111.
- deps: Bump astral-sh/setup-uv from 7.1.3 to 7.1.4.
- cargo: Bump sdp from 0.8.0 to 0.10.0.
- Remove two outdated todo comments ([#7550](https://github.com/chatmail/core/pull/7550)).

## [2.29.0] - 2025-12-01

### API-Changes

- deltachat-rpc-client: Add Message.exists().

### Features / Changes

- [**breaking**] Increase backup version from 3 to 4.
- Hide `To` header in encrypted messages.
- `deltachat_rpc_client.Rpc` accepts `rpc_server_path` for using a particular deltachat-rpc-server ([#7493](https://github.com/chatmail/core/pull/7493)).
- Don't send `Chat-Group-Avatar` header in unencrypted groups.
- Don't update `self-{avatar,status}` from received messages ([#7002](https://github.com/chatmail/core/pull/7002)).

### Fixes

- `CREATE INDEX imap_only_rfc724_mid ON imap(rfc724_mid)` ([#7490](https://github.com/chatmail/core/pull/7490)).
- Use the same webxdc ratelimit for all email servers.
- Handle the case when account does not exist in `get_existing_msg_ids()`.
- Don't send self-avatar in unencrypted messages ([#7136](https://github.com/chatmail/core/pull/7136)).
- Do not configure folders during transport configuration.
- Upload sync messages only with the primary transport.
- Do not use deprecated ConfiguredProvider in get_configured_provider.

### Build system

- Make scripts for remote testing usable.
- Increase minimum supported Python version to 3.10.
- Use SPDX license expression in Python package metadata.

### CI

- Set timeout-minutes for all jobs in ci.yaml workflow.
- Do not install Python manually to bulid RPC server wheels.
- Do not build fake RPC server source packages.
- Build Python wheels in separate jobs.

### Refactor

- [**breaking**] Remove some unneeded stock strings ([#7496](https://github.com/chatmail/core/pull/7496)).
- Strike events in rpc-client request handling, get result from queue.
- Use ConfiguredProvider config directly when loading legacy settings.
- Remove update_icons and disable_server_delete migrations.
- Use `SYMMETRIC_KEY_ALGORITHM` constant in `symm_encrypt_message()`.
- Make signing key non-optional for `pk_encrypt`.

### Tests

- `test_remove_member_bcc`: Test unencrypted group as it was initially.

### Miscellaneous Tasks

- deps: Bump cachix/install-nix-action from 31.8.1 to 31.8.4.
- cargo: Bump hyper from 1.7.0 to 1.8.1.
- cargo: Bump human-panic from 2.0.3 to 2.0.4.
- cargo: Bump hyper-util from 0.1.17 to 0.1.18.
- cargo: Bump rusqlite from 0.36.0 to 0.37.0.
- cargo: Bump tokio-util from 0.7.16 to 0.7.17.
- cargo: Bump toml from 0.9.7 to 0.9.8.
- cargo: Bump proptest from 1.8.0 to 1.9.0.
- cargo: Bump parking_lot from 0.12.4 to 0.12.5.
- cargo: Bump syn from 2.0.106 to 2.0.110.
- cargo: Bump quick-xml from 0.38.3 to 0.38.4.
- cargo: Bump rustls-pki-types from 1.12.0 to 1.13.0.
- cargo: Bump nu-ansi-term from 0.50.1 to 0.50.3.
- cargo: Bump sanitize-filename from 0.5.0 to 0.6.0.
- cargo: Bump quote from 1.0.41 to 1.0.42.
- cargo: Bump libc from 0.2.176 to 0.2.177.
- cargo: Bump bytes from 1.10.1 to 1.11.0.
- cargo: Bump image from 0.25.8 to 0.25.9.
- cargo: Bump rand from 0.9.0 to 0.9.2 ([#7501](https://github.com/chatmail/core/pull/7501)).
- cargo: Bump tokio from 1.45.1 to 1.48.0.

## [2.28.0] - 2025-11-23

### API-Changes

- New API `get_existing_msg_ids()` to check if the messages with given IDs exist.
- Add API to get storage usage information. (JSON-RPC method: `get_storage_usage_report_string`) ([#7486](https://github.com/chatmail/core/pull/7486)).

### Features / Changes

- Experimentaly allow adding second transport.
  There is no synchronization yet, so UIs should not allow the user to change the address manually and only expose the ability to add transports if `bcc_self` is disabled.
- Default `bcc_self` to 0 for all new accounts.
- Rephrase "Establishing end-to-end encryption" -> "Establishing connection".
- Stock string for joining a channel ([#7480](https://github.com/chatmail/core/pull/7480)).

### Fixes

- Limit the range of `Date` to up to 6 days in the past.
- `ContactId::set_name_ex()`: Emit ContactsChanged when transaction is completed.
- Set SQLite busy timeout to 1 minute on iOS.
- Sort system messages to the bottom of the chat.
- Assign outgoing self-sent unencrypted messages to ad-hoc groups with only SELF ([#7409](https://github.com/chatmail/core/pull/7409)).
- Add missing stock strings.
- Look up or create ad-hoc group if there are duplicate addresses in "To".

### Documentation

- Add missing RFC 9788, link 'Header Protection for Cryptographically Protected Email' as other RFC.
- Remove unsupported RFC 3503 (`$MDNSent` flag) from the list of standards.
- Mark database encryption support as deprecated ([#7403](https://github.com/chatmail/core/pull/7403)).

### Build system

- Increase Minimum Supported Rust Version to 1.88.0.
- Update rPGP from 0.17.0 to 0.18.0.
- nix: Update `fenix` and use it for all Rust builds.

### CI

- Do not use --encoding option for rst-lint.

### Refactor

- Use `HashMap::extract_if()` stabilized in Rust 1.88.0.
- Remove some easy to remove unwrap() calls.

### Tests

- Contact shalln't be verified by another having unknown verifier.

## [2.27.0] - 2025-11-16

### API-Changes

- Add APIs to stop background fetch.
- [**breaking**]: rename JSON-RPC method accounts_background_fetch() into background_fetch()
- rpc-client: Add APIs for background fetch.
- rpc-client: Add Account.wait_for_msg().
- Deprecate deletion timer string for '1 Minute'.

### Features / Changes

- Implement RFC 9788 (Header Protection for Cryptographically Protected Email) ([#7130](https://github.com/chatmail/core/pull/7130)).
- Tweak initial info-message for unencrypted chats ([#7427](https://github.com/chatmail/core/pull/7427)).
- Add Contact::get_or_gen_color. Use it in CFFI and JSON-RPC to avoid gray self-color ([#7374](https://github.com/chatmail/core/pull/7374)).
- [**breaking**] Withdraw broadcast invites. Add Qr::WithdrawJoinBroadcast and Qr::ReviveJoinBroadcast QR code types. ([#7439](https://github.com/chatmail/core/pull/7439)).

### Fixes

- Set `get_max_smtp_rcpt_to` for chatmail to the actual limit of 1000 instead of unlimited. ([#7432](https://github.com/chatmail/core/pull/7432)).
- Always set bcc_self on backup import/export.
- Escape connectivity HTML.
- Send webm as file, it is not supported by all UI.

### Build system

- nix: Exclude CONTRIBUTING.md from the source files.

### Refactor

- Use wait_for_incoming_msg() in more tests.

### Tests

- Fix flaky test_send_receive_locations.
- Port folder-related CFFI tests to JSON-RPC.
- HP-Outer headers are added to messages with standard Header Protection ([#7130](https://github.com/chatmail/core/pull/7130)).
- rpc-client: Test_qr_securejoin_broadcast: Wait for incoming message before getting chatlist ([#7442](https://github.com/chatmail/core/pull/7442)).
- Add pytest fixture for account manager.
- Test background_fetch() and stop_background_fetch().

## [2.26.0] - 2025-11-11

### API-Changes

- [**breaking**] JSON-RPC: `chat_type` now contains a variant of a string enum/union. Affected places: `FullChat.chat_type`, `BasicChat.chat_type`, `ChatListItemFetchResult::ChatListItem.chat_type`, `Event:: SecurejoinInviterProgress.chat_type` and `MessageSearchResult.chat_type` ([#7285](https://github.com/chatmail/core/pull/7285))

### Features / Changes

- Error toast for "Not creating securejoin QR for old broadcast".

### Fixes

- `is_encrypted()` should be true for Saved Messages chat so messages there are editable.
- Do not return an error from `receive_imf` if we fail to add a member because we are not in chat.
- Do not add QR inviter to groups immediately.
- Do not ignore I/O errors in `BlobObject::store_from_base64`.

### Miscellaneous Tasks

- Rustfmt.

### Refactor

- imap: Move resync request from Context to Imap.
- Replace imap:: calls in migration 73 with SQL queries.
- Remove unused imports.

### Documentation

- Readme: update language binding section to avoid usage of cffi in new projects ([#7380](https://github.com/chatmail/core/pull/7380)).
- Fix Context::set_stock_translation reference.

### Tests

- Test editing saved messages.
- Remove ThreadPoolExecutor from test_wait_next_messages.
- Move test_two_group_securejoins from receive_imf to securejoin module.
- At the end of securejoin Bob has two members in a group chat.
- Bob has 0 members in the chat until securejoin finishes.
- Do not add QR inviter to groups right after scanning the code.

## [2.25.0] - 2025-11-05

### Features / Changes

- Put self-name into group invite codes ([#7398](https://github.com/chatmail/core/pull/7398)).
- Slightly nicer and shorter QR and invite codes ([#7390](https://github.com/chatmail/core/pull/7390))

### Fixes

- Add device message instead of partial message when receive_imf fails. This fixes a rare bug where the IMAP loop got stuck.
- Add info message if user tries to create a QR code for deprecated channel ([#7399](https://github.com/chatmail/core/pull/7399)).

### Miscellaneous Tasks

- deps: Bump actions/upload-artifact from 4 to 5.
- deps: Bump actions/download-artifact from 5 to 6.
- deps: Bump astral-sh/setup-uv from 7.1.0 to 7.1.2.

### Refactor

- sql: Do not expose rusqlite Error type in query_map methods.

## [2.24.0] - 2025-11-03

***Note that in v2.24.0, the IMAP loop can get stuck in rare circumstances;
use v2.23.0 or v2.25.0 instead.***

### Documentation

- Comment why spaced en dash is used to separate message Subject from text.

### Features / Changes

- [**breaking**] QR codes and symmetric encryption for broadcast channels ([#7268](https://github.com/chatmail/core/pull/7268)).
  - A new QR type AskJoinBroadcast; cloning a broadcast
    channel is no longer possible; manually adding a member to a broadcast
    channel is no longer possible (the only way to join a channel is scanning a QR code or clicking a link)

### Refactor

- Split "transport" module out of "login_param".

## [2.23.0] - 2025-11-01

### API-Changes

- Make `dc_chat_is_protected` always return 0.
- [**breaking**] Remove public APIs to check if the chat is protected.
- [**breaking**] Remove APIs to create protected chats.
- [**breaking**] Remove Chat.is_protected().
- deltachat-rpc-client: Add Account.add_transport_from_qr() API.
- JSON-RPC: add `get_push_state` to check push notification state ([#7356](https://github.com/chatmail/core/pull/7356)).
- JSON-RPC: remove unused TypeScript constants ([#7355](https://github.com/chatmail/core/pull/7355)).
- Remove `Config::SentboxWatch` ([#7178](https://github.com/chatmail/core/pull/7178)).
- Remove `Config::ConfiguredSentboxFolder` and everything related.

### Build system

- Ignore configuration for the zed editor ([#7322](https://github.com/chatmail/core/pull/7322)).
- nix: Fix build of deltachat-rpc-server-x86_64-darwin.
- Update rand to 0.9.
- Do not install `pdbpp` in the test environment for CFFI Python bindings.
- Migrate from tokio-tar to astral-tokio-tar.
- deps: Bump actions/setup-node from 5 to 6.
- deps: Bump cachix/install-nix-action from 31.8.0 to 31.8.1.
- Fix Rust 1.91.0 lint for derivable Default.

### CI

- Pin GitHub action `astral-sh/setup-uv`.
- Set 7 days cooldown on Dependabot updates.
- Update Rust to 1.91.0.

### Documentation

- Document Autocrypt-Gossip `_verified` attribute.

### Features/Changes

Metadata reduction:
- Protect Autocrypt header.
- Anonymize OpenPGP recipients (temorarily disabled due to interoperability problems, see <https://github.com/chatmail/core/issues/7384>).
- Protect the `Date` header.

Onboarding improvements:
- Allow plain domain in `dcaccount:` scheme.
- Do not resolve MX records during configuration.

Preparation for multi-transport:
- Move the messages only from INBOX and Spam folders.
- deltachat-rpc-client: Support multiple transports in resetup_account().

Various other changes:
- Opt-in weekly sending of statistics ([#6851](https://github.com/chatmail/core/pull/6851))
- Synchronize encrypted groups creation across devices ([#7001](https://github.com/chatmail/core/pull/7001)).
- Do not send Autocrypt in MDNs.
- Do not run SecureJoin if we are already in the group.
- Show if proxy is enabled in connectivity view ([#7359](https://github.com/chatmail/core/pull/7359)).

### Fixes

- Don't ignore QR token timestamp from sync messages.
- Do not allow sync item timestamps to be in the future.
- jsonrpc: Fix `ChatListItem::is_self_in_group`.
- Delete obsolete "configured*" keys from `config` table ([#7171](https://github.com/chatmail/core/pull/7171)).
- Fix flaky tests::verified_chats::test_verified_chat_editor_reordering and receive_imf::receive_imf_tests::test_two_group_securejoins.
- Stop using `leftgrps` table.
- Stop notifying about messages in contact request chats.

### Refactor

- Remove invalid Gmail OAuth2 tokens.
- Remove ProtectionStatus.
- Rename chat::create_group_chat() to create_group().
- Remove error stock strings that are rarely used these days ([#7327](https://github.com/chatmail/core/pull/7327)).
- Jsonrpc rename change casing in names of jsonrpc structs/enums to comply with rust naming conventions. ([#7324](https://github.com/chatmail/core/pull/7324)).
- Stop using deprecated Account.configure().
- add_transport_from_qr: Do not set deprecated config values.
- sql: Change second query_map function from FnMut to FnOnce.
- sql: Add query_map_vec().
- sql: Add query_map_collect().
- Use rand::fill() instead of rand::rng().fill().
- Use SampleString.
- Remove unused call to get_credentials().

### Tests

- rpc-client: VCard color is the same as the contact color ([#7294](https://github.com/chatmail/core/pull/7294)).
- Add unique offsets to ids generated by `TestContext` to increase test correctness ([#7297](https://github.com/chatmail/core/pull/7297)).

## [2.22.0] - 2025-10-17

### Fixes

- Do not notify about incoming calls for contact requests and blocked contacts.

### Tests

- Accept the chat with the caller before accepting calls.

## [2.21.0] - 2025-10-16

### Build system

- nix: Remove unused dependencies.

### Features / Changes

- TLS 1.3 session resumption.
- REPL: Add send-sync command.
- Set `User-Agent` for tile.openstreetmap.org requests.
- Cache tile.openstreetmap.org tiles for 7 days.

### Fixes

- Remove Exif with non-fatal errors from images.
- jsonrpc: Use Core's logic for computing VcardContact.color ([#7294](https://github.com/chatmail/core/pull/7294)).

### Miscellaneous Tasks

- deps: Bump cachix/install-nix-action from 31.7.0 to 31.8.0.
- cargo: Bump async_zip from 0.0.17 to 0.0.18 ([#7257](https://github.com/chatmail/core/pull/7257)).
- deps: Bump github/codeql-action from 3 to 4 ([#7304](https://github.com/chatmail/core/pull/7304)).

### Refactor

- Use rustls reexported from tokio_rustls.
- Pass ALPN around as &str.
- mimeparser: Store only one signature fingerprint.

### Tests

- Test expiration of ephemeral messages with unknown viewtype.
- Test expiration of non-ephemeral message with unknown viewtype.

## [2.20.0] - 2025-10-13

This release fixes a bug that resulted in ephemeral loop getting stuck in infinite loop
when trying to delete a message with unknown viewtype.

### Fixes

- Accept unknown viewtype in ephemeral loop.
- Accept unknown viewtype in delete-old-messages loop.

## [2.19.0] - 2025-10-12

### Features / Changes

- Slightly increase saturation of colors.

### Fixes

- Do not fail to receive call accepted/ended messages referring to non-call Message-ID.
- Do not fail to fully download previously trashed messages.
- Emit AccountsItemChanged when own key is generated/imported, use gray self-color until that ([#7296](https://github.com/chatmail/core/pull/7296)).
- Do not try to process calls from partial messages.

### CI

- Update to Python 3.14.

### Refactor

- Use variables directly in formatted strings ([#7284](https://github.com/chatmail/core/pull/7284)).
- Set_chat_profile_image(): Remove !chat.is_mailing_list() check.

### Miscellaneous Tasks

- cargo: Bump quick-xml from 0.37.5 to 0.38.3.
- Add nodejs to nix dev env ([#7283](https://github.com/chatmail/core/pull/7283))

## [2.18.0] - 2025-10-08

### API-Changes

- [**breaking**] Remove APIs for video chat invitations.

### CI

- nix: Run the workflow when workflow file changes.
- nix: Switch from DeterminateSystems/nix-installer-action to cachix/install-nix-action.

### Features / Changes

- No implicit member changes from old Delta Chat clients ([#7220](https://github.com/chatmail/core/pull/7220)).

### Fixes

- Do not fail to load messages with unknown viewtype.
- Only omit group changes messages if SELF is really added ([#7220](https://github.com/chatmail/core/pull/7220)).

### Refactor

- Assert that Iroh node addresses have home relay URL.

## [2.17.0] - 2025-10-04

### API-Changes

- [**breaking**] Remove deprecated verified_one_on_one_chats config.

### CI

- Require that Cargo.lock is up to date.
- Fix CI checking Nix formatting.

### Documentation

- Comment about outdated timespan.
- Clarify CALL events ([#7188](https://github.com/chatmail/core/pull/7188)).
- Add docs for JS `BaseDeltaChat`.

### Features / Changes

- Make `text/calendar` alternative available as an attachment.
- Better summary for calls.
- Add strings 'You left the channel.' and 'Scan to join Channel' ([#7266](https://github.com/chatmail/core/pull/7266)).
- Stock strings for calls.
- ffi: Add DC_STR_CANT_DECRYPT_OUTGOING_MSGS define.

### Fixes

- Prefer last part in `multipart/alternative`.
- Prefetch messages in limited batches ([#6915](https://github.com/chatmail/core/pull/6915)).
- Forward calls as text messages.
- Consistent spelling of "canceled" with a single "l".
- Lowercase "call" in "Missed call" and similar strings.

### Refactor

- Return the reason when failing to place calls.

### Tests

- Test reception of `multipart/alternative` with `text/calendar`.

## [2.16.0] - 2025-10-01

### API-Changes

- [**breaking**] Get rid of inviter progress other than 0 and 1000.
- Add has_video attribute to incoming call events.
- Add JSON-RPC API to get ICE servers.
- Add call_info() JSON-RPC API.
- Add chat ID to SecureJoinInviterProgress.
- deltachat-rpc-client: Add Chat.resend_messages().
- Add `chat_id` to all call events ([#7216](https://github.com/chatmail/core/pull/7216)).

### Build system

- Update rPGP from 0.16.0 to 0.17.0.

### CI

- Update Rust to 1.90.0.
- Install rustfmt before checking provider database.

### Documentation

- Add more `get_next_event` docs.
- SecurejoinInviterProgress never returns an error.

### Features / Changes

- Don't fetch messages from unknown folders ([#7190](https://github.com/chatmail/core/pull/7190)).
- Get ICE servers from IMAP METADATA.
- Don't ignore receive_imf_inner() errors, try adding partially downloaded message instead ([#7196](https://github.com/chatmail/core/pull/7196)).
- Set dimensions for outgoing Sticker messages.

### Fixes

- Create 1:1 chat only if auth token is for setup contact.
- Ignore vc-/vg- prefix for SecurejoinInviterProgress.
- Don't init Iroh on channel leave ([#7210](https://github.com/chatmail/core/pull/7210)).
- Take the last valid Autocrypt header ([#7167](https://github.com/chatmail/core/pull/7167)).
- Don't add "member removed" messages from nonmembers ([#7207](https://github.com/chatmail/core/pull/7207)).
- Do not consider the call stale if it is not sent out yet.
- Receive_imf: Report replaced message id in `MsgsChanged` if chat is the same.
- Allow Exif for stickers, don't recode them because of that ([#6447](https://github.com/chatmail/core/pull/6447)).

### Refactor

- Remove unused prop (TS, `BaseDeltaChat`).
- Remove unused FolderMeaning::Drafts.

### Tests

- Rename test_udpate_call_text into test_update_call_text.
- Update timestamp_sent in pop_sent_msg_opt().
- Do not match call ID from second alice with first alice event.

## [2.15.0] - 2025-09-15

### API-Changes

- Add JSON-RPC API for calls ([#7194](https://github.com/chatmail/core/pull/7194)).

### Build system

- Remove unused `quoted_printable` dependency.

## [2.14.0] - 2025-09-12

### API-Changes

- Put the chattype into the SecurejoinInviterProgress event ([#7181](https://github.com/chatmail/core/pull/7181)).

### Fixes

- param: Split params only on \n.
- B-encode SDP offer and answer sent in headers.

### Refactor

- Use recv_msg_trash() instead of recv_msg_opt().
- Prepare_msg_raw(): don't return MsgId.

### Tests

- Message is OutFailed if all keys are missing ([#6849](https://github.com/chatmail/core/pull/6849)).
- Test sending SDP offer and answer with newlines.

## [2.13.0] - 2025-09-09

### API-Changes

- [**breaking**] Remove `is_profile_verified` APIs.
- [**breaking**] Remove deprecated `is_protection_broken`.
- [**breaking**] Remove `e2ee_enabled` preference.

### Features / Changes

- Add call ringing API ([#6650](https://github.com/chatmail/core/pull/6650), [#7174](https://github.com/chatmail/core/pull/7174), [#7175](https://github.com/chatmail/core/pull/7175), [#7179](https://github.com/chatmail/core/pull/7179))
- Warn for outdated versions after 6 months instead of 1 year ([#7144](https://github.com/chatmail/core/pull/7144)).
- Do not set "unknown sender for this chat" error.
- Do not replace messages with an error on verification failure.
- Support receiving Autocrypt-Gossip with `_verified` attribute.
- Withdraw all QR codes when one is withdrawn.

### Fixes

- Don't reverify contacts by SELF on receipt of a message from another device.
- Don't verify contacts by others having an unknown verifier.
- Update verifier_id if it's "unknown" and new verifier has known verifier.
- Mark message as failed if it can't be sent ([#7143](https://github.com/chatmail/core/pull/7143)).
- Add "Messages are end-to-end encrypted." to non-protected groups.

### Documentation

- Fix for SecurejoinInviterProgress with progress == 600.
- STYLE.md: Prefer BTreeMap and BTreeSet over hash variants.

### Miscellaneous Tasks

- Update provider database.
- Update dependencies.

### Refactor

- Check that verifier is verified in turn.
- Remove unused `EncryptPreference::Reset`.
- Remove `Aheader::new`.

### Tests

- Add another TimeShiftFalsePositiveNote ([#7142](https://github.com/chatmail/core/pull/7142)).
- Add TestContext.create_chat_id.

## [2.12.0] - 2025-08-26

### API-Changes

- api!(python): remove remaining broken API for reactions

### Features / Changes

- Use Group ID for chat color generation instead of the name for encrypted groups.
- Use key fingerprints instead of addresses for key-contacts color generation.
- Replace HSLuv colors with OKLCh.
- `wal_checkpoint()`: Do `wal_checkpoint(PASSIVE)` and `wal_checkpoint(FULL)` before `wal_checkpoint(TRUNCATE)`.
- Assign messages to key-contacts based on Issuer Fingerprint.
- Create_group_ex(): Log and replace invalid chat name with "…".

### Fixes

- Do not create a group if the sender includes self in the `To` field.
- Do not reverify already verified contacts via gossip.
- `get_connectivity()`: Get rid of locking SchedulerState::inner ([#7124](https://github.com/chatmail/core/pull/7124)).
- Make reaction message hidden only if there are no other parts.

### Refactor

- Do not return `Result` from `valid_signature_fingerprints()`.
- Make `ConnectivityStore` use a non-async lock ([#7129](https://github.com/chatmail/core/pull/7129)).

### Documentation

- Remove broken link from documentation comments.
- Remove the comment about Color Vision Deficiency correction.

## [2.11.0] - 2025-08-13

### Features / Changes

- Contact::lookup_id_by_addr_ex: Prefer returning key-contact.
- Contact::lookup_id_by_addr_ex: Prefer returning accepted contacts.
- Better string when using disappearing messages of one year (365..367 days, so it can be tweaked later).
- Do not require resent messages to be from the same chat.
- `lookup_key_contact_by_address()`: Allow looking up ContactId::SELF without chat id.
- `get_securejoin_qr()`: Log error if group doesn't have grpid.
- `receive_imf::add_parts()`: Get rid of extra `Chat::load_from_db()` calls.

### Fixes

- Ignore case when trying to detect 'invalid unencrypted mail' and add an info-message.
- Run wal_checkpoint during housekeeping ([#6089](https://github.com/chatmail/core/pull/6089)).
- Allow receiving empty files.
- Set correct sent_timestamp for saved outgoing messages.
- Do not remove query parameters from URLs.
- Log and set imex progress error ([#7091](https://github.com/chatmail/core/pull/7091)).
- Do not add key-contacts to unencrypted groups.
- Do not reset `GuaranteeE2ee` in the database when resending messages.
- Assign messages to a group if there is a `Chat-Group-Name`.
- Take `Chat-Group-Name` into account when matching ad hoc groups.
- Don't break long group names with non-ASCII characters.
- Add messages that can't be verified as `DownloadState::Available` ([#7059](https://github.com/chatmail/core/pull/7059)).

### Tests

- Log the number of the test account if there are multiple alices ([#7087](https://github.com/chatmail/core/pull/7087)).

### CI

- Update Rust to 1.89.0.

### Refactor

- Rename icon-address-contact to icon-unencrypted.
- Skip loading the contact of 1:1 unencrypted chat to show the avatar.
- Chat::is_encrypted(): Make one query instead of two for 1:1 chats.

### Miscellaneous Tasks

- cargo: Bump toml from 0.8.23 to 0.9.4.
- cargo: Bump human-panic from 2.0.2 to 2.0.3.
- deny.toml: Add exception for duplicate toml_datetime 0.6.11 dependency.
- deps: Bump actions/checkout from 4 to 5.
- deps: Bump actions/download-artifact from 4 to 5.

## [2.10.0] - 2025-08-04

### Features / Changes

- Also lookup key contacts in lookup_id_by_addr() ([#7073](https://github.com/chatmail/core/pull/7073)).

### Miscellaneous Tasks

- cargo: Bump serde_json from 1.0.140 to 1.0.142.
- cargo: Bump bolero from 0.13.3 to 0.13.4.
- cargo: Bump async-channel from 2.3.1 to 2.5.0.
- cargo: Bump hyper-util from 0.1.14 to 0.1.16.
- cargo: Bump criterion from 0.6.0 to 0.7.0.
- cargo: Bump strum from 0.27.1 to 0.27.2.
- cargo: Bump strum_macros from 0.27.1 to 0.27.2.
- Upgrade async-imap to 0.11.1.

## [2.9.0] - 2025-07-31

### Features / Changes

- repl: Add import-vcard and make-vcard commands ([#7048](https://github.com/chatmail/core/pull/7048)).

### Fixes

- Display correct timer value for ephemeral timer changes.
- Get_chat_msgs_ex(): Report local midnight in ChatItem::DayMarker.

### Refactor

- Rename add_or_lookup_key_contacts_by_address_list() to add_or_lookup_key_contacts().
- Don't call add_or_lookup_key_contacts() in advance.

## [2.8.0] - 2025-07-28

### Features / Changes

- Remove ProtectionBroken, make such  chats Unprotected ([#7041](https://github.com/chatmail/core/pull/7041)).

### Fixes

- Lookup self by address if there is no fingerprint or gossip.

## [2.7.0] - 2025-07-26

### Features / Changes

- Mimefactory: Order message recipients by time of addition ([#6872](https://github.com/chatmail/core/pull/6872)).
- Put the debug/release build version into the info ([#7034](https://github.com/chatmail/core/pull/7034)).

### Fixes

- Realtime late join ([#6869](https://github.com/chatmail/core/pull/6869)).
- Do not fail to upgrade if the verifier of a contact doesn't exist anymore ([#7044](https://github.com/chatmail/core/pull/7044)).

### Tests

- Add regression test for verification-gossiping crash ([#7033](https://github.com/chatmail/core/pull/7033)).

## [2.6.0] - 2025-07-23

### Fixes

- Fix crash when receiving a verification-gossiping message which a contact also sends to itself ([#7032](https://github.com/chatmail/core/pull/7032)).

## [2.5.0] - 2025-07-22

### Fixes

- Correctly migrate "verified by me".
- Mark all email chats as unprotected in the migration ([#7026](https://github.com/chatmail/core/pull/7026)).
- Do not ignore errors in add_flag_finalized_with_set.

### Documentation

- Deprecate protection-broken and related stuff ([#7018](https://github.com/chatmail/core/pull/7018)).
- Clarify the meaning of is_verified() vs verifier_id() ([#7027](https://github.com/chatmail/core/pull/7027)).
- STYLE.md: Prefer `try_next()` over `next()`.

## [2.4.0] - 2025-07-21

### Fixes

- Do not ignore errors when draining FETCH responses. This avoids IMAP loop getting stuck in an infinite loop retrying reading from the connection.
- Update `tokio-io-timeout` to 1.2.1. This release includes a fix to reset timeout after every error, so timeout error is returned at most once a minute if read is attempted after a timeout.

### Miscellaneous Tasks

- Update async-imap to 0.11.0.

### Refactor

- Use `try_next()` when processing FETCH responses.

## [2.3.0] - 2025-07-19

### Features / Changes

- Add "e2ee encrypted" info message to all e2ee chats ([#7008](https://github.com/chatmail/core/pull/7008)).
- repl: Print errors and debug logs to stderr.
- `{ensure_and,logged}_debug_assert`: Don't evaluate condition twice.
- Log when background fetch of all accounts finishes successfully.
- Log the number of read/written bytes on IMAP stream read error ([#6924](https://github.com/chatmail/core/pull/6924)).

### Fixes

- Ignore protected headers in outer message part ([#6357](https://github.com/chatmail/core/pull/6357)).
- List e-mail contacts in repl listcontacts command.
- Save peer address for LoggingStream early.

## [2.2.0] - 2025-07-14

### API-Changes

- Add chat::create_group_ex(), deprecate create_group_chat() ([#6927](https://github.com/chatmail/core/pull/6927)).
- jsonrpc: Add CommandApi::create_group_chat_unencrypted() ([#6927](https://github.com/chatmail/core/pull/6927)).
- [**breaking**] In ChatListItem, replace is_group and is_(out_)broadcast with chat_type property ([#7003](https://github.com/chatmail/core/pull/7003)).

### Features / Changes

- Log failed debug assertions in all configurations.
- Donation request device message ([#6913](https://github.com/chatmail/core/pull/6913)).
- Advance next UID even if connection fails while fetching.

### Fixes

- Always prefer the last header.

### Tests

- Tune down DELTACHAT_SAVE_TMP_DB hint ([#6998](https://github.com/chatmail/core/pull/6998)).
- Unencrypted group creation ([#6927](https://github.com/chatmail/core/pull/6927)).

## [2.1.0] - 2025-07-11

### Features / Changes

- Add account ordering functionality ([#6993](https://github.com/chatmail/core/pull/6993)).
- feat: Make it possible to leave broadcast channels ([#6984](https://github.com/chatmail/core/pull/6984))
- Migrations: Use tools::Time to measure time for logging.
- Log emitted logging events with `tracing`.
- Ensure_and_debug_assert{,_eq,_ne} macros combining `debug_assert*` and anyhow::ensure ([#6907](https://github.com/chatmail/core/pull/6907)).

### Fixes

- Use Viewtype::File for messages with invalid images, images of unknown size, images > 50 Mpx ([#6825](https://github.com/chatmail/core/pull/6825)).
- Don't apply chat name and avatar changes from non-members.

### Documentation

- Update showpadlock ffi.

### Miscellaneous Tasks

- cargo: Update cordyceps from 0.3.2 to 0.3.4.

### Tests

- Add option to save database on test failure ([#6992](https://github.com/chatmail/core/pull/6992)).

## [2.0.0] - 2025-07-09

This release changes the way the core handles contact keys.
Instead of tracking OpenPGP keys corresponding to the
contacts in [Autocrypt](https://autocrypt.org/) peerstate,
the core creates a new "key-contact" for each known public key.
Reception of a message signed with a new unknown key
no longer results in warnings about setup changes,
but creates a new contact and a new 1:1 chat if necessary.
Additionally, there are "address-contacts" corresponding
to the e-mail addresses.

### Features / Changes

- Key-contacts ([#6796](https://github.com/chatmail/core/pull/6796), [#6941](https://github.com/chatmail/core/pull/6941)).
- Increase event channel size from 1000 to 10000.
- Minimize the amount of data preserved for trashed messages.
- Show broadcast channels in their own, proper "Channel" chat ([#6901](https://github.com/chatmail/core/pull/6901), [#6975](https://github.com/chatmail/core/pull/6975)).
- Check images passed as `File` before making them `Image`.

### API-Changes

- CFFI: Add dc_contact_is_key_contact() ([#6955](https://github.com/chatmail/core/pull/6955)).
- Contact::get_all(): Support listing address-contacts.
- [**breaking**] Add InBroadcastChannel, OutBroadcastChannel chattypes, add create_broadcast_channel() ([#6901](https://github.com/chatmail/core/pull/6901)).
- deltachat-rpc-client: Add Message.get_read_receipts().

### Fixes

- Remove display name from get_info(). This information usually goes at the top of the log and we don't want users to include it in bug reports.
- Wait for scheduler tasks shutdown in parallel.
- Update deltachat-repl help and autocomplete to match implementation ([#6978](https://github.com/chatmail/core/pull/6978), ([#6979](https://github.com/chatmail/core/pull/6979)).
- Send Autocrypt header in MDNs. This is needed to assign MDNs to key-contacts.
- Prefer encrypted List-Id header ([#6983](https://github.com/chatmail/core/pull/6983)).
- Treat "tgs" as Viewtype::File.
- Treat and send images that can't be decoded as Viewtype::File.
- Decide on filename used for sending depending on the original Viewtype.
- Migrate_key_contacts(): Remove "id>9" from encrypted messages SELECT.
- Save msgs to key-contacts migration state and run migration periodically ([#6956](https://github.com/chatmail/core/pull/6956)).
- Do not try to lookup key-contacts for unencrypted 1:1 messages.
- Add query to post request for account creation ([#6989](https://github.com/chatmail/core/pull/6989)).

### CI

- Update Rust to 1.88.0.

### Documentation

- Remove outdated comment that says MDNs are unencrypted.

### Refactor

- Upgrade to Rust 2024.
- Build_body_file(): Remove guessing mimetype by file extension.

### Tests

- Add online test for read receipts.
- Add a test reproducing chat assignment bug.

### Miscellaneous Tasks

- cargo: Bump smallvec from 1.15.0 to 1.15.1.
- cargo: Bump syn from 2.0.101 to 2.0.104.
- cargo: Bump hyper-util from 0.1.13 to 0.1.14.
- cargo: Bump toml from 0.8.19 to 0.8.23.
- cargo: Bump proptest from 1.6.0 to 1.7.0.
- cargo: Bump libc from 0.2.172 to 0.2.174.

## [1.160.0] - 2025-06-22

### API-Changes

- [**breaking**] jsonrpc: remove webxdc info from MessageObject.
  Users need to call `get_webxdc_info` separately now
  and expect that the call may fail e.g. if WebXDC is not a valid ZIP archive.
- [**breaking**] Deprecate `DC_GCL_VERIFIED_ONLY`.
- [**breaking**] Make logging macros private.

### Features / Changes

- Add more IMAP logging.
- Sort apps by recently-updated ([#6875](https://github.com/chatmail/core/pull/6875)).
- Better error for quoting a message from another chat.
- Put "biography" in the vCard ([#6819](https://github.com/chatmail/core/pull/6819)).

### Fixes

- Do not allow chat creation if decryption failed.
- Remove faulty test ([#6880](https://github.com/chatmail/core/pull/6880)).
- Reduce the scope of the last_full_folder_scan lock in scan_folders.
- Ignore verification error if the chat is not protected yet.
- Create group chats unprotected on verification error.
- `fetch_url`: return err on non 2xx reponses.
- Sort multiple saved messages by timestamp ([#6862](https://github.com/chatmail/core/pull/6862)).
- contact-tools: Escape commas in vCards' FN, KEY, PHOTO, NOTE ([#6912](https://github.com/chatmail/core/pull/6912)).
- Don't change ConfiguredAddr when adding a transport ([#6804](https://github.com/chatmail/core/pull/6804)).

### Build system

- Increase MSRV to 1.85.0.
- Update Doxygen config and layout file.
- Update to rPGP 0.16.0 ([#6719](https://github.com/chatmail/core/pull/6719)).
- Enable async-native-tls/vendored feature.
- Update rusqlite to 0.36.0.

### CI

- Update Rust to 1.87.0.
- nix: Test build on macOS without cross-compilation.
- Use installed toolchain to lint Rust.

### Refactor

- Remove explicit lock drop at the end of scope.
- Use CancellationToken instead of a 1-message channel.

### Documentation

- Add more code style guide references.

## [1.159.5] - 2025-05-14

### Fixes

- Don't change webxdc self-addr when saving and loading draft ([#6854](https://github.com/chatmail/core/pull/6854)).

### Miscellaneous Tasks

- Remove duplicate miniz_oxide dependency.
- Update async-smtp to 0.10.2.

## [1.159.4] - 2025-05-13

### Documentation

- Add missing documentation to deltachat-rpc-client.

### Features / Changes

- Better avatar quality ([#6822](https://github.com/chatmail/core/pull/6822)).
- Update iroh from 0.33.0 to 0.35.0 ([#6687](https://github.com/chatmail/core/pull/6687)).
- Other dependency updates.

### Fixes

- Emit progress(0) in case AEAP is tried.
- Replace `FuturesUnordered` from `futures` with `JoinSet` from `tokio`.
- Fix order of operations when handling "vc-request-with-auth" ([#6850](https://github.com/chatmail/core/pull/6850)).
- Generate rfc724_mid when creating Message ([#6704](https://github.com/chatmail/core/pull/6704))

### Tests

- Profile data is attached to group leave messages.

## [1.159.3] - 2025-04-24

### CI

- Use `ubuntu-latest` runner for `@deltachat/jsonrpc-client` publishing.

## [1.159.2] - 2025-04-23

### Fixes

- Allow to send to chats after failed securejoin again ([#6817](https://github.com/chatmail/core/pull/6817)).
- Parse login scheme in `add_transport_from_qr()` ([#6802](https://github.com/chatmail/core/pull/6802)).
- Lowercase address in add_transport() ([#6805](https://github.com/chatmail/core/pull/6805)).

### API-Changes

- Rename add_transport() -> add_or_update_transport() ([#6800](https://github.com/chatmail/core/pull/6800)).

### Miscellaneous Tasks

- Update yerpc to 0.6.4.
- Clean up `deltachat-jsonrpc` dependencies.

### Refactor

- Move logins into SQL table ([#6724](https://github.com/chatmail/core/pull/6724)).

### Tests

- Check headers absense straightforwardly.
- Fix mismatch between the contact and the account in securejoin tests.
- Test that key of the recipient is gossiped in 1:1 chats.

## [1.159.1] - 2025-04-12

### API-Changes

- deltachat-rpc-client: Add `Account.add_transport()`.
- Add jsonrpc for info_contact_id.

### Build system

- Update crossbeam-channel from 0.5.14 to 0.5.15.
- Increase MSRV to 1.82.0.

### CI

- Don't make ruff format quiet ([#6785](https://github.com/chatmail/core/pull/6785)).

### Documentation

- MimeFactory.member_timestamps has the same order as To: rather than RCPT TO:.
- Two JsonRPC doc improvements ([#6778](https://github.com/chatmail/core/pull/6778)).

### Features / Changes

- Improve error message when the user tries to do AEAP ([#6786](https://github.com/chatmail/core/pull/6786)).
- Pass email and password via env in python-jsonrpc.
- Track gossiping per (chat, fingerprint) pair.

### Fixes

- Add missing ChatDeleted event to python jsonrpc client.
- Never send Autocrypt-Gossip in broadcast lists.
- Restart I/O when mvbox_move setting is changed.

### Tests

- Port test_delete_deltachat_folder to JSON-RPC.
- Autocrypt-Gossip header isn't sent in broadcast messages.
- Encrypt test_subject_in_group().
- Encrypt test_remove_member_bcc.

## [1.159.0] - 2025-04-08

### API-Changes

- deltachat-rpc-client: Add Message.get_info().
- CFFI: Add `dc_make_vcard()` and `dc_import_vcard()`.
- Add legacy Python bindings for `make_vcard` and `import_vcard`.

### CI

- Upgrade Rust from 1.84.1 to 1.86.0 ([#6784](https://github.com/chatmail/core/pull/6784)).

### Features / Changes

- Add name resp. "Me" to contact encryption info ([#6720](https://github.com/chatmail/core/pull/6720)).
- Get contact-id for info messages ([#6714](https://github.com/chatmail/core/pull/6714)).
- No unencrypted chat when securejoin times out ([#6722](https://github.com/chatmail/core/pull/6722)).
- Clear `Param::IsEdited` when forwarding a message.
- Remove email address from 'add second device' qr code ([#6760](https://github.com/chatmail/core/pull/6760)).
- Parse Proton Mail vCards again ([#6771](https://github.com/chatmail/core/pull/6771)).
- Do not consider encrypting to the primary OpenPGP key.

### Fixes

- jsonrpc: Fix deadlock in get_all_accounts().
- Set GroupNameTimestamp on group promotion ([#6729](https://github.com/chatmail/core/pull/6729)).
- Encrypt broadcast lists.

### Miscellaneous Tasks

- Update yerpc to 0.6.3.
- cargo: Update textwrap from 0.16.1 to 0.16.2.
- cargo: Bump uuid from 1.15.1 to 1.16.0.
- cargo: Bump libc from 0.2.170 to 0.2.171.
- cargo: Bump anyhow from 1.0.96 to 1.0.97.
- cargo: Bump bytes from 1.10.0 to 1.10.1.
- cargo: Bump once_cell from 1.20.3 to 1.21.3.
- cargo: Bump thiserror from 2.0.11 to 2.0.12.
- cargo: Bump pin-project from 1.1.9 to 1.1.10.
- cargo: Bump hyper-util from 0.1.10 to 0.1.11.
- cargo: Bump log from 0.4.26 to 0.4.27.
- cargo: Bump tokio-util from 0.7.13 to 0.7.14.
- cargo: Bump syn from 2.0.98 to 2.0.100.
- cargo: Bump serde_json from 1.0.139 to 1.0.140.
- cargo: Bump quote from 1.0.38 to 1.0.40.
- cargo: Bump http-body-util from 0.1.2 to 0.1.3.
- cargo: Bump openssl from 0.10.71 to 0.10.72.
- cargo: Bump quick-xml from 0.37.2 to 0.37.4.
- cargo: Bump blake3 from 1.6.1 to 1.8.0.
- cargo: Bump tokio from 1.43.0 to 1.43.1 ([#6780](https://github.com/chatmail/core/pull/6780)).
- Add issue template.
- Add bug label on bug issue template.
- cargo: Bump tokio from 1.43.0 to 1.44.1.
- cargo: Bump fd-lock from 4.0.2 to 4.0.4.
- Update async-smtp from 0.10.0 to 0.10.1.
- Update async-imap from 0.10.3 to 0.10.4.
- cargo: Bump tempfile from 3.14.0 to 3.19.1.
- cargo: Bump image from 0.25.5 to 0.25.6.
- cargo: Bump serde from 1.0.218 to 1.0.219.

### Other

- Add python and tox to flake.nix devshell ([#6233](https://github.com/chatmail/core/pull/6233))
- Update spec wrt edit/delete, minor rewordings ([#6708](https://github.com/chatmail/core/pull/6708))
- Update 'takes longer' fallback wording.
- Handle classic emails as such only in classic profiles ([#6767](https://github.com/chatmail/core/pull/6767))
- Move ASM strings to core, point to "Add Second Device" ([#6777](https://github.com/chatmail/core/pull/6777))

### Refactor

- Replace `once_cell::sync::Lazy` with `std::sync::LazyLock`.
- Move vCard code to its own file ([#6776](https://github.com/chatmail/core/pull/6776)).

### Tests

- Use encryption in more Rust tests.
- Use encryption in all JSON-RPC online tests.
- Encrypt legacy Python tests.
- Send only encrypted messages in online JS tests.
- Add APIs to create `dom@example.net` and `elena@example.net`.
- Split public keys from secret keys in runtime.
- Remove fetch_existing tests.
- Port test_forward_encrypted_to_unencrypted from legacy Python to Rust.
- Port test_one_account_send_bcc_setting from legacy Python to JSON-RPC.
- Port test_multidevice_sync_seen to JSON-RPC.
- Use QR codes to setup contact with test bots.
- Remove flaky key::tests::test_load_self_existing test ([#6763](https://github.com/chatmail/core/pull/6763)).
- Update blob hash in blob::blob_tests::test_selfavatar_outside_blobdir.

## [1.158.0] - 2025-03-29

### API-Changes

- deltachat-rpc-client: Accept `Account` as `Account.create_contact()` argument.
- Rust: Add `ContactId.set_name()`.
- JSON-RPC: Rename parameter name in `get_webxdc_href` to `info_msg_id` to reduce confusion potential ([#6681](https://github.com/chatmail/core/pull/6681)).

### Features / Changes

- Nicer configuration error ([#6684](https://github.com/chatmail/core/pull/6684)).
- securejoin: Do not create 1:1 chat on Alice's side until `vc-request-with-auth`.
- Understandable error message when accounts.lock can't be locked ([#6695](https://github.com/chatmail/core/pull/6695)).
- Simplify e2ee decision logic, remove majority vote.
- Stop saving txt_raw.

### Fixes

- Do not fail to send the message if some keys are missing.
- Synchronize contact name changes.
- Move group name timestamp update up in create_send_msg_jobs().
- Fixes for transport JSON-RPC  ([#6680](https://github.com/chatmail/core/pull/6680)).

### Build system

- deltachat-rpc-client: Move development dependencies from tox.ini to pyproject.toml.
- Update resolve-conf from 0.7.0 to 0.7.1.

### Refactor

- Do not convert SQL arguments to `String` unnecessarily.
- Factor out `update_chat_names()`.
- Use `created_timestamp()` instead of duplicating its code ([#6692](https://github.com/chatmail/core/pull/6692)).
- Use `chat_id.get_timestamp()` instead of duplicating its code ([#6691](https://github.com/chatmail/core/pull/6691)).
- Move `mark_recipients_as_verified()` call out of `has_verified_encryption()`.
- Move `proxy_config` out of `ConfiguredLoginParam` ([#6712](https://github.com/chatmail/core/pull/6712)).

### Tests

- Use vCard in TestContext.add_or_lookup_contact().
- Remove test_group_with_removed_message_id.
- Use add_or_lookup_address_contact() in get_chat().
- Use add_or_lookup_address_contact in test_setup_contact_ex.
- Use vCards more in Python tests.
- Use TestContextManager in more tests.
- Use vCards to create contacts in more Rust tests.
- Set chat name multiple times in a row.
- Online test for renaming the group multiple times.

## [1.157.3] - 2025-03-19

### API-Changes

- jsonrpc: Add `copy_to_blob_dir` api ([#6660](https://github.com/chatmail/core/pull/6660)).
- Add "delete_for_all" function in json-rpc ([#6672](https://github.com/chatmail/core/pull/6672)).
- Sketch add_transport_from_qr(), add_transport(), list_transports(), delete_transport() APIs ([#6589](https://github.com/chatmail/core/pull/6589)).

### Build system

- Remove websocket support from deltachat-jsonrpc.
- Remove encoded-words dependency.

### Fixes

- Never send empty `To:` header ([#6663](https://github.com/chatmail/core/pull/6663)).
- Use protected `Date` header for signed messages.
- Fix setting up a profile and immediately transferring to a second device ([#6657](https://github.com/chatmail/core/pull/6657)).
- Don't SMTP-send self-only messages if DeleteServerAfter is "immediate" ([#6661](https://github.com/chatmail/core/pull/6661)).
- Use protected `Date` with protected Autocrypt.

### Miscellaneous Tasks

- cargo: Bump uuid from 1.12.1 to 1.15.1.
- Update `strum` dependency.

### Refactor

- deltachat-rpc-client: Use wait_for_event() type argument.

### Tests

- Avoid creating contacts in `test_sync_{accept,block}_before_first_msg()`.
- Fix `test_no_old_msg_is_fresh` flakiness.

## [1.157.2] - 2025-03-15

### Fixes

- Prefer hidden Message-ID header if any.
- Update async-compression to 0.4.21 to fix IMAP COMPRESS getting stuck.

### Refactor

- Extract handle_edit_delete() function for message edit/delete  ([#6664](https://github.com/chatmail/core/pull/6664)).

### Tests

- test_secure_join: Bob should not create a 1:1 chat before sending a message.
- Return chat ID from TestContext.exec_securejoin_qr().

## [1.157.1] - 2025-03-13

### Miscellaneous Tasks

- Update repository URLs to make npm and PyPI publishing possible.

## [1.157.0] - 2025-03-12

### Features / Changes

- Ignore encryption preferences.

### API-Changes

- deltachat-rpc-client: Make it possible to clone accounts.
- deltachat-rpc-client: Add Account.device_contact.
- deltachat-rpc-client: Add Account.get_device_chat().
- deltechat-rpc-client: Add Account.wait_for_msgs_noticed_event().
- ffi: Store reference pointer to Context in dc_chat_t.

### Build system

- Intergrate `fuzz` crate into workspace.
- Update env_logger to get rid of unmaintained humantime dependency.
- nix: Update NDK to 27.2.12479018.
- Build Android wheels for PyPI.

### Documentation

- deltachat-rpc-client: Document Account.check_qr().
- deltachat-rpc-client: Document Account.import_vcard().

### Fixes

- Update async-imap to 0.10.23 to fix division by zero.
- Ignore hidden headers in IMF section.
- Process Autocrypt-Gossip only after merging protected headers.

### Miscellaneous Tasks

- cargo: Bump smallvec from 1.13.2 to 1.14.0.

### Tests

- Deletion request fails in an unencrypted chat and the message remains.
- python: port `test_no_old_msg_is_fresh` to JSON-RPC.

## [1.156.3] - 2025-03-09

### API-Changes

- jsonrpc: Add import_vcard_contents() method.
- jsonrpc: Add API to make and import vCards.
- [**breaking**] Remove save_mime_headers config option and dc_get_mime_headers().
- [**breaking**] Remove key_gen_type config.

### Features / Changes

- Add chat-deleted event.
- Delete messages on IMAP when deleting chat ([#6613](https://github.com/chatmail/core/pull/6613)).
- Allow doubled avatar resolution

### Fixes

- Move Chat-Group-Avatar to hidden headers.
- Ignore outer Chat-User-Avatar header in Autocrypt-encrypted messages.

### Build system

- Use mailbuilder from crates.io.
- Update iroh to 0.33.

### Documentation

- Nonstandard headers needing DKIM protection should be hidden.

### Refactor

- Recode_to_size(): Rename strict_limits to is_avatar.

### Tests

- Test for ChatDeleted event.
- Replace create_chat() with get_chat() in test_setup_contact_ex() and test_secure_join().
- Transfer vCards in TestContext.create_chat().

## [1.156.2] - 2025-03-02

### Fixes

- Upgrade native-tls from 0.2.13 to 0.2.14. This fixes "Accept invalid certificates" failing on Android with "OpenSSL error". The bug was there since 1.156.0 due to upgrade of native-tls from 0.2.11 to 0.2.13.

### Features / Changes

- Show sender name in 'Saved Messages' summary ([#6607](https://github.com/chatmail/core/pull/6607)).
- Sync chats deletion across devices.

### Documentation

- Add DC_QR_BACKUP_TOO_NEW documentation.

### Miscellaneous Tasks

- cargo: Bump anyhow from 1.0.95 to 1.0.96.
- cargo: Bump serde from 1.0.217 to 1.0.218.

## [1.156.1] - 2025-02-28

### Fixes

- Update mailparse to 0.16.1 to fix panic when parsing a message.
- Add Chat-Group-Name-Timestamp header and use it to update group names ([#6412](https://github.com/chatmail/core/pull/6412)).
- Log tokio::fs::metadata errors.

### Build system

- Update fuzzing setup.

## [1.156.0] - 2025-02-26

### API-Changes

- Save messages API in JSON RPC ([#6554](https://github.com/chatmail/core/pull/6554)).
- jsonrpc: Add `MessageObject.is_edited`.
- jsonrpc: Add `send_edit_request`.
- Deduplicate blob files in the JsonRPC API ([#6470](https://github.com/chatmail/core/pull/6470)).
- Message deletion request API ([#6576](https://github.com/chatmail/core/pull/6576))

### Features / Changes

- Edit message's text ([#6550](https://github.com/chatmail/core/pull/6550))
- Sync message deletion to other devices ([#6573](https://github.com/chatmail/core/pull/6573))
- Allow scanning multiple securejoin QR codes in parallel.
- When reactions are seen, remove notification from second device ([#6480](https://github.com/chatmail/core/pull/6480)).
- Enable bcc-self automatically when doing Autocrypt Setup Message.
- Don't send a notification when a group member left ([#6575](https://github.com/chatmail/core/pull/6575)).
- Fail on too new backups ([#6580](https://github.com/chatmail/core/pull/6580)).

### Fixes

- Make it impossible to overwrite default key.
- Do not allow to edit html messages ([#6564](https://github.com/chatmail/core/pull/6564)).
- `get_config(Config::Selfavatar)` returns the path, not the name ([#6570](https://github.com/chatmail/core/pull/6570)).
- `chat::save_msgs`: Interrupt inbox loop to send a sync message.
- Do not delete files if cannot read their metadata.

### Build system

- nix: Update hashes of git dependencies.
- Update some dependencies.

### CI

- Remove deprecated DeterminateSystems/magic-nix-cache-action.

### Refactor

- Use mail-builder instead of lettre_email.
- Move even even more tests into their own files ([#6559](https://github.com/chatmail/core/pull/6559)).
- Remove `Message.set_file()`, `dc_msg_set_file()` and related code ([#6558](https://github.com/chatmail/core/pull/6558)).
- Remove unused blob functions ([#6563](https://github.com/chatmail/core/pull/6563)).
- Let `BlobObject::from_name()` take `&str` ([#6571](https://github.com/chatmail/core/pull/6571)).
- Don't use traits where it's not necessary ([#6567](https://github.com/chatmail/core/pull/6567)).

## [1.155.6] - 2025-02-17

### Features / Changes

- Sort past members by the timestamp of removal.
- Use UUID v4 to generate Message-IDs.

### Fixes

- Use dedicated ID for sync messages affecting device chat.
- Do not allow non-members to change ephemeral timer settings.
- Show padlock when the message is not sent over the network.

### Build system

- Remove deprecated node module.

### CI

- Audit workflows with zizmor.

### Documentation

- Improve docstrings ([#6496](https://github.com/chatmail/core/pull/6496)).

## [1.155.5] - 2025-02-14

### Fixes

- Get_filename() is now guaranteed to return a valid filename ([#6537](https://github.com/chatmail/core/pull/6537)).

### Miscellaneous Tasks

- Add RUSTSEC-2025-0006 to deny.toml.

### Refactor

- Do not cancel the task returned from async_imap `Handle.wait_with_timeout`.

## [1.155.4] - 2025-02-10

### CI

- Upgrade Rust from 1.84.0 to 1.84.1.

### Fixes

- Use CRLF newlines in vCards.
- Make vCard parsing more robust in case of trailing newlines.
- Do not include CRLF before MIME boundary in the part body.
- Accept QR codes with 'broken' JSON ([#6528](https://github.com/chatmail/core/pull/6528)).

### Other

- Add `MessageQuote.chat_id`.

### Refactor

- Move even more tests into their own files ([#6521](https://github.com/chatmail/core/pull/6521)).

## [1.155.3] - 2025-02-05

### Fixes

- Store device token in IMAP METADATA on each connection.

### Miscellaneous Tasks

- Upgrade iroh from 0.30 to 0.32.
- Update `pgp` to 0.15.
- cargo: Bump thiserror from 1.0.69 to 2.0.9.
- cargo: Bump pin-project from 1.1.7 to 1.1.8.
- cargo: Bump dirs from 5.0.1 to 6.0.0.
- cargo: Bump hyper from 1.5.2 to 1.6.0.
- cargo: Bump webpki-roots from 0.26.7 to 0.26.8.
- cargo: Bump futures-lite from 2.5.0 to 2.6.0.
- Update OpenSSL to fix RUSTSEC-2025-0004.
- cargo: Bump tokio from 1.42.0 to 1.43.0.
- cargo: Bump syn from 2.0.94 to 2.0.98.
- cargo: Bump rustls from 0.23.20 to 0.23.22.
- cargo: Bump data-encoding from 2.6.0 to 2.7.0.
- cargo: Bump serde_json from 1.0.134 to 1.0.138.
- cargo: Bump uuid from 1.11.0 to 1.12.1.
- cargo: Bump log from 0.4.22 to 0.4.25.
- cargo: Bump rustls-pki-types from 1.10.1 to 1.11.0.
- Update futures-concurrency.

### Documentation

- Assign docs to correct object.

### Tests

- Make sure DCBACKUP2 compatibility does not break again.

## [1.155.2] - 2025-01-31

This release accidentally broke compatibility
with previous versions of `DCBACKUP2` QR codes
due to iroh upgrade.

### API-Changes

- Add `IncomingReaction.chat_id` ([#6459](https://github.com/chatmail/core/pull/6459)).

### Features / Changes

- Deduplicate blob files in `chat.rs`, `config.rs`, and `integration.rs`.
- Improve logging around IMAP IDLE.
- Upgrade to iroh@0.30.0.

### Fixes

- Don't remove file extension when recoding avatars.
- Use `BufReader` when reading .xdc files.
- No implicit member changes when we are added to the group ([#6493](https://github.com/chatmail/core/pull/6493)).

### Documentation

- jsonrpc: Update documentation for `select_account` and `get_selected_account_id` ([#6483](https://github.com/chatmail/core/pull/6483)).
- jsonrpc: Add docs for some functions.

## [1.155.1] - 2025-01-25

### Features / Changes

- Only accept SetContacts sync messages for broadcast lists.

### Fixes

- Don't create tombstones when synchronizing broadcast list members.
- Use non-empty `To:` field for "saved messages".
- Only send Chat-Group-Member-Timestamps in groups.
- Use 0 timestamps if Chat-Group-Member-Timestamps is not set.

### Refactor

- Remove BlobObject::create(), use create_and_deduplicate_from_bytes() instead ([#6467](https://github.com/chatmail/core/pull/6467)).
- Move more tests into their own files ([#6473](https://github.com/chatmail/core/pull/6473)).

## [1.155.0] - 2025-01-23

### API-Changes

- Add JSON-RPC API to get past members.

### Build system

- Update Rust.
- Increase MSRV to 1.81.0

### Features / Changes

- feat: Set BccSelf to true when receiving a sync message  ([#6434](https://github.com/chatmail/core/pull/6434))
- File deduplication ([#6332](https://github.com/chatmail/core/pull/6332))

### Refactor

- Move tests to their own files.
- Extract `group_changes_msgs()` function ([#6460](https://github.com/chatmail/core/pull/6460)).

## [1.154.3] - 2025-01-20

### Build system

- Remove encoded-words from flake.nix.
- nix: Update rust-email hash in flake.nix.

### Miscellaneous Tasks

- Remove unused function delete_files_in_dir() ([#6454](https://github.com/chatmail/core/pull/6454)).

## [1.154.2] - 2025-01-20

### Features / Changes

- Add API to save messages ([#5606](https://github.com/chatmail/core/pull/5606)).

### Fixes

- fix: Don't accidentally remove Self from groups ([#6455](https://github.com/chatmail/core/pull/6455)).
- Do not create tombstones for members removed from unpromoted groups.

### Build system

- Switch to non-git version of encoded-words.

### Refactor

- Make memberlist update logic easier to follow.

## [1.154.1] - 2025-01-15

### Tests

- Expect trashing of no-op "member added" in non_member_cannot_modify_member_list.

## [1.154.0] - 2025-01-15

### Features / Changes

- New group consistency algorithm.

### Fixes

- Migration: Set bcc_self=1 if it's unset and delete_server_after!=1 ([#6432](https://github.com/chatmail/core/pull/6432)).
- Clear the config cache after every migration ([#6438](https://github.com/chatmail/core/pull/6438)).

### Build system

- Increase minimum supported Python version to 3.8.
- [**breaking**] Remove jsonrpc feature flag.

### CI

- Update Rust to 1.84.0.

### Miscellaneous Tasks

- Beta Clippy suggestions ([#6422](https://github.com/chatmail/core/pull/6422)).

### Refactor

- Use let..else.
- Add why_cant_send_ex() capable to only ignore specified conditions.
- Remove unnecessary is_contact_in_chat check.
- Eliminate remaining repeat_vars() calls ([#6359](https://github.com/chatmail/core/pull/6359)).

### Tests

- Use assert_eq! to compare chatlist length.

## [1.153.0] - 2025-01-05

### Features / Changes

- Remove "jobs" from imap_markseen if folder doesn't exist ([#5870](https://github.com/chatmail/core/pull/5870)).
- Delete `vg-request-with-auth` from IMAP after processing ([#6208](https://github.com/chatmail/core/pull/6208)).

### API-Changes

- Add `IncomingWebxdcNotify.chat_id` ([#6356](https://github.com/chatmail/core/pull/6356)).
- rpc-client: Add INCOMING_REACTION to const.EventType ([#6349](https://github.com/chatmail/core/pull/6349)).

### Documentation

- Viewtype::Sticker may be changed to Image and how to disable that ([#6352](https://github.com/chatmail/core/pull/6352)).

### Fixes

- Never change Viewtype::Sticker to Image if file has non-image extension ([#6352](https://github.com/chatmail/core/pull/6352)).
- Change BccSelf default to 0 for chatmail ([#6340](https://github.com/chatmail/core/pull/6340)).
- Mark holiday notice messages as bot-generated.
- Don't treat location-only and sync messages as bot ones ([#6357](https://github.com/chatmail/core/pull/6357)).
- Update shadowsocks crate to 1.22.0 to avoid panic when parsing some QR codes.
- Prefer to encrypt if E2eeEnabled even if peers have EncryptPreference::NoPreference.
- Prioritize mailing list over self-sent messages.
- Allow empty `To` field for self-sent messages.
- Default `to_id` to self instead of 0.

### Refactor

- Remove unused parameter and return value from `build_body_file(…)` ([#6369](https://github.com/chatmail/core/pull/6369)).
- Deprecate Param::ErroneousE2ee.
- Add `emit_msgs_changed_without_msg_id`.
- Add_parts: Remove excessive `is_mdn` checks.
- Simplify `self_sent` condition.
- Don't ignore get_for_contact errors.

### Tests

- Messages without recipients are assigned to self chat.
- Message with empty To: field should have a valid to_id.
- Fix `test_logged_ac_process_ffi_failure` flakiness.

## [1.152.2] - 2024-12-24

### Features / Changes

- Emit ImexProgress(1) after receiving backup size.
- `delete_msgs`: Use `transaction()` instead of `call_write()`.
- Start ephemeral timers when the chat is noticed.
- Start ephemeral timers when the chat is archived.
- Revalidate HTTP cache entries once per minute maximum.

### Fixes

- Reduce number of `repeat_vars()` calls.
- `sanitise_name`: Don't consider punctuation and control chars as part of file extension ([#6362](https://github.com/chatmail/core/pull/6362)).

### Refactor

- Remove marknoticed_chat_if_older_than().

### Miscellaneous Tasks

- Remove contrib/ directory.

## [1.152.1] - 2024-12-17

### Build system

- Downgrade Rust version used to build binaries.
- Reduce MSRV to 1.77.0.

## [1.152.0] - 2024-12-12

### API-Changes

- [**breaking**] Remove `dc_prepare_msg` and `dc_msg_is_increation`.

### Build system

- Increase MSRV to 1.81.0.

### Features / Changes

- Cache HTTP GET requests.
- Prefix server-url in info.
- Set `mime_modified` for the last message part, not the first ([#4462](https://github.com/chatmail/core/pull/4462)).

### Fixes

- Render "message" parts in multipart messages' HTML ([#4462](https://github.com/chatmail/core/pull/4462)).
- Ignore garbage at the end of the keys.

## [1.151.6] - 2024-12-11

### Features / Changes

- Don't add "Failed to send message to ..." info messages to group chats.
- Add info messages about implicit membership changes if group member list is recreated ([#6314](https://github.com/chatmail/core/pull/6314)).

### Fixes

- Add self-addition message to chat when recreating member list.
- Do not subscribe to heartbeat if already subscribed via metadata.

### Build system

- Add idna 0.5.0 exception into deny.toml.

### Documentation

- Update links to Node.js bindings in the README.

### Refactor

- Factor out `wait_for_all_work_done()`.

### Tests

- Notifiy more prominently & in more tests about false positives when running `cargo test` ([#6308](https://github.com/chatmail/core/pull/6308)).

## [1.151.5] - 2024-12-05

### API-Changes

- [**breaking**] Remove dc_all_work_done().

### Security

- cargo: Update rPGP to 0.14.2.

  This fixes [Panics on Malformed Untrusted Input](https://github.com/rpgp/rpgp/security/advisories/GHSA-9rmp-2568-59rv)
  and [Potential Resource Exhaustion when handling Untrusted Messages](https://github.com/rpgp/rpgp/security/advisories/GHSA-4grw-m28r-q285).
  This allows the attacker to crash the application via specially crafted messages and keys.
  We recommend all users and bot operators to upgrade to the latest version.
  There is no impact on the confidentiality of the messages and keys so no action other than upgrading is needed.

### Fixes

- Store plaintext in mime_headers of truncated sent messages ([#6273](https://github.com/chatmail/core/pull/6273)).

### Documentation

- Document `push` module.
- Remove mention of non-existent `nightly` feature.

### Tests

- Fix panic in `receive_emails` benchmark ([#6306](https://github.com/chatmail/core/pull/6306)).

## [1.151.4] - 2024-12-03

### Features / Changes

- Encrypt notification tokens.

### Fixes

- Replace connectivity state "Connected" with "Preparing".

### Miscellaneous Tasks

- Beta clippy suggestions ([#6271](https://github.com/chatmail/core/pull/6271)).

### Tests

- Fix `cargo check` for `receive_emails` benchmark.

### CI

- Also run cargo check without all-features.

## [1.151.3] - 2024-12-02

### API-Changes

- Remove experimental `request_internet_access` option from webxdc's `manifest.toml`.
- Add getWebxdcHref to json api ([#6281](https://github.com/chatmail/core/pull/6281)).

### CI

- Update Rust to 1.83.0.

### Documentation

- Update dc_msg_get_info_type() and dc_get_securejoin_qr() ([#6269](https://github.com/chatmail/core/pull/6269)).
- Fix references to iroh-related headers in peer_channels docs.
- Improve CFFI docs, link to corresponding JSON-RPC docs.

### Features / Changes

- Allow the user to replace maps integration ([#5678](https://github.com/chatmail/core/pull/5678)).
- Mark saved messages chat as protected.

### Fixes

- Close iroh endpoint when I/O is stopped.
- Do not add protection messages to Saved Messages chat.
- Mark Saved Messages chat as protected if it exists.
- Sync chat action even if sync message arrives before first one from contact ([#6259](https://github.com/chatmail/core/pull/6259)).

### Refactor

- Remove some .unwrap() calls.
- Create_status_update_record: Remove double check of info_msg_id.
- Use Option::or_else() to dedup emitting IncomingWebxdcNotify.

## [1.151.2] - 2024-11-26

### API-Changes

- Deprecate webxdc `descr` parameter ([#6255](https://github.com/chatmail/core/pull/6255)).

### Features / Changes

- AEAP: Check that the old peerstate verified key fingerprint hasn't changed when removing it.
- Add `AccountsChanged` and `AccountsItemChanged` events ([#6118](https://github.com/chatmail/core/pull/6118)).
- Do not use format=flowed in outgoing messages ([#6256](https://github.com/chatmail/core/pull/6256)).
- Add webxdc limits api.
- Add href to IncomingWebxdcNotify event ([#6266](https://github.com/chatmail/core/pull/6266)).

### Fixes

- Revert treating some transient SMTP errors as permanent.

### Refactor

- Create_status_update_record: Get rid of `notify` var.

### Tests

- Check that IncomingMsg isn't emitted for reactions.

## [1.151.1] - 2024-11-24

### Build system

- nix: Fix deltachat-rpc-server-source installable.

### CI

- Test building nix targets to avoid regressions.

## [1.151.0] - 2024-11-23

### Features / Changes

- Trim whitespace from scanned QR codes.
- Use privacy-preserving webxdc addresses ([#6237](https://github.com/chatmail/core/pull/6237)).
- Webxdc notify ([#6230](https://github.com/chatmail/core/pull/6230)).
- `update.href` api ([#6248](https://github.com/chatmail/core/pull/6248)).

### Fixes

- Never notify SELF ([#6251](https://github.com/chatmail/core/pull/6251)).

### Build system

- Use underscores in deltachat-rpc-server source package filename.
- Remove imap_tools from dependencies ([#6238](https://github.com/chatmail/core/pull/6238)).
- cargo: Update Rustls from 0.23.14 to 0.23.18.
- deps: Bump curve25519-dalek from 3.2.0 to 4.1.3 in /fuzz.

### Documentation

- Move style guide into a separate document.
- Clarify DC_EVENT_INCOMING_WEBXDC_NOTIFY documentation ([#6249](https://github.com/chatmail/core/pull/6249)).

### Tests

- After AEAP, 1:1 chat isn't available for sending, but unprotected groups are ([#6222](https://github.com/chatmail/core/pull/6222)).

## [1.150.0] - 2024-11-21

### API-Changes

- Correct `DC_CERTCK_ACCEPT_*` values and docs ([#6176](https://github.com/chatmail/core/pull/6176)).

### Features / Changes

- Use Rustls for connections with strict TLS ([#6186](https://github.com/chatmail/core/pull/6186)).
- Experimental header protection for Autocrypt.
- Tune down io-not-started info in connectivity-html.
- Clear config cache in start_io() ([#6228](https://github.com/chatmail/core/pull/6228)).
- Line-before-quote may be up to 120 character long instead of 80.
- Use i.delta.chat in qr codes ([#6223](https://github.com/chatmail/core/pull/6223)).

### Fixes

- Prevent accidental wrong-password-notifications ([#6122](https://github.com/chatmail/core/pull/6122)).
- Remove footers from "Show Full Message...".
- `send_msg_to_smtp`: Return Ok if `smtp` row is deleted in parallel.
- Only add "member added/removed" messages if they actually do that ([#5992](https://github.com/chatmail/core/pull/5992)).
- Do not fail to load chatlist summary if the message got removed.
- deltachat-jsonrpc: Do not fail `get_chatlist_items_by_entries` if the message got deleted.
- deltachat-jsonrpc: Do not fail `get_draft` if draft is deleted.
- `markseen_msgs`: Limit not yet downloaded messages state to `InNoticed` ([#2970](https://github.com/chatmail/core/pull/2970)).
- Update state of message when fully downloading it.
- Dont overwrite equal drafts ([#6212](https://github.com/chatmail/core/pull/6212)).

### Build system

- Silence RUSTSEC-2024-0384.
- cargo: Update rPGP from 0.13.2 to 0.14.0.
- cargo: Update futures-concurrency from 7.6.1 to 7.6.2.
- Update flake.nix ([#6200](https://github.com/chatmail/core/pull/6200))

### CI

- Ensure flake is formatted.

### Documentation

- Scanned proxies are added and normalized.

### Refactor

- Fix nightly clippy warnings.
- Remove slicing from `is_file_in_use`.
- Remove unnecessary `allow(clippy::indexing_slicing)`.
- Don't use slicing in `remove_nonstandard_footer`.
- Do not use slicing in `qr` module.
- Eliminate indexing in `compute_mailinglist_name`.
- Remove unused `allow(clippy::indexing_slicing)`.
- Remove indexing/slicing from `remove_message_footer`.
- Remove indexing/slicing from `squash_attachment_parts`.
- Remove unused allow(clippy::indexing_slicing) for heuristically_parse_ndn.
- Remove indexing/slicing from `parse_message_ids`.
- Remove slicing from `remove_bottom_quote`.
- Get rid of slicing in `remove_top_quote`.
- Remove unused allow(clippy::indexing_slicing) from 'truncate'.
- Forbid clippy::indexing_slicing.
- Forbid clippy::string_slice.
- Delete chat in a transaction.
- Fix typo in `context.rs`.

### Tests

- Remove all calls to print() from deltachat-rpc-client tests.
- Reply to protected group from MUA.
- Mark not downloaded message as seen ([#2970](https://github.com/chatmail/core/pull/2970)).
- Mark `receive_imf()` as only for tests and "internals" feature ([#6235](https://github.com/chatmail/core/pull/6235)).

## [1.149.0] - 2024-11-05

### Build system

- Update tokio to 1.41 and Android NDK to r27.
- `nix flake update android`.

### Fixes

- cargo: Update iroh to 0.28.1.
  This fixes the problem with iroh not sending the `Host:` header and not being able to connect to relays behind nginx reverse proxy.

## [1.148.7] - 2024-11-03

### API-Changes

- Add API to reset contact encryption.

### Features / Changes

- Emit chatlist events only if message still exists.

### Fixes

- send_msg_to_smtp: Do not fail if the message does not exist anymore.
- Do not percent-encode dot when passing to autoconfig server.
- Save contact name from SecureJoin QR to `authname`, not to `name` ([#6115](https://github.com/chatmail/core/pull/6115)).
- Always exit fake IDLE after at most 60 seconds.
- Concat NDNs ([#6129](https://github.com/chatmail/core/pull/6129)).

### Refactor

- Remove `has_decrypted_pgp_armor()`.

### Miscellaneous Tasks

- Update dependencies.

## [1.148.6] - 2024-10-31

### API-Changes

- Add Message::new_text() ([#6123](https://github.com/chatmail/core/pull/6123)).
- Add `MessageSearchResult.chat_id` ([#6120](https://github.com/chatmail/core/pull/6120)).

### Features / Changes

- Enable Webxdc realtime by default ([#6125](https://github.com/chatmail/core/pull/6125)).

### Fixes

- Save full text to mime_headers for long outgoing messages ([#6091](https://github.com/chatmail/core/pull/6091)).
- Show root SMTP connection failure in connectivity view ([#6121](https://github.com/chatmail/core/pull/6121)).
- Skip IDLE if we got unsolicited FETCH ([#6130](https://github.com/chatmail/core/pull/6130)).

### Miscellaneous Tasks

- Silence another rust-analyzer false-positive ([#6124](https://github.com/chatmail/core/pull/6124)).
- cargo: Upgrade iroh to 0.26.0.

### Refactor

- Directly use connectives ([#6128](https://github.com/chatmail/core/pull/6128)).
- Use Message::new_text() more ([#6127](https://github.com/chatmail/core/pull/6127)).

## [1.148.5] - 2024-10-27

### Fixes

- Set Config::NotifyAboutWrongPw before saving configuration ([#5896](https://github.com/chatmail/core/pull/5896)).
- Do not take write lock for maybe_network_lost() and set_push_device_token().
- Do not lock the account manager for the whole duration of background_fetch.

### Features / Changes

- Auto-restore 1:1 chat protection after receiving old unverified message.

### CI

- Take `CHATMAIL_DOMAIN` from variables instead of secrets.

### Other

- Revert "build: nix flake update fenix" to fix `nix build .#deltachat-rpc-server-armeabi-v7a-android`.

### Refactor

- Receive_imf::add_parts: Remove excessive `from_id == ContactId::SELF` checks.
- Factor out `add_gossip_peer_from_header()`.

## [1.148.4] - 2024-10-24

### Features / Changes

- Jsonrpc: add `private_tag` to `Account::Configured` Object ([#6107](https://github.com/chatmail/core/pull/6107)).

### Fixes

- Normalize proxy URLs before saving into proxy_url.
- Do not wait for connections in maybe_add_gossip_peers().

## [1.148.3] - 2024-10-24

### Fixes

- Fix reception of realtime advertisements.

### Features / Changes

- Allow sending realtime messages up to 128 KB in size.

### API-Changes

- deltachat-rpc-client: Add EventType.WEBXDC_REALTIME_ADVERTISEMENT_RECEIVED.

### Documentation

- Fix DC_QR_PROXY docs ([#6099](https://github.com/chatmail/core/pull/6099)).

### Refactor

- Generate topic inside create_iroh_header().

### Tests

- Test that realtime advertisements work after chatting.

## [1.148.2] - 2024-10-23

### Fixes

- Never initialize Iroh if realtime is disabled.

### Features / Changes

- Add more logging for iroh initialization and peer addition.

### Build system

- `nix flake update nixpkgs`.
- `nix flake update fenix`.

## [1.148.1] - 2024-10-23

### Build system

- Revert "build: nix flake update"

This reverts commit 6f22ce2722b51773d7fbb0d89e4764f963cafd91..

## [1.148.0] - 2024-10-22

### API-Changes

- Create QR codes from any data ([#6090](https://github.com/chatmail/core/pull/6090)).
- Add delta chat logo to QR codes ([#6093](https://github.com/chatmail/core/pull/6093)).
- Add realtime advertisement received event ([#6043](https://github.com/chatmail/core/pull/6043)).
- Notify adding reactions ([#6072](https://github.com/chatmail/core/pull/6072))
- Internal profile names ([#6088](https://github.com/chatmail/core/pull/6088)).

### Features / Changes

- IMAP COMPRESS support.
- Sort received outgoing message down if it's fresher than all non fresh messages.
- Prioritize cached results if DNS resolver returns many results.
- Add in-memory cache for DNS.
- deltachat-repl: Built-in QR code printer.
- Log the logic for (not) doing AEAP.
- Log when late Autocrypt header is ignored.
- Add more context to `send_msg` errors.

### Fixes

- Replace old draft with a new one atomically.
- ChatId::maybe_delete_draft: Don't delete message if it's not a draft anymore ([#6053](https://github.com/chatmail/core/pull/6053)).
- Call update_connection_history for proxified connections.
- sql: Set PRAGMA query_only to avoid writing on read-only connections.
- sql: Run `PRAGMA incremental_vacuum` on a write connection.
- Increase MAX_SECONDS_TO_LEND_FROM_FUTURE to 30.

### Build system

- Nix flake update.
- Resolve warning about default-features, and make it possible to disable vendoring ([#6079](https://github.com/chatmail/core/pull/6079)).
- Silence a rust-analyzer false-positive ([#6077](https://github.com/chatmail/core/pull/6077)).

### CI

- Update Rust to 1.82.0.

### Documentation

- Set_protection_for_timestamp_sort does not send messages.
- Document MimeFactory.req_mdn.
- Fix `too_long_first_doc_paragraph` clippy lint.

### Refactor

- Update_msg_state: Don't avoid downgrading OutMdnRcvd to OutDelivered.
- Fix elided_named_lifetimes warning.
- set_protection_for_timestamp_sort: Do not log bubbled up errors.
- Fix clippy::needless_lifetimes warnings.
- Use `HeaderDef` constant for Chat-Disposition-Notification-To.
- Resultify get_self_fingerprint().
- sql: Move write mutex into connection pool.

### Tests

- test_qr_setup_contact_svg: Stop testing for no display name.
- Always gossip if gossip_period is set to 0.
- test_aeap_flow_verified: Wait for "member added" before sending messages ([#6057](https://github.com/chatmail/core/pull/6057)).
- Make test_verified_group_member_added_recovery more reliable.
- test_aeap_flow_verified: Do not start ac1new.
- Fix `test_securejoin_after_contact_resetup` flakiness.
- Message from old setup preserves contact verification, but breaks 1:1 protection.

## [1.147.1] - 2024-10-13

### Build system

- Build Python 3.13 wheels.
- deltachat-rpc-client: Add classifiers for all supported Python versions.

### CI

- Update to Python 3.13.

### Documentation

- CONTRIBUTING.md: Add a note on deleting/changing db columns.

### Fixes

- Reset quota on configured address change ([#5908](https://github.com/chatmail/core/pull/5908)).
- Do not emit progress 1000 when configuration is canceled.
- Assume file extensions are 32 chars max and don't contain whitespace ([#5338](https://github.com/chatmail/core/pull/5338)).
- Re-add tokens.foreign_id column ([#6038](https://github.com/chatmail/core/pull/6038)).

### Miscellaneous Tasks

- cargo: Bump futures-* from 0.3.30 to 0.3.31.
- cargo: Upgrade async_zip to 0.0.17 ([#6035](https://github.com/chatmail/core/pull/6035)).

### Refactor

- MsgId::update_download_state: Don't fail if the message doesn't exist anymore.

## [1.147.0] - 2024-10-05

### API-Changes

- [**breaking**] Remove deprecated get_next_media() APIs.

### Features / Changes

- Reuse existing connections in background_fetch() if I/O is started.
- MsgId::get_info(): Report original filename as well.
- More context for the "Cannot establish guaranteed..." info message ([#6022](https://github.com/chatmail/core/pull/6022)).
- deltachat-repl: Add `fetch` command to test `background_fetch()`.
- deltachat-repl: Print send-backup QR code to the terminal.

### Fixes

- Do not attempt to reference info messages.
- query_row_optional: Do not treat rows with NULL as missing rows.
- Skip unconfigured folders in `background_fetch()`.
- Break out of accept() loop if there is an error transferring backup.
- Make it possible to cancel ongoing backup transfer.
- Make backup reception cancellable by stopping ongoing process.
- Smooth progress bar for backup transfer.
- Emit progress 0 if get_backup() fails.

### Documentation

- CONTRIBUTING.md: Add more SQL advices.

## [1.146.0] - 2024-10-03

### Fixes

- download_msg: Do not fail if the message does not exist anymore.
- Better log message for failed QR scan.

### Features / Changes

- Assign message to ad-hoc group with matching name and members ([#5385](https://github.com/chatmail/core/pull/5385)).
- Use Rustls instead of native TLS for HTTPS requests.

### Miscellaneous Tasks

- cargo: Bump anyhow from 1.0.86 to 1.0.89.
- cargo: Bump tokio-stream from 0.1.15 to 0.1.16.
- cargo: Bump thiserror from 1.0.63 to 1.0.64.
- cargo: Bump bytes from 1.7.1 to 1.7.2.
- cargo: Bump libc from 0.2.158 to 0.2.159.
- cargo: Bump tempfile from 3.10.1 to 3.13.0.
- cargo: Bump pretty_assertions from 1.4.0 to 1.4.1.
- cargo: Bump hyper-util from 0.1.7 to 0.1.9.
- cargo: Bump rustls-pki-types from 1.8.0 to 1.9.0.
- cargo: Bump quick-xml from 0.36.1 to 0.36.2.
- cargo: Bump serde from 1.0.209 to 1.0.210.
- cargo: Bump syn from 2.0.77 to 2.0.79.

### Refactor

- Move group name calculation out of create_adhoc_group().
- Merge build_tls() function into wrap_tls().

## [1.145.0] - 2024-09-26

### Fixes

- Avoid changing `delete_server_after` default for existing configurations.

### Miscellaneous Tasks

- Sort dependency list.

### Refactor

- Do not wrap shadowsocks::ProxyClientStream.

## [1.144.0] - 2024-09-21

### API-Changes

- [**breaking**] Make QR code type for proxy not specific to SOCKS5 ([#5980](https://github.com/chatmail/core/pull/5980)).

  `DC_QR_SOCKS5_PROXY` is replaced with `DC_QR_PROXY`.

### Features / Changes

- Make resending OutPending messages possible ([#5817](https://github.com/chatmail/core/pull/5817)).
- Don't SMTP-send messages to self-chat if BccSelf is disabled.
- HTTP(S) tunneling.
- Don't put displayname into From/To/Sender if it equals to address ([#5983](https://github.com/chatmail/core/pull/5983)).
- Use IMAP APPEND command to upload sync messages ([#5845](https://github.com/chatmail/core/pull/5845)).
- Generate 144-bit group IDs.
- smtp: More verbose SMTP connection establishment errors.
- Log unexpected message state when resending fails.

### Fixes

- Save QR code token regardless of whether the group exists ([#5954](https://github.com/chatmail/core/pull/5954)).
- Shorten message text in locally sent messages too ([#2281](https://github.com/chatmail/core/pull/2281)).

### Documentation

- CONTRIBUTING.md: Document how to format SQL statements.

### Miscellaneous Tasks

- Update provider database.
- cargo: Update iroh to 0.25.
- cargo: Update lazy_static to 1.5.0.
- deps: Bump async-imap from 0.10.0 to 0.10.1.

### Refactor

- Do not store deprecated `addr` and `is_default` into `keypairs`.
- Remove `addr` from KeyPair.
- Use `KeyPair::new()` in `create_keypair()`.

## [1.143.0] - 2024-09-12

### Features / Changes

- Automatic reconfiguration, e.g. switching to implicit TLS if STARTTLS port stops working.
- Always use preloaded DNS results.
- Add "Auto-Submitted: auto-replied" header to appropriate SecureJoin messages.
- Parallelize IMAP and SMTP connection attempts ([#5915](https://github.com/chatmail/core/pull/5915)).
- securejoin: Ignore invalid *-request-with-auth messages silently.
- ChatId::create_for_contact_with_blocked: Don't emit events on no op.
- Delete messages from a chatmail server immediately by default ([#5805](https://github.com/chatmail/core/pull/5805)) ([#5840](https://github.com/chatmail/core/pull/5840)).
- Shadowsocks support.
- Recognize t.me SOCKS5 proxy QR codes ([#5895](https://github.com/chatmail/core/pull/5895))
- Remove old iroh 0.4 and support for old `DCBACKUP` QR codes.

### Fixes

- http: Set I/O timeout to 1 minute rather than whole request timeout.
- Add Auto-Submitted header in a single place.
- Do not allow quotes with "... wrote:" headers in chat messages.
- Don't sync QR code token before populating the group ([#5935](https://github.com/chatmail/core/pull/5935)).

### Documentation

- Document that `bcc_self` is enabled by default.

### CI

- Update Rust to 1.81.0.

### Miscellaneous Tasks

- Update provider database.
- cargo: Update iroh to 0.23.0.
- cargo: Reduce number of duplicate dependencies.
- cargo: Replace unmaintained ansi_term with nu-ansi-term.
- Replace `reqwest` with direct usage of `hyper`.

### Refactor

- login_param: Use Config:: constants to avoid typos in key names.
- Make Context::config_exists() crate-public.
- Get_config_bool_opt(): Return None if only default value exists.

### Tests

- Test that alternative port 443 works.
- Alice is (non-)bot on Bob's side after QR contact setup.

## [1.142.12] - 2024-09-02

### Fixes

- Display Config::MdnsEnabled as true by default ([#5948](https://github.com/chatmail/core/pull/5948)).

## [1.142.11] - 2024-08-30

### Fixes

- Set backward verification when observing vc-contact-confirm or `vg-member-added` ([#5930](https://github.com/chatmail/core/pull/5930)).

## [1.142.10] - 2024-08-26

### Fixes

- Only include one From: header in securejoin messages ([#5917](https://github.com/chatmail/core/pull/5917)).

## [1.142.9] - 2024-08-24

### Fixes

- Fix reading of multiline SMTP greetings ([#5911](https://github.com/chatmail/core/pull/5911)).

### Features / Changes

- Update preloaded DNS cache.

## [1.142.8] - 2024-08-21

### Fixes

- Do not panic on unknown CertificateChecks values.

## [1.142.7] - 2024-08-17

### Fixes

- Do not save "Automatic" into configured_imap_certificate_checks. **This fixes regression introduced in core 1.142.4. Versions 1.142.4..1.142.6 should not be used in releases.**
- Create a group unblocked for bot even if 1:1 chat is blocked ([#5514](https://github.com/chatmail/core/pull/5514)).
- Update rpgp from 0.13.1 to 0.13.2 to fix "unable to decrypt" errors when sending messages to old Delta Chat clients and using Ed25519 keys to encrypt.
- Do not request ALPN on standard ports and when using STARTTLS.

### Features / Changes

- jsonrpc: Add ContactObject::e2ee_avail.

### Tests

- Protected group for bot is auto-accepted.

## [1.142.6] - 2024-08-15

### Fixes

- Default to strict TLS checks if not configured.

### Miscellaneous Tasks

- deltachat-rpc-client: Fix ruff 0.6.0 warnings.

## [1.142.5] - 2024-08-14

### Fixes

- Still try to create "INBOX.DeltaChat" if couldn't create "DeltaChat" ([#5870](https://github.com/chatmail/core/pull/5870)).
- `store_seen_flags_on_imap`: Skip to next messages if couldn't select folder ([#5870](https://github.com/chatmail/core/pull/5870)).
- Increase timeout for QR generation to 60s ([#5882](https://github.com/chatmail/core/pull/5882)).

### Documentation

- Document new `mdns_enabled` behavior (bots do not send MDNs by default).

### CI

- Configure Dependabot to update GitHub Actions.

### Miscellaneous Tasks

- cargo: Bump regex from 1.10.5 to 1.10.6.
- cargo: Bump serde from 1.0.204 to 1.0.205.
- deps: Bump horochx/deploy-via-scp from 1.0.1 to 1.1.0.
- deps: Bump dependabot/fetch-metadata from 1.1.1 to 2.2.0.
- deps: Bump actions/setup-node from 2 to 4.
- Update provider database.

## [1.142.4] - 2024-08-09

### Build system

- Downgrade Tokio to 1.38 to fix Android compilation.
- Use `--locked` with `cargo install`.

### Features / Changes

- Add Config::FixIsChatmail.
- Always move outgoing auto-generated messages to the mvbox.
- Disable requesting MDNs for bots by default.
- Allow using OAuth 2 with SOCKS5.
- Allow autoconfig when SOCKS5 is enabled.
- Update provider database.
- cargo: Update iroh from 0.21 to 0.22 ([#5860](https://github.com/chatmail/core/pull/5860)).

### CI

- Update Rust to 1.80.1.
- Update EmbarkStudios/cargo-deny-action.

### Documentation

- Point to active Header Protection draft

### Refactor

- Derive `Default` for `CertificateChecks`.
- Merge imap_certificate_checks and smtp_certificate_checks.
- Remove param_addr_urlencoded argument from get_autoconfig().
- Pass address to moz_autoconfigure() instead of LoginParam.

## [1.142.3] - 2024-08-04

### Build system

- cargo: Update rusqlite and libsqlite3-sys.
- Fix cargo warnings about default-features
- Do not disable "vendored" feature in the workspace.
- cargo: Bump quick-xml from 0.35.0 to 0.36.1.
- cargo: Bump uuid from 1.9.1 to 1.10.0.
- cargo: Bump tokio from 1.38.0 to 1.39.2.
- cargo: Bump env_logger from 0.11.3 to 0.11.5.
- Remove sha2 dependency.
- Remove `backtrace` dependency.
- Remove direct "quinn" dependency.

## [1.142.2] - 2024-08-02

### Features / Changes

- Try only the full email address if username is unspecified.
- Sort DNS results by successful connection timestamp ([#5818](https://github.com/chatmail/core/pull/5818)).

### Fixes

- Await the tasks after aborting them.
- Do not reset is_chatmail config on failed reconfiguration.
- Fix compilation on iOS.
- Reset configured_provider on reconfiguration.

### Refactor

- Don't update message state to `OutMdnRcvd` anymore.

### Build system

- Use workspace dependencies to make cargo-deny 0.15.1 happy.
- cargo: Update bytemuck from 0.14.3 to 0.16.3.
- cargo: Bump toml from 0.8.14 to 0.8.15.
- cargo: Bump serde_json from 1.0.120 to 1.0.122.
- cargo: Bump human-panic from 2.0.0 to 2.0.1.
- cargo: Bump thiserror from 1.0.61 to 1.0.63.
- cargo: Bump syn from 2.0.68 to 2.0.72.
- cargo: Bump quoted_printable from 0.5.0 to 0.5.1.
- cargo: Bump serde from 1.0.203 to 1.0.204.

## [1.142.1] - 2024-07-30

### Features / Changes

- Do not reveal sender's language in read receipts ([#5802](https://github.com/chatmail/core/pull/5802)).
- Try next DNS resolution result if TLS setup fails.
- Report first error instead of the last on connection failure.

### Fixes

- smtp: Use DNS cache for implicit TLS connections.
- Imex::import_backup: Unpack all blobs before importing a db ([#4307](https://github.com/chatmail/core/pull/4307)).
- Import_backup_stream: Fix progress stucking at 0.
- Sql::import: Detach backup db if any step of the import fails.
- Imex::import_backup: Ignore errors from delete_and_reset_all_device_msgs().
- Explicitly close the database on account removal.

### Miscellaneous Tasks

- cargo: Update time from 0.3.34 to 0.3.36.
- cargo: Update iroh from 0.20.0 to 0.21.0.

### Refactor

- Add net/dns submodule.
- Pass single ALPN around instead of ALPN list.
- Replace {IMAP,SMTP,HTTP}_TIMEOUT with a single constant.
- smtp: Unify SMTP connection setup between TLS and STARTTLS.
- imap: Unify IMAP connection setup in Client::connect().
- Move DNS resolution into IMAP and SMTP connect code.

### CI

- Update Rust to 1.80.0.

## [1.142.0] - 2024-07-23

### API-Changes

- deltachat-jsonrpc: Add `pinned` property to `FullChat` and `BasicChat`.
- deltachat-jsonrpc: Allow to set message quote text without referencing quoted message ([#5695](https://github.com/chatmail/core/pull/5695)).

### Features / Changes

- cargo: Update iroh from 0.17 to 0.20.
- iroh: Pass direct addresses from Endpoint to Gossip.
- New BACKUP2 transfer protocol.
- Use `[...]` instead of `...` for protected subject.
- Add email address and fingerprint to exported key file names ([#5694](https://github.com/chatmail/core/pull/5694)).
- Request `imap` ALPN for IMAP TLS connections and `smtp` ALPN for SMTP TLS connections.
- Limit the size of aggregated WebXDC update to 100 KiB ([#4825](https://github.com/chatmail/core/pull/4825)).
- Don't create ad-hoc group on a member removal message ([#5618](https://github.com/chatmail/core/pull/5618)).
- Don't unarchive a group on a member removal except SELF ([#5618](https://github.com/chatmail/core/pull/5618)).
- Use custom DNS resolver for HTTP(S).
- Promote fallback DNS results to cached on successful use.
- Set summary thumbnail path for WebXDCs to "webxdc-icon://last-msg-id" ([#5782](https://github.com/chatmail/core/pull/5782)).
- Do not show the address in invite QR code SVG.
- Report better error from DcKey::from_asc() ([#5539](https://github.com/chatmail/core/pull/5539)).
- Contact::create_ex: Don't send sync message if nothing changed ([#5705](https://github.com/chatmail/core/pull/5705)).

### Fixes

- `Message::set_quote`: Don't forget to remove `Param::ProtectQuote`.
- Randomize avatar blob filenames to work around caching.
- Correct copy-pasted DCACCOUNT parsing errors message.
- Call `send_sync_msg()` only from the SMTP loop ([#5780](https://github.com/chatmail/core/pull/5780)).
- Emit MsgsChanged if the number of unnoticed archived chats could decrease ([#5768](https://github.com/chatmail/core/pull/5768)).
- Reject message with forged From even if no valid signatures are found.

### Refactor

- Move key transfer into its own submodule.
- Move TempPathGuard into `tools` and use instead of `DeleteOnDrop`.
- Return error from export_backup() without logging.
- Reduce boilerplate for migration version increment.

### Tests

- Add test for `get_http_response` JSON-RPC call.

### Build system

- node: Pin node-gyp to version 10.1.

### Miscellaneous Tasks

- cargo: Update hashlink to remove allocator-api2 dependency.
- cargo: Update openssl to v0.10.66.
- deps: Bump openssl from 0.10.60 to 0.10.66 in /fuzz.
- cargo: Update `image` crate to 0.25.2.

## [1.141.2] - 2024-07-09

### Features / Changes

- Add `is_muted` config option.
- Parse vcards exported by protonmail ([#5723](https://github.com/chatmail/core/pull/5723)).
- Disable sending sync messages for bots ([#5705](https://github.com/chatmail/core/pull/5705)).

### Fixes

- Don't fail if going to send plaintext, but some peerstate is missing.
- Correctly sanitize input everywhere ([#5697](https://github.com/chatmail/core/pull/5697)).
- Do not try to register non-iOS tokens for heartbeats.
- imap: Reset new_mail if folder is ignored.
- Use and prefer Date from signed message part ([#5716](https://github.com/chatmail/core/pull/5716)).
- Distinguish between database errors and no gossip topic.
- MimeFactory::verified: Return true for self-chat.

### Refactor

- `MimeFactory::is_e2ee_guaranteed()`: always respect `Param::ForcePlaintext`.
- Protect from reusing migration versions ([#5719](https://github.com/chatmail/core/pull/5719)).
- Move `quota_needs_update` calculation to a separate function ([#5683](https://github.com/chatmail/core/pull/5683)).

### Documentation

- Document vCards in the specification ([#5724](https://github.com/chatmail/core/pull/5724))

### Miscellaneous Tasks

- cargo: Bump toml from 0.8.13 to 0.8.14.
- cargo: Bump serde_json from 1.0.117 to 1.0.120.
- cargo: Bump syn from 2.0.66 to 2.0.68.
- cargo: Bump async-broadcast from 0.7.0 to 0.7.1.
- cargo: Bump url from 2.5.0 to 2.5.2.
- cargo: Bump log from 0.4.21 to 0.4.22.
- cargo: Bump regex from 1.10.4 to 1.10.5.
- cargo: Bump proptest from 1.4.0 to 1.5.0.
- cargo: Bump uuid from 1.8.0 to 1.9.1.
- cargo: Bump backtrace from 0.3.72 to 0.3.73.
- cargo: Bump quick-xml from 0.31.0 to 0.35.0.
- cargo: Update yerpc to 0.6.2.
- cargo: Update rPGP from 0.11 to 0.13.

## [1.141.1] - 2024-06-27

### Fixes

- Update quota if it's stale, not fresh ([#5683](https://github.com/chatmail/core/pull/5683)).
- sql: Assign migration adding msgs.deleted a new number.

### Refactor

- mimefactory: Factor out header confidentiality policy ([#5715](https://github.com/chatmail/core/pull/5715)).
- Improve logging during SMTP/IMAP configuration.

## [1.141.0] - 2024-06-24

### API-Changes

- deltachat-jsonrpc: Add `get_chat_securejoin_qr_code()`.
- api!(deltachat-rpc-client): make {Account,Chat}.get_qr_code() return no SVG
  This is a breaking change, old method is renamed into `get_qr_code_svg()`.

### Features / Changes

- Prefer references to fully downloaded messages for chat assignment ([#5645](https://github.com/chatmail/core/pull/5645)).
- Protect From name for verified chats and To names for encrypted chats ([#5166](https://github.com/chatmail/core/pull/5166)).
- Display vCard contact name in the message summary.
- Case-insensitive search for non-ASCII messages ([#5052](https://github.com/chatmail/core/pull/5052)).
- Remove subject prefix from ad-hoc group names ([#5385](https://github.com/chatmail/core/pull/5385)).
- Replace "Unnamed group" with "👥📧" to avoid translation.
- Sync `Config::MvboxMove` across devices ([#5680](https://github.com/chatmail/core/pull/5680)).
- Don't reveal profile data to a not yet verified contact ([#5166](https://github.com/chatmail/core/pull/5166)).
- Don't reveal profile data in MDNs ([#5166](https://github.com/chatmail/core/pull/5166)).

### Fixes

- Fetch existing messages for bots as `InFresh` ([#4976](https://github.com/chatmail/core/pull/4976)).
- Keep tombstones for two days before deleting ([#3685](https://github.com/chatmail/core/pull/3685)).
- Housekeeping: Delete MDNs and webxdc status updates for tombstones.
- Delete user-deleted messages on the server even if they show up on IMAP later.
- Do not send sync messages if bcc_self is disabled.
- Don't generate Config sync messages for unconfigured accounts.
- Do not require the Message to render MDN.

### CI

- Update Rust to 1.79.0.

### Documentation

- Remove outdated documentation comment from `send_smtp_messages`.
- Remove misleading configuration comment.

### Miscellaneous Tasks

- Update curve25519-dalek 4.1.x and suppress 3.2.0 warning.
- Update provider database.

### Refactor

- Deduplicate dependency versions ([#5691](https://github.com/chatmail/core/pull/5691)).
- Store public key instead of secret key for peer channels.

### Tests

- Image drafted as Viewtype::File is sent as is.
- python: Set delete_server_after=1 ("delete immediately") for bots ([#4976](https://github.com/chatmail/core/pull/4976)).
- deltachat-rpc-client: Test that webxdc realtime data is not reordered on the sender.
- python: Wait for bot's DC_EVENT_IMAP_INBOX_IDLE before sending messages to it ([#5699](https://github.com/chatmail/core/pull/5699)).

## [1.140.2] - 2024-06-07

### API-Changes

- jsonrpc: Add set_draft_vcard(.., msg_id, contacts).

### Fixes

- Allow fetch_existing_msgs for bots ([#4976](https://github.com/chatmail/core/pull/4976)).
- Remove group member locally even if send_msg() fails ([#5508](https://github.com/chatmail/core/pull/5508)).
- Revert member addition if the corresponding message couldn't be sent ([#5508](https://github.com/chatmail/core/pull/5508)).
- @deltachat/stdio-rpc-server: Make local non-symlinked installation possible by using absolute paths for local dev version ([#5679](https://github.com/chatmail/core/pull/5679)).

### Miscellaneous Tasks

- cargo: Bump schemars from 0.8.19 to 0.8.21.
- cargo: Bump backtrace from 0.3.71 to 0.3.72.

### Refactor

- @deltachat/stdio-rpc-server: Use old school require instead of the experimental json import ([#5628](https://github.com/chatmail/core/pull/5628)).

### Tests

- Set fetch_existing_msgs for bots ([#4976](https://github.com/chatmail/core/pull/4976)).
- Don't leave protected group if some member's key is missing ([#5508](https://github.com/chatmail/core/pull/5508)).

## [1.140.1] - 2024-06-05

### Fixes

- Retry sending MDNs on temporary error.
- Set Config::IsChatmail in configure().
- Do not miss new messages while expunging the folder.
- Log messages with `info!` instead of `println!`.

### Documentation

- imap: Document why CLOSE is faster than EXPUNGE.

### Refactor

- imap: Make select_folder() accept non-optional folder.
- Improve SMTP logs and errors.
- Remove unused `select_folder::Error` variants.

### Tests

- deltachat-rpc-client: re-enable `log_cli`.

## [1.140.0] - 2024-06-04

### Features / Changes

- Remove limit on number of email recipients for chatmail clients ([#5598](https://github.com/chatmail/core/pull/5598)).
- Add config option to enable iroh ([#5607](https://github.com/chatmail/core/pull/5607)).
- Map `*.wav` to Viewtype::Audio ([#5633](https://github.com/chatmail/core/pull/5633)).
- Add a db index for reactions by msg_id ([#5507](https://github.com/chatmail/core/pull/5507)).

### Fixes

- Set Param::Bot for messages on the sender side as well ([#5615](https://github.com/chatmail/core/pull/5615)).
- AEAP: Remove old peerstate verified_key instead of removing the whole peerstate ([#5535](https://github.com/chatmail/core/pull/5535)).
- Allow creation of groups by outgoing messages without recipients.
- Prefer `Chat-Group-ID` over references for new groups.
- Do not fail to send images with wrong extensions.

### Build system

- Unpin OpenSSL version and update to OpenSSL 3.3.0.

### CI

- Remove cargo-nextest bug workaround.

### Documentation

- Add vCard as supported standard.
- Create_group() does not find chats, only creates them.
- Fix a typo in test_partial_group_consistency().

### Refactor

- Factor create_adhoc_group() call out of create_group().
- Put duplicate code into `lookup_chat_or_create_adhoc_group`.

### Tests

- Fix logging of TestContext created using TestContext::new_alice().
- Refactor `test_alias_*` into 8 separate tests.

## [1.139.6] - 2024-05-25

### Build system

- Update `iroh` to the git version.
- nix: Add iroh-base output hash.
- Upgrade iroh to 0.17.0.

### Fixes

- @deltachat/stdio-rpc-server: Do not set RUST_LOG to "info" by default.
- Acquire write lock on iroh_channels before checking for subscribe_loop.

### Miscellaneous Tasks

- Fix python lint.
- cargo-deny: Remove unused entry from deny.toml.

### Refactor

- Log IMAP connection type on connection failure.

### Tests

- Viewtype::File attachments are sent unchanged and preserve extensions.
- deltachat-rpc-client: Add realtime channel tests.
- deltachat-rpc-client: Regression test for double gossip subscription.

## [1.139.5] - 2024-05-23

### API-Changes

- deltachat-ffi: Make WebXdcRealtimeData data usable in CFFI.
- Add event channel overflow event.
- deltachat-rpc-client: Add EventType.WEBXDC_REALTIME_DATA constant.
- deltachat-rpc-client: Add Message.send_webxdc_realtime_advertisement().
- deltachat-rpc-client: Add Message.send_webxdc_realtime_data().

### Features / Changes

- deltachat-repl: Add start-realtime and send-realtime commands.

### Fixes

- peer_channels: Connect to peers that advertise to you.
- Don't recode images in `Viewtype::File` messages ([#5617](https://github.com/chatmail/core/pull/5617)).

### Tests

- peer_channels: Add test_parallel_connect().
- "SecureJoin wait" state and info messages.

## [1.139.4] - 2024-05-21

### Features / Changes

- Scale up contact origins to OutgoingTo when sending a message.
- Add import_vcard() ([#5202](https://github.com/chatmail/core/pull/5202)).

### Fixes

- Do not log warning if iroh relay metadata is NIL.
- contact-tools: Parse_vcard: Support `\r\n` newlines.
- Make_vcard: Add authname and key for ContactId::SELF.

### Other

- nix: Add nextest ([#5610](https://github.com/chatmail/core/pull/5610)).

## [1.139.3] - 2024-05-20

### API-Changes

- [**breaking**] @deltachat/stdio-rpc-server: change api: don't search in path unless `options.takeVersionFromPATH` is set to `true`
- @deltachat/stdio-rpc-server: remove `DELTA_CHAT_SKIP_PATH` environment variable
- @deltachat/stdio-rpc-server: remove version check / search for dc rpc server in $PATH
- @deltachat/stdio-rpc-server: remove `options.skipSearchInPath`
- @deltachat/stdio-rpc-server: add `options.takeVersionFromPATH`
- deltachat-rpc-client: Add Account.wait_for_incoming_msg().

### Features / Changes

- Replace env_logger with tracing_subscriber.

### Fixes

- Ignore event channel overflows.
- mimeparser: Take the last header of multiple ones with the same name.
- Db migration version 59, it contained an sql syntax error.
- Sql syntax error in db migration 27.
- Log/print exit error of deltachat-rpc-server ([#5601](https://github.com/chatmail/core/pull/5601)).
- @deltachat/stdio-rpc-server: set default options for `startDeltaChat`.
- Always convert absolute paths to relative in accounts.toml.

### Refactor

- receive_imf: Do not check for ContactId::UNDEFINED.
- receive_imf: Remove unnecessary check for is_mdn.
- receive_imf: Only call create_or_lookup_group() with allow_creation=true.
- Use let..else in create_or_lookup_group().
- Stop trying to extract chat ID from Message-IDs.
- Do not try to lookup group in create_or_lookup_group().

## [1.139.2] - 2024-05-18

### Build system

- Add repository URL to @deltachat/jsonrpc-client.

## [1.139.1] - 2024-05-18

### CI

- Set `--access public` when publishing to npm.

## [1.139.0] - 2024-05-18

### Features / Changes

- Ephemeral peer channels ([#5346](https://github.com/chatmail/core/pull/5346)).

### Fixes

- Save override sender displayname for outgoing messages.
- Do not mark the message as seen if it has `location.kml`.
- @deltachat/stdio-rpc-server: fix version check when deltachat-rpc-server is found in path ([#5579](https://github.com/chatmail/core/pull/5579)).
- @deltachat/stdio-rpc-server: fix local desktop development ([#5583](https://github.com/chatmail/core/pull/5583)).
- @deltachat/stdio-rpc-server: rename `shutdown` method to `close` and add `muteStdErr` option to mute the stderr output ([#5588](https://github.com/chatmail/core/pull/5588))
- @deltachat/stdio-rpc-server: fix `convert_platform.py`: 32bit `i32` -> `ia32` ([#5589](https://github.com/chatmail/core/pull/5589))
- @deltachat/stdio-rpc-server: fix example ([#5580](https://github.com/chatmail/core/pull/5580))

### API-Changes

- deltachat-jsonrpc: Return vcard contact directly in MessageObject.
- deltachat-jsonrpc: Add api `migrate_account` and `get_blob_dir` ([#5584](https://github.com/chatmail/core/pull/5584)).
- deltachat-rpc-client: Add ViewType.VCARD constant.
- deltachat-rpc-client: Add Contact.make_vcard().
- deltachat-rpc-client: Add Chat.send_contact().

### CI

- Publish @deltachat/jsonrpc-client directly to npm.
- Check that constants are always up-to-date.

### Build system

- nix: Add git-cliff to flake.
- nix: Use rust-analyzer nightly

### Miscellaneous Tasks

- cargo: Downgrade libc from 0.2.154 to 0.2.153.

### Tests

- deltachat-rpc-client: Test sending vCard.

## [1.138.5] - 2024-05-16

### API-Changes

- jsonrpc: Add parse_vcard() ([#5202](https://github.com/chatmail/core/pull/5202)).
- Add Viewtype::Vcard ([#5202](https://github.com/chatmail/core/pull/5202)).
- Add make_vcard() ([#5203](https://github.com/chatmail/core/pull/5203)).

### Build system

- Add repository URL to deltachat-rpc-server packages.

### Fixes

- Parsing vCards with avatars exported by Android's "Contacts" app.

### Miscellaneous Tasks

- Rebuild node constants.

### Refactor

- contact-tools: VcardContact: rename display_name to authname.
- VcardContact: Change timestamp type to i64.

## [1.138.4] - 2024-05-15

### CI

- Run actions/setup-node before npm publish.

## [1.138.3] - 2024-05-15

### CI

- Give CI job permission to publish binaries to the release.

## [1.138.2] - 2024-05-15

### API-Changes

- deltachat-rpc-client: Add CONFIG_SYNCED constant.

### CI

- Add npm token to publish deltachat-rpc-server packages.

### Features / Changes

- Reset more settings when configuring a chatmail account.

### Tests

- Set configuration after configure() finishes.

## [1.138.1] - 2024-05-14

### Features / Changes

- Detect XCHATMAIL capability and expose it as `is_chatmail` config.

### Fixes

- Never treat message with Chat-Group-ID as a private reply.
- Always prefer Chat-Group-ID over In-Reply-To and References.
- Ignore parent message if message references itself.

### CI

- Set RUSTUP_WINDOWS_PATH_ADD_BIN to work around `nextest` issue <https://github.com/nextest-rs/nextest/issues/1493>.
- deltachat-rpc-server: Fix upload of npm packages to github releases ([#5564](https://github.com/chatmail/core/pull/5564)).

### Refactor

- Add MimeMessage.get_chat_group_id().
- Make MimeMessage.get_header() return Option<&str>.
- sql: Make open flags immutable.
- Resultify token::lookup_or_new().

### Miscellaneous Tasks

- cargo: Bump parking_lot from 0.12.1 to 0.12.2.
- cargo: Bump libc from 0.2.153 to 0.2.154.
- cargo: Bump hickory-resolver from 0.24.0 to 0.24.1.
- cargo: Bump serde_json from 1.0.115 to 1.0.116.
- cargo: Bump human-panic from 1.2.3 to 2.0.0.
- cargo: Bump brotli from 5.0.0 to 6.0.0.

## [1.138.0] - 2024-05-13

### API-Changes

- Add dc_msg_save_file() which saves file copy at the provided path ([#4309](https://github.com/chatmail/core/pull/4309)).
- Api!(jsonrpc): replace EphemeralTimer tag "variant" with "kind"

### CI

- Use rsync instead of 3rd party github action.
- Replace `black` with `ruff format`.
- Update Rust to 1.78.0.

### Documentation

- Fix references in Message.set_location() documentation.
- Remove Doxygen markup from Message.has_location().
- Add `location` module documentation.

### Features / Changes

- Delete expired path locations in ephemeral loop.
- Delete orphaned POI locations during housekeeping.
- Parsing vCards for contacts sharing ([#5482](https://github.com/chatmail/core/pull/5482)).
- contact-tools: Support parsing profile images from "PHOTO:data:image/jpeg;base64,...".
- contact-tools: Add make_vcard().
- Do not add location markers to messages with non-POI location.
- Make one-to-one chats read-only the first seconds of a SecureJoin ([#5512](https://github.com/chatmail/core/pull/5512)).

### Fixes

- Message::set_file_from_bytes(): Set Param::Filename.
- Do not fail to send encrypted quotes to unencrypted chats.
- Never prepend subject to message text when bot receives it.
- Interrupt location loop when new location is stored.
- Correct message viewtype before recoding image blob ([#5496](https://github.com/chatmail/core/pull/5496)).
- Delete POI location when disappearing message expires.
- Delete non-POI locations after `delete_device_after`, not immediately.
- Update special chats icons even if they are blocked ([#5509](https://github.com/chatmail/core/pull/5509)).
- Use ChatIdBlocked::lookup_by_contact() instead of ChatId's method when applicable.

### Miscellaneous Tasks

- cargo: Bump quote from 1.0.35 to 1.0.36.
- cargo: Bump base64 from 0.22.0 to 0.22.1.
- cargo: Bump serde from 1.0.197 to 1.0.200.
- cargo: Bump async-channel from 2.2.0 to 2.2.1.
- cargo: Bump thiserror from 1.0.58 to 1.0.59.
- cargo: Bump anyhow from 1.0.81 to 1.0.82.
- cargo: Bump chrono from 0.4.37 to 0.4.38.
- cargo: Bump imap-proto from 0.16.4 to 0.16.5.
- cargo: Bump syn from 2.0.57 to 2.0.60.
- cargo: Bump mailparse from 0.14.1 to 0.15.0.
- cargo: Bump schemars from 0.8.16 to 0.8.19.

### Other

- Build ts docs with ci + nix.
- Push docs to delta.chat instead of codespeak
- Implement jsonrpc-docs build in github action
- Rm unneeded rust install from ts docs ci
- Correct folder for js.jsonrpc docs
- Add npm install to upload-docs.yml
- Add : to upload-docs.yml
- Upload-docs npm run => npm run build
- Rm leading slash
- Rm npm install
- Merge pull request #5515 from deltachat/dependabot/cargo/quote-1.0.36
- Merge pull request #5522 from deltachat/dependabot/cargo/chrono-0.4.38
- Merge pull request #5523 from deltachat/dependabot/cargo/mailparse-0.15.0
- Add webxdc internal integration commands in jsonrpc ([#5541](https://github.com/chatmail/core/pull/5541))
- Limit quote replies ([#5543](https://github.com/chatmail/core/pull/5543))
- Stdio jsonrpc server npm package ([#5332](https://github.com/chatmail/core/pull/5332))

### Refactor

- python: Fix ruff 0.4.2 warnings.
- Move `delete_poi_location` to location module and document it.
- Remove allow_keychange.

### Tests

- Explain test_was_seen_recently false-positive and give workaround instructions ([#5474](https://github.com/chatmail/core/pull/5474)).
- Test that member is added even if "Member added" is lost.
- Test that POIs are deleted when ephemeral message expires.
- Test ts build on branch


## [1.137.4] - 2024-04-24

### API-Changes

- [**breaking**] Remove `Stream` implementation for `EventEmitter`.
- Experimental Webxdc Integration API, Maps Integration ([#5461](https://github.com/chatmail/core/pull/5461)).

### Features / Changes

- Add progressive backoff for failing IMAP connection attempts ([#5443](https://github.com/chatmail/core/pull/5443)).
- Replace event channel with broadcast channel.
- Mark contact request messages as seen on IMAP.

### Fixes

- Convert images to RGB8 (without alpha) before encoding into JPEG to fix sending of large RGBA images.
- Don't set `is_bot` for webxdc status updates ([#5445](https://github.com/chatmail/core/pull/5445)).
- Do not fail if Autocrypt Setup Message has no encryption preference to fix key transfer from K-9 Mail to Delta Chat.
- Use only CRLF in Autocrypt Setup Message.
- python: Use cached message object if `dc_get_msg()` returns `NULL`.
- python: `Message::is_outgoing`: Don't reload message from db.
- python: `_map_ffi_event`: Always check if `get_message_by_id()` returned None.
- node: Undefine `NAPI_EXPERIMENTAL` to fix build with new clang.

### Build system

- nix: Add `imap-tools` as `deltachat-rpc-client` dependency.
- nix: Add `./deltachat-contact-tools` to sources.
- nix: Update nix flake.
- deps: Update rustls to 0.21.11.

### Documentation

- Update references to SecureJoin protocols.
- Fix broken references in documentation comments.

### Refactor

- imap: remove `RwLock` from `ratelimit`.
- deltachat-ffi: Remove unused `ResultNullableExt`.
- Remove duplicate clippy exceptions.
- Group `use` at the top of the test modules.

## [1.137.3] - 2024-04-16

### API-Changes

- [**breaking**] Remove reactions ffi; all implementations use jsonrpc.
- Don't load trashed messages with `Message::load_from_db`.
- Add `ChatListChanged` and `ChatListItemChanged` events ([#4476](https://github.com/chatmail/core/pull/4476)).
- deltachat-rpc-client: Add `check_qr` and `set_config_from_qr` APIs.
- deltachat-rpc-client: Add `Account.create_chat()`.
- deltachat-rpc-client: Add `Message.wait_until_delivered()`.
- deltachat-rpc-client: Add `Chat.send_file()`.
- deltachat-rpc-client: Add `Account.wait_for_reactions_changed()`.
- deltachat-rpc-client: Return Message from `Message.send_reaction()`.
- deltachat-rpc-client: Add `Account.bring_online()`.
- deltachat-rpc-client: Add `ACFactory.get_accepted_chat()`.

### Features / Changes

- Port `direct_imap.py` into deltachat-rpc-client.

### Fixes

- Do not emit `MSGS_CHANGED` event for outgoing hidden messages.
- `Message::get_summary()` must not return reaction summary.
- Fix emitting `ContactsChanged` events on "recently seen" status change ([#5377](https://github.com/chatmail/core/pull/5377)).
- deltachat-jsonrpc: block in `inner_get_backup_qr`.
- Add tolerance to `MemberListTimestamp` ([#5366](https://github.com/chatmail/core/pull/5366)).
- Keep webxdc instance for `delete_device_after` period after a status update ([#5365](https://github.com/chatmail/core/pull/5365)).
- Don't try to do `fetch_move_delete()` if Trash is needed but not yet configured.
- Assign messages to chats based on not fully downloaded references.
- Do not create ad-hoc groups from partial downloads.
- deltachat-rpc-client: construct Thread with `target` keyword argument.
- Format error context in `Message::load_from_db`.

### Build system

- cmake: adapt target install path if env var `CARGO_BUILD_TARGET` is set.
- nix: Use stable Rust in flake.nix devshell.

### CI

- Use cargo-nextest instead of cargo-test.
- Run doc tests with cargo test --workspace --doc ([#5459](https://github.com/chatmail/core/pull/5459)).
- Typos in CI files ([#5453](https://github.com/chatmail/core/pull/5453)).

### Documentation

- Add <https://deps.rs> badge.
- Add 'Ubuntu Touch' to the list of 'frontend projects'

### Refactor

- Do not ignore `Contact::get_by_id` errors in `get_encrinfo`.
- deltachat-rpc-client: Use `list`, `set` and `tuple` instead of `typing`.
- Use `clone_from()` ([#5451](https://github.com/chatmail/core/pull/5451)).
- Do not check for `is_trash()` in `get_last_reaction_if_newer_than()`.
- Split off functional contact tools into its own crate ([#5444](https://github.com/chatmail/core/pull/5444))
- Fix nightly clippy warnings.

### Tests

- Test withdrawing group join QR codes.
- `display_chat()`: Don't add day markers.
- Move reaction tests to JSON-RPC.
- node: Increase 'static tests' timeout to 5 minutes.

## [1.137.2] - 2024-04-05

### API-Changes

- [**breaking**] Increase Minimum Supported Rust Version to 1.77.0.

### Features / Changes

- Show reactions in summaries ([#5387](https://github.com/chatmail/core/pull/5387)).

### Tests

- Test reactions for forwarded messages

### Refactor

- `is_probably_private_reply`: Remove reaction-specific code.
- Use Rust 1.77.0 support for recursion in async functions.

### Miscellaneous Tasks

- cargo: Bump rustyline from 13.0.0 to 14.0.0.
- Update chrono from 0.4.34 to 0.4.37.
- Update from brotli 3.4.0 to brotli 4.0.0.
- Upgrade `h2` from 0.4.3 to 0.4.4.
- Upgrade `image` from 0.24.9 to 0.25.1.
- cargo: Bump fast-socks5 from 0.9.5 to 0.9.6.

## [1.137.1] - 2024-04-03

### CI

- Remove android builds for `x86` and `x86_64`.

## [1.137.0] - 2024-04-02

### API-Changes

- [**breaking**] Remove data from `DC_EVENT_INCOMING_MSG_BUNCH`.
- [**breaking**] Remove unused `dc_accounts_all_work_done()` ([#5384](https://github.com/chatmail/core/pull/5384)).
- deltachat-rpc-client: Add futures.

### Build system

- cmake: Build outside the source tree.
- nix: Add outputs for Android binaries.
- Add `repository` to Cargo.toml.
- python: Remove `setuptools_scm` dependency.
- Add development shell ([#5390](https://github.com/chatmail/core/pull/5390)).

### CI

- Update to Rust 1.77.0.
- Build deltachat-rpc-server for Android.
- Shorter names for deltachat-rpc-server jobs.

### Features / Changes

- Do not include provider hostname in `Message-ID`.
- Include 3 recent Message-IDs in `References` header.
- Include more entries into DNS fallback cache.

### Fixes

- Preserve upper-/lowercase of links parsed by `dehtml()` ([#5362](https://github.com/chatmail/core/pull/5362)).
- Rescan folders after changing `Config::SentboxWatch`.
- Do not ignore `Contact::get_by_id()` error in `from_field_to_contact_id()`.
- Put overridden sender name into message info.
- Don't send selfavatar in `SecureJoin` messages before contact verification ([#5354](https://github.com/chatmail/core/pull/5354)).
- Always set correct `chat_id` for `DC_EVENT_REACTIONS_CHANGED` ([#5419](https://github.com/chatmail/core/pull/5419)).

### Refactor

- Remove `MessageObject::from_message_id()`.
- jsonrpc: Add `msg_id` and `account_id` to `get_message()` errors.
- Cleanup `jobs` and `Params` relicts.

### Tests

- `Test_mvbox_sentbox_threads`: Check that sentbox gets configured after setting `sentbox_watch` ([#5105](https://github.com/chatmail/core/pull/5105)).
- Remove flaky time check from `test_list_from()`.
- Add failing test for #5418 (wrong `DC_EVENT_REACTIONS_CHANGED`)

### Miscellaneous Tasks

- Add `result` to .gitignore.
- cargo: Bump thiserror from 1.0.57 to 1.0.58.
- cargo: Bump tokio from 1.36.0 to 1.37.0.
- cargo: Bump pin-project from 1.1.4 to 1.1.5.
- cargo: Bump strum from 0.26.1 to 0.26.2.
- cargo: Bump uuid from 1.7.0 to 1.8.0.
- cargo: Bump toml from 0.8.10 to 0.8.12.
- cargo: Bump tokio-stream from 0.1.14 to 0.1.15.
- cargo: Bump smallvec from 1.13.1 to 1.13.2.
- cargo: Bump async-smtp from 0.9.0 to 0.9.1.
- cargo: Bump strum_macros from 0.26.1 to 0.26.2.
- cargo: Bump serde_json from 1.0.114 to 1.0.115.
- cargo: Bump anyhow from 1.0.80 to 1.0.81.
- cargo: Bump syn from 2.0.52 to 2.0.57.
- cargo: Bump futures-lite from 2.2.0 to 2.3.0.
- cargo: Bump axum from 0.7.4 to 0.7.5.
- cargo: Bump reqwest from 0.11.24 to 0.12.2.
- cargo: Bump backtrace from 0.3.69 to 0.3.71.
- cargo: Bump regex from 1.10.3 to 1.10.4.
- cargo: Update aho-corasick from 1.1.2 to 1.1.3.
- Update deny.toml.

## [1.136.6] - 2024-03-19

### Build system

- Add description to deltachat-rpc-server wheels.
- Read version from Cargo.toml in wheel-rpc-server.py.

### CI

- Update actions/cache from v3 to v4.
- Automate publishing of deltachat-rpc-server to PyPI.

### Documentation

- deltachat-rpc-server: Update deltachat-rpc-client URL.

### Miscellaneous Tasks

- Nix flake update.

## [1.136.5] - 2024-03-18

### Features / Changes

- Nicer summaries: prefer emoji over names
- Add `save_mime_headers` to debug info ([#5350](https://github.com/chatmail/core/pull/5350))

### Fixes

- Terminate ephemeral and location loop immediately on channel close.
- Update MemberListTimestamp when sending a group message.
- On iOS, use FILE (default) instead of MEMORY ([#5349](https://github.com/chatmail/core/pull/5349)).
- Add white background to recoded avatars ([#3787](https://github.com/chatmail/core/pull/3787)).

### Build system

- Add README to deltachat-rpc-client Python packages.

### Documentation

- deltachat-rpc-client: Document that 0 is a special value of `set_ephemeral_timer()`.

### Tests

- Test that reordering of Member added message results in square bracket error.

## [1.136.4] - 2024-03-11

### Build system

- nix: Make .#libdeltachat buildable on macOS.
- Build deltachat-rpc-server wheels with nix.

### CI

- Add workflow for automatic publishing of deltachat-rpc-client.

### Fixes

- Remove duplicate CHANGELOG entries for 1.135.1.

## [1.136.3] - 2024-03-09

### Features / Changes

- Start IMAP loop for sentbox only if it is configured ([#5105](https://github.com/chatmail/core/pull/5105)).

### Fixes

- Remove leading whitespace from Subject ([#5106](https://github.com/chatmail/core/pull/5106)).
- Create new Peerstate for unencrypted message with already known Autocrypt key, but a new address.

### Build system

- nix: Cleanup cross-compilation code.
- nix: Include SystemConfiguration framework on darwin systems.

### CI

- Wait for `build_windows` task before trying to publish it.
- Remove artifacts from npm package.

### Refactor

- Don't parse Autocrypt header for outgoing messages ([#5259](https://github.com/chatmail/core/pull/5259)).
- Remove `deduplicate_peerstates()`.
- Fix 2024-03-05 nightly clippy warnings.

### Miscellaneous Tasks

- deps: Bump mio from 0.8.8 to 0.8.11 in /fuzz.
- RPC client: Add missing constants ([#5110](https://github.com/chatmail/core/pull/5110)).

## [1.136.2] - 2024-03-05

### Build system

- Downgrade `cc` to 1.0.83 to fix build for Android.

### CI

- Update setup-node action.

## [1.136.1] - 2024-03-05

### Build system

- Revert to OpenSSL 3.1.
- Restore MSRV 1.70.0.

### Miscellaneous Tasks

- Update node constants.

## [1.136.0] - 2024-03-04

### Features / Changes

- Recognise Trash folder by name ([#5275](https://github.com/chatmail/core/pull/5275)).
- Send Chat-Group-Avatar as inline base64 ([#5253](https://github.com/chatmail/core/pull/5253)).
- Self-Reporting: Report number of protected/encrypted/unencrypted chats ([#5292](https://github.com/chatmail/core/pull/5292)).

### Fixes

- Don't send sync messages on self-{status,avatar} update from self-sent messages ([#5289](https://github.com/chatmail/core/pull/5289)).
- imap: Allow `maybe_network` to interrupt connection ratelimit.
- imap: Set connectivity to "connecting" only after ratelimit.
- Remove `Group-ID` from `Message-ID`.
- Prioritize protected `Message-ID` over `X-Microsoft-Original-Message-ID`.

### API-Changes

- Make `store_self_keypair` private.
- Add `ContextBuilder.build()` to build Context without opening.
- `dc_accounts_set_push_device_token` and `dc_get_push_state` APIs for iOS push notifications.

### Build system

- Tag armv6 wheels with tags accepted by PyPI.
- Unpin OpenSSL.
- Remove deprecated `unmaintained` field from deny.toml.
- Do not vendor OpenSSL when cross-compiling ([#5316](https://github.com/chatmail/core/pull/5316)).
- Increase MSRV to 1.74.0.

### CI

- Upgrade setup-python GitHub Action.
- Update to Rust 1.76 and fix clippy warnings.
- Build Python docs with Nix.
- Upload python docs without GH actions.
- Upload cffi docs without GH actions.
- Build c.delta.chat docs with nix.

### Other

- refactor: move more methods from Imap into Session.
- Add deltachat-time to sources.

### Refactor

- Remove Session from Imap structure.
- Merge ImapConfig into Imap.
- Get rid of ImapActionResult.
- Build contexts using ContextBuilder.
- Do not send `Secure-Join-Group` in `vg-request`.

### Tests

- Fix `test_verified_oneonone_chat_broken_by_device_change()` ([#5280](https://github.com/chatmail/core/pull/5280)).
- `get_protected_chat()`: Use FFIEventTracker instead of `dc_wait_next_msgs()` ([#5207](https://github.com/chatmail/core/pull/5207)).
- Fixup `tests/test_3_offline.py::TestOfflineAccountBasic::test_wrong_db`.
- Fix pytest compat ([#5317](https://github.com/chatmail/core/pull/5317)).

## [1.135.1] - 2024-02-20

### Features / Changes

- Sync self-avatar across devices ([#4893](https://github.com/chatmail/core/pull/4893)).
- Sync Config::Selfstatus across devices ([#4893](https://github.com/chatmail/core/pull/4893)).
- Remove webxdc sending limit.

### Fixes

- Never encrypt `{vc,vg}-request` SecureJoin messages.
- Apply Autocrypt headers if timestamp is unchanged.
- `Context::get_info`: Report displayname as "displayname" (w/o underscore).

### Tests

- Mock `SystemTime::now()` for the tests.
- Add a test on protection message sort timestamp ([#5088](https://github.com/chatmail/core/pull/5088)).

### Build system

- Add flake.nix.
- Add footer template for git-cliff.

### CI

- Update GitHub Actions `actions/upload-artifact`, `actions/download-artifact`, `actions/checkout`.
- Build deltachat-repl for Windows with nix.
- Build deltachat-rpc-server with nix.
- Try to upload deltachat-rpc-server only on release.
- Fixup node-package.yml after artifact actions upgrade.
- Update to actions/checkout@v4.
- Replace download-artifact v1 with v4.

### Refactor

- `create_keypair`: Remove unnecessary `map_err`.
- Return error with a cause when failing to export keys.
- Rename incorrectly named variables in `create_keypair`.

## [1.135.0] - 2024-02-13

### Features / Changes

- Add wildcard pattern support to provider database.
- Add device message about outgoing undecryptable messages ([#5164](https://github.com/chatmail/core/pull/5164)).
- Context::set_config(): Restart IO scheduler if needed ([#5111](https://github.com/chatmail/core/pull/5111)).
- Server_sent_unsolicited_exists(): Log folder name.
- Cache system time instead of looking at the clock several times in a row.
- Basic self-reporting ([#5129](https://github.com/chatmail/core/pull/5129)).

### Fixes

- Dehtml: Don't just truncate text when trying to decode ([#5223](https://github.com/chatmail/core/pull/5223)).
- Mark the gossip keys from the message as verified, not the ones from the db ([#5247](https://github.com/chatmail/core/pull/5247)).
- Guarantee immediate message deletion if delete_server_after == 0 ([#5201](https://github.com/chatmail/core/pull/5201)).
- Never allow a message timestamp to be a lot in the future ([#5249](https://github.com/chatmail/core/pull/5249)).
- Imap::configure_mvbox: Do select_with_uidvalidity() before return.
- ImapSession::select_or_create_folder(): Don't fail if folder is created in parallel.
- Emit ConfigSynced event on the second device.
- Create mvbox on setting mvbox_move.
- Use SystemTime instead of Instant everywhere.
- Restore database rows removed in previous release; this ensures compatibility when adding second device or importing backup and not all devices run the new core ([#5254](https://github.com/chatmail/core/pull/5254))

### Miscellaneous Tasks

- cargo: Bump image from 0.24.7 to 0.24.8.
- cargo: Bump chrono from 0.4.31 to 0.4.33.
- cargo: Bump futures-lite from 2.1.0 to 2.2.0.
- cargo: Bump pin-project from 1.1.3 to 1.1.4.
- cargo: Bump iana-time-zone from yanked 0.1.59 to 0.1.60.
- cargo: Bump smallvec from 1.11.2 to 1.13.1.
- cargo: Bump base64 from 0.21.5 to 0.21.7.
- cargo: Bump regex from 1.10.2 to 1.10.3.
- cargo: Bump libc from 0.2.151 to 0.2.153.
- cargo: Bump reqwest from 0.11.23 to 0.11.24.
- cargo: Bump axum from 0.7.3 to 0.7.4.
- cargo: Bump uuid from 1.6.1 to 1.7.0.
- cargo: Bump fast-socks5 from 0.9.2 to 0.9.5.
- cargo: Bump serde_json from 1.0.111 to 1.0.113.
- cargo: Bump syn from 2.0.46 to 2.0.48.
- cargo: Bump serde from 1.0.194 to 1.0.196.
- cargo: Bump toml from 0.8.8 to 0.8.10.
- cargo: Update to strum 0.26.
- Cargo update.
- scripts: Do not install deltachat-rpc-client twice.

### Other

- Update welcome image, thanks @paulaluap
- Merge pull request #5243 from deltachat/dependabot/cargo/pin-project-1.1.4
- Merge pull request #5241 from deltachat/dependabot/cargo/futures-lite-2.2.0
- Merge pull request #5236 from deltachat/dependabot/cargo/chrono-0.4.33
- Merge pull request #5235 from deltachat/dependabot/cargo/image-0.24.8


### Refactor

- Resultify token::exists.

### Tests

- Delete_server_after="1" should cause immediate message deletion ([#5201](https://github.com/chatmail/core/pull/5201)).

## [1.134.0] - 2024-01-31

### API-Changes

- [**breaking**] JSON-RPC: device message api now requires `Option<MessageData>` instead of `String` for the message ([#5211](https://github.com/chatmail/core/pull/5211)).
- CFFI: add `dc_accounts_background_fetch` and event `DC_EVENT_ACCOUNTS_BACKGROUND_FETCH_DONE`.
- JSON-RPC: add `accounts_background_fetch`.

### Features / Changes

- `Qr::check_qr()`: Accept i.delta.chat invite links ([#5217](https://github.com/chatmail/core/pull/5217)).
- Add support for IMAP METADATA, fetching `/shared/comment` and `/shared/admin` and displaying it in account info.

### Fixes

- Add tolerance for macOS and iOS changing `#` to `%23`.
- Do not drop unknown report attachments, such as TLS reports.
- Treat only "Auto-Submitted: auto-generated" messages as bot-sent ([#5213](https://github.com/chatmail/core/pull/5213)).
- `Chat::resend_msgs`: Guarantee strictly increasing time in the `Date` header.
- Delete resent messages on receiver side ([#5155](https://github.com/chatmail/core/pull/5155)).
- Fix iOS build issue.

### CI

- Add/remove necessary newlines to fix Python lint.

### Tests

- `test_import_export_online_all`: Send the message to the existing address to avoid errors ([#5220](https://github.com/chatmail/core/pull/5220)).

## [1.133.2] - 2024-01-24

### Fixes

- Downgrade OpenSSL from 3.2.0 to 3.1.4 ([#5206](https://github.com/chatmail/core/issues/5206))
- No new chats for MDNs with alias ([#5196](https://github.com/chatmail/core/issues/5196)) ([#5199](https://github.com/chatmail/core/pull/5199)).

## [1.133.1] - 2024-01-21

### API-Changes

- Add `is_bot` to cffi and jsonrpc ([#5197](https://github.com/chatmail/core/pull/5197)).

### Features / Changes

- Add system message when provider does not allow unencrypted messages ([#5195](https://github.com/chatmail/core/pull/5195)).

### Fixes

- `Chat::send_msg`: Remove encryption-related params from already sent message. This allows to send received encrypted `dc_msg_t` object to unencrypted chat, e.g. in a Python bot.
- Set message download state to Failure on IMAP errors. This avoids partially downloaded messages getting stuck in "Downloading..." state without actually being in a download queue.
- BCC-to-self even if server deletion is set to "at once". This is a workaround for SMTP servers which do not return response in time, BCC-self works as a confirmation that message was sent out successfully and does not need more retries.
- node: Run tests with native ESM modules instead of `esm` ([#5194](https://github.com/chatmail/core/pull/5194)).
- Use Quoted-Printable MIME encoding for the text part ([#3986](https://github.com/chatmail/core/pull/3986)).

### Tests

- python: Add `get_protected_chat` to testplugin.py.

## [1.133.0] - 2024-01-14

### Features / Changes

- Securejoin protocol implementation refinements
  - Track forward and backward verification separately ([#5089](https://github.com/chatmail/core/pull/5089)) to avoid inconsistent states.
  - Mark 1:1 chat as verified for Bob early. 1:1 chat with Alice is verified as soon as Alice's key is verified rather than at the end of the protocol.
- Put Message-ID into hidden headers and take it from there on receiver ([#4798](https://github.com/chatmail/core/pull/4798)). This works around servers which generate their own Message-ID and overwrite the one generated by Delta Chat.
- deltachat-repl: Enable INFO logging by default and add timestamps.
- Add `ConfigSynced` (`DC_EVENT_CONFIG_SYNCED`) event which is emitted when configuration is changed via synchronization message or synchronization message for configuration is sent. UI may refresh elements based on the configuration key which is a part of the event.
- Sync contact creation/rename across devices ([#5163](https://github.com/chatmail/core/pull/5163)).
- Encrypt MDNs ([#5175](https://github.com/chatmail/core/pull/5175)).
- Only try to configure non-strict TLS checks if explicitly set ([#5181](https://github.com/chatmail/core/pull/5181)).

### Build system

- Use released version of iroh 0.4.2 for "setup second device" feature.

### CI

- Update to Rust 1.75.0.
- Downgrade `chai` from 4.4.0 to 4.3.10.

### Documentation

- Add a link <https://www.ietf.org/archive/id/draft-bucksch-autoconfig-00.html> to autoconfig RFC draft.
- Update securejoin link in `standards.md` from <https://countermitm.readthedocs.io/> to <https://securejoin.readthedocs.io>.
- Restore "Constants" page in Doxygen >=1.9.8

### Fixes

- imap: Limit the rate of LOGIN attempts rather than connection attempts. This is to avoid having to wait for rate limiter right after switching from a bad or offline network to a working network while still guarding against reconnection loop.
- Do not ignore `peerstate.save_to_db()` errors.
- securejoin: Mark 1:1s as protected regardless of the Config::VerifiedOneOnOneChats.
- Delete received outgoing messages from SMTP queue ([#5115](https://github.com/chatmail/core/pull/5115)).
- imap: Fail fast on `LIST` errors to avoid busy loop when connection is lost.
- Split SMTP jobs already in `chat::create_send_msg_jobs()` ([#5115](https://github.com/chatmail/core/pull/5115)).
- Do not remove contents from unencrypted [Schleuder](https://schleuder.org/) mailing lists messages.
- Reset message error when scheduling resending ([#5119](https://github.com/chatmail/core/pull/5119)).
- Emit events more reliably when starting and stopping I/O ([#5101](https://github.com/chatmail/core/pull/5101)).
- Fix timestamp of chat protection info message for correct message ordering after restoring a backup ([#5088](https://github.com/chatmail/core/pull/5088)).

### Refactor

- sql: Recreate `config` table with UNIQUE constraint.
- sql: Recreate `keypairs` table to remove unused `addr` and `created` fields and move `is_default` flag to `config` table.
- Send `Secure-Join-Fingerprint` only in `*-request-with-auth`.

### Tests

- Test joining non-protected group.
- Test that read receipts don't degrade encryption.
- Test that changing default private key breaks backward verification.
- Test recovery from lost vc-contact-confirm.
- Use `wait_for_incoming_msg_event()` more.

## [1.132.1] - 2023-12-12

### Features / Changes

- Add "From:" to protected headers for signed-only messages.
- Sync user actions for ad-hoc groups across devices ([#5065](https://github.com/chatmail/core/pull/5065)).

### Fixes

- Add padlock to empty part if the whole message is empty.
- Renew IDLE timeout on keepalives and reduce it to 5 minutes.
- connectivity: Return false from `all_work_done()` immediately after connecting (iOS notification fix).

### API-Changes

- deltachat-jsonrpc-client: add `Account.{import,export}_self_keys`.

### CI

- Update to Rust 1.74.1.

## [1.132.0] - 2023-12-06

### Features / Changes

- Increase TCP timeouts from 30 to 60 seconds.

### Fixes

- Don't sort message creating a protected group over a protection message ([#4963](https://github.com/chatmail/core/pull/4963)).
- Do not lock accounts.toml on iOS.
- Protect groups even if some members are not verified and add `test_securejoin_after_contact_resetup` regression test.

## [1.131.9] - 2023-12-02

### API-Changes

- Remove `dc_get_http_response()`, `dc_http_response_get_mimetype()`, `dc_http_response_get_encoding()`, `dc_http_response_get_blob()`, `dc_http_response_get_size()`, `dc_http_response_unref()` and `dc_http_response_t` from cffi.
- Deprecate CFFI APIs `dc_send_reaction()`, `dc_get_msg_reactions()`, `dc_reactions_get_contacts()`, `dc_reactions_get_by_contact_id()`, `dc_reactions_unref` and `dc_reactions_t`.
- Make `Contact.is_verified()` return bool.

### Build system

- Switch from fork of iroh to iroh 0.4.2 pre-release.

### Features / Changes

- Send `Chat-Verified` headers in 1:1 chats.
- Ratelimit IMAP connections ([#4940](https://github.com/chatmail/core/pull/4940)).
- Remove receiver limit on `.xdc` size.
- Don't affect MimeMessage with "From" and secured headers from encrypted unsigned messages.
- Sync `Config::{MdnsEnabled,ShowEmails}` across devices ([#4954](https://github.com/chatmail/core/pull/4954)).
- Sync `Config::Displayname` across devices ([#4893](https://github.com/chatmail/core/pull/4893)).
- `Chat::rename_ex`: Don't send sync message if usual message is sent.

### Fixes

- Lock the database when INSERTing a webxdc update, avoid "Database is locked" errors.
- Use keyring with all private keys when decrypting a message ([#5046](https://github.com/chatmail/core/pull/5046)).

### Tests

- Make Result-returning tests produce a line number.
- Add `test_utils::sync()`.
- Test inserting lots of webxdc updates.
- Split `test_sync_alter_chat()` into smaller tests.

## [1.131.8] - 2023-11-27

### Features / Changes

- webxdc: Add unique IDs to status updates sent outside and deduplicate based on IDs.

### Fixes

- Allow IMAP servers not returning UIDNEXT on SELECT and STATUS such as mail.163.com.
- Use the correct securejoin strings used in the UI, remove old TODO ([#5047](https://github.com/chatmail/core/pull/5047)).
- Do not emit events about webxdc update events logged into debug log webxdc.

### Tests

- Check that `receive_status_update` has forward compatibility and unique webxdc IDs will be ignored by previous Delta Chat versions.

## [1.131.7] - 2023-11-24

### Fixes

- Revert "fix: check UIDNEXT with a STATUS command before going IDLE". This attempts to fix mail.163.com which has broken STATUS command.

## [1.131.6] - 2023-11-21

### Fixes

- Fail fast if IMAP FETCH cannot be parsed instead of getting stuck in infinite loop.

### Documentation

- Generate deltachat-rpc-client documentation and publish it to <https://py.delta.chat>.

## [1.131.5] - 2023-11-20

### API-Changes

- deltachat-rpc-client: Add `Message.get_sender_contact()`.
- Turn `ContactAddress` into an owned type.

### Features / Changes

- Lowercase addresses in Autocrypt and Autocrypt-Gossip headers.
- Lowercase the address in member added/removed messages.
- Lowercase `addr` when it is set.
- Do not replace the message with an error in square brackets when the sender is not a member of the protected group.

### Fixes

- `Chat::sync_contacts()`: Fetch contact addresses in a single query.
- `Chat::rename_ex()`: Sync improved chat name to other devices.
- Recognize `Chat-Group-Member-Added` of self case-insensitively.
- Compare verifier addr to peerstate addr case-insensitively.

### Tests

- Port [Secure-Join](https://securejoin.readthedocs.io/) tests to JSON-RPC.

### CI

- Test with Rust 1.74.


## [1.131.4] - 2023-11-16

### Documentation

- Document DC_DOWNLOAD_UNDECIPHERABLE.

### Fixes

- Always add "Member added" as system message.

## [1.131.3] - 2023-11-15

### Fixes

- Update async-imap to 0.9.4 which does not ignore EOF on FETCH.
- Reset gossiped timestamp on securejoin.
- sync: Ignore unknown sync items to provide forward compatibility and avoid creating empty message bubbles.
- sync: Skip sync when chat name is set to the current one.
- Return connectivity HTML with an error when IO is stopped.

## [1.131.2] - 2023-11-14

### API-Changes

- deltachat-rpc-client: add `Account.get_chat_by_contact()`.

### Features / Changes

- Do not post "... verified" messages on QR scan success.
- Never drop better message from `apply_group_changes()`.

### Fixes

- Assign MDNs to the trash chat early to prevent received MDNs from creating or unblocking 1:1 chats.
- Allow to securejoin groups when 1:1 chat with the inviter is a contact request.
- Add "setup changed" message for verified key before the message.
- Ignore special chats when calculating similar chats.

## [1.131.1] - 2023-11-13

### Fixes

- Do not skip actual message parts when group change messages are inserted.

## [1.131.0] - 2023-11-13

### Features / Changes

- Sync chat contacts across devices ([#4953](https://github.com/chatmail/core/pull/4953)).
- Sync creating broadcast lists across devices ([#4953](https://github.com/chatmail/core/pull/4953)).
- Sync Chat::name across devices ([#4953](https://github.com/chatmail/core/pull/4953)).
- Multi-device broadcast lists ([#4953](https://github.com/chatmail/core/pull/4953)).

### Fixes

- Encode chat name in the `List-ID` header to avoid SMTPUTF8 errors.
- Ignore errors from generating sync messages.
- `Context::execute_sync_items`: Ignore all errors ([#4817](https://github.com/chatmail/core/pull/4817)).
- Allow to send unverified securejoin messages to protected chats ([#4982](https://github.com/chatmail/core/pull/4982)).

## [1.130.0] - 2023-11-10

### API-Changes

- Emit JoinerProgress(1000) event when Bob verifies Alice.
- JSON-RPC: add `ContactObject.is_profile_verified` property.
- Hide `ChatId::get_for_contact()` from public API.

### Features / Changes

- Add secondary verified key.
- Add info messages about implicitly added members.
- Treat reset state as encryption not preferred.
- Grow sleep durations on errors in Imap::fake_idle() ([#4424](https://github.com/chatmail/core/pull/4424)).

### Fixes

- Mark 1:1 chat as protected when joining a group.
- Raise lower auto-download limit to 160k.
- Remove `Reporting-UA` from read receipts.
- Do not apply group changes to special chats. Avoid adding members to the trash chat.
- imap: make `UidGrouper` robust against duplicate UIDs.
- Do not return hidden chat from `dc_get_chat_id_by_contact_id`.
- Smtp_loop(): Don't grow timeout if interrupted early ([#4833](https://github.com/chatmail/core/pull/4833)).

### Refactor

- imap: Do not FETCH right after `scan_folders()`.
- deltachat-rpc-client: Use `itertools` instead of `Lock` for thread-safe request ID generation.

### Tests

- Remove unused `--liveconfig` option.
- Test chatlist can load for corrupted chats ([#4979](https://github.com/chatmail/core/pull/4979)).

### Miscellaneous Tasks

- Update provider-db ([#4949](https://github.com/chatmail/core/pull/4949)).

## [1.129.1] - 2023-11-06

### Fixes

- Update tokio-imap to fix Outlook STATUS parsing bug.
- deltachat-rpc-client: Add the Lock around request ID.
- `apply_group_changes`: Don't implicitly delete members locally, add absent ones instead ([#4934](https://github.com/chatmail/core/pull/4934)).
- Partial messages do not change group state ([#4900](https://github.com/chatmail/core/pull/4900)).

### Tests

- Group chats device synchronisation.

## [1.129.0] - 2023-11-06

### API-Changes

- Add JSON-RPC `get_chat_id_by_contact_id` API ([#4918](https://github.com/chatmail/core/pull/4918)).
- [**breaking**] Remove deprecated `get_verifier_addr`.

### Features / Changes

- Sync chat `Blocked` state, chat visibility, chat mute duration and contact blocked status across devices ([#4817](https://github.com/chatmail/core/pull/4817)).
- Add 'group created instructions' as info message ([#4916](https://github.com/chatmail/core/pull/4916)).
- Add hardcoded fallback DNS cache.

### Fixes

- Switch to `EncryptionPreference::Mutual` on a receipt of encrypted+signed message ([#4707](https://github.com/chatmail/core/pull/4707)).
- imap: Check UIDNEXT with a STATUS command before going IDLE.
- Allow to change verified key via "member added" message.
- json-rpc: Return verifier even if the contact is not "verified" (Autocrypt key does not equal Secure-Join key).

### Documentation

- Refine `Contact::get_verifier_id` and `Contact::is_verified` documentation ([#4922](https://github.com/chatmail/core/pull/4922)).
- Contact profile view should not use `dc_contact_is_verified()`.
- Remove documentation for non-existing `dc_accounts_new` `os_name` param.

### Refactor

- Remove unused or useless code paths in Secure-Join ([#4897](https://github.com/chatmail/core/pull/4897)).
- Improve error handling in Secure-Join code.
- Add hostname to "no DNS resolution results" error message.
- Accept `&str` instead of `Option<String>` in idle().

## [1.128.0] - 2023-11-02

### Build system
- [**breaking**] Upgrade nodejs version to 18 ([#4903](https://github.com/chatmail/core/pull/4903)).

### Features / Changes

- deltachat-rpc-client: Add `Account.wait_for_incoming_msg_event()`.
- Decrease ratelimit for .testrun.org subdomains.

### Fixes

- Do not fail securejoin due to unrelated pending bobstate  ([#4896](https://github.com/chatmail/core/pull/4896)).
- Allow other verified group recipients to be unverified, only check the sender verification.
- Remove not working attempt to recover from verified key changes.

## [1.127.2] - 2023-10-29

### API-Changes

- [**breaking**] Jsonrpc `misc_set_draft` now requires setting the viewtype.
- jsonrpc: Add `get_message_info_object`.

### Tests

- deltachat-rpc-client: Move pytest option from pyproject.toml to tox.ini and set log level.
- deltachat-rpc-client: Test securejoin.
- Increase pytest timeout to 10 minutes.
- Compile deltachat-rpc-server in debug mode for tests.

## [1.127.1] - 2023-10-27

### API-Changes

- jsonrpc: add `.is_protection_broken` to `FullChat` and `BasicChat`.
- jsonrpc: Add `id` to `ProviderInfo`.

## [1.127.0] - 2023-10-26

### API-Changes

- [**breaking**] `dc_accounts_new` API is changed. Unused `os_name` argument is removed and `writable` argument is added.
- jsonrpc: Add `resend_messages`.
- [**breaking**] Remove unused function `is_verified_ex()` ([#4551](https://github.com/chatmail/core/pull/4551))
- [**breaking**] Make `MsgId.delete_from_db()` private.
- [**breaking**] deltachat-jsonrpc: use `kind` as a tag for all union types
- json-rpc: Force stickers to be sent as stickers ([#4819](https://github.com/chatmail/core/pull/4819)).
- Add mailto parse api ([#4829](https://github.com/chatmail/core/pull/4829)).
- [**breaking**] Remove unused `DC_STR_PROTECTION_(EN)ABLED` strings
- [**breaking**] Remove unused `dc_set_chat_protection()`
- Hide `DcSecretKey` trait from the API.
- Verified 1:1 chats ([#4315](https://github.com/chatmail/core/pull/4315)). Disabled by default, enable with `verified_one_on_one_chats` config.
- Add api `chat::Chat::is_protection_broken`
- Add `dc_chat_is_protection_broken()` C API.

### CI

- Run Rust tests with `RUST_BACKTRACE` set.
- Replace `master` branch with `main`.  Run CI only on `main` branch pushes.
- Test `deltachat-rpc-client` on Windows.

### Documentation

- Document how logs and error messages should be formatted in `CONTRIBUTING.md`.
- Clarify transitive behaviour of `dc_contact_is_verfified()`.
- Document `configured_addr`.

### Features / Changes

- Add lockfile to account manager ([#4314](https://github.com/chatmail/core/pull/4314)). 
- Don't show a contact as verified if their key changed since the verification ([#4574](https://github.com/chatmail/core/pull/4574)).
- deltachat-rpc-server: Add `--openrpc` option to print OpenRPC specification for JSON-RPC API. This specification can be used to generate JSON-RPC API clients.
- Track whether contact is a bot or not ([#4821](https://github.com/chatmail/core/pull/4821)).
- Replace `Config::SendSyncMsgs` with `SyncMsgs` ([#4817](https://github.com/chatmail/core/pull/4817)).

### Fixes

- Don't create 1:1 chat as protected for contact who doesn't prefer to encrypt ([#4538](https://github.com/chatmail/core/pull/4538)).
- Allow to save a draft if the verification is broken ([#4542](https://github.com/chatmail/core/pull/4542)).
- Fix info-message orderings of verified 1:1 chats ([#4545](https://github.com/chatmail/core/pull/4545)).
- Fix example; this was changed some time ago, see https://docs.webxdc.org/spec.html#sendupdate
- `receive_imf`: Update peerstate from db after handling Securejoin handshake ([#4600](https://github.com/chatmail/core/pull/4600)).
- Sort old incoming messages below all outgoing ones ([#4621](https://github.com/chatmail/core/pull/4621)).
- Do not mark non-verified group chats as verified when using securejoin.
- `receive_imf`: Set protection only for Chattype::Single ([#4597](https://github.com/chatmail/core/pull/4597)).
- Return from `dc_get_chatlist(DC_GCL_FOR_FORWARDING)` only chats where we can send ([#4616](https://github.com/chatmail/core/pull/4616)).
- Clear VerifiedOneOnOneChats config on backup ([#4615](https://github.com/chatmail/core/pull/4615)).
- Try removal of accounts multiple times with timeouts in case the database file is blocked (restore `try_many_times` workaround).

### Build system

- Remove examples/simple.rs.
- Increase MSRV to 1.70.0.
- Update dependencies.
- Switch to iroh 0.4.x fork with updated dependencies.

## [1.126.1] - 2023-10-24

### Fixes

- Do not hardcode version in deltachat-rpc-server source package.
- Do not interrupt IMAP loop from `get_connectivity_html()`.

### Features / Changes

- imap: Buffer `STARTTLS` command.

### Build system

- Build `deltachat-rpc-server` binary for aarch64 macOS.
- Build `deltachat-rpc-server` wheels for macOS and Windows.

### Refactor

- Remove job queue.

### Miscellaneous Tasks

- cargo: Update `ahash` to make `cargo-deny` happy.

## [1.126.0] - 2023-10-22

### API-Changes

- Allow to filter by unread in `chatlist:try_load` ([#4824](https://github.com/chatmail/core/pull/4824)).
- Add `misc_send_draft()` to JSON-RPC API ([#4839](https://github.com/chatmail/core/pull/4839)).

### Features / Changes

- [**breaking**] Make broadcast lists create their own chat ([#4644](https://github.com/chatmail/core/pull/4644)).
  - This means that UIs need to ask for the name when creating a broadcast list, similar to <https://github.com/deltachat/deltachat-android/pull/2653>.
- Add self-address to backup filename ([#4820](https://github.com/chatmail/core/pull/4820))

### CI

- Build Python wheels for deltachat-rpc-server.

### Build system

- Strip release binaries.
- Workaround OpenSSL crate expecting libatomic to be available.

### Fixes

- Set `soft_heap_limit` on SQLite database.
- imap: Fallback to `STATUS` if `SELECT` did not return UIDNEXT.

## [1.125.0] - 2023-10-14

### API-Changes

- [**breaking**] deltachat-rpc-client: Replace `asyncio` with threads.
- Validate boolean values passed to `set_config`. Attempts to set values other than `0` and `1` will result in an error.

### CI

- Reduce required Python version for deltachat-rpc-client from 3.8 to 3.7.

### Features / Changes

- Add developer option to disable IDLE.

### Fixes

- `deltachat-rpc-client`: Run `deltachat-rpc-server` in its own process group. This prevents reception of `SIGINT` by the server when the bot is terminated with `^C`.
- python: Don't automatically set the displayname to "bot" when setting log level.
- Don't update `timestamp`, `timestamp_rcvd`, `state` when replacing partially downloaded message ([#4700](https://github.com/chatmail/core/pull/4700)).
- Assign encrypted partially downloaded group messages to 1:1 chat ([#4757](https://github.com/chatmail/core/pull/4757)).
- Return all contacts from `Contact::get_all` for bots ([#4811](https://github.com/chatmail/core/pull/4811)).
- Set connectivity status to "connected" during fake idle.
- Return verifier contacts regardless of their origin.
- Don't try to send more MDNs if there's a temporary SMTP error ([#4534](https://github.com/chatmail/core/pull/4534)).

### Refactor

- deltachat-rpc-client: Close stdin instead of sending `SIGTERM`.
- deltachat-rpc-client: Remove print() calls. Standard `logging` package is for logging instead.

### Tests

- deltachat-rpc-client: Enable logs in pytest.

## [1.124.1] - 2023-10-05

### Fixes

- Remove footer from reactions on the receiver side ([#4780](https://github.com/chatmail/core/pull/4780)).

### CI

- Pin `urllib3` version to `<2`. ([#4788](https://github.com/chatmail/core/issues/4788))

## [1.124.0] - 2023-10-04

### API-Changes

- [**breaking**] Return `DC_CONTACT_ID_SELF` from `dc_contact_get_verifier_id()` for directly verified contacts.
- Deprecate `dc_contact_get_verifier_addr`.
- python: use `dc_contact_get_verifier_id()`. `get_verifier()` returns a Contact rather than an address now.
- Deprecate `get_next_media()`.
- Ignore public key argument in `dc_preconfigure_keypair()`. Public key is extracted from the private key.

### Fixes

- Wrap base64-encoded parts to 76 characters.
- Require valid email addresses in `dc_provider_new_from_email[_with_dns]`.
- Do not trash messages with attachments and no text when `location.kml` is attached ([#4749](https://github.com/chatmail/core/issues/4749)).
- Initialise `last_msg_id` to the highest known row id. This ensures bots migrated from older version to `dc_get_next_msgs()` API do not process all previous messages from scratch.
- Do not put the status footer into reaction MIME parts.
- Ignore special chats in `get_similar_chat_ids()`. This prevents trash chat from showing up in similar chat list ([#4756](https://github.com/chatmail/core/issues/4756)).
- Cap percentage in connectivity layout to 100% ([#4765](https://github.com/chatmail/core/pull/4765)).
- Add Let's Encrypt root certificate to `reqwest`. This should allow scanning `DCACCOUNT` QR-codes on older Android phones when the server has a Let's Encrypt certificate.
- deltachat-rpc-client: Increase stdio buffer to 64 MiB to avoid Python bots crashing when trying to load large messages via a JSON-RPC call.
- Add `protected-headers` directive to Content-Type of encrypted messages with attachments ([#2302](https://github.com/chatmail/core/issues/2302)). This makes Thunderbird show encrypted Subject for Delta Chat messages.
- webxdc: Reset `document.update` on forwarding. This fixes the test `test_forward_webxdc_instance()`.

### Features / Changes

- Remove extra members from the local list in sake of group membership consistency ([#3782](https://github.com/chatmail/core/issues/3782)).
- deltachat-rpc-client: Log exceptions when long-running tasks die.

### Build

- Build wheels for Python 3.12 and PyPy 3.10.

## [1.123.0] - 2023-09-22

### API-Changes

- Make it possible to import secret key from a file with `DC_IMEX_IMPORT_SELF_KEYS`.
- [**breaking**] Make `dc_jsonrpc_blocking_call` accept JSON-RPC request.

### Fixes

- `lookup_chat_by_reply()`: Skip not fully downloaded and undecipherable messages ([#4676](https://github.com/chatmail/core/pull/4676)).
- `lookup_chat_by_reply()`: Skip undecipherable parent messages created by older versions ([#4676](https://github.com/chatmail/core/pull/4676)).
- imex: Use "default" in the filename of the default key.

### Miscellaneous Tasks

- Update OpenSSL from 3.1.2 to 3.1.3.

## [1.122.0] - 2023-09-12

### API-Changes

- jsonrpc: Return only chat IDs for similar chats.

### Fixes

- Reopen all connections on database passpharse change.
- Do not block new group chats if 1:1 chat is blocked.
- Improve group membership consistency algorithm ([#3782](https://github.com/chatmail/core/pull/3782))([#4624](https://github.com/chatmail/core/pull/4624)).
- Forbid membership changes from possible non-members ([#3782](https://github.com/chatmail/core/pull/3782)).
- `ChatId::parent_query()`: Don't filter out OutPending and OutFailed messages.

### Build system

- Update to OpenSSL 3.0.
- Bump webpki from 0.22.0 to 0.22.1.
- python: Add link to Mastodon into projects.urls.

### Features / Changes

- Add RSA-4096 key generation support.

### Refactor

- pgp: Add constants for encryption algorithm and hash.

## [1.121.0] - 2023-09-06

### API-Changes

- Add `dc_context_change_passphrase()`.
- Add `Message.set_file_from_bytes()` API.
- Add experimental API to get similar chats.

### Build system

- Build node packages on Ubuntu 18.04 instead of Debian 10.
  This reduces the requirement for glibc version from 2.28 to 2.27.

### Fixes

- Allow membership changes by a MUA if we're not in the group ([#4624](https://github.com/chatmail/core/pull/4624)).
- Save mime headers for messages not signed with a known key ([#4557](https://github.com/chatmail/core/pull/4557)).
- Return from `dc_get_chatlist(DC_GCL_FOR_FORWARDING)` only chats where we can send ([#4616](https://github.com/chatmail/core/pull/4616)).
- Do not allow dots at the end of email addresses.
- deltachat-rpc-client: Remove `aiodns` optional dependency from required dependencies.
  `aiodns` depends on `pycares` which [fails to install in Termux](https://github.com/saghul/aiodns/issues/98).

## [1.120.0] - 2023-08-28

### API-Changes

- jsonrpc: Add `resend_messages`.

### Fixes

- Update async-imap to 0.9.1 to fix memory leak.
- Delete messages from SMTP queue only on user demand ([#4579](https://github.com/chatmail/core/pull/4579)).
- Do not send images without transparency as stickers ([#4611](https://github.com/chatmail/core/pull/4611)).
- `prepare_msg_blob()`: do not use the image if it has Exif metadata but the image cannot be recoded.

### Refactor

- Hide accounts.rs constants from public API.
- Hide pgp module from public API.

### Build system

- Update to Zig 0.11.0.
- Update to Rust 1.72.0.

### CI

- Run on push to stable branch.

### Miscellaneous Tasks

- python: Fix lint errors.
- python: Fix `ruff` 0.0.286 warnings.
- Fix beta clippy warnings.

## [1.119.1] - 2023-08-06

Bugfix release attempting to fix the [iOS build error](https://github.com/chatmail/core/issues/4610).

### Features / Changes

- Guess message viewtype from "application/octet-stream" attachment extension ([#4378](https://github.com/chatmail/core/pull/4378)).

### Fixes

- Update `xattr` from 1.0.0 to 1.0.1 to fix UnsupportedPlatformError import.

### Tests

- webxdc: Ensure unknown WebXDC update properties do not result in an error.

## [1.119.0] - 2023-08-03

### Fixes

- imap: Avoid IMAP move loops when DeltaChat folder is aliased.
- imap: Do not resync IMAP after initial configuration.

- webxdc: Accept WebXDC updates in mailing lists.
- webxdc: Base64-encode WebXDC updates to prevent corruption of large unencrypted WebXDC updates.
- webxdc: Delete old webxdc status updates during housekeeping.

- Return valid MsgId from `receive_imf()` when the message is replaced.
- Emit MsgsChanged event with correct chat id for replaced messages.

- deltachat-rpc-server: Update tokio-tar to fix backup import.

### Features / Changes

- deltachat-rpc-client: Add `MSG_DELETED` constant.
- Make `dc_msg_get_filename()` return the original attachment filename ([#4309](https://github.com/chatmail/core/pull/4309)).

### API-Changes

- deltachat-rpc-client: Add `Account.{import,export}_backup` methods.
- deltachat-jsonrpc: Make `MessageObject.text` non-optional.

### Documentation

- Update default value for `show_emails` in `dc_set_config()` documentation.

### Refactor

- Improve IMAP logs.

### Tests

- Add basic import/export test for async python.
- Add `test_webxdc_download_on_demand`.
- Add tests for deletion of webxdc status-updates.

## [1.118.0] - 2023-07-07

### API-Changes

- [**breaking**] Remove `Contact::load_from_db()` in favor of `Contact::get_by_id()`.
- Add `Contact::get_by_id_optional()` API.
- [**breaking**] Make `Message.text` non-optional.
- [**breaking**] Replace `message::get_msg_info()` with `MsgId.get_info()`.
- Move `handle_mdn` and `handle_ndn` to mimeparser and make them private.
  Previously `handle_mdn` was erroneously exposed in the public API.
- python: flatten the API of `deltachat` module.

### Fixes

- Use different member added/removal messages locally and on the network.
- Update tokio to 1.29.1 to fix core panic after sending 29 offline messages ([#4414](https://github.com/chatmail/core/issues/4414)).
- Make SVG avatar image work on more platforms (use `xlink:href`).
- Preserve indentation when converting plaintext to HTML.
- Do not run simplify() on dehtml() output.
- Rewrite member added/removed messages even if the change is not allowed PR ([#4529](https://github.com/chatmail/core/pull/4529)).

### Documentation

- Document how to regenerate Node.js constants before the release.

### Build system

- git-cliff: Do not fail if commit.footers is undefined.

### Other

- Dependency updates.
- Update MPL 2.0 license text.
- Add LICENSE file to deltachat-rpc-client.
- deltachat-rpc-client: Add Trove classifiers.
- python: Change bindings status to production/stable.

### Tests

- Add `make-python-testenv.sh` script.

## [1.117.0] - 2023-06-15

### Features

- New group membership update algorithm.

  New algorithm improves group consistency
  in cases of missing messages,
  restored old backups and replies from classic MUAs.

- Add `DC_EVENT_MSG_DELETED` event.

  This event notifies the UI about the message
  being deleted from the messagelist, e.g. when the message expires
  or the user deletes it.

### Fixes

- Emit `DC_EVENT_MSGS_CHANGED` without IDs when the message expires.

  Specifying msg IDs that cannot be loaded in the event payload
  results in an error when the UI tries to load the message.
  Instead, emit an event without IDs
  to make the UI reload the whole messagelist.

- Ignore address case when comparing the `To:` field to `Autocrypt-Gossip:`.

  This bug resulted in failure to propagate verification
  if the contact list already contained a new verified group member
  with a non-lowercase address.

- dehtml: skip links with empty text.

  Links like `<a href="https://delta.chat/"></a>` in HTML mails are now skipped
  instead of being converted to a link without a label like `[](https://delta.chat/)`.

- dehtml: Do not insert unnecessary newlines when parsing `<p>` tags.

- Update from yanked `libc` 0.2.145 to 0.2.146.
- Update to async-imap 0.9.0 to remove deprecated `ouroboros` dependency.

### API-Changes

- Emit `DC_EVENT_MSGS_CHANGED` per chat when messages are deleted.

  Previously a single event with zero chat ID was emitted.

- python: make `Contact.is_verified()` return bool.

- rust: add API endpoint `get_status_update` ([#4468](https://github.com/chatmail/core/pull/4468)).

- rust: make `WebxdcManifest` type public.

### Build system

- Use Rust 1.70.0 to compile deltachat-rpc-server releases.
- Disable unused `brotli` feature `ffi-api` and use 1 codegen-units for release builds to reduce the size of the binaries.

### CI

- Run `cargo check` with musl libc.
- concourse: Install devpi in a virtual environment.
- Remove [mergeable](https://mergeable.us/) configuration.

### Documentation

- README: mark napi.rs bindings as experimental. CFFI bindings are not legacy and are the recommended Node.js bindings currently.
- CONTRIBUTING: document how conventional commits interact with squash merges.

### Refactor

- Rename `MimeMessage.header` into `MimeMessage.headers`.

- Derive `Default` trait for `WebxdcManifest`.

### Tests

- Regression test for case-sensitive comparison of gossip header to contact address.
- Multiple new group consistency tests in Rust.
- python: Replace legacy `tmpdir` fixture with `tmp_path`.

## [1.116.0] - 2023-06-05

### API-Changes

- Add `dc_jsonrpc_blocking_call()`.

### Changes

- Generate OpenRPC definitions for JSON-RPC.
- Add more context to message loading errors.

### Fixes

- Build deltachat-node prebuilds on Debian 10.

### Documentation

- Document release process in `RELEASE.md`.
- Add contributing guidelines `CONTRIBUTING.md`.
- Update instructions for python devenv.
- python: Document pytest fixtures.

### Tests

- python: Make `test_mdn_asymmetric` less flaky.
- Make `test_group_with_removed_message_id` less flaky.
- Add golden tests infrastructure ([#4395](https://github.com/chatmail/core/pull/4395)).

### Build system

- git-cliff: Changelog generation improvements.
- `set_core_version.py`: Expect release date in the changelog.

### CI

- Require Python 3.8 for deltachat-rpc-client.
- mergeable: Allow PR titles to start with "ci" and "build".
- Remove incorrect comment.
- dependabot: Use `chore` prefix for dependency updates.
- Remove broken `node-delete-preview.yml` workflow.
- Add top comments to GH Actions workflows.
- Run node.js lint on Windows.
- Update clippy to 1.70.0.

### Miscellaneous Tasks

- Remove release.toml.
- gitattributes: Configure LF line endings for JavaScript files.
- Update dependencies

## [1.112.10] - 2023-06-01

### Fixes

- Disable `fetch_existing_msgs` setting by default.
- Update `h2` to fix RUSTSEC-2023-0034.

## [1.115.0] - 2023-05-12

### JSON-RPC API Changes

- Sort reactions in descending order ([#4388](https://github.com/chatmail/core/pull/4388)).
- Add API to get reactions outside the message snapshot.
- `get_chatlist_items_by_entries` now takes only chatids instead of `ChatListEntries`.
- `get_chatlist_entries` now returns `Vec<u32>` of chatids instead of `ChatListEntries`.
- `JSONRPCReactions.reactions` is now a `Vec<JSONRPCReaction>` with unique reactions and their count, sorted in descending order.
- `Event`: `context_id` property is now called `contextId`.
- Expand `MessageSearchResult`:
  - Always include `chat_name`(not an option anymore).
  - Add `author_id`, `chat_type`, `chat_color`, `is_chat_protected`, `is_chat_contact_request`, `is_chat_archived`.
  - `author_name` now contains the overridden sender name.
- `ChatListItemFetchResult` gets new properties: `summary_preview_image`, `last_message_type` and `last_message_id`
- New `MessageReadReceipt` type and `get_message_read_receipts(account_id, message_id)` jsonrpc method.

### API Changes

- New rust API `send_webxdc_status_update_struct` to send a `StatusUpdateItem`.
- Add `get_msg_read_receipts(context, msg_id)` - get the contacts that send read receipts for a message.

### Features / Changes

- Build deltachat-rpc-server releases for x86\_64 macOS.
- Generate changelogs using git-cliff ([#4393](https://github.com/chatmail/core/pull/4393), [#4396](https://github.com/chatmail/core/pull/4396)).
- Improve SMTP logging.
- Do not cut incoming text if "bot" config is set.

### Fixes

- JSON-RPC: typescript client: fix types of events in event emitter ([#4373](https://github.com/chatmail/core/pull/4373)).
- Fetch at most 100 existing messages even if EXISTS was not received ([#4383](https://github.com/chatmail/core/pull/4383)).
- Don't put a double dot at the end of error messages ([#4398](https://github.com/chatmail/core/pull/4398)).
- Recreate `smtp` table with AUTOINCREMENT `id` ([#4390](https://github.com/chatmail/core/pull/4390)).
- Do not return an error from `send_msg_to_smtp` if retry limit is exceeded.
- Make the bots automatically accept group chat contact requests ([#4377](https://github.com/chatmail/core/pull/4377)).
- Delete `smtp` rows when message sending is canceled ([#4391](https://github.com/chatmail/core/pull/4391)).

### Refactor

- Iterate over `msg_ids` without .iter().

## [1.112.9] - 2023-05-12

### Fixes

- Fetch at most 100 existing messages even if EXISTS was not received.
- Delete `smtp` rows when message sending is canceled.

### Changes

- Improve SMTP logging.

## [1.114.0] - 2023-04-24

### Changes
- JSON-RPC: Use long polling instead of server-sent notifications to retrieve events.
  This better corresponds to JSON-RPC 2.0 server-client distinction
  and is expected to simplify writing new bindings
  because dispatching events can be done on higher level.
- JSON-RPC: TS: Client now has a mandatory argument whether you want to start listening for events.

### Fixes
- JSON-RPC: do not print to stdout on failure to find an account.


## [1.113.0] - 2023-04-18

### Added
- New JSON-RPC API `can_send()`.
- New `dc_get_next_msgs()` and `dc_wait_next_msgs()` C APIs.
  New `get_next_msgs()` and `wait_next_msgs()` JSON-RPC API.
  These APIs can be used by bots to get all unprocessed messages
  in the order of their arrival and wait for them without relying on events.
- New Python bindings API `Account.wait_next_incoming_message()`.
- New Python bindings APIs `Message.is_from_self()` and `Message.is_from_device()`.

### Changes
- Increase MSRV to 1.65.0. #4236
- Remove upper limit on the attachment size. #4253
- Update rPGP to 0.10.1. #4236
- Compress HTML emails stored in the `mime_headers` column of the database.
- Strip BIDI characters in system messages, files, group names and contact names. #3479
- Use release date instead of the provider database update date in `maybe_add_time_based_warnings()`.
- Gracefully terminate `deltachat-rpc-server` on Ctrl+C (`SIGINT`), `SIGTERM` and EOF.
- Async Python API `get_fresh_messages_in_arrival_order()` is deprecated
  in favor of `get_next_msgs()` and `wait_next_msgs()`.
- Remove metadata from avatars and JPEG images before sending. #4037
- Recode PNG and other supported image formats to JPEG if they are > 500K in size. #4037

### Fixes
- Don't let blocking be bypassed using groups. #4316
- Show a warning if quota list is empty. #4261
- Do not reset status on other devices when sending signed reaction messages. #3692
- Update `accounts.toml` atomically.
- Fix python bindings README documentation on installing the bindings from source.
- Remove confusing log line "ignoring unsolicited response Recent(…)". #3934

## [1.112.8] - 2023-04-20

### Changes
- Add `get_http_response` JSON-RPC API.
- Add C API to get HTTP responses.

## [1.112.7] - 2023-04-17

### Fixes

- Updated `async-imap` to v0.8.0 to fix erroneous EOF detection in long IMAP responses.

## [1.112.6] - 2023-04-04

### Changes

- Add a device message after backup transfer #4301

### Fixed

- Updated `iroh` from 0.4.0 to 0.4.1 to fix transfer of large accounts with many blob files.

## [1.112.5] - 2023-04-02

### Fixes

- Run SQL database migrations after receiving a backup from the network. #4287

## [1.112.4] - 2023-03-31

### Fixes
- Fix call to `auditwheel` in `scripts/run_all.sh`.

## [1.112.3] - 2023-03-30

### Fixes
- `transfer::get_backup` now frees ongoing process when canceled. #4249

## [1.112.2] - 2023-03-30

### Changes
- Update iroh, remove `default-net` from `[patch.crates-io]` section.
- transfer backup: Connect to multiple provider addresses concurrently.  This should speed up connection time significantly on the getter side.  #4240
- Make sure BackupProvider is canceled on drop (or `dc_backup_provider_unref`).  The BackupProvider will now always finish with an IMEX event of 1000 or 0, previously it would sometimes finished with 1000 (success) when it really was 0 (failure). #4242

### Fixes
- Do not return media from trashed messages in the "All media" view. #4247

## [1.112.1] - 2023-03-27

### Changes
- Add support for `--version` argument to `deltachat-rpc-server`. #4224
  It can be used to check the installed version without starting the server.

### Fixes
- deltachat-rpc-client: fix bug in `Chat.send_message()`: invalid `MessageData` field `quotedMsg` instead of `quotedMsgId`
- `receive_imf`: Mark special messages as seen. Exactly: delivery reports, webxdc status updates. #4230


## [1.112.0] - 2023-03-23

### Changes
- Increase MSRV to 1.64. #4167
- Core takes care of stopping and re-starting IO itself where needed,
  e.g. during backup creation.
  It is no longer needed to call `dc_stop_io()`.
  `dc_start_io()` can now be called at any time without harm. #4138
- Pick up system's light/dark mode in generated message HTML. #4150
- More accurate `maybe_add_bcc_self` device message text. #4175
- "Full message view" not needed because of footers that go to contact status. #4151
- Support non-persistent configuration with `DELTACHAT_*` env. #4154
- Print deltachat-repl errors with causes. #4166

### Fixes
- Fix segmentation fault if `dc_context_unref()` is called during
  background process spawned by `dc_configure()` or `dc_imex()`
  or `dc_jsonrpc_instance_t` is unreferenced
  during handling the JSON-RPC request. #4153
- Delete expired messages using multiple SQL requests. #4158
- Do not emit "Failed to run incremental vacuum" warnings on success. #4160
- Ability to send backup over network and QR code to setup second device #4007
- Disable buffering during STARTTLS setup. #4190
- Add `DC_EVENT_IMAP_INBOX_IDLE` event to wait until the account
  is ready for testing.
  It is used to fix race condition between fetching
  existing messages and starting the test. #4208


## [1.111.0] - 2023-03-05

### Changes
- Make smeared timestamp generation non-async. #4075
- Set minimum TLS version to 1.2. #4096
- Run `cargo-deny` in CI. #4101
- Check provider database with CI. #4099 
- Switch to DEFERRED transactions #4100

### Fixes
- Do not block async task executor while decrypting the messages. #4079
- Housekeeping: delete the blobs backup dir #4123

### API-Changes
- jsonrpc: add more advanced API to send a message. #4097
- jsonrpc: add get webxdc blob API `getWebxdcBlob` #4070


## 1.110.0

### Changes
- use transaction in `Contact::add_or_lookup()` #4059
- Organize the connection pool as a stack rather than a queue to ensure that
  connection page cache is reused more often.
  This speeds up tests by 28%, real usage will have lower speedup. #4065
- Use transaction in `update_blocked_mailinglist_contacts`. #4058
- Remove `Sql.get_conn()` interface in favor of `.call()` and `.transaction()`. #4055
- Updated provider database.
- Disable DKIM-Checks again #4076
- Switch from "X.Y.Z" and "py-X.Y.Z" to "vX.Y.Z" tags. #4089
- mimeparser: handle headers from the signed part of unencrypted signed message #4013

### Fixes
- Start SQL transactions with IMMEDIATE behaviour rather than default DEFERRED one. #4063
- Fix a problem with Gmail where (auto-)deleted messages would get archived instead of deleted.
  Move them to the Trash folder for Gmail which auto-deletes trashed messages in 30 days #3972
- Clear config cache after backup import. This bug sometimes resulted in the import to seemingly work at first. #4067
- Update timestamps in `param` columns with transactions. #4083

### API-Changes


## 1.109.0

### Changes
- deltachat-rpc-client: use `dataclass` for `Account`, `Chat`, `Contact` and `Message` #4042

### Fixes
- deltachat-rpc-server: do not block stdin while processing the request. #4041
  deltachat-rpc-server now reads the next request as soon as previous request handler is spawned.
- Enable `auto_vacuum` on all SQL connections. #2955
- Replace `r2d2` connection pool with an own implementation. #4050 #4053 #4043 #4061
  This change improves reliability
  by closing all database connections immediately when the context is closed.

### API-Changes

- Remove `MimeMessage::from_bytes()` public interface. #4033
- BREAKING Types: jsonrpc: `get_messages` now returns a map with `MessageLoadResult` instead of failing completely if one of the requested messages could not be loaded. #4038
- Add `dc_msg_set_subject()`. C-FFI #4057
- Mark python bindings as supporting typing according to PEP 561 #4045


## 1.108.0

### Changes
- Use read/write timeouts instead of per-command timeouts for SMTP #3985
- Cache DNS results for SMTP connections #3985
- Prefer TLS over STARTTLS during autoconfiguration #4021
- Use SOCKS5 configuration for HTTP requests #4017
- Show non-deltachat emails by default for new installations #4019
- Re-enabled SMTP pipelining after disabling it in #4006

### Fixes
- Fix Securejoin for multiple devices on a joining side #3982
- python: handle NULL value returned from `dc_get_msg()` #4020
  Account.`get_message_by_id` may return `None` in this case.

### API-Changes
- Remove bitflags from `get_chat_msgs()` interface #4022
  C interface is not changed.
  Rust and JSON-RPC API have `flags` integer argument
  replaced with two boolean flags `info_only` and `add_daymarker`.
- jsonrpc: add API to check if the message is sent by a bot #3877


## 1.107.1

### Changes
- Log server security (TLS/STARTTLS/plain) type #4005

### Fixes
- Disable SMTP pipelining #4006


## 1.107.0

### Changes
- Pipeline SMTP commands #3924
- Cache DNS results for IMAP connections #3970

### Fixes
- Securejoin: Fix adding and handling Autocrypt-Gossip headers #3914
- fix verifier-by addr was empty string instead of None #3961
- Emit DC_EVENT_MSGS_CHANGED for DC_CHAT_ID_ARCHIVED_LINK when the number of archived chats with
  unread messages increases #3959
- Fix Peerstate comparison #3962
- Log SOCKS5 configuration for IMAP like already done for SMTP #3964
- Fix SOCKS5 usage for IMAP #3965
- Exit from recently seen loop on interrupt channel errors to avoid busy looping #3966

### API-Changes
- jsonrpc: add verified-by information to `Contact`-Object
- Remove `attach_selfavatar` config #3951

### Changes
- add debug logging support for webxdcs #3296

## 1.106.0

### Changes
- Only send IncomingMsgBunch if there are more than 0 new messages #3941

### Fixes
- fix: only send contact changed event for recently seen if it is relevant (not too old to matter) #3938
- Immediately save `accounts.toml` if it was modified by a migration from absolute paths to relative paths #3943
- Do not treat invalid email addresses as an exception #3942
- Add timeouts to HTTP requests #3948

## 1.105.0

### Changes
- Validate signatures in try_decrypt() even if the message isn't encrypted #3859
- Don't parse the message again after detached signatures validation #3862
- Move format=flowed support to a separate crate #3869
- cargo: bump quick-xml from 0.23.0 to 0.26.0 #3722
- Add fuzzing tests #3853
- Add mappings for some file types to Viewtype / MIME type #3881
- Buffer IMAP client writes #3888
- move `DC_CHAT_ID_ARCHIVED_LINK` to the top of chat lists
  and make `dc_get_fresh_msg_cnt()` work for `DC_CHAT_ID_ARCHIVED_LINK` #3918
- make `dc_marknoticed_chat()` work for `DC_CHAT_ID_ARCHIVED_LINK` #3919
- Update provider database

### API-Changes
- jsonrpc: add python API for webxdc updates #3872
- jsonrpc: add fresh message count to ChatListItemFetchResult::ArchiveLink
- Add ffi functions to retrieve `verified by` information #3786
- resultify `Message::get_filebytes()` #3925

### Fixes
- Do not add an error if the message is encrypted but not signed #3860
- Do not strip leading spaces from message lines #3867
- Fix uncaught exception in JSON-RPC tests #3884
- Fix STARTTLS connection and add a test for it #3907
- Trigger reconnection when failing to fetch existing messages #3911
- Do not retry fetching existing messages after failure, prevents infinite reconnection loop #3913
- Ensure format=flowed formatting is always reversible on the receiver side #3880


## 1.104.0

### Changes
- Don't use deprecated `chrono` functions #3798
- Document accounts manager #3837
- If a classical-email-user sends an email to a group and adds new recipients,
  add the new recipients as group members #3781
- Remove `pytest-async` plugin #3846
- Only send the message about ephemeral timer change if the chat is promoted #3847
- Use relative paths in `accounts.toml` #3838

### Fixes
- Set read/write timeouts for IMAP over SOCKS5 #3833
- Treat attached PGP keys as peer keys with mutual encryption preference #3832
- fix migration of old databases #3842
- Fix cargo clippy and doc errors after Rust update to 1.66 #3850
- Don't send GroupNameChanged message if the group name doesn't change in terms of
  `improve_single_line_input()` #3852
- Prefer encryption for the peer if the message is encrypted or signed with the known key #3849


## 1.103.0

### Changes
- Disable Autocrypt & Authres-checking for mailing lists,
  because they don't work well with mailing lists #3765
- Refactor: Remove the remaining AsRef<str> #3669
- Add more logging to `fetch_many_msgs` and refactor it #3811
- Small speedup #3780
- Log the reason when the message cannot be sent to the chat #3810
- Add IMAP server ID line to the context info only when it is known #3814
- Remove autogenerated typescript files #3815
- Move functions that require an IMAP session from `Imap` to `Session`
  to reduce the number of code paths where IMAP session may not exist.
  Drop connection on error instead of trying to disconnect,
  potentially preventing IMAP task from getting stuck. #3812

### API-Changes
- Add Python API to send reactions #3762
- jsonrpc: add message errors to MessageObject #3788
- jsonrpc: Add async Python client #3734

### Fixes
- Make sure malformed messages will never block receiving further messages anymore #3771
- strip leading/trailing whitespace from "Chat-Group-Name{,-Changed}:" headers content #3650
- Assume all Thunderbird users prefer encryption #3774
- refactor peerstate handling to ensure no duplicate peerstates #3776
- Fetch messages in order of their INTERNALDATE (fixes reactions for Gmail f.e.) #3789
- python: do not pass NULL to ffi.gc if the context can't be created #3818
- Add read/write timeouts to IMAP sockets #3820
- Add connection timeout to IMAP sockets #3828
- Disable read timeout during IMAP IDLE #3826
- Bots automatically accept mailing lists #3831

## 1.102.0

### Changes

- If an email has multiple From addresses, handle this as if there was
  no From address, to prevent from forgery attacks. Also, improve
  handling of emails with invalid From addresses in general #3667

### API-Changes

### Fixes
- fix detection of "All mail", "Trash", "Junk" etc folders. #3760
- fetch messages sequentially to fix reactions on partially downloaded messages #3688
- Fix a bug where one malformed message blocked receiving any further messages #3769


## 1.101.0

### Changes
- add `configured_inbox_folder` to account info #3748
- `dc_delete_contact()` hides contacts if referenced #3751
- add IMAP UIDs to message info #3755

### Fixes
- improve IMAP logging, in particular fix incorrect "IMAP IDLE protocol
  timed out" message on network error during IDLE #3749
- pop Recently Seen Loop event out of the queue when it is in the past
  to avoid busy looping #3753
- fix build failures by going back to standard `async_zip` #3747


## 1.100.0

### API-Changes
- jsonrpc: add `miscSaveSticker` method

### Changes
- add JSON-RPC stdio server `deltachat-rpc-server` and use it for JSON-RPC tests #3695
- update rPGP from 0.8 to 0.9 #3737
- jsonrpc: typescript client: use npm released deltachat fork of the tiny emitter package #3741
- jsonrpc: show sticker image in quote #3744



## 1.99.0

### API-Changes
- breaking jsonrpc: changed function naming
  - `autocryptInitiateKeyTransfer` -> `initiateAutocryptKeyTransfer`
  - `autocryptContinueKeyTransfer` -> `continueAutocryptKeyTransfer`
  - `chatlistGetFullChatById` -> `getFullChatById`
  - `messageGetMessage` -> `getMessage`
  - `messageGetMessages` -> `getMessages`
  - `messageGetNotificationInfo` -> `getMessageNotificationInfo`
  - `contactsGetContact` -> `getContact`
  - `contactsCreateContact` -> `createContact`
  - `contactsCreateChatByContactId` -> `createChatByContactId`
  - `contactsBlock` -> `blockContact`
  - `contactsUnblock` -> `unblockContact`
  - `contactsGetBlocked` -> `getBlockedContacts`
  - `contactsGetContactIds` -> `getContactIds`
  - `contactsGetContacts` -> `getContacts`
  - `contactsGetContactsByIds` -> `getContactsByIds`
  - `chatGetMedia` -> `getChatMedia`
  - `chatGetNeighboringMedia` -> `getNeighboringChatMedia`
  - `webxdcSendStatusUpdate` -> `sendWebxdcStatusUpdate`
  - `webxdcGetStatusUpdates` -> `getWebxdcStatusUpdates`
  - `messageGetWebxdcInfo` -> `getWebxdcInfo`
- jsonrpc: changed method signature
  - `miscSendTextMessage(accountId, text, chatId)` -> `miscSendTextMessage(accountId, chatId, text)`
- jsonrpc: add `SystemMessageType` to `Message`
- cffi: add missing `DC_INFO_` constants
- Add DC_EVENT_INCOMING_MSG_BUNCH event #3643
- Python bindings: Make get_matching() only match the
  whole event name, e.g. events.get_matching("DC_EVENT_INCOMING_MSG")
  won't match DC_EVENT_INCOMING_MSG_BUNCH anymore #3643


- Rust: Introduce a ContextBuilder #3698

### Changes
- allow sender timestamp to be in the future, but not too much
- Disable the new "Authentication-Results/DKIM checking" security feature
  until we have tested it a bit #3728
- refactorings #3706

### Fixes
- `dc_search_msgs()` returns unaccepted requests #3694
- emit "contacts changed" event when the contact is no longer "seen recently" #3703
- do not allow peerstate reset if DKIM check failed #3731


## 1.98.0

### API-Changes
- jsonrpc: typescript client: export constants under `C` enum, similar to how its exported from `deltachat-node` #3681
- added reactions support #3644
- jsonrpc: reactions: added reactions to `Message` type and the `sendReaction()` method #3686

### Changes
- simplify `UPSERT` queries #3676

### Fixes


## 1.97.0

### API-Changes
- jsonrpc: add function: #3641, #3645, #3653
  - `getChatContacts()`
  - `createGroupChat()`
  - `createBroadcastList()`
  - `setChatName()`
  - `setChatProfileImage()`
  - `downloadFullMessage()`
  - `lookupContactIdByAddr()`
  - `sendVideochatInvitation()`
  - `searchMessages()`
  - `messageIdsToSearchResults()`
  - `setChatVisibility()`
  - `getChatEphemeralTimer()`
  - `setChatEphemeralTimer()`
  - `getLocations()`
  - `getAccountFileSize()`
  - `estimateAutoDeletionCount()`
  - `setStockStrings()`
  - `exportSelfKeys()`
  - `importSelfKeys()`
  - `sendSticker()`
  - `changeContactName()`
  - `deleteContact()`
  - `joinSecurejoin()`
  - `stopIoForAllAccounts()`
  - `startIoForAllAccounts()`
  - `startIo()`
  - `stopIo()`
  - `exportBackup()`
  - `importBackup()`
  - `getMessageHtml()` #3671
  - `miscGetStickerFolder` and `miscGetStickers` #3672
- breaking: jsonrpc: remove function `messageListGetMessageIds()`, it is replaced by `getMessageIds()` and `getMessageListItems()` the latter returns a new `MessageListItem` type, which is the now preferred way of using the message list.
- jsonrpc: add type: #3641, #3645
  - `MessageSearchResult`
  - `Location`
- jsonrpc: add `viewType` to quoted message(`MessageQuote` type) in `Message` object type #3651


### Changes
- Look at Authentication-Results. Don't accept Autocrypt key changes
  if they come with negative authentication results while this contact
  sent emails with positive authentication results in the past. #3583
- jsonrpc in cffi also sends events now #3662
- jsonrpc: new format for events and better typescript autocompletion
- Join all "[migration] vXX" log messages into one

### Fixes
- share stock string translations across accounts created by the same account manager #3640
- suppress welcome device messages after account import #3642
- fix unix timestamp used for daymarker #3660

## 1.96.0

### Changes
- jsonrpc js client:
  - Change package name from `deltachat-jsonrpc-client` to `@deltachat/jsonrpc-client`
  - remove relative file dependency to it from `deltachat-node` (because it did not work anyway and broke the nix build of desktop)
  - ci: add github ci action to upload it to our download server automatically on release

## 1.95.0

### API-Changes
- jsonrpc: add `mailingListAddress` property to `FullChat` #3607
- jsonrpc: add `MessageNotificationInfo` & `messageGetNotificationInfo()` #3614
- jsonrpc: add `chat_get_neighboring_media` function #3610

### Changes
- added `dclogin:` scheme to allow configuration from a qr code
  (data inside qrcode, contrary to `dcaccount:` which points to an API to create an account) #3541
- truncate incoming messages by lines instead of just length #3480
- emit separate `DC_EVENT_MSGS_CHANGED` for each expired message,
  and `DC_EVENT_WEBXDC_INSTANCE_DELETED` when a message contains a webxdc #3605
- enable `bcc_self` by default #3612


## 1.94.0

### API-Changes
- breaking change: replace `dc_accounts_event_emitter_t` with `dc_event_emitter_t` #3422

  Type `dc_accounts_event_emitter_t` is removed.
  `dc_accounts_get_event_emitter()` returns `dc_event_emitter_t` now, so
  `dc_get_next_event()` should be used instead of `dc_accounts_get_next_event`
  and `dc_event_emitter_unref()` should be used instead of
  `dc_accounts_event_emitter_unref`.
- add `dc_contact_was_seen_recently()` #3560
- Fix `get_connectivity_html` and `get_encrinfo` futures not being Send. See rust-lang/rust#101650 for more information
- jsonrpc: add functions: #3586, #3587, #3590
  - `deleteChat()`
  - `getChatEncryptionInfo()`
  - `getChatSecurejoinQrCodeSvg()`
  - `leaveGroup()`
  - `removeContactFromChat()`
  - `addContactToChat()`
  - `deleteMessages()`
  - `getMessageInfo()`
  - `getBasicChatInfo()`
  - `marknoticedChat()`
  - `getFirstUnreadMessageOfChat()`
  - `markseenMsgs()`
  - `forwardMessages()`
  - `removeDraft()`
  - `getDraft()`
  - `miscSendMsg()`
  - `miscSetDraft()`
  - `maybeNetwork()`
  - `getConnectivity()`
  - `getContactEncryptionInfo()`
  - `getConnectivityHtml()`
- jsonrpc: add `is_broadcast` property to `ChatListItemFetchResult` #3584
- jsonrpc: add `was_seen_recently` property to `ChatListItemFetchResult`, `FullChat` and `Contact` #3584
- jsonrpc: add `webxdc_info` property to `Message` #3588
- python: move `get_dc_event_name()` from `deltachat` to `deltachat.events` #3564
- jsonrpc: add `webxdc_info`, `parent_id` and `download_state` property to `Message` #3588, #3590
- jsonrpc: add `BasicChat` object as a leaner alternative to `FullChat` #3590
- jsonrpc: add `last_seen` property to `Contact` #3590
- breaking! jsonrpc: replace `Message.quoted_text` and `Message.quoted_message_id` with `Message.quote` #3590
- add separate stock strings for actions done by contacts to make them easier to translate #3518
- `dc_initiate_key_transfer()` is non-blocking now. #3553
  UIs don't need to display a button to cancel sending Autocrypt Setup Message with
  `dc_stop_ongoing_process()` anymore.

### Changes
- order contact lists by "last seen";
  this affects `dc_get_chat_contacts()`, `dc_get_contacts()` and `dc_get_blocked_contacts()` #3562
- add `internet_access` flag to `dc_msg_get_webxdc_info()` #3516
- `DC_EVENT_WEBXDC_INSTANCE_DELETED` is emitted when a message containing a webxdc gets deleted #3592

### Fixes
- do not emit notifications for blocked chats #3557
- Show attached .eml files correctly #3561
- Auto accept contact requests if `Config::Bot` is set for a client #3567 
- Don't prepend the subject to chat messages in mailinglists
- fix `set_core_version.py` script to also update version in `deltachat-jsonrpc/typescript/package.json` #3585
- Reject webxdc-updates from contacts who are not group members #3568


## 1.93.0

### API-Changes
- added a JSON RPC API, accessible through a WebSocket server, the CFFI bindings and the Node.js bindings #3463 #3554 #3542
- JSON RPC methods in CFFI #3463:
 - `dc_jsonrpc_instance_t* dc_jsonrpc_init(dc_accounts_t* account_manager);`
 - `void dc_jsonrpc_unref(dc_jsonrpc_instance_t* jsonrpc_instance);`
 - `void dc_jsonrpc_request(dc_jsonrpc_instance_t* jsonrpc_instance, char* request);`
 - `char* dc_jsonrpc_next_response(dc_jsonrpc_instance_t* jsonrpc_instance);`
- node: JSON RPC methods #3463:
 - `AccountManager.prototype.startJsonRpcHandler(callback: ((response: string) => void)): void`
 - `AccountManager.prototype.jsonRpcRequest(message: string): void`

### Changes
- use [pathlib](https://docs.python.org/3/library/pathlib.html) in provider update script #3543
- `dc_get_chat_media()` can return media globally #3528
- node: add `getMailinglistAddr()` #3524
- avoid duplicate encoded-words package and test `cargo vendor` in ci #3549
- python: don't raise an error if addr changes #3530
- improve coverage script #3530

### Fixes
- improved error handling for account setup from qrcode #3474
- python: enable certificate checks in cloned accounts #3443


## 1.92.0

### API-Changes
- add `dc_chat_get_mailinglist_addr()` #3520


## 1.91.0

### Added
- python bindings: extra method to get an account running

### Changes
- refactorings #3437

### Fixes
- mark "group image changed" as system message on receiver side #3517


## 1.90.0

### Changes
- handle drafts from mailto links in scanned QR #3492
- do not overflow ratelimiter leaky bucket #3496
- (AEAP) Add device message after you changed your address #3505
- (AEAP) Revert #3491, instead only replace contacts in verified groups #3510
- improve python bindings and tests #3502 #3503

### Fixes
- don't squash text parts of NDN into attachments #3497
- do not treat non-failed DSNs as NDNs #3506


## 1.89.0

### Changes

- (AEAP) When one of your contacts changed their address, they are
  only replaced in the chat where you got a message from them
  for now #3491

### Fixes
- replace musl libc name resolution errors with a better message #3485
- handle updates for not yet downloaded webxdc instances #3487


## 1.88.0

### Changes
- Implemented "Automatic e-mail address Porting" (AEAP). You can
  configure a new address in DC now, and when receivers get messages
  they will automatically recognize your moving to a new address. #3385
- switch from `async-std` to `tokio` as the async runtime #3449
- upgrade to `pgp@0.8.0` #3467
- add IMAP ID extension support #3468
- configure DeltaChat folder by selecting it, so it is configured even if not LISTed #3371
- build PyPy wheels #6683
- improve default error if NDN does not provide an error #3456
- increase ratelimit from 3 to 6 messages per 60 seconds #3481

### Fixes
- mailing list: remove square-brackets only for first name #3452
- do not use footers from mailinglists as the contact status #3460
- don't ignore KML parsing errors #3473


## 1.87.0

### Changes
- limit the rate of MDN sending #3402
- ignore ratelimits for bots #3439
- remove `msgs_mdns` references to deleted messages during housekeeping #3387
- format message lines starting with `>` as quotes #3434
- node: remove `split2` dependency #3418
- node: add git installation info to readme #3418
- limit the rate of webxdc update sending #3417

### Fixes
- set a default error if NDN does not provide an error #3410
- python: avoid exceptions when messages/contacts/chats are compared with `None`
- node: wait for the event loop to stop before destroying contexts #3431 #3451
- emit configuration errors via event on failure #3433
- report configure and imex success/failure after freeing ongoing process #3442

### API-Changes
- python: added `Message.get_status_updates()`  #3416
- python: added `Message.send_status_update()`  #3416
- python: added `Message.is_webxdc()`  #3416
- python: added `Message.is_videochat_invitation()`  #3416
- python: added support for "videochat" and "webxdc" view types to `Message.new_empty()`  #3416


## 1.86.0

### API-Changes
- python: added optional `closed` parameter to `Account` constructor #3394
- python: added optional `passphrase` parameter to `Account.export_all()` and `Account.import_all()` #3394
- python: added `Account.open()` #3394
- python: added `Chat.is_single()` #3394
- python: added `Chat.is_mailinglist()` #3394
- python: added `Chat.is_broadcast()` #3394
- python: added `Chat.is_multiuser()` #3394
- python: added `Chat.is_self_talk()` #3394
- python: added `Chat.is_device_talk()` #3394
- python: added `Chat.is_pinned()` #3394
- python: added `Chat.pin()` #3394
- python: added `Chat.unpin()` #3394
- python: added `Chat.archive()` #3394
- python: added `Chat.unarchive()` #3394
- python: added `Message.get_summarytext()` #3394
- python: added optional `closed` parameter to `ACFactory.get_unconfigured_account()` (pytest plugin) #3394
- python: added optional `passphrase` parameter to `ACFactory.get_pseudo_configured_account()` (pytest plugin) #3394

### Changes
- clean up series of webxdc info messages;
  `DC_EVENT_MSGS_CHANGED` is emitted on changes of existing info messages #3395
- update provider database #3399
- refactorings #3375 #3403 #3398 #3404

### Fixes
- do not reset our database if imported backup cannot be decrypted #3397
- node: remove `npx` from build script, this broke flathub build #3396


## 1.85.0

### Changes
- refactorings #3373 #3345 #3380 #3382
- node: move split2 to devDependencies
- python: build Python 3.10 wheels #3392
- update Rust dependencies

### Fixes
- delete outgoing MDNs found in the Sent folder on Gmail #3372
- fix searching one-to-one chats #3377
- do not add legacy info-messages on resending webxdc #3389


## 1.84.0

### Changes
- refactorings #3354 #3347 #3353 #3346

### Fixes
- do not unnecessarily SELECT folders if there are no operations planned on
  them #3333
- trim chat encryption info #3350
- fix failure to decrypt first message to self after key synchronization
  via Autocrypt Setup Message #3352
- Keep pgp key when you change your own email address #3351
- Do not ignore Sent and Spam folders on Gmail #3369
- handle decryption errors explicitly and don't get confused by encrypted mail attachments #3374


## 1.83.0

### Fixes
- fix node prebuild & package ci #3337


## 1.82.0

### API-Changes
- re-add removed `DC_MSG_ID_MARKER1` as in use on iOS #3330

### Changes
- refactorings #3328

### Fixes
- fix node package ci #3331
- fix race condition in ongoing process (import/export, configuration) allocation #3322


## 1.81.0

### API-Changes
- deprecate unused `marker1before` argument of `dc_get_chat_msgs`
  and remove `DC_MSG_ID_MARKER1` constant #3274

### Changes
- now the node-bindings are also part of this repository 🎉 #3283
- support `source_code_url` from Webxdc manifests #3314
- support Webxdc document names and add `document` to `dc_msg_get_webxdc_info()` #3317 #3324
- improve chat encryption info, make it easier to find contacts without keys #3318
- improve error reporting when creating a folder fails #3325
- node: remove unmaintained coverage scripts
- send normal messages with higher priority than MDNs #3243
- make Scheduler stateless #3302
- abort instead of unwinding on panic #3259
- improve python bindings #3297 #3298
- improve documentation #3307 #3306 #3309 #3319 #3321
- refactorings #3304 #3303 #3323

### Fixes
- node: throw error when getting context with an invalid account id
- node: throw error when instantiating a wrapper class on `null` (Context, Message, Chat, ChatList and so on)
- use same contact-color if email address differ only in upper-/lowercase #3327
- repair encrypted mails "mixed up" by Google Workspace "Append footer" function #3315


## 1.80.0

### Changes
- update provider database #3284
- improve python bindings, tests and ci #3287 #3286 #3287 #3289 #3290 #3292

### Fixes
- fix escaping in generated QR-code-SVG #3295


## 1.79.0

### Changes
- Send locations in the background regardless of SMTP loop activity #3247
- refactorings #3268
- improve tests and ci #3266 #3271

### Fixes
- simplify `dc_stop_io()` and remove potential panics and race conditions #3273
- fix correct message escaping consisting of a dot in SMTP protocol #3265


## 1.78.0

### API-Changes
- replaced stock string `DC_STR_ONE_MOMENT` by `DC_STR_NOT_CONNECTED` #3222
- add `dc_resend_msgs()` #3238
- `dc_provider_new_from_email()` does no longer do an DNS lookup for checking custom domains,
  this is done by `dc_provider_new_from_email_with_dns()` now #3256

### Changes
- introduce multiple self addresses with the "configured" address always being the primary one #2896
- Further improve finding the correct server after logging in #3208
- `get_connectivity_html()` returns HTML as non-scalable #3213
- add update-serial to `DC_EVENT_WEBXDC_STATUS_UPDATE` #3215
- Speed up message receiving via IMAP a bit #3225
- mark messages as seen on IMAP in batches #3223
- remove Received: based draft detection heuristic #3230
- Use pkgconfig for building Python package #2590
- don't start io on unconfigured context #2664
- do not assign group IDs to ad-hoc groups #2798
- dynamic libraries use dylib extension on Darwin #3226
- refactorings #3217 #3219 #3224 #3235 #3239 #3244 #3254
- improve documentation #3214 #3220 #3237
- improve tests and ci #3212 #3233 #3241 #3242 #3252 #3250 #3255 #3260

### Fixes
- Take `delete_device_after` into account when calculating ephemeral loop timeout #3211 #3221
- Fix a bug where a blocked contact could send a contact request #3218
- Make sure, videochat-room-names are always URL-safe #3231
- Try removing account folder multiple times in case of failure #3229
- Ignore messages from all spam folders if there are many #3246
- Hide location-only messages instead of displaying empty bubbles #3248


## 1.77.0

### API changes
- change semantics of `dc_get_webxdc_status_updates()` second parameter
  and remove update-id from `DC_EVENT_WEBXDC_STATUS_UPDATE` #3081

### Changes
- add more SMTP logging #3093
- place common headers like `From:` before the large `Autocrypt:` header #3079
- keep track of securejoin joiner status in database to survive restarts #2920
- remove never used `SentboxMove` option #3111
- improve speed by caching config values #3131 #3145
- optimize `markseen_msgs` #3141
- automatically accept chats with outgoing messages #3143
- `dc_receive_imf` refactorings #3154 #3156 #3159
- add index to speedup deletion of expired ephemeral messages #3155
- muted chats stay archived on new messages #3184
- support `min_api` from Webxdc manifests #3206
- do not read whole webxdc file into memory #3109
- improve tests, refactorings #3073 #3096 #3102 #3108 #3139 #3128 #3133 #3142 #3153 #3151 #3174 #3170 #3148 #3179 #3185
- improve documentation #2983 #3112 #3103 #3118 #3120

### Fixes
- speed up loading of chat messages by a factor of 20 #3171 #3194 #3173
- fix an issue where the app crashes when trying to export a backup #3195
- hopefully fix a bug where outgoing messages appear twice with Amazon SES #3077
- do not delete messages without Message-IDs as duplicates #3095
- assign replies from a different email address to the correct chat #3119
- assign outgoing private replies to the correct chat #3177
- start ephemeral timer when seen status is synchronized via IMAP #3122
- do not create empty contact requests with "setup changed" messages;
  instead, send a "setup changed" message into all chats we share with the peer #3187
- do not delete duplicate messages on IMAP immediately to accidentally deleting
  the last copy #3138
- clear more columns when message expires due to `delete_device_after` setting #3181
- do not try to use stale SMTP connections #3180
- slightly improve finding the correct server after logging in #3207
- retry message sending automatically if loop is not interrupted #3183
- fix a bug where sometimes the file extension of a long filename containing a dot was cropped #3098


## 1.76.0

### Changes
- move messages in batches #3058
- delete messages in batches #3060
- python: remove arbitrary timeouts from tests #3059
- refactorings #3026

### Fixes
- avoid archived, fresh chats #3053
- Also resync UIDs in folders that are not configured #2289
- treat "NO" IMAP response to MOVE and COPY commands as an error #3058
- Fix a bug where messages in the Spam folder created contact requests #3015
- Fix a bug where drafts disappeared after some days #3067
- Parse MS Exchange read receipts and mark the original message as read #3075
- do not retry message sending infinitely in case of permanent SMTP failure #3070
- set message state to failed when retry limit is exceeded #3072


## 1.75.0

### Changes
- optimize `delete_expired_imap_messages()` #3047


## 1.74.0

### Fixes
- avoid reconnection loop when message without Message-ID is marked as seen #3044


## 1.73.0

### API changes
- added `only_fetch_mvbox` config #3028

### Changes
- don't watch Sent folder by default #3025
- use webxdc app name in chatlist/quotes/replies etc. #3027
- make it possible to cancel message sending by removing the message #3034,
  this was previously removed in 1.71.0 #2939
- synchronize Seen flags only on watched folders to speed up
  folder scanning #3041
- remove direct dependency on `byteorder` crate #3031
- refactorings #3023 #3013
- update provider database #3043
- improve documentation #3017 #3018 #3021

### Fixes
- fix splitting off text from webxdc messages #3032
- call slow `delete_expired_imap_messages()` less often #3037
- make synchronization of Seen status more robust in case unsolicited FETCH
  result without UID is returned #3022
- fetch Inbox before scanning folders to ensure iOS does
  not kill the app before it gets to fetch the Inbox in background #3040


## 1.72.0

### Fixes
- run migrations on backup import #3006


## 1.71.0

### API Changes
- added APIs to handle database passwords: `dc_context_new_closed()`, `dc_context_open()`,
  `dc_context_is_open()` and `dc_accounts_add_closed_account()` #2956 #2972
- use second parameter of `dc_imex` to provide backup passphrase #2980
- added `DC_MSG_WEBXDC`, `dc_send_webxdc_status_update()`,
  `dc_get_webxdc_status_updates()`, `dc_msg_get_webxdc_blob()`, `dc_msg_get_webxdc_info()`
  and `DC_EVENT_WEBXDC_STATUS_UPDATE` #2826 #2971 #2975 #2977 #2979 #2993 #2994 #2998 #3001 #3003
- added `dc_msg_get_parent()` #2984
- added `dc_msg_force_plaintext()` API for bots #2847
- allow removing quotes on drafts `dc_msg_set_quote(msg, NULL)` #2950
- removed `mvbox_watch` option; watching is enabled when `mvbox_move` is enabled #2906
- removed `inbox_watch` option #2922
- deprecated `os_name` in `dc_context_new()`, pass `NULL` or an empty string #2956

### Changes
- start making it possible to write to mailing lists #2736
- add `hop_info` to `dc_get_info()` #2751 #2914 #2923
- add information about whether the database is encrypted or not to `dc_get_info()` #3000
- selfstatus now defaults to empty #2951 #2960
- validate detached cryptographic signatures as used eg. by Thunderbird #2865
- do not change the draft's `msg_id` on updates and sending #2887
- add `imap` table to keep track of message UIDs #2909 #2938
- replace `SendMsgToSmtp` jobs which stored outgoing messages in blobdir with `smtp` SQL table #2939 #2996
- sql: enable `auto_vacuum=INCREMENTAL` #2931
- sql: build rusqlite with sqlcipher #2934
- synchronize Seen status across devices #2942
- `dc_preconfigure_keypair` now takes ascii armored keys instead of base64 #2862
- put removed member in Bcc instead of To in the message about removal #2864
- improve group updates #2889
- re-write the blob filename creation loop #2981
- update provider database (11 Jan 2022) #2959
- python: allow timeout for internal configure tracker API #2967
- python: remove API deprecated in Python 3.10 #2907
- refactorings #2932 #2957 #2947
- improve tests #2863 #2866 #2881 #2908 #2918 #2901 #2973
- improve documentation #2880 #2886 #2895
- improve ci #2919 #2926 #2969 #2999

### Fixes
- fix leaving groups #2929
- fix unread count #2861
- make `add_parts()` not early-exit #2879
- recognize MS Exchange read receipts as read receipts #2890
- create parent directory if creating a new file fails #2978
- save "configured" flag later #2974
- improve log #2928
- `dc_receive_imf`: don't fail on invalid address in the To field #2940


## 1.70.0

### Fixes
- fix: do not abort Param parsing on unknown keys #2856
- fix: execute `Chat-Group-Member-Removed:` even when arriving disordered #2857


## 1.69.0

### Fixes
- fix group-related system messages in multi-device setups #2848
- fix "Google Workspace" (former "G Suite") issues related to bad resolvers #2852


## 1.68.0

### Fixes
- fix chat assignment when forwarding #2843
- fix layout issues with the generated QR code svg #2842


## 1.67.0

### API changes
- `dc_get_securejoin_qr_svg(chat_id)` added #2815
- added stock-strings `DC_STR_SETUP_CONTACT_QR_DESC` and `DC_STR_SECURE_JOIN_GROUP_QR_DESC`


## 1.66.0

### API changes
- `dc_contact_get_last_seen()` added #2823
- python: `Contact.last_seen` added #2823
- removed `DC_STR_NEWGROUPDRAFT`, we don't set draft after creating group anymore #2805

### Changes
- python: add cutil.from_optional_dc_charpointer() #2824
- refactorings #2807 #2822 #2825


## 1.65.0

### Changes
- python: add mypy support and some type hints #2809

### Fixes
- do not disable ephemeral timer when downloading a message partially #2811
- apply existing ephemeral timer also to partially downloaded messages;
  after full download, the ephemeral timer starts over #2811
- replace user-visible error on verification failure with warning;
  the error is logged to the corresponding chat anyway #2808


## 1.64.0

### Fixes
- add 'waiting for being added to the group' only for group-joins,
  not for setup-contact #2797
- prioritize In-Reply-To: and References: headers over group IDs when assigning
  messages to chats to fix incorrect assignment of Delta Chat replies to
  classic email threads #2795


## 1.63.0

### API changes
- `dc_get_last_error()` added #2788

### Changes
- Optimize Autocrypt gossip #2743

### Fixes
- fix permanently hiding of one-to-one chats after secure-join #2791


## 1.62.0

### API Changes
- `dc_join_securejoin()` now always returns immediately;
  the returned chat may not allow sending (`dc_chat_can_send()` returns false)
  which may change as usual on `DC_EVENT_CHAT_MODIFIED` #2508 #2767
- introduce multi-device-sync-messages;
  as older cores display them as files in self-chat,
  they are currently only sent if config option `send_sync_msgs` is set #2669
- add `DC_EVENT_SELFAVATAR_CHANGED` #2742

### Changes
- use system DNS instead of google for MX queries #2780
- improve error logging #2758
- improve tests #2764 #2781
- improve ci #2770
- refactorings #2677 #2728 #2740 #2729 #2766 #2778

### Fixes
- add Let's Encrypt certificate to core as it may be missing older devices #2752
- prioritize certificate setting from user over the one from provider-db #2749
- fix "QR process failed" error #2725
- do not update quota in endless loop #2726


## 1.61.0

### API Changes
- download-on-demand added: `dc_msg_get_download_state()`, `dc_download_full_msg()`
  and `download_limit` config option #2631 #2696
- `dc_create_broadcast_list()` and chat type `DC_CHAT_TYPE_BROADCAST` added #2707 #2722
- allow ui-specific configs using `ui.`-prefix in key (`dc_set_config(context, "ui.*", value)`) #2672
- new strings from `DC_STR_PARTIAL_DOWNLOAD_MSG_BODY`
  to `DC_STR_PART_OF_TOTAL_USED` #2631 #2694 #2707 #2723
- emit warnings and errors from account manager with account-id 0 #2712

### Changes
- notify about incoming contact requests #2690
- messages are marked as read on first read receipt #2699
- quota warning reappears after import, rewarning at 95% #2702
- lock strict TLS if certificate checks are automatic #2711
- always check certificates strictly when connecting over SOCKS5 in Automatic mode #2657
- `Accounts` is not cloneable anymore #2654 #2658
- update chat/contact data only when there was no newer update #2642
- better detection of mailing list names #2665 #2685
- log all decisions when applying ephemeral timer to chats #2679
- connectivity view now translatable #2694 #2723
- improve Doxygen documentation #2647 #2668 #2684 #2688 #2705
- refactorings #2656 #2659 #2677 #2673 #2678 #2675 #2663 #2692 #2706
- update provider database #2618

### Fixes
- ephemeral timer rollback protection #2693 #2709
- recreate configured folders if they are deleted #2691
- ignore MDNs sent to self #2674
- recognize NDNs that put headers into "message/global-headers" part #2598
- avoid `dc_get_contacts()` returning duplicate contact ids #2591
- do not leak group names on forwarding messages #2719
- in case of smtp-errors, iterate over all addresses to fix ipv6/v4 problems #2720
- fix pkg-config file #2660
- fix "QR process failed" error #2725


## 1.60.0

### Added
- add device message to warn about QUOTA #2621
- add SOCKS5 support #2474 #2620

### Changes
- don't emit multiple events with the same import/export progress number #2639
- reduce message length limit to 5000 chars #2615

### Fixes
- keep event emitter from closing when there are no accounts #2636


## 1.59.0

### Added
- add quota information to `dc_get_connectivity_html()`

### Changes
- refactorings #2592 #2570 #2581
- add 'device chat about' to now existing status #2613
- update provider database #2608

### Fixes
- provider database supports socket=PLAIN and dotless domains now #2604 #2608
- add migrated accounts to events emitter #2607
- fix forwarding quote-only mails #2600
- do not set WantsMdn param for outgoing messages #2603
- set timestamps for system messages #2593
- do not treat gmail labels as folders #2587
- avoid timing problems in `dc_maybe_network_lost()` #2551
- only set smtp to "connected" if the last message was actually sent #2541


## 1.58.0

### Fixes
- move WAL file together with database
  and avoid using data if the database was not closed correctly before #2583


## 1.57.0

### API Changes

- breaking change: removed deaddrop chat #2514 #2563

  Contact request chats are not merged into a single virtual
  "deaddrop" chat anymore. Instead, they are shown in the chatlist the
  same way as other chats, but sending of messages to them is not
  allowed and MDNs are not sent automatically until the chat is
  "accepted" by the user.

  New API:
  - `dc_chat_is_contact_request()`: returns true if chat is a contact
    request.  In this case an option to accept the chat via
    `dc_accept_chat()` should be shown in the UI.
  - `dc_accept_chat()`: unblock the chat or accept contact request
  - `dc_block_chat()`: block the chat, currently works only for mailing
    lists.

  Removed API:
  - `dc_create_chat_by_msg_id()`: deprecated 2021-02-07 in favor of
    `dc_decide_on_contact_request()`
  - `dc_marknoticed_contact()`: deprecated 2021-02-07 in favor of
    `dc_decide_on_contact_request()`
  - `dc_decide_on_contact_request()`: this call requires a message ID
    from deaddrop chat as input. As deaddrop chat is removed, this
    call can't be used anymore.
  - `dc_msg_get_real_chat_id()`: use `dc_msg_get_chat_id()` instead, the
    only difference between these calls was in handling of deaddrop
    chat
  - removed `DC_CHAT_ID_DEADDROP` and `DC_STR_DEADDROP` constants

- breaking change: removed `DC_EVENT_ERROR_NETWORK` and `DC_STR_SERVER_RESPONSE`
  Instead, there is a new api `dc_get_connectivity()`
  and `dc_get_connectivity_html()`;
  `DC_EVENT_CONNECTIVITY_CHANGED` is emitted on changes

- breaking change: removed `dc_accounts_import_account()`
  Instead you need to add an account and call `dc_imex(DC_IMEX_IMPORT_BACKUP)`
  on its context

- update account api, 2 new methods:
  `int dc_all_work_done (dc_context_t* context);`
  `int dc_accounts_all_work_done (dc_accounts_t* accounts);`

- add api to check if a message was `Auto-Submitted`
  cffi: `int dc_msg_is_bot (const dc_msg_t* msg);`
  python: `Message.is_bot()`

- `dc_context_t* dc_accounts_get_selected_account (dc_accounts_t* accounts);`
  now returns `NULL` if there is no selected account

- added `dc_accounts_maybe_network_lost()` for systems core cannot find out
  connectivity loss on its own (eg. iOS) #2550

### Added
- use Auto-Submitted: auto-generated header to identify bots #2502
- allow sending stickers via repl tool
- chat: make `get_msg_cnt()` and `get_fresh_msg_cnt()` work for deaddrop chat #2493
- withdraw/revive own qr-codes #2512
- add Connectivity view (a better api for getting the connection status) #2319 #2549 #2542

### Changes
- updated spec: new `Chat-User-Avatar` usage, `Chat-Content: sticker`, structure, copyright year #2480
- update documentation #2548 #2561 #2569
- breaking: `Accounts::create` does not also create an default account anymore #2500
- remove "forwarded" from stickers, as the primary way of getting stickers
  is by asking a bot and then forwarding them currently #2526
- mimeparser: use mailparse to parse RFC 2231 filenames #2543
- allow email addresses without dot in the domain part #2112
- allow installing lib and include under different prefixes #2558
- remove counter from name provided by `DC_CHAT_ID_ARCHIVED_LINK` #2566
- improve tests #2487 #2491 #2497
- refactorings #2492 #2503 #2504 #2506 #2515 #2520 #2567 #2575 #2577 #2579
- improve ci #2494
- update provider-database #2565

### Removed
- remove `dc_accounts_import_account()` api #2521
- remove `DC_EVENT_ERROR_NETWORK` and `DC_STR_SERVER_RESPONSE` #2319

### Fixes
- allow stickers with gif-images #2481
- fix database migration #2486
- do not count hidden messages in get_msg_cnt(). #2493
- improve drafts detection #2489
- fix panic when removing last, selected account from account manager #2500
- set_draft's message-changed-event returns now draft's msg id instead of 0 #2304
- avoid hiding outgoing classic emails #2505
- fixes for message timestamps #2517
- do not process names, avatars, location XMLs, message signature etc.
  for duplicate messages #2513
- fix `can_send` for users not in group #2479
- fix receiving events for accounts added by `dc_accounts_add_account()` #2559
- fix which chats messages are assigned to #2465
- fix: don't create chats when MDNs are received #2578


## 1.56.0

- fix downscaling images #2469

- fix outgoing messages popping up in selfchat #2456

- securejoin: display error reason if there is any #2470

- do not allow deleting contacts with ongoing chats #2458

- fix: ignore drafts folder when scanning #2454

- fix: scan folders also when inbox is not watched #2446

- more robust In-Reply-To parsing #2182

- update dependencies #2441 #2438 #2439 #2440 #2447 #2448 #2449 #2452 #2453 #2460 #2464 #2466

- update provider-database #2471

- refactorings #2459 #2457

- improve tests and ci #2445 #2450 #2451


## 1.55.0

- fix panic when receiving some HTML messages #2434

- fix downloading some messages multiple times #2430

- fix formatting of read receipt texts #2431

- simplify SQL error handling #2415

- explicit rust API for creating chats with blocked status #2282

- debloat the binary by using less AsRef arguments #2425


## 1.54.0

- switch back from `sqlx` to `rusqlite` due to performance regressions #2380 #2381 #2385 #2387

- global search performance improvement #2364 #2365 #2366

- improve SQLite performance with `PRAGMA synchronous=normal` #2382

- python: fix building of bindings against system-wide install of `libdeltachat` #2383 #2385

- python: list `requests` as a requirement #2390

- fix creation of many delete jobs when being offline #2372

- synchronize status between devices #2386

- deaddrop (contact requests) chat improvements #2373

- add "Forwarded:" to notification and chatlist summaries #2310

- place user avatar directly into `Chat-User-Avatar` header #2232 #2384

- improve tests #2360 #2362 #2370 #2377 #2387

- cleanup #2359 #2361 #2374 #2376 #2379 #2388


## 1.53.0

- fix sqlx performance regression #2355 2356

- add a `ci_scripts/coverage.sh` #2333 #2334

- refactorings and tests #2348 #2349 #2350

- improve python bindings #2332 #2326


## 1.52.0

- database library changed from rusqlite to sqlx #2089 #2331 #2336 #2340

- add alias support: UIs should check for `dc_msg_get_override_sender_name()`
  also in single-chats now and display divergent names and avatars #2297

- parse blockquote-tags for better quote detection #2313

- ignore unknown classical emails from spam folder #2311

- support "Mixed Up” encryption repairing #2321

- fix single chat search #2344

- fix nightly clippy and rustc errors #2341

- update dependencies #2350

- improve ci #2342

- improve python bindings #2332 #2326


## 1.51.0

- breaking change: You have to call `dc_stop_io()`/`dc_start_io()`
  before/after `dc_imex(DC_IMEX_EXPORT_BACKUP)`:
  fix race condition and db corruption
  when a message was received during backup #2253

- save subject for messages: new api `dc_msg_get_subject()`,
  when quoting, use the subject of the quoted message as the new subject,
  instead of the last subject in the chat #2274 #2283

- new apis to get full or html message,
  `dc_msg_has_html()` and `dc_get_msg_html()` #2125 #2151 #2264 #2279

- new chat type and apis for the new mailing list support,
  `DC_CHAT_TYPE_MAILINGLIST`, `dc_msg_get_real_chat_id()`,
  `dc_msg_get_override_sender_name()` #1964 #2181 #2185 #2195 #2211 #2210 #2240
  #2241 #2243 #2258 #2259 #2261 #2267 #2270 #2272 #2290

- new api `dc_decide_on_contact_request()`,
  deprecated `dc_create_chat_by_msg_id()` and `dc_marknoticed_contact()` #1964

- new flag `DC_GCM_INFO_ONLY` for api `dc_get_chat_msgs()` #2132

- new api `dc_get_chat_encrinfo()` #2186

- new api `dc_contact_get_status()`, returning the recent footer #2218 #2307

- improve contact name update rules,
  add api `dc_contact_get_auth_name()` #2206 #2212 #2225

- new api for bots: `dc_msg_set_html()` #2153

- new api for bots: `dc_msg_set_override_sender_name()` #2231

- api removed: `dc_is_io_running()` #2139

- api removed: `dc_contact_get_first_name()` #2165 #2171

- improve compatibility with providers changing the Message-ID
  (as Outlook.com) #2250 #2265

- correctly show emails that were sent to an alias and then bounced 

- implement Consistent Color Generation (XEP-0392),
  that results in contact colors be be changed #2228 #2229 #2239

- fetch recent existing messages
  and create corresponding chats after configure #2106

- improve e-mail compatibility
  by scanning all folders from time to time #2067 #2152 #2158 #2184 #2215 #2224

- better support videochat-services not supporting random rooms #2191

- export backups as .tar files #2023

- scale avatars based on media_quality, fix avatar rotation #2063

- compare ephemeral timer to parent message to deal with reordering better #2100

- better ephemeral system messages #2183

- read quotes out of html messages #2104

- prepend subject to messages with attachments, if needed #2111

- run housekeeping at least once a day #2114

- resolve MX domain only once per OAuth2 provider #2122

- configure provider based on MX record #2123 #2134

- make transient bad destination address error permanent
  after n tries #2126 #2202

- enable strict TLS for known providers by default #2121

- improve and harden secure join #2154 #2161 #2251

- update `dc_get_info()` to return more information #2156

- prefer In-Reply-To/References
  over group-id stored in Message-ID #2164 #2172 #2173

- apply gossiped encryption preference to new peerstates #2174

- fix: do not return quoted messages from the trash chat #2221

- fix: allow emojis for location markers #2177

- fix encoding of Chat-Group-Name-Changed messages that could even lead to
  messages not being delivered #2141

- fix error when no temporary directory is available #1929

- fix marking read receipts as seen #2117

- fix read-notification for mixed-case addresses #2103

- fix decoding of attachment filenames #2080 #2094 #2102

- fix downloading ranges of message #2061

- fix parsing quoted encoded words in From: header #2193 #2204

- fix import/export race condition #2250

- fix: exclude muted chats from notified-list #2269 #2275

- fix: update uid_next if the server rewind it #2288

- fix: return error on fingerprint mismatch on qr-scan #2295

- fix ci #2217 #2226 #2244 #2245 #2249 #2277 #2286

- try harder on backup opening #2148

- trash messages more thoroughly #2273

- nicer logging #2284

- add CMakeLists.txt #2260

- switch to rust 1.50, update toolchains, deps #2150 #2155 #2165 #2107 #2262 #2271

- improve python bindings #2113 #2115 #2133 #2214

- improve documentation #2143 #2160 #2175 #2146

- refactorings #2110 #2136 #2135 #2168 #2178 #2189 #2190 #2198 #2197 #2201 #2196
  #2200 #2230 #2262 #2203

- update provider-database #2299


## 1.50.0

- do not fetch emails in between inbox_watch disabled and enabled again #2087

- fix: do not fetch from INBOX if inbox_watch is disabled #2085

- fix: do not use STARTTLS when PLAIN connection is requested
  and do not allow downgrade if STARTTLS is not available #2071


## 1.49.0

- add timestamps to image and video filenames #2068

- forbid quoting messages from another context #2069

- fix: preserve quotes in messages with attachments #2070


## 1.48.0

- `fetch_existing` renamed to `fetch_existing_msgs` and disabled by default
  #2035 #2042

- skip fetch existing messages/contacts if config-option `bot` set #2017

- always log why a message is sorted to trash #2045

- display a quote if top posting is detected #2047

- add ephemeral task cancellation to `dc_stop_io()`;
  before, there was no way to quickly terminate pending ephemeral tasks #2051

- when saved-messages chat is deleted,
  a device-message about recreation is added #2050

- use `max_smtp_rcpt_to` from provider-db,
  sending messages to many recipients in configurable chunks #2056

- fix handling of empty autoconfigure files #2027

- fix adding saved messages to wrong chats on multi-device #2034 #2039

- fix hang on android4.4 and other systems
  by adding a workaround to executer-blocking-handling bug #2040

- fix secret key export/import roundtrip #2048

- fix mistakenly unarchived chats #2057

- fix outdated-reminder test that fails only 7 days a year,
  including halloween :) #2059

- improve python bindings #2021 #2036 #2038

- update provider-database #2037


## 1.47.0

- breaking change: `dc_update_device_chats()` removed;
  this is now done automatically during configure
  unless the new config-option `bot` is set #1957

- breaking change: split `DC_EVENT_MSGS_NOTICED` off `DC_EVENT_MSGS_CHANGED`
  and remove `dc_marknoticed_all_chats()` #1942 #1981

- breaking change: remove unused starring options #1965

- breaking change: `DC_CHAT_TYPE_VERIFIED_GROUP` replaced by
  `dc_chat_is_protected()`; also single-chats may be protected now, this may
  happen over the wire even if the UI do not offer an option for that #1968

- breaking change: split quotes off message text,
  UIs should use at least `dc_msg_get_quoted_text()` to show quotes now #1975

- new api for quote handling: `dc_msg_set_quote()`, `dc_msg_get_quoted_text()`,
  `dc_msg_get_quoted_msg()` #1975 #1984 #1985 #1987 #1989 #2004

- require quorum to enable encryption #1946

- speed up and clean up account creation #1912 #1927 #1960 #1961

- configure now collects recent contacts and fetches last messages
  unless disabled by `fetch_existing` config-option #1913 #2003
  EDIT: `fetch_existing` renamed to `fetch_existing_msgs` in 1.48.0 #2042

- emit `DC_EVENT_CHAT_MODIFIED` on contact rename
  and set contact-id on `DC_EVENT_CONTACTS_CHANGED` #1935 #1936 #1937

- add `dc_set_chat_protection()`; the `protect` parameter in
  `dc_create_group_chat()` will be removed in an upcoming release;
  up to then, UIs using the "verified group" paradigm
  should not use `dc_set_chat_protection()` #1968 #2014 #2001 #2012 #2007

- remove unneeded `DC_STR_COUNT` #1991

- mark all failed messages as failed when receiving an NDN #1993

- check some easy cases for bad system clock and outdated app #1901

- fix import temporary directory usage #1929

- fix forcing encryption for reset peers #1998

- fix: do not allow to save drafts in non-writeable chats #1997

- fix: do not show HTML if there is no content and there is an attachment #1988

- fix recovering offline/lost connections, fixes background receive bug #1983

- fix ordering of accounts returned by `dc_accounts_get_all()` #1909

- fix whitespace for summaries #1938

- fix: improve sentbox name guessing #1941

- fix: avoid manual poll impl for accounts events #1944

- fix encoding newlines in param as a preparation for storing quotes #1945

- fix: internal and ffi error handling #1967 #1966 #1959 #1911 #1916 #1917 #1915

- fix ci #1928 #1931 #1932 #1933 #1934 #1943

- update provider-database #1940 #2005 #2006

- update dependencies #1919 #1908 #1950 #1963 #1996 #2010 #2013


## 1.46.0

- breaking change: `dc_configure()` report errors in
  `DC_EVENT_CONFIGURE_PROGRESS`: capturing error events is no longer working
  #1886 #1905

- breaking change: removed `DC_LP_{IMAP|SMTP}_SOCKET*` from `server_flags`;
  added `mail_security` and `send_security` using `DC_SOCKET` enum #1835

- parse multiple servers in Mozilla autoconfig #1860

- try multiple servers for each protocol #1871

- do IMAP and SMTP configuration in parallel #1891

- configuration cleanup and speedup #1858 #1875 #1889 #1904 #1906

- secure-join cleanup, testing, fixing #1876 #1877 #1887 #1888 #1896 #1899 #1900

- do not reset peerstate on encrypted messages,
  ignore reordered autocrypt headers #1885 #1890

- always sort message replies after parent message #1852

- add an index to significantly speed up `get_fresh_msg_cnt()` #1881

- improve mimetype guessing for PDF and many other formats #1857 #1861

- improve accepting invalid html #1851

- improve tests, cleanup and ci #1850 #1856 #1859 #1861 #1884 #1894 #1895

- tweak HELO command #1908

- make `dc_accounts_get_all()` return accounts sorted #1909

- fix KML coordinates precision used for location streaming #1872

- fix cancelling import/export #1855


## 1.45.0

- add `dc_accounts_t` account manager object and related api functions #1784

- add capability to import backups as .tar files,
  which will become the default in a subsequent release #1749

- try various server domains on configuration #1780 #1838

- recognize .tgs files as stickers #1826

- remove X-Mailer debug header #1819

- improve guessing message types from extension #1818

- fix showing unprotected subjects in encrypted messages #1822

- fix threading in interaction with non-delta-clients #1843

- fix handling if encryption degrades #1829

- fix webrtc-servers names set by the user #1831

- update provider database #1828

- update async-imap to fix Oauth2 #1837

- optimize jpeg assets with trimage #1840

- add tests and documentations #1809 #1820


## 1.44.0

- fix peerstate issues #1800 #1805

- fix a crash related to muted chats #1803

- fix incorrect dimensions sometimes reported for images #1806

- fixed `dc_chat_get_remaining_mute_duration` function #1807

- handle empty tags (e.g. `<br/>`) in HTML mails #1810

- always translate the message about disappearing messages timer change #1813

- improve footer detection in plain text email #1812

- update device chat icon to fix warnings in iOS logs #1802

- fix deletion of multiple messages #1795


## 1.43.0

- improve using own jitsi-servers #1785

- fix smtp-timeout tweaks for larger mails #1797

- more bug fixes and updates #1794 #1792 #1789 #1787


## 1.42.0

- new qr-code type `DC_QR_WEBRTC` #1779

- tweak smtp-timeout for larger mails #1782

- optimize read-receipts #1765

- improve tests #1769

- bug fixes #1766 #1772 #1773 #1775 #1776 #1777


## 1.41.0

- new apis to initiate video chats #1718 #1735

- new apis `dc_msg_get_ephemeral_timer()`
  and `dc_msg_get_ephemeral_timestamp()`

- new api `dc_chatlist_get_summary2()` #1771

- improve IMAP handling #1703 #1704

- improve ephemeral messages #1696 #1705

- mark location-messages as auto-generated #1715

- multi-device avatar-sync #1716 #1717

- improve python bindings #1732 #1733 #1738 #1769

- Allow http scheme for DCACCOUNT urls #1770

- more fixes #1702 #1706 #1707 #1710 #1719 #1721
  #1723 #1734 #1740 #1744 #1748 #1760 #1766 #1773 #1765

- refactorings #1712 #1714 #1757

- update toolchains and dependencies #1726 #1736 #1737 #1742 #1743 #1746


## 1.40.0

- introduce ephemeral messages #1540 #1680 #1683 #1684 #1691 #1692

- `DC_MSG_ID_DAYMARKER` gets timestamp attached #1677 #1685

- improve idle #1690 #1688

- fix message processing issues by sequential processing #1694

- refactorings #1670 #1673


## 1.39.0

- fix handling of `mvbox_watch`, `sentbox_watch`, `inbox_watch` #1654 #1658

- fix potential panics, update dependencies #1650 #1655


## 1.38.0

- fix sorting, esp. for multi-device


## 1.37.0

- improve ndn heuristics #1630

- get oauth2 authorizer from provider-db #1641

- removed linebreaks and spaces from generated qr-code #1631

- more fixes #1633 #1635 #1636 #1637


## 1.36.0

- parse ndn (network delivery notification) reports
  and report failed messages as such #1552 #1622 #1630

- add oauth2 support for gsuite domains #1626

- read image orientation from exif before recoding #1619

- improve logging #1593 #1598

- improve python and bot bindings #1583 #1609

- improve imap logout #1595

- fix sorting #1600 #1604

- fix qr code generation #1631

- update rustcrypto releases #1603

- refactorings #1617


## 1.35.0

- enable strict-tls from a new provider-db setting #1587

- new subject 'Message from USER' for one-to-one chats #1395

- recode images #1563

- improve reconnect handling #1549 #1580

- improve importing addresses #1544

- improve configure and folder detection #1539 #1548

- improve test suite #1559 #1564 #1580 #1581 #1582 #1584 #1588:

- fix ad-hoc groups #1566

- preventions against being marked as spam #1575

- refactorings #1542 #1569


## 1.34.0

- new api for io, thread and event handling #1356,
  see the example atop of `deltachat.h` to get an overview

- LOTS of speed improvements due to async processing #1356

- enable WAL mode for sqlite #1492

- process incoming messages in bulk #1527

- improve finding out the sent-folder #1488

- several bug fixes


## 1.33.0

- let `dc_set_muted()` also mute one-to-one chats #1470

- fix a bug that led to load and traffic if the server does not use sent-folder
  #1472


## 1.32.0

- fix endless loop when trying to download messages with bad RFC Message-ID,
  also be more reliable on similar errors #1463 #1466 #1462

- fix bug with comma in contact request #1438

- do not refer to hidden messages on replies #1459

- improve error handling #1468 #1465 #1464


## 1.31.0

- always describe the context of the displayed error #1451

- do not emit `DC_EVENT_ERROR` when message sending fails;
  `dc_msg_get_state()` and `dc_get_msg_info()` are sufficient #1451

- new config-option `media_quality` #1449

- try over if writing message to database fails #1447


## 1.30.0

- expunge deleted messages #1440

- do not send `DC_EVENT_MSGS_CHANGED|INCOMING_MSG` on hidden messages #1439


## 1.29.0

- new config options `delete_device_after` and `delete_server_after`,
  each taking an amount of seconds after which messages
  are deleted from the device and/or the server #1310 #1335 #1411 #1417 #1423

- new api `dc_estimate_deletion_cnt()` to estimate the effect
  of `delete_device_after` and `delete_server_after`

- use Ed25519 keys by default, these keys are much shorter
  than RSA keys, which results in saving traffic and speed improvements #1362

- improve message ellipsizing #1397 #1430

- emit `DC_EVENT_ERROR_NETWORK` also on smtp-errors #1378

- do not show badly formatted non-delta-messages as empty #1384

- try over SMTP on potentially recoverable error 5.5.0 #1379

- remove device-chat from forward-to-chat-list #1367

- improve group-handling #1368

- `dc_get_info()` returns uptime (how long the context is in use)

- python improvements and adaptions #1408 #1415

- log to the stdout and stderr in tests #1416

- refactoring, code improvements #1363 #1365 #1366 #1370 #1375 #1389 #1390 #1418 #1419

- removed api: `dc_chat_get_subtitle()`, `dc_get_version_str()`, `dc_array_add_id()`

- removed events: `DC_EVENT_MEMBER_ADDED`, `DC_EVENT_MEMBER_REMOVED`


## 1.28.0

- new flag DC_GCL_FOR_FORWARDING for dc_get_chatlist()
  that will sort the "saved messages" chat to the top of the chatlist #1336
- mark mails as being deleted from server in dc_empty_server() #1333
- fix interaction with servers that do not allow folder creation on root-level;
  use path separator as defined by the email server #1359
- fix group creation if group was created by non-delta clients #1357
- fix showing replies from non-delta clients #1353
- fix member list on rejoining left groups #1343
- fix crash when using empty groups #1354
- fix potential crash on special names #1350


## 1.27.0

- handle keys reliably on armv7 #1327


## 1.26.0

- change generated key type back to RSA as shipped versions
  have problems to encrypt to Ed25519 keys

- update rPGP to encrypt reliably to Ed25519 keys;
  one of the next versions can finally use Ed25519 keys then


## 1.25.0

- save traffic by downloading only messages that are really displayed #1236

- change generated key type to Ed25519, these keys are much shorter
  than RSA keys, which results in saving traffic and speed improvements #1287

- improve key handling #1237 #1240 #1242 #1247

- mute handling, apis are dc_set_chat_mute_duration()
  dc_chat_is_muted() and dc_chat_get_remaining_mute_duration() #1143

- pinning chats, new apis are dc_set_chat_visibility() and
  dc_chat_get_visibility() #1248

- add dc_provider_new_from_email() api that queries the new, integrated
  provider-database #1207

- account creation by scanning a qr code
  in the DCACCOUNT scheme (https://mailadm.readthedocs.io),
  new api is dc_set_config_from_qr() #1249

- if possible, dc_join_securejoin(), returns the new chat-id immediately
  and does the handshake in background #1225

- update imap and smtp dependencies #1115

- check for MOVE capability before using MOVE command #1263

- allow inline attachments from RFC 2183 #1280

- fix updating names from incoming mails #1298

- fix error messages shown on import #1234

- directly attempt to re-connect if the smtp connection is maybe stale #1296

- improve adding group members #1291

- improve rust-api #1261

- cleanup #1302 #1283 #1282 #1276 #1270-#1274 #1267 #1258-#1260
  #1257 #1239 #1231 #1224

- update spec #1286 #1291


## 1.0.0-beta.24

- fix oauth2/gmail bug introduced in beta23 (not used in releases) #1219

- fix panic when receiving eg. cyrillic filenames #1216

- delete all consumed secure-join handshake messagess #1209 #1212

- Rust-level cleanups #1218 #1217 #1210 #1205

- python-level cleanups #1204 #1202 #1201


## 1.0.0-beta.23

- #1197 fix imap-deletion of messages 

- #1171 Combine multiple MDNs into a single mail, reducing traffic 

- #1155 fix to not send out gossip always, reducing traffic

- #1160 fix reply-to-encrypted determination 

- #1182 Add "Auto-Submitted: auto-replied" header to MDNs

- #1194 produce python wheels again, fix c/py.delta.chat
  master-deployment 

- rust-level housekeeping and improvements #1161 #1186 #1185 #1190 #1194 #1199 #1191 #1190 #1184 and more

- #1063 clarify licensing 

- #1147 use mailparse 0.10.2 


## 1.0.0-beta.22

- #1095 normalize email lineends to CRLF

- #1095 enable link-time-optimization, saves eg. on android 11 mb

- #1099 fix import regarding devicechats

- #1092 improve logging

- #1096 #1097 #1094 #1090 #1091 internal cleanups

## 1.0.0-beta.21

- #1078 #1082 ensure RFC compliance by producing 78 column lines for
  encoded attachments. 

- #1080 don't recreate and thus break group membership if an unknown 
  sender (or mailer-daemon) sends a message referencing the group chat 

- #1081 #1079 some internal cleanups 

- update imap-proto dependency, to fix yandex/oauth 

## 1.0.0-beta.20

- #1074 fix OAUTH2/gmail
- #1072 fix group members not appearing in contact list
- #1071 never block interrupt_idle (thus hopefully also not on maybe_network())
- #1069 reduce smtp-timeout to 30 seconds
- #1066 #1065 avoid unwrap in dehtml, make literals more readable

## 1.0.0-beta.19

- #1058 timeout smtp-send if it doesn't complete in 15 minutes 

- #1059 trim down logging

## 1.0.0-beta.18

- #1056 avoid panicking when we couldn't read imap-server's greeting
  message 

- #1055 avoid panicking when we don't have a selected folder

- #1052 #1049 #1051 improve logging to add thread-id/name and
  file/lineno to each info/warn message.

- #1050 allow python bindings to initialize Account with "os_name".


## 1.0.0-beta.17

- #1044 implement avatar recoding to 192x192 in core to keep file sizes small. 

- #1024 fix #1021 SQL/injection malformed Chat-Group-Name breakage

- #1036 fix smtp crash by pulling in a fixed async-smtp 

- #1039 fix read-receipts appearing as normal messages when you change
  MDN settings 

- #1040 do not panic on SystemTimeDifference

- #1043 avoid potential crashes in malformed From/Chat-Disposition... headers  

- #1045 #1041 #1038 #1035 #1034 #1029 #1025 various cleanups and doc
  improvements

## 1.0.0-beta.16

- alleviate login problems with providers which only
  support RSA1024 keys by switching back from Rustls 
  to native-tls, by using the new async-email/async-native-tls 
  crate from @dignifiedquire. thanks @link2xt. 

- introduce per-contact profile images to send out 
  own profile image heuristically, and fix sending
  out of profile images in "in-prepare" groups. 
  this also extends the Chat-spec that is maintained
  in core to specify Chat-Group-Image and Chat-Group-Avatar
  headers. thanks @r10s and @hpk42.

- fix merging of protected headers from the encrypted
  to the unencrypted parts, now not happening recursively
  anymore.  thanks @hpk and @r10s

- fix/optimize autocrypt gossip headers to only get 
  sent when there are more than 2 people in a chat. 
  thanks @link2xt

- fix displayname to use the authenticated name 
  when available (displayname as coming from contacts 
  themselves). thanks @simon-laux

- introduce preliminary support for offline autoconfig 
  for nauta provider. thanks @hpk42 @r10s

## 1.0.0-beta.15

- fix #994 attachment appeared doubled in chats (and where actually
  downloaded after smtp-send). @hpk42

## 1.0.0-beta.14

- fix packaging issue with our rust-email fork, now we are tracking
  master again there. hpk42

## 1.0.0-beta.13

- fix #976 -- unicode-issues in display-name of email addresses. @hpk42

- fix #985 group add/remove member bugs resulting in broken groups.  @hpk42

- fix hanging IMAP connections -- we now detect with a 15second timeout
  if we cannot terminate the IDLE IMAP protocol. @hpk42 @link2xt

- fix incoming multipart/mixed containing html, to show up as
  attachments again.  Fixes usage for simplebot which sends html
  files for users to interact with the bot. @adbenitez @hpk42 

- refinements to internal autocrypt-handling code, do not send
  prefer-encrypt=nopreference as it is the default if no attribute
  is present.  @linkxt 

- simplify, modularize and rustify several parts 
  of dc-core (general WIP). @link2xt @flub @hpk42 @r10s

- use async-email/async-smtp to handle SMTP connections, might
  fix connection/reconnection issues. @link2xt 

- more tests and refinements for dealing with blobstorage @flub @hpk42 

- use a dedicated build-server for CI testing of core PRs


## 1.0.0-beta.12

- fix python bindings to use core for copying attachments to blobdir
  and fix core to actually do it. @hpk42

## 1.0.0-beta.11

- trigger reconnect more often on imap error states.  Should fix an 
  issue observed when trying to empty a folder.  @hpk42

- un-split qr tests: we fixed qr-securejoin protocol flakiness 
  last weeks. @hpk42

## 1.0.0-beta.10

- fix grpid-determination from in-reply-to and references headers. @hpk42

- only send Autocrypt-gossip headers on encrypted messages. @dignifiedquire

- fix reply-to-encrypted message to also be encrypted. @hpk42

- remove last unsafe code from dc_receive_imf :) @hpk42

- add experimental new dc_chat_get_info_json FFI/API so that desktop devs
  can play with using it. @jikstra

- fix encoding of subjects and attachment-filenames @hpk42
  @dignifiedquire . 

## 1.0.0-beta.9

- historic: we now use the mailparse crate and lettre-email to generate mime
  messages.  This got rid of mmime completely, the C2rust generated port of the libetpan 
  mime-parse -- IOW 22KLocs of cumbersome code removed! see 
  https://github.com/chatmail/core/pull/904#issuecomment-561163330
  many thanks @dignifiedquire for making everybody's life easier 
  and @jonhoo (from rust-imap fame) for suggesting to use the mailparse crate :) 

- lots of improvements and better error handling in many rust modules 
  thanks @link2xt @flub @r10s, @hpk42 and @dignifiedquire 

- @r10s introduced a new device chat which has an initial
  welcome message.  See 
  https://c.delta.chat/classdc__context__t.html#a1a2aad98bd23c1d21ee42374e241f389
  for the main new FFI-API.

- fix moving self-sent messages, thanks @r10s, @flub, @hpk42

- fix flakiness/sometimes-failing verified/join-protocols, 
  thanks @flub, @r10s, @hpk42

- fix reply-to-encrypted message to keep encryption 

- new DC_EVENT_SECUREJOIN_MEMBER_ADDED event 

- many little fixes and rustifications (@link2xt, @flub, @hpk42)


## 1.0.0-beta.8

- now uses async-email/async-imap as the new base 
  which makes imap-idle interruptible and thus fixes
  several issues around the imap thread being in zombie state . 
  thanks @dignifiedquire, @hpk42 and @link2xt. 

- fixes imap-protocol parsing bugs that lead to infinitely
  repeated crashing while trying to receive messages with
  a subject that contained non-utf8. thanks @link2xt

- fixed logic to find encryption subkey -- previously 
  delta chat would use the primary key for encryption
  (which works with RSA but not ECC). thanks @link2xt

- introduce a new device chat where core and UIs can 
  add "device" messages.  Android uses it for an initial
  welcome message. thanks @r10s

- fix time smearing (when two message are virtually send
  in the same second, there would be misbehaviour because
  we didn't persist smeared time). thanks @r10s

- fix double-dotted extensions like .html.zip or .tar.gz  
  to not mangle them when creating blobfiles.  thanks @flub

- fix backup/exports where the wrong sql file would be modified,
  leading to problems when exporting twice.  thanks @hpk42

- several other little fixes and improvements 


## 1.0.0-beta.7

- fix location-streaming #782

- fix display of messages that could not be decrypted #785
 
- fix smtp MAILER-DAEMON bug #786 

- fix a logging of durations #783

- add more error logging #779

- do not panic on some bad utf-8 mime #776

## 1.0.0-beta.6

- fix chatlist.get_msg_id to return id, instead of wrongly erroring

## 1.0.0-beta.5

- fix dc_get_msg() to return empty messages when asked for special ones 

## 1.0.0-beta.4

- fix more than one sending of autocrypt setup message

- fix recognition of mailto-address-qr-codes, add tests

- tune down error to warning when adding self to chat

## 1.0.0-beta.3

- add back `dc_empty_server()` #682

- if `show_emails` is set to `DC_SHOW_EMAILS_ALL`,
  email-based contact requests are added to the chatlist directly

- fix IMAP hangs #717 and cleanups

- several rPGP fixes

- code streamlining and rustifications


## 1.0.0-beta.2

- https://c.delta.chat docs are now regenerated again through our CI 

- several rPGP cleanups, security fixes and better multi-platform support 

- reconnect on io errors and broken pipes (imap)

- probe SMTP with real connection not just setup

- various imap/smtp related fixes

- use to_string_lossy in most places instead of relying on valid utf-8
  encodings
 
- rework, rustify and test autoconfig-reading and parsing 

- some rustifications/boolifications of c-ints 


## 1.0.0-beta.1 

- first beta of the Delta Chat Rust core library. many fixes of crashes
  and other issues compared to 1.0.0-alpha.5.

- Most code is now "rustified" and does not do manual memory allocation anymore. 

- The `DC_EVENT_GET_STRING` event is not used anymore, removing the last
  event where the core requested a return value from the event callback. 

  Please now use `dc_set_stock_translation()` API for core messages
  to be properly localized. 

- Deltachat FFI docs are automatically generated and available here: 
  https://c.delta.chat 

- New events ImapMessageMoved and ImapMessageDeleted

For a full list of changes, please see our closed Pull Requests: 

https://github.com/chatmail/core/pulls?q=is%3Apr+is%3Aclosed

[1.111.0]: https://github.com/chatmail/core/compare/v1.110.0...v1.111.0
[1.112.0]: https://github.com/chatmail/core/compare/v1.111.0...v1.112.0
[1.112.1]: https://github.com/chatmail/core/compare/v1.112.0...v1.112.1
[1.112.2]: https://github.com/chatmail/core/compare/v1.112.1...v1.112.2
[1.112.3]: https://github.com/chatmail/core/compare/v1.112.2...v1.112.3
[1.112.4]: https://github.com/chatmail/core/compare/v1.112.3...v1.112.4
[1.112.5]: https://github.com/chatmail/core/compare/v1.112.4...v1.112.5
[1.112.6]: https://github.com/chatmail/core/compare/v1.112.5...v1.112.6
[1.112.7]: https://github.com/chatmail/core/compare/v1.112.6...v1.112.7
[1.112.8]: https://github.com/chatmail/core/compare/v1.112.7...v1.112.8
[1.112.9]: https://github.com/chatmail/core/compare/v1.112.8...v1.112.9
[1.112.10]: https://github.com/chatmail/core/compare/v1.112.9...v1.112.10
[1.113.0]: https://github.com/chatmail/core/compare/v1.112.9...v1.113.0
[1.114.0]: https://github.com/chatmail/core/compare/v1.113.0...v1.114.0
[1.115.0]: https://github.com/chatmail/core/compare/v1.114.0...v1.115.0
[1.116.0]: https://github.com/chatmail/core/compare/v1.115.0...v1.116.0
[1.117.0]: https://github.com/chatmail/core/compare/v1.116.0...v1.117.0
[1.118.0]: https://github.com/chatmail/core/compare/v1.117.0...v1.118.0
[1.119.0]: https://github.com/chatmail/core/compare/v1.118.0...v1.119.0
[1.119.1]: https://github.com/chatmail/core/compare/v1.119.0...v1.119.1
[1.120.0]: https://github.com/chatmail/core/compare/v1.119.1...v1.120.0
[1.121.0]: https://github.com/chatmail/core/compare/v1.120.0...v1.121.0
[1.122.0]: https://github.com/chatmail/core/compare/v1.121.0...v1.122.0
[1.123.0]: https://github.com/chatmail/core/compare/v1.122.0...v1.123.0
[1.124.0]: https://github.com/chatmail/core/compare/v1.123.0...v1.124.0
[1.124.1]: https://github.com/chatmail/core/compare/v1.124.0...v1.124.1
[1.125.0]: https://github.com/chatmail/core/compare/v1.124.1...v1.125.0
[1.126.0]: https://github.com/chatmail/core/compare/v1.125.0...v1.126.0
[1.126.1]: https://github.com/chatmail/core/compare/v1.126.0...v1.126.1
[1.127.0]: https://github.com/chatmail/core/compare/v1.126.1...v1.127.0
[1.127.1]: https://github.com/chatmail/core/compare/v1.127.0...v1.127.1
[1.127.2]: https://github.com/chatmail/core/compare/v1.127.1...v1.127.2
[1.128.0]: https://github.com/chatmail/core/compare/v1.127.2...v1.128.0
[1.129.0]: https://github.com/chatmail/core/compare/v1.128.0...v1.129.0
[1.129.1]: https://github.com/chatmail/core/compare/v1.129.0...v1.129.1
[1.130.0]: https://github.com/chatmail/core/compare/v1.129.1...v1.130.0
[1.131.0]: https://github.com/chatmail/core/compare/v1.130.0...v1.131.0
[1.131.1]: https://github.com/chatmail/core/compare/v1.131.0...v1.131.1
[1.131.2]: https://github.com/chatmail/core/compare/v1.131.1...v1.131.2
[1.131.3]: https://github.com/chatmail/core/compare/v1.131.2...v1.131.3
[1.131.4]: https://github.com/chatmail/core/compare/v1.131.3...v1.131.4
[1.131.5]: https://github.com/chatmail/core/compare/v1.131.4...v1.131.5
[1.131.6]: https://github.com/chatmail/core/compare/v1.131.5...v1.131.6
[1.131.7]: https://github.com/chatmail/core/compare/v1.131.6...v1.131.7
[1.131.8]: https://github.com/chatmail/core/compare/v1.131.7...v1.131.8
[1.131.9]: https://github.com/chatmail/core/compare/v1.131.8...v1.131.9
[1.132.0]: https://github.com/chatmail/core/compare/v1.131.9...v1.132.0
[1.132.1]: https://github.com/chatmail/core/compare/v1.132.0...v1.132.1
[1.133.0]: https://github.com/chatmail/core/compare/v1.132.1...v1.133.0
[1.133.1]: https://github.com/chatmail/core/compare/v1.133.0...v1.133.1
[1.133.2]: https://github.com/chatmail/core/compare/v1.133.1...v1.133.2
[1.134.0]: https://github.com/chatmail/core/compare/v1.133.2...v1.134.0
[1.135.0]: https://github.com/chatmail/core/compare/v1.134.0...v1.135.0
[1.135.1]: https://github.com/chatmail/core/compare/v1.135.0...v1.135.1
[1.136.0]: https://github.com/chatmail/core/compare/v1.135.1...v1.136.0
[1.136.1]: https://github.com/chatmail/core/compare/v1.136.0...v1.136.1
[1.136.2]: https://github.com/chatmail/core/compare/v1.136.1...v1.136.2
[1.136.3]: https://github.com/chatmail/core/compare/v1.136.2...v1.136.3
[1.136.4]: https://github.com/chatmail/core/compare/v1.136.3...v1.136.4
[1.136.5]: https://github.com/chatmail/core/compare/v1.136.4...v1.136.5
[1.136.6]: https://github.com/chatmail/core/compare/v1.136.5...v1.136.6
[1.137.0]: https://github.com/chatmail/core/compare/v1.136.6...v1.137.0
[1.137.1]: https://github.com/chatmail/core/compare/v1.137.0...v1.137.1
[1.137.2]: https://github.com/chatmail/core/compare/v1.137.1...v1.137.2
[1.137.3]: https://github.com/chatmail/core/compare/v1.137.2...v1.137.3
[1.137.4]: https://github.com/chatmail/core/compare/v1.137.3...v1.137.4
[1.138.0]: https://github.com/chatmail/core/compare/v1.137.4...v1.138.0
[1.138.1]: https://github.com/chatmail/core/compare/v1.138.0...v1.138.1
[1.138.2]: https://github.com/chatmail/core/compare/v1.138.1...v1.138.2
[1.138.3]: https://github.com/chatmail/core/compare/v1.138.2...v1.138.3
[1.138.4]: https://github.com/chatmail/core/compare/v1.138.3...v1.138.4
[1.138.5]: https://github.com/chatmail/core/compare/v1.138.4...v1.138.5
[1.139.0]: https://github.com/chatmail/core/compare/v1.138.5...v1.139.0
[1.139.1]: https://github.com/chatmail/core/compare/v1.139.0...v1.139.1
[1.139.2]: https://github.com/chatmail/core/compare/v1.139.1...v1.139.2
[1.139.3]: https://github.com/chatmail/core/compare/v1.139.2...v1.139.3
[1.139.4]: https://github.com/chatmail/core/compare/v1.139.3...v1.139.4
[1.139.5]: https://github.com/chatmail/core/compare/v1.139.4...v1.139.5
[1.139.6]: https://github.com/chatmail/core/compare/v1.139.5...v1.139.6
[1.140.0]: https://github.com/chatmail/core/compare/v1.139.6...v1.140.0
[1.140.1]: https://github.com/chatmail/core/compare/v1.140.0...v1.140.1
[1.140.2]: https://github.com/chatmail/core/compare/v1.140.1...v1.140.2
[1.141.0]: https://github.com/chatmail/core/compare/v1.140.2...v1.141.0
[1.141.1]: https://github.com/chatmail/core/compare/v1.141.0...v1.141.1
[1.141.2]: https://github.com/chatmail/core/compare/v1.141.1...v1.141.2
[1.142.0]: https://github.com/chatmail/core/compare/v1.141.2...v1.142.0
[1.142.1]: https://github.com/chatmail/core/compare/v1.142.0...v1.142.1
[1.142.2]: https://github.com/chatmail/core/compare/v1.142.1...v1.142.2
[1.142.3]: https://github.com/chatmail/core/compare/v1.142.2...v1.142.3
[1.142.4]: https://github.com/chatmail/core/compare/v1.142.3...v1.142.4
[1.142.5]: https://github.com/chatmail/core/compare/v1.142.4...v1.142.5
[1.142.6]: https://github.com/chatmail/core/compare/v1.142.5...v1.142.6
[1.142.7]: https://github.com/chatmail/core/compare/v1.142.6...v1.142.7
[1.142.8]: https://github.com/chatmail/core/compare/v1.142.7...v1.142.8
[1.142.9]: https://github.com/chatmail/core/compare/v1.142.8...v1.142.9
[1.142.10]: https://github.com/chatmail/core/compare/v1.142.9..v1.142.10
[1.142.11]: https://github.com/chatmail/core/compare/v1.142.10..v1.142.11
[1.142.12]: https://github.com/chatmail/core/compare/v1.142.11..v1.142.12
[1.143.0]: https://github.com/chatmail/core/compare/v1.142.12..v1.143.0
[1.144.0]: https://github.com/chatmail/core/compare/v1.143.0..v1.144.0
[1.145.0]: https://github.com/chatmail/core/compare/v1.144.0..v1.145.0
[1.146.0]: https://github.com/chatmail/core/compare/v1.145.0..v1.146.0
[1.147.0]: https://github.com/chatmail/core/compare/v1.146.0..v1.147.0
[1.147.1]: https://github.com/chatmail/core/compare/v1.147.0..v1.147.1
[1.148.0]: https://github.com/chatmail/core/compare/v1.147.1..v1.148.0
[1.148.1]: https://github.com/chatmail/core/compare/v1.148.0..v1.148.1
[1.148.2]: https://github.com/chatmail/core/compare/v1.148.1..v1.148.2
[1.148.3]: https://github.com/chatmail/core/compare/v1.148.2..v1.148.3
[1.148.4]: https://github.com/chatmail/core/compare/v1.148.3..v1.148.4
[1.148.5]: https://github.com/chatmail/core/compare/v1.148.4..v1.148.5
[1.148.6]: https://github.com/chatmail/core/compare/v1.148.5..v1.148.6
[1.148.7]: https://github.com/chatmail/core/compare/v1.148.6..v1.148.7
[1.149.0]: https://github.com/chatmail/core/compare/v1.148.7..v1.149.0
[1.150.0]: https://github.com/chatmail/core/compare/v1.149.0..v1.150.0
[1.151.0]: https://github.com/chatmail/core/compare/v1.150.0..v1.151.0
[1.151.1]: https://github.com/chatmail/core/compare/v1.151.0..v1.151.1
[1.151.2]: https://github.com/chatmail/core/compare/v1.151.1..v1.151.2
[1.151.3]: https://github.com/chatmail/core/compare/v1.151.2..v1.151.3
[1.151.4]: https://github.com/chatmail/core/compare/v1.151.3..v1.151.4
[1.151.5]: https://github.com/chatmail/core/compare/v1.151.4..v1.151.5
[1.151.6]: https://github.com/chatmail/core/compare/v1.151.5..v1.151.6
[1.152.0]: https://github.com/chatmail/core/compare/v1.151.6..v1.152.0
[1.152.1]: https://github.com/chatmail/core/compare/v1.152.0..v1.152.1
[1.152.2]: https://github.com/chatmail/core/compare/v1.152.1..v1.152.2
[1.153.0]: https://github.com/chatmail/core/compare/v1.152.2..v1.153.0
[1.154.0]: https://github.com/chatmail/core/compare/v1.153.0..v1.154.0
[1.154.1]: https://github.com/chatmail/core/compare/v1.154.0..v1.154.1
[1.154.2]: https://github.com/chatmail/core/compare/v1.154.1..v1.154.2
[1.154.3]: https://github.com/chatmail/core/compare/v1.154.2..v1.154.3
[1.155.0]: https://github.com/chatmail/core/compare/v1.154.3..v1.155.0
[1.155.1]: https://github.com/chatmail/core/compare/v1.155.0..v1.155.1
[1.155.2]: https://github.com/chatmail/core/compare/v1.155.1..v1.155.2
[1.155.3]: https://github.com/chatmail/core/compare/v1.155.2..v1.155.3
[1.155.4]: https://github.com/chatmail/core/compare/v1.155.3..v1.155.4
[1.155.5]: https://github.com/chatmail/core/compare/v1.155.4..v1.155.5
[1.155.6]: https://github.com/chatmail/core/compare/v1.155.5..v1.155.6
[1.156.0]: https://github.com/chatmail/core/compare/v1.155.6..v1.156.0
[1.156.1]: https://github.com/chatmail/core/compare/v1.156.0..v1.156.1
[1.156.2]: https://github.com/chatmail/core/compare/v1.156.1..v1.156.2
[1.156.3]: https://github.com/chatmail/core/compare/v1.156.2..v1.156.3
[1.157.0]: https://github.com/chatmail/core/compare/v1.156.3..v1.157.0
[1.157.1]: https://github.com/chatmail/core/compare/v1.157.0..v1.157.1
[1.157.2]: https://github.com/chatmail/core/compare/v1.157.1..v1.157.2
[1.157.3]: https://github.com/chatmail/core/compare/v1.157.2..v1.157.3
[1.158.0]: https://github.com/chatmail/core/compare/v1.157.3..v1.158.0
[1.159.0]: https://github.com/chatmail/core/compare/v1.158.0..v1.159.0
[1.159.1]: https://github.com/chatmail/core/compare/v1.159.0..v1.159.1
[1.159.2]: https://github.com/chatmail/core/compare/v1.159.1..v1.159.2
[1.159.3]: https://github.com/chatmail/core/compare/v1.159.2..v1.159.3
[1.159.4]: https://github.com/chatmail/core/compare/v1.159.3..v1.159.4
[1.159.5]: https://github.com/chatmail/core/compare/v1.159.4..v1.159.5
[1.160.0]: https://github.com/chatmail/core/compare/v1.159.5..v1.160.0
[2.0.0]: https://github.com/chatmail/core/compare/v1.160.0..v2.0.0
[2.1.0]: https://github.com/chatmail/core/compare/v2.0.0..v2.1.0
[2.2.0]: https://github.com/chatmail/core/compare/v2.1.0..v2.2.0
[2.3.0]: https://github.com/chatmail/core/compare/v2.2.0..v2.3.0
[2.4.0]: https://github.com/chatmail/core/compare/v2.3.0..v2.4.0
[2.5.0]: https://github.com/chatmail/core/compare/v2.4.0..v2.5.0
[2.6.0]: https://github.com/chatmail/core/compare/v2.5.0..v2.6.0
[2.7.0]: https://github.com/chatmail/core/compare/v2.6.0..v2.7.0
[2.8.0]: https://github.com/chatmail/core/compare/v2.7.0..v2.8.0
[2.9.0]: https://github.com/chatmail/core/compare/v2.8.0..v2.9.0
[2.10.0]: https://github.com/chatmail/core/compare/v2.9.0..v2.10.0
[2.11.0]: https://github.com/chatmail/core/compare/v2.10.0..v2.11.0
[2.12.0]: https://github.com/chatmail/core/compare/v2.11.0..v2.12.0
[2.13.0]: https://github.com/chatmail/core/compare/v2.12.0..v2.13.0
[2.14.0]: https://github.com/chatmail/core/compare/v2.13.0..v2.14.0
[2.15.0]: https://github.com/chatmail/core/compare/v2.14.0..v2.15.0
[2.16.0]: https://github.com/chatmail/core/compare/v2.15.0..v2.16.0
[2.17.0]: https://github.com/chatmail/core/compare/v2.16.0..v2.17.0
[2.18.0]: https://github.com/chatmail/core/compare/v2.17.0..v2.18.0
[2.19.0]: https://github.com/chatmail/core/compare/v2.18.0..v2.19.0
[2.20.0]: https://github.com/chatmail/core/compare/v2.19.0..v2.20.0
[2.21.0]: https://github.com/chatmail/core/compare/v2.20.0..v2.21.0
[2.22.0]: https://github.com/chatmail/core/compare/v2.21.0..v2.22.0
[2.23.0]: https://github.com/chatmail/core/compare/v2.22.0..v2.23.0
[2.24.0]: https://github.com/chatmail/core/compare/v2.23.0..v2.24.0
[2.25.0]: https://github.com/chatmail/core/compare/v2.24.0..v2.25.0
[2.26.0]: https://github.com/chatmail/core/compare/v2.25.0..v2.26.0
[2.27.0]: https://github.com/chatmail/core/compare/v2.26.0..v2.27.0
[2.28.0]: https://github.com/chatmail/core/compare/v2.27.0..v2.28.0
[2.29.0]: https://github.com/chatmail/core/compare/v2.28.0..v2.29.0
[2.30.0]: https://github.com/chatmail/core/compare/v2.29.0..v2.30.0
[2.31.0]: https://github.com/chatmail/core/compare/v2.30.0..v2.31.0
[2.32.0]: https://github.com/chatmail/core/compare/v2.31.0..v2.32.0
[2.33.0]: https://github.com/chatmail/core/compare/v2.32.0..v2.33.0
[2.34.0]: https://github.com/chatmail/core/compare/v2.33.0..v2.34.0
[2.35.0]: https://github.com/chatmail/core/compare/v2.34.0..v2.35.0
[2.36.0]: https://github.com/chatmail/core/compare/v2.35.0..v2.36.0
[2.37.0]: https://github.com/chatmail/core/compare/v2.36.0..v2.37.0
[2.38.0]: https://github.com/chatmail/core/compare/v2.37.0..v2.38.0
[2.39.0]: https://github.com/chatmail/core/compare/v2.38.0..v2.39.0
[2.40.0]: https://github.com/chatmail/core/compare/v2.39.0..v2.40.0
[2.41.0]: https://github.com/chatmail/core/compare/v2.40.0..v2.41.0
[2.42.0]: https://github.com/chatmail/core/compare/v2.41.0..v2.42.0
[2.43.0]: https://github.com/chatmail/core/compare/v2.42.0..v2.43.0
