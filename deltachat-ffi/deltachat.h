#ifndef __DELTACHAT_H__
#define __DELTACHAT_H__
#ifdef __cplusplus
extern "C" {
#endif


#ifndef PY_CFFI
#include <stdint.h>
#include <time.h>
#endif


typedef struct _dc_context   dc_context_t;
typedef struct _dc_accounts  dc_accounts_t;
typedef struct _dc_array     dc_array_t;
typedef struct _dc_chatlist  dc_chatlist_t;
typedef struct _dc_chat      dc_chat_t;
typedef struct _dc_msg       dc_msg_t;
typedef struct _dc_contact   dc_contact_t;
typedef struct _dc_lot       dc_lot_t;
typedef struct _dc_provider  dc_provider_t;
typedef struct _dc_event     dc_event_t;
typedef struct _dc_event_emitter dc_event_emitter_t;
typedef struct _dc_event_channel dc_event_channel_t;
typedef struct _dc_jsonrpc_instance dc_jsonrpc_instance_t;
typedef struct _dc_backup_provider dc_backup_provider_t;

// Alias for backwards compatibility, use dc_event_emitter_t instead.
typedef struct _dc_event_emitter dc_accounts_event_emitter_t;

/**
 * @mainpage Getting started
 *
 * This document describes how to handle the Delta Chat core library.
 * For general information about Delta Chat itself,
 * see <https://delta.chat> and <https://github.com/deltachat>.
 *
 * Let's start.
 *
 * First of all, you have to **create a context object**
 * bound to a database.
 * The database is a normal SQLite file with a "blob directory" beside it.
 * This will create "example.db" database and "example.db-blobs"
 * directory if they don't exist already:
 *
 * ~~~
 * dc_context_t* context = dc_context_new(NULL, "example.db", NULL);
 * ~~~
 *
 * After that, make sure you can **receive events from the context**.
 * For that purpose, create an event emitter you can ask for events.
 * If there is no event, the emitter will wait until there is one,
 * so, in many situations, you will do this in a thread:
 *
 * ~~~
 * void* event_handler(void* context)
 * {
 *     dc_event_emitter_t* emitter = dc_get_event_emitter(context);
 *     dc_event_t* event;
 *     while ((event = dc_get_next_event(emitter)) != NULL) {
 *         // use the event as needed, e.g. dc_event_get_id() returns the type.
 *         // once you're done, unref the event to avoid memory leakage:
 *         dc_event_unref(event);
 *     }
 *     dc_event_emitter_unref(emitter);
 * }
 *
 * static pthread_t event_thread;
 * pthread_create(&event_thread, NULL, event_handler, context);
 * ~~~
 *
 * The example above uses "pthreads",
 * however, you can also use anything else for thread handling.
 *
 * Now you can **configure the context:**
 *
 * ~~~
 * // use some real test credentials here
 * dc_set_config(context, "addr", "alice@example.org");
 * dc_set_config(context, "mail_pw", "***");
 * dc_configure(context);
 * ~~~
 *
 * dc_configure() returns immediately.
 * The configuration itself runs in the background and may take a while.
 * Once done, the #DC_EVENT_CONFIGURE_PROGRESS reports success
 * to the event_handler() you've defined above.
 *
 * The configuration result is saved in the database.
 * On subsequent starts it is not needed to call dc_configure()
 * (you can check this using dc_is_configured()).
 *
 * On a successfully configured context,
 * you can finally **connect to the servers:**
 *
 * ~~~
 * dc_start_io(context);
 * ~~~
 *
 * Now you can **send the first message:**
 *
 * ~~~
 * // use a real testing address here
 * uint32_t contact_id = dc_create_contact(context, NULL, "bob@example.org");
 * uint32_t chat_id    = dc_create_chat_by_contact_id(context, contact_id);
 *
 * dc_send_text_msg(context, chat_id, "Hi, here is my first message!");
 * ~~~
 *
 * dc_send_text_msg() returns immediately;
 * the sending itself is done in the background.
 * If you check the testing address (bob),
 * you should receive a normal e-mail.
 * Answer this e-mail in any e-mail program with "Got it!",
 * and the IO you started above will **receive the message**.
 *
 * You can then **list all messages** of a chat as follows:
 *
 * ~~~
 * dc_array_t* msglist = dc_get_chat_msgs(context, chat_id, 0, 0);
 * for (int i = 0; i < dc_array_get_cnt(msglist); i++)
 * {
 *     uint32_t  msg_id = dc_array_get_id(msglist, i);
 *     dc_msg_t* msg    = dc_get_msg(context, msg_id);
 *     char*     text   = dc_msg_get_text(msg);
 *
 *     printf("Message %i: %s\n", i+1, text);
 *
 *     dc_str_unref(text);
 *     dc_msg_unref(msg);
 * }
 * dc_array_unref(msglist);
 * ~~~
 *
 * This will output the following two lines:
 *
 * ~~~
 * Message 1: Hi, here is my first message!
 * Message 2: Got it!
 * ~~~
 *
 *
 * ## Thread safety
 *
 * All deltachat-core functions, unless stated otherwise, are thread-safe.
 * In particular, it is safe to pass the same dc_context_t pointer
 * to multiple functions running concurrently in different threads.
 *
 * All the functions are guaranteed not to use the reference passed to them
 * after returning. If the function spawns a long-running process,
 * such as dc_configure() or dc_imex(), it will ensure that the objects
 * passed to them are not deallocated as long as they are needed.
 * For example, it is safe to call dc_imex(context, ...) and
 * call dc_context_unref(context) immediately after return from dc_imex().
 * It is however **not safe** to call dc_context_unref(context) concurrently
 * until dc_imex() returns, because dc_imex() may have not increased
 * the reference count of dc_context_t yet.
 *
 * This means that the context may be still in use after
 * dc_context_unref() call.
 * For example, it is possible to start the import/export process,
 * call dc_context_unref(context) immediately after
 * and observe #DC_EVENT_IMEX_PROGRESS events via the event emitter.
 * Once dc_get_next_event() returns NULL,
 * it is safe to terminate the application.
 *
 * It is recommended to create dc_context_t in the main thread
 * and only call dc_context_unref() once other threads that may use it,
 * such as the event loop thread, are terminated.
 * Common mistake is to use dc_context_unref() as a way
 * to cause dc_get_next_event() return NULL and terminate event loop this way.
 * If event loop thread is inside a function taking dc_context_t
 * as an argument at the moment dc_context_unref() is called on the main thread,
 * the behavior is undefined.
 *
 * Recommended way to safely terminate event loop
 * and shutdown the application is
 * to use a boolean variable
 * indicating that the event loop should stop
 * and check it in the event loop thread
 * every time before calling dc_get_next_event().
 * To terminate the event loop, main thread should:
 * 1. Notify background threads,
 *    such as event loop (blocking in dc_get_next_event())
 *    and message processing loop (blocking in dc_wait_next_msgs()),
 *    that they should terminate by atomically setting the
 *    boolean flag in the memory
 *    shared between the main thread and background loop threads.
 * 2. Call dc_stop_io() or dc_accounts_stop_io(), depending
 *    on whether a single account or account manager is used.
 *    Stopping I/O is guaranteed to emit at least one event
 *    and interrupt the event loop even if it was blocked on dc_get_next_event().
 *    Stopping I/O is guaranteed to interrupt a single dc_wait_next_msgs().
 * 3. Wait until the event loop thread notices the flag,
 *    exits the event loop and terminates.
 * 4. Call dc_context_unref() or dc_accounts_unref().
 * 5. Keep calling dc_get_next_event() in a loop until it returns NULL,
 *    indicating that the contexts are deallocated.
 * 6. Terminate the application.
 *
 * When using C API via FFI in runtimes that use automatic memory management,
 * such as CPython, JVM or Node.js, take care to ensure the correct
 * shutdown order and avoid calling dc_context_unref() or dc_accounts_unref()
 * on the objects still in use in other threads,
 * e.g. by keeping a reference to the wrapper object.
 * The details depend on the runtime being used.
 *
 *
 * ## Class reference
 *
 * For a class reference, see the "Classes" link atop.
 *
 *
 * ## Further hints
 *
 * Here are some additional, unsorted hints that may be useful.
 *
 * - For `get`-functions, you have to unref the return value in some way.
 *
 * - Strings in function arguments or return values are usually UTF-8 encoded.
 *
 * - The issue-tracker for the core library is here:
 *   <https://github.com/chatmail/core/issues>
 *
 * If you need further assistance,
 * please do not hesitate to contact us
 * through the channels shown at https://delta.chat/en/contribute
 *
 * Please keep in mind, that your derived work
 * must respect the Mozilla Public License 2.0 of libdeltachat
 * and the respective licenses of the libraries libdeltachat links with.
 *
 * See you.
 */


/**
 * @class dc_context_t
 *
 * An object representing a single account.
 *
 * Each account is linked to an IMAP/SMTP account and uses a separate
 * SQLite database for offline functionality and for account related
 * settings.
 */

// create/open/config/information

/**
 * Create a new context object and try to open it. If
 * database is encrypted, the result is the same as using
 * dc_context_new_closed() and the database should be opened with
 * dc_context_open() before using.
 *
 * @memberof dc_context_t
 * @param os_name Deprecated, pass NULL or empty string here.
 * @param dbfile The file to use to store the database,
 *     something like `~/file` won't work, use absolute paths.
 * @param blobdir Deprecated, pass NULL or an empty string here.
 * @return A context object with some public members.
 *     The object must be passed to the other context functions
 *     and must be freed using dc_context_unref() after usage.
 */
dc_context_t*   dc_context_new               (const char* os_name, const char* dbfile, const char* blobdir);


/**
 * Create a new context object. After creation it is usually opened with
 * dc_context_open() and started with dc_start_io() so it is connected and
 * mails are fetched.
 *
 * @memberof dc_context_t
 * @param dbfile The file to use to store the database,
 *     something like `~/file` won't work, use absolute paths.
 * @return A context object with some public members.
 *     The object must be passed to the other context functions
 *     and must be freed using dc_context_unref() after usage.
 *
 * If you want to use multiple context objects at the same time,
 * this can be managed using dc_accounts_t.
 */
dc_context_t*   dc_context_new_closed        (const char* dbfile);


/**
 * Opens the database with the given passphrase.
 * NB: Nonempty passphrase (db encryption) is deprecated 2025-11:
 * - Db encryption does nothing with blobs, so fs/disk encryption is recommended.
 * - Isolation from other apps is needed anyway.
 *
 * This can only be used on closed context, such as
 * created by dc_context_new_closed(). If the database
 * is new, this operation sets the database passphrase. For existing databases
 * the passphrase should be the one used to encrypt the database the first
 * time.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param passphrase The passphrase to use with the database. Pass NULL or
 * empty string to use no passphrase and no encryption.
 * @return 1 if the database is opened with this passphrase, 0 if the
 * passphrase is incorrect and on error.
 */
int             dc_context_open              (dc_context_t *context, const char* passphrase);


/**
 * Changes the passphrase on the open database.
 * Deprecated 2025-11, see `dc_context_open()` for reasoning.
 *
 * Existing database must already be encrypted and the passphrase cannot be NULL or empty.
 * It is impossible to encrypt unencrypted database with this method and vice versa.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param passphrase The new passphrase.
 * @return 1 on success, 0 on error.
 */
int             dc_context_change_passphrase (dc_context_t* context, const char* passphrase);


/**
 * Returns 1 if database is open.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return 1 if database is open, 0 if database is closed.
 */
int             dc_context_is_open           (dc_context_t *context);


/**
 * Free a context object.
 *
 * You have to call this function
 * also for accounts returned by dc_accounts_get_account() or dc_accounts_get_selected_account().
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new(),
 *     dc_accounts_get_account() or dc_accounts_get_selected_account().
 *     If NULL is given, nothing is done.
 */
void            dc_context_unref             (dc_context_t* context);


/**
 * Get the ID of a context object.
 * Each context has an ID assigned.
 * If the context was created through the dc_accounts_t account manager,
 * the ID is unique, no other context handled by the account manager will have the same ID.
 * If the context was created by dc_context_new(), a random ID is assigned.
 *
 * @memberof dc_context_t
 * @param context The context object as created e.g. by dc_accounts_get_account() or dc_context_new().
 * @return The context-id.
 */
uint32_t        dc_get_id                    (dc_context_t* context);


/**
 * Create the event emitter that is used to receive events.
 * The library will emit various @ref DC_EVENT events, such as "new message", "message read" etc.
 * To get these events, you have to create an event emitter using this function
 * and call dc_get_next_event() on the emitter.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 * @return Returns the event emitter, NULL on errors.
 *     Must be freed using dc_event_emitter_unref() after usage.
 *
 * Note: Use only one event emitter per context.
 * The result of having multiple event emitters is unspecified.
 * Currently events are broadcasted to all existing event emitters,
 * but previous versions delivered events to only one event emitter
 * and this behavior may change again in the future.
 * Events emitted before creation of event emitter
 * may or may not be available to event emitter.
 */
dc_event_emitter_t* dc_get_event_emitter(dc_context_t* context);


/**
 * Get the blob directory.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return The blob directory associated with the context object, empty string if unset or on errors. NULL is never returned.
 *     The returned string must be released using dc_str_unref().
 */
char*           dc_get_blobdir               (const dc_context_t* context);


/**
 * Configure the context. The configuration is handled by key=value pairs as:
 *
 * - `addr`         = Email address to use for configuration.
 *                    If dc_configure() fails this is not the email address actually in use.
 *                    Use `configured_addr` to find out the email address actually in use.
 * - `configured_addr` = Email address actually in use.
 *                    Unless for testing, do not set this value using dc_set_config().
 *                    Instead, set `addr` and call dc_configure().
 * - `mail_server`  = IMAP-server, guessed if left out
 * - `mail_user`    = IMAP-username, guessed if left out
 * - `mail_pw`      = IMAP-password (always needed)
 * - `mail_port`    = IMAP-port, guessed if left out
 * - `mail_security`= IMAP-socket, one of @ref DC_SOCKET, defaults to #DC_SOCKET_AUTO
 * - `send_server`  = SMTP-server, guessed if left out
 * - `send_user`    = SMTP-user, guessed if left out
 * - `send_pw`      = SMTP-password, guessed if left out
 * - `send_port`    = SMTP-port, guessed if left out
 * - `send_security`= SMTP-socket, one of @ref DC_SOCKET, defaults to #DC_SOCKET_AUTO
 * - `server_flags` = IMAP-/SMTP-flags as a combination of @ref DC_LP flags, guessed if left out
 * - `proxy_enabled` = Proxy enabled. Disabled by default.
 * - `proxy_url` = Proxy URL. May contain multiple URLs separated by newline, but only the first one is used.
 * - `imap_certificate_checks` = how to check IMAP certificates, one of the @ref DC_CERTCK flags, defaults to #DC_CERTCK_AUTO (0)
 * - `smtp_certificate_checks` = deprecated option, should be set to the same value as `imap_certificate_checks` but ignored by the new core
 * - `displayname`  = Own name to use when sending messages. MUAs are allowed to spread this way e.g. using CC, defaults to empty
 * - `selfstatus`   = Own status to display, e.g. in e-mail footers, defaults to empty
 * - `selfavatar`   = File containing avatar. Will immediately be copied to the 
 *                    `blobdir`; the original image will not be needed anymore.
 *                    NULL to remove the avatar.
 *                    As for `displayname` and `selfstatus`, also the avatar is sent to the recipients.
 *                    To save traffic, however, the avatar is attached only as needed
 *                    and also recoded to a reasonable size.
 * - `mdns_enabled` = 0=do not send or request read receipts,
 *                    1=send and request read receipts
 *                    default=send and request read receipts, only send but not request if `bot` is set
 * - `bcc_self`     = 0=do not send a copy of outgoing messages to self,
 *                    1=send a copy of outgoing messages to self (default).
 *                    Sending messages to self is needed for a proper multi-account setup,
 *                    however, on the other hand, may lead to unwanted notifications in non-delta clients.
 * - `mvbox_move`   = 1=detect chat messages,
 *                    move them to the `DeltaChat` folder,
 *                    and watch the `DeltaChat` folder for updates (default),
 *                    0=do not move chat-messages
 * - `only_fetch_mvbox` = 1=Do not fetch messages from folders other than the
 *                    `DeltaChat` folder. Messages will still be fetched from the
 *                    spam folder.
 *                    0=watch all folders normally (default)
 * - `show_emails`  = DC_SHOW_EMAILS_OFF (0)=
 *                    show direct replies to chats only,
 *                    DC_SHOW_EMAILS_ACCEPTED_CONTACTS (1)=
 *                    also show all mails of confirmed contacts,
 *                    DC_SHOW_EMAILS_ALL (2)=
 *                    also show mails of unconfirmed contacts (default).
 * - `delete_device_after` = 0=do not delete messages from device automatically (default),
 *                    >=1=seconds, after which messages are deleted automatically from the device.
 *                    Messages in the "saved messages" chat (see dc_chat_is_self_talk()) are skipped.
 *                    Messages are deleted whether they were seen or not, the UI should clearly point that out.
 *                    See also dc_estimate_deletion_cnt().
 * - `delete_server_after` = 0=do not delete messages from server automatically (default),
 *                    1=delete messages directly after receiving from server, mvbox is skipped.
 *                    >1=seconds, after which messages are deleted automatically from the server, mvbox is used as defined.
 *                    "Saved messages" are deleted from the server as well as
 *                    e-mails matching the `show_emails` settings above, the UI should clearly point that out.
 *                    See also dc_estimate_deletion_cnt().
 * - `media_quality` = DC_MEDIA_QUALITY_BALANCED (0) =
 *                    good outgoing images/videos/voice quality at reasonable sizes (default)
 *                    DC_MEDIA_QUALITY_WORSE (1)
 *                    allow worse images/videos/voice quality to gain smaller sizes,
 *                    suitable for providers or areas known to have a bad connection.
 *                    The library uses the `media_quality` setting to use different defaults
 *                    for recoding images sent with type #DC_MSG_IMAGE.
 *                    If needed, recoding other file types is up to the UI.
 * - `bot`          = Set to "1" if this is a bot.
 *                    Prevents adding the "Device messages" and "Saved messages" chats,
 *                    adds Auto-Submitted header to outgoing messages,
 *                    accepts contact requests automatically (calling dc_accept_chat() is not needed),
 *                    does not cut large incoming text messages,
 *                    handles existing messages the same way as new ones if `fetch_existing_msgs=1`.
 * - `last_msg_id` = database ID of the last message processed by the bot.
 *                   This ID and IDs below it are guaranteed not to be returned
 *                   by dc_get_next_msgs() and dc_wait_next_msgs().
 *                   The value is updated automatically
 *                   when dc_markseen_msgs() is called,
 *                   but the bot can also set it manually if it processed
 *                   the message but does not want to mark it as seen.
 *                   For most bots calling `dc_markseen_msgs()` is the
 *                   recommended way to update this value
 *                   even for self-sent messages.
 * - `fetch_existing_msgs` = 0=do not fetch existing messages on configure (default),
 *                    1=fetch most recent existing messages on configure.
 *                    In both cases, existing recipients are added to the contact database.
 * - `disable_idle` = 1=disable IMAP IDLE even if the server supports it,
 *                    0=use IMAP IDLE if the server supports it.
 *                    This is a developer option used for testing polling used as an IDLE fallback.
 * - `download_limit` = Messages up to this number of bytes are downloaded automatically.
 *                    For messages with large attachments, two messages are sent:
 *                    a Pre-Message containing metadata and text and a Post-Message additionally
 *                    containing the attachment. NB: Some "extra" metadata like avatars and gossiped
 *                    encryption keys is stripped from post-messages to save traffic.
 *                    Pre-Messages are shown as placeholder messages. They can be downloaded fully
 *                    using dc_download_full_msg() later. Post-Messages are automatically
 *                    downloaded if they are smaller than the download_limit. Other messages are
 *                    always auto-downloaded.
 *                    0 = no limit (default).
 *                    Changes affect future messages only.
 * - `protect_autocrypt` = Enable Header Protection for Autocrypt header.
 *                    This is an experimental option not compatible to other MUAs
 *                    and older Delta Chat versions.
 *                    1 = enable.
 *                    0 = disable (default).
 * - `gossip_period` = How often to gossip Autocrypt keys in chats with multiple recipients, in
 *                    seconds. 2 days by default.
 *                    This is not supposed to be changed by UIs and only used for testing.
 * - `is_chatmail` = 1 if the the server is a chatmail server, 0 otherwise.
 * - `is_muted`     = Whether a context is muted by the user.
 *                    Muted contexts should not sound, vibrate or show notifications.
 *                    In contrast to `dc_set_chat_mute_duration()`,
 *                    fresh message and badge counters are not changed by this setting,
 *                    but should be tuned down where appropriate.
 * - `private_tag`  = Optional tag as "Work", "Family".
 *                    Meant to help profile owner to differ between profiles with similar names.
 * - `ui.*`         = All keys prefixed by `ui.` can be used by the user-interfaces for system-specific purposes.
 *                    The prefix should be followed by the system and maybe subsystem,
 *                    e.g. `ui.desktop.foo`, `ui.desktop.linux.bar`, `ui.android.foo`, `ui.dc40.bar`, `ui.bot.simplebot.baz`.
 *                    These keys go to backups and allow easy per-account settings when using @ref dc_accounts_t,
 *                    however, are not handled by the core otherwise.
 * - `webxdc_realtime_enabled` = Whether the realtime APIs should be enabled.
 *                               0 = WebXDC realtime API is disabled and behaves as noop.
 *                               1 = WebXDC realtime API is enabled (default).
 * - `who_can_call_me` = Who can cause call notifications.
 *                       0 = Everybody (except explicitly blocked contacts),
 *                       1 = Contacts (default, does not include contact requests),
 *                       2 = Nobody (calls never result in a notification).
 *
 * If you want to retrieve a value, use dc_get_config().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param key The option to change, see above.
 * @param value The value to save for "key"
 * @return 0=failure, 1=success
 */
int             dc_set_config                (dc_context_t* context, const char* key, const char* value);


/**
 * Get a configuration option.
 * The configuration option is set by dc_set_config() or by the library itself.
 *
 * Beside the options shown at dc_set_config(),
 * this function can be used to query some global system values:
 *
 * - `sys.version` = get the version string e.g. as `1.2.3` or as `1.2.3special4`.
 * - `sys.msgsize_max_recommended` = maximal recommended attachment size in bytes.
 *                    All possible overheads are already subtracted and this value can be used e.g. for direct comparison
 *                    with the size of a file the user wants to attach. If an attachment is larger than this value,
 *                    an error (no warning as it should be shown to the user) is logged but the attachment is sent anyway.
 * - `sys.config_keys` = get a space-separated list of all config-keys available.
 *                    The config-keys are the keys that can be passed to the parameter `key` of this function.
 * - `quota_exceeding` = 0: quota is unknown or in normal range;
 *                    >=80: quota is about to exceed, the value is the concrete percentage,
 *                    a device message is added when that happens, however, that value may still be interesting for bots.
 *
 * @memberof dc_context_t
 * @param context The context object. For querying system values, this can be NULL.
 * @param key The key to query.
 * @return Returns current value of "key", if "key" is unset, the default
 *     value is returned. The returned value must be released using dc_str_unref(), NULL is never
 *     returned. If there is an error an empty string will be returned.
 */
char*           dc_get_config                (dc_context_t* context, const char* key);


/**
 * Set stock string translation.
 *
 * The function will emit warnings if it returns an error state.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param stock_id The integer ID of the stock message, one of the @ref DC_STR constants.
 * @param stock_msg The message to be used.
 * @return int (==0 on error, 1 on success)
 */
int             dc_set_stock_translation(dc_context_t* context, uint32_t stock_id, const char* stock_msg);


/**
 * Set configuration values from a QR code.
 * Before this function is called, dc_check_qr() should be used to get the QR code type.
 *
 * DC_QR_ACCOUNT and DC_QR_LOGIN QR codes configure the context, but I/O mustn't be started for such
 * QR codes.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param qr The scanned QR code.
 * @return int (==0 on error, 1 on success)
 */
int             dc_set_config_from_qr   (dc_context_t* context, const char* qr);


/**
 * Get information about the context.
 *
 * The information is returned by a multi-line string
 * and contains information about the current configuration.
 *
 * If the context is not open or configured only a subset of the information
 * will be available. There is no guarantee about which information will be
 * included when however.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return The string which must be released using dc_str_unref() after usage. Never returns NULL.
 */
char*           dc_get_info                  (const dc_context_t* context);


/**
 * Get URL that can be used to initiate an OAuth2 authorization.
 *
 * If an OAuth2 authorization is possible for a given e-mail address,
 * this function returns the URL that should be opened in a browser.
 *
 * If the user authorizes access,
 * the given redirect_uri is called by the provider.
 * It's up to the UI to handle this call.
 *
 * The provider will attach some parameters to the URL,
 * most important the parameter `code` that should be set as the `mail_pw`.
 * With `server_flags` set to #DC_LP_AUTH_OAUTH2,
 * dc_configure() can be called as usual afterwards.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param addr E-mail address the user has entered.
 *     In case the user selects a different e-mail address during
 *     authorization, this is corrected in dc_configure()
 * @param redirect_uri URL that will get `code` that is used as `mail_pw` then.
 *     Not all URLs are allowed here, however, the following should work:
 *     `chat.delta:/PATH`, `http://localhost:PORT/PATH`,
 *     `https://localhost:PORT/PATH`, `urn:ietf:wg:oauth:2.0:oob`
 *     (the latter just displays the code the user can copy+paste then)
 * @return URL that can be opened in the browser to start OAuth2.
 *     Returned strings must be released using dc_str_unref().
 *     If OAuth2 is not possible for the given e-mail address, NULL is returned.
 */
char*           dc_get_oauth2_url            (dc_context_t* context, const char* addr, const char* redirect_uri);


#define DC_CONNECTIVITY_NOT_CONNECTED        1000
#define DC_CONNECTIVITY_CONNECTING           2000
#define DC_CONNECTIVITY_WORKING              3000
#define DC_CONNECTIVITY_CONNECTED            4000


/**
 * Get the current connectivity, i.e. whether the device is connected to the IMAP server.
 * One of:
 * - DC_CONNECTIVITY_NOT_CONNECTED (1000-1999): Show e.g. the string "Not connected" or a red dot
 * - DC_CONNECTIVITY_CONNECTING (2000-2999): Show e.g. the string "Connecting…" or a yellow dot
 * - DC_CONNECTIVITY_WORKING (3000-3999): Show e.g. the string "Getting new messages" or a spinning wheel
 * - DC_CONNECTIVITY_CONNECTED (>=4000): Show e.g. the string "Connected" or a green dot
 *
 * We don't use exact values but ranges here so that we can split up
 * states into multiple states in the future.
 *
 * Meant as a rough overview that can be shown 
 * e.g. in the title of the main screen.
 *
 * If the connectivity changes, a #DC_EVENT_CONNECTIVITY_CHANGED will be emitted.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return The current connectivity.
 */
int             dc_get_connectivity          (dc_context_t* context);


/**
 * Get an overview of the current connectivity, and possibly more statistics.
 * Meant to give the user more insight about the current status than
 * the basic connectivity info returned by dc_get_connectivity(); show this
 * e.g., if the user taps on said basic connectivity info.
 *
 * If this page changes, a #DC_EVENT_CONNECTIVITY_CHANGED will be emitted.
 *
 * This comes as an HTML from the core so that we can easily improve it
 * and the improvement instantly reaches all UIs.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return An HTML page with some info about the current connectivity and status.
 */
char*           dc_get_connectivity_html     (dc_context_t* context);


#define DC_PUSH_NOT_CONNECTED 0
#define DC_PUSH_HEARTBEAT     1
#define DC_PUSH_CONNECTED     2

/**
 * Get the current push notification state.
 * One of:
 * - DC_PUSH_NOT_CONNECTED
 * - DC_PUSH_HEARTBEAT
 * - DC_PUSH_CONNECTED
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return Push notification state.
 */
int              dc_get_push_state           (dc_context_t* context);


// connect

/**
 * Configure a context.
 * During configuration IO must not be started,
 * if needed stop IO using dc_accounts_stop_io() or dc_stop_io() first.
 * If the context is already configured,
 * this function will try to change the configuration.
 *
 * - Before you call this function,
 *   you must set at least `addr` and `mail_pw` using dc_set_config().
 *
 * - Use `mail_user` to use a different user name than `addr`
 *   and `send_pw` to use a different password for the SMTP server.
 *
 *     - If _no_ more options are specified,
 *       the function **uses autoconfigure/autodiscover**
 *       to get the full configuration from well-known URLs.
 *
 *     - If _more_ options as `mail_server`, `mail_port`, `send_server`,
 *       `send_port`, `send_user` or `server_flags` are specified,
 *       **autoconfigure/autodiscover is skipped**.
 *
 * While dc_configure() returns immediately,
 * the started configuration-job may take a while.
 *
 * During configuration, #DC_EVENT_CONFIGURE_PROGRESS events are emitted;
 * they indicate a successful configuration as well as errors
 * and may be used to create a progress bar.
 *
 * Additional calls to dc_configure() while a config-job is running are ignored.
 * To interrupt a configuration prematurely, use dc_stop_ongoing_process();
 * this is not needed if #DC_EVENT_CONFIGURE_PROGRESS reports success.
 *
 * If #DC_EVENT_CONFIGURE_PROGRESS reports failure,
 * the core continues to use the last working configuration
 * and parameters as `addr`, `mail_pw` etc. are set to that.
 *
 * @memberof dc_context_t
 * @param context The context object.
 *
 * There is no need to call dc_configure() on every program start,
 * the configuration result is saved in the database
 * and you can use the connection directly:
 *
 * ~~~
 * if (!dc_is_configured(context)) {
 *     dc_configure(context);
 *     // wait for progress events
 * }
 * ~~~
 */
void            dc_configure                 (dc_context_t* context);


/**
 * Check if the context is already configured.
 *
 * Typically, for unconfigured accounts, the user is prompted
 * to enter some settings and dc_configure() is called in a thread then.
 *
 * A once successfully configured context cannot become unconfigured again;
 * if a subsequent call to dc_configure() fails,
 * the prior configuration is used.
 *
 * However, of course, also a configuration may stop working,
 * as e.g. the password was changed on the server.
 * To check that use e.g. dc_get_connectivity().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return 1=context is configured and can be used;
 *     0=context is not configured and a configuration by dc_configure() is required.
 */
int             dc_is_configured   (const dc_context_t* context);


/**
 * Start job and IMAP/SMTP tasks.
 * If IO is already running, nothing happens.
 *
 * If the context was created by the dc_accounts_t account manager,
 * use dc_accounts_start_io() instead of this function.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 */
void            dc_start_io     (dc_context_t* context);

/**
 * Stop job, IMAP, SMTP and other tasks and return when they
 * are finished.
 *
 * Even if IO is not running, there may be pending tasks,
 * so this function should always be called before releasing
 * context to ensure clean termination of event loop.
 *
 * If the context was created by the dc_accounts_t account manager,
 * use dc_accounts_stop_io() instead of this function.
 *
 * @memberof dc_context_t
 * @param context The context object as created by dc_context_new().
 */
void            dc_stop_io(dc_context_t* context);

/**
 * This function should be called when there is a hint
 * that the network is available again,
 * e.g. as a response to system event reporting network availability.
 * The library will try to send pending messages out immediately.
 *
 * Moreover, to have a reliable state
 * when the app comes to foreground with network available,
 * it may be reasonable to call the function also at that moment.
 *
 * It is okay to call the function unconditionally when there is
 * network available, however, calling the function
 * _without_ having network may interfere with the backoff algorithm
 * and will led to let the jobs fail faster, with fewer retries
 * and may avoid messages being sent out.
 *
 * Finally, if the context was created by the dc_accounts_t account manager,
 * use dc_accounts_maybe_network() instead of this function.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 */
void            dc_maybe_network             (dc_context_t* context);



/**
 * Save a keypair as the default keys for the user.
 *
 * This API is only for testing purposes and should not be used as part of a
 * normal application, use the import-export APIs instead.
 *
 * This saves a public/private keypair as the default keypair in the context.
 * It allows avoiding having to generate a secret key for unittests which need
 * one.
 *
 * @memberof dc_context_t
 * @param context The context as created by dc_context_new().
 * @param secret_data ASCII armored secret key.
 * @return 1 on success, 0 on failure.
 */
int             dc_preconfigure_keypair        (dc_context_t* context, const char *secret_data);


// handle chatlists

#define         DC_GCL_ARCHIVED_ONLY         0x01
#define         DC_GCL_NO_SPECIALS           0x02
#define         DC_GCL_ADD_ALLDONE_HINT      0x04
#define         DC_GCL_FOR_FORWARDING        0x08


/**
 * Get a list of chats.
 * The list can be filtered by query parameters.
 *
 * The list is already sorted and starts with the most recent chat in use.
 * The sorting takes care of invalid sending dates, drafts and chats without messages.
 * Clients should not try to re-sort the list as this would be an expensive action
 * and would result in inconsistencies between clients.
 *
 * To get information about each entry, use e.g. dc_chatlist_get_summary().
 *
 * By default, the function adds some special entries to the list.
 * These special entries can be identified by the ID returned by dc_chatlist_get_chat_id():
 * - DC_CHAT_ID_ARCHIVED_LINK (6) - this special chat is present if the user has
 *   archived _any_ chat using dc_set_chat_visibility(). The UI should show a link as
 *   "Show archived chats", if the user clicks this item, the UI should show a
 *   list of all archived chats that can be created by this function hen using
 *   the DC_GCL_ARCHIVED_ONLY flag.
 * - DC_CHAT_ID_ALLDONE_HINT (7) - this special chat is present
 *   if DC_GCL_ADD_ALLDONE_HINT is added to listflags
 *   and if there are only archived chats.
 *
 * @memberof dc_context_t
 * @param context The context object as returned by dc_context_new().
 * @param flags A combination of flags:
 *     - if the flag DC_GCL_ARCHIVED_ONLY is set, only archived chats are returned.
 *       if DC_GCL_ARCHIVED_ONLY is not set, only unarchived chats are returned and
 *       the pseudo-chat DC_CHAT_ID_ARCHIVED_LINK is added if there are _any_ archived
 *       chats
 *     - the flag DC_GCL_FOR_FORWARDING sorts "Saved messages" to the top of the chatlist
 *       and hides the "Device chat", contact requests and incoming broadcasts.
 *       typically used on forwarding, may be combined with DC_GCL_NO_SPECIALS
 *       to also hide the archive link.
 *     - if the flag DC_GCL_NO_SPECIALS is set, archive link is not added
 *       to the list (may be used e.g. for selecting chats on forwarding, the flag is
 *       not needed when DC_GCL_ARCHIVED_ONLY is already set)
 *     - if the flag DC_GCL_ADD_ALLDONE_HINT is set, DC_CHAT_ID_ALLDONE_HINT
 *       is added as needed.
 * @param query_str An optional query for filtering the list. Only chats matching this query
 *     are returned. Give NULL for no filtering. When `is:unread` is contained in the query,
 *     the chatlist is filtered such that only chats with unread messages show up.
 * @param query_id An optional contact ID for filtering the list. Only chats including this contact ID
 *     are returned. Give 0 for no filtering.
 * @return A chatlist as an dc_chatlist_t object.
 *     On errors, NULL is returned.
 *     Must be freed using dc_chatlist_unref() when no longer used.
 *
 * See also: dc_get_chat_msgs() to get the messages of a single chat.
 */
dc_chatlist_t*  dc_get_chatlist              (dc_context_t* context, int flags, const char* query_str, uint32_t query_id);


// handle chats

/**
 * Create a normal chat with a single user. To create group chats,
 * see dc_create_group_chat().
 *
 * If a chat already exists, this ID is returned, otherwise a new chat is created;
 * to get the chat messages, use dc_get_chat_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param contact_id The contact ID to create the chat for. If there is already
 *     a chat with this contact, the already existing ID is returned.
 * @return The created or reused chat ID on success. 0 on errors.
 */
uint32_t        dc_create_chat_by_contact_id (dc_context_t* context, uint32_t contact_id);


/**
 * Check, if there is a normal chat with a given contact.
 * To get the chat messages, use dc_get_chat_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param contact_id The contact ID to check.
 * @return If there is a normal chat with the given contact_id, this chat_id is
 *     returned. If there is no normal chat with the contact_id, the function
 *     returns 0.
 */
uint32_t        dc_get_chat_id_by_contact_id (dc_context_t* context, uint32_t contact_id);


/**
 * Send a message defined by a dc_msg_t object to a chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on success.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed e.g. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * Example:
 * ~~~
 * dc_msg_t* msg = dc_msg_new(context, DC_MSG_IMAGE);
 *
 * dc_msg_set_file_and_deduplicate(msg, "/file/to/send.jpg", NULL, NULL);
 * dc_send_msg(context, chat_id, msg);
 *
 * dc_msg_unref(msg);
 * ~~~
 *
 * If you send images with the #DC_MSG_IMAGE type,
 * they will be recoded to a reasonable size before sending, if possible
 * (cmp the dc_set_config()-option `media_quality`).
 * If that fails, is not possible, or the image is already small enough, the image is sent as original.
 * If you want images to be always sent as the original file, use the #DC_MSG_FILE type.
 *
 * Videos and other file types are currently not recoded by the library.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID to send the message to.
 * @param msg The message object to send to the chat defined by the chat ID.
 *     On success, msg_id of the object is set up,
 *     The function does not take ownership of the object,
 *     so you have to free it using dc_msg_unref() as usual.
 * @return The ID of the message that is about to be sent. 0 in case of errors.
 */
uint32_t        dc_send_msg                  (dc_context_t* context, uint32_t chat_id, dc_msg_t* msg);

/**
 * Send a message defined by a dc_msg_t object to a chat, synchronously.
 * This bypasses the IO scheduler and creates its own SMTP connection. Which means
 * this is useful when the scheduler is not running.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID to send the message to.
 * @param msg The message object to send to the chat defined by the chat ID.
 *     On success, msg_id of the object is set up,
 *     The function does not take ownership of the object,
 *     so you have to free it using dc_msg_unref() as usual.
 * @return The ID of the message that is about to be sent. 0 in case of errors.
 */
uint32_t        dc_send_msg_sync                  (dc_context_t* context, uint32_t chat_id, dc_msg_t* msg);


/**
 * Send a simple text message a given chat.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on success.
 * However, this does not imply, the message really reached the recipient -
 * sending may be delayed e.g. due to network problems. However, from your
 * view, you're done with the message. Sooner or later it will find its way.
 *
 * See also dc_send_msg().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID to send the text message to.
 * @param text_to_send Text to send to the chat defined by the chat ID.
 *     Passing an empty text here causes an empty text to be sent,
 *     it's up to the caller to handle this if undesired.
 *     Passing NULL as the text causes the function to return 0.
 * @return The ID of the message that is about being sent.
 */
uint32_t        dc_send_text_msg             (dc_context_t* context, uint32_t chat_id, const char* text_to_send);


/**
 * Send chat members a request to edit the given message's text.
 *
 * Only outgoing messages sent by self can be edited.
 * Edited messages should be flagged as such in the UI, see dc_msg_is_edited().
 * UI is informed about changes using the event #DC_EVENT_MSGS_CHANGED.
 * If the text is not changed, no event and no edit request message are sent.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param msg_id The message ID of the message to edit.
 * @param new_text The new text.
 *      This must not be NULL nor empty.
 */
void            dc_send_edit_request         (dc_context_t* context, uint32_t msg_id, const char* new_text);


/**
 * Send chat members a request to delete the given messages.
 *
 * Only outgoing messages can be deleted this way
 * and all messages must be in the same chat.
 * No tombstone or sth. like that is left.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param msg_ids An array of uint32_t containing all message IDs to delete.
 * @param msg_cnt The number of messages IDs in the msg_ids array.
 */
 void            dc_send_delete_request       (dc_context_t* context, const uint32_t* msg_ids, int msg_cnt);


/**
 * A webxdc instance sends a status update to its other members.
 *
 * In JS land, that would be mapped to something as:
 * ```
 * success = window.webxdc.sendUpdate('{payload: {"action":"move","src":"A3","dest":"B4"}}', 'move A3 B4');
 * ```
 * `context` and `msg_id` are not needed in JS as those are unique within a webxdc instance.
 * See dc_get_webxdc_status_updates() for the receiving counterpart.
 *
 * If the webxdc instance is a draft, the update is not sent immediately.
 * Instead, the updates are collected and sent out in a batch when the instance is actually sent.
 * This allows preparing webxdc instances,
 * e.g. defining a poll with predefined answers.
 *
 * Other members will be informed by #DC_EVENT_WEBXDC_STATUS_UPDATE that there is a new update.
 * You will also get the #DC_EVENT_WEBXDC_STATUS_UPDATE yourself
 * and the update you sent will also be included in dc_get_webxdc_status_updates().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The ID of the message with the webxdc instance.
 * @param json program-readable data, this is created in JS land as:
 *     - `payload`: any JS object or primitive.
 *     - `info`: optional informational message. Will be shown in chat and may be added as system notification.
 *       note that also users that are not notified explicitly get the `info` or `summary` update shown in the chat.
 *     - `document`: optional document name. shown eg. in title bar.
 *     - `summary`: optional summary. shown beside app icon.
 *     - `notify`: optional array of other users `selfAddr` to be notified e.g. by a sound about `info` or `summary`.
 * @param descr Deprecated, set to NULL
 * @return 1=success, 0=error
 */
int dc_send_webxdc_status_update (dc_context_t* context, uint32_t msg_id, const char* json, const char* descr);


/**
 * Get webxdc status updates.
 * The status updates may be sent by yourself or by other members using dc_send_webxdc_status_update().
 * In both cases, you will be informed by #DC_EVENT_WEBXDC_STATUS_UPDATE
 * whenever there is a new update.
 *
 * In JS land, that would be mapped to something as:
 * ```
 * window.webxdc.setUpdateListener((update) => {
 *    if (update.payload.action === "move") {
 *       print(update.payload.src)
 *       print(update.payload.dest)
 *    }
 * });
 * ```
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The ID of the message with the webxdc instance.
 * @param serial The last known serial. Pass 0 if there are no known serials to receive all updates.
 * @return JSON-array containing the requested updates.
 *     Each `update` comes with the following properties:
 *     - `update.payload`: equals the payload given to dc_send_webxdc_status_update()
 *     - `update.serial`: the serial number of this update. Serials are larger `0` and newer serials have higher numbers.
 *     - `update.max_serial`: the maximum serial currently known.
 *        If `max_serial` equals `serial` this update is the last update (until new network messages arrive).
 *     - `update.info`: optional, short, informational message.
 *     - `update.summary`: optional, short text, shown beside app icon.
 *        If there are no updates, an empty JSON-array is returned.
 */
char* dc_get_webxdc_status_updates (dc_context_t* context, uint32_t msg_id, uint32_t serial);


/**
 * Set Webxdc file as integration.
 * see dc_init_webxdc_integration() for more details about Webxdc integrations.
 *
 * @warning This is an experimental API which may change in the future
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param file The .xdc file to use as Webxdc integration.
 */
void             dc_set_webxdc_integration (dc_context_t* context, const char* file);


/**
 * Init a Webxdc integration.
 *
 * A Webxdc integration is
 * a Webxdc showing a map, getting locations via setUpdateListener(), setting POIs via sendUpdate();
 * core takes eg. care of feeding locations to the Webxdc or sending the data out.
 *
 * @warning This is an experimental API, esp. support of integration types (eg. image editor, tools) is left out for simplicity
 *
 * Currently, Webxdc integrations are .xdc files shipped together with the main app.
 * Before dc_init_webxdc_integration() can be called,
 * UI has to call dc_set_webxdc_integration() to define a .xdc file to be used as integration.
 *
 * dc_init_webxdc_integration() returns a Webxdc message ID that
 * UI can open and use mostly as usual.
 *
 * Concrete behaviour and status updates depend on the integration, driven by UI needs.
 *
 * There is no need to de-initialize the integration,
 * however, unless documented otherwise,
 * the integration is valid only as long as not re-initialized
 * In other words, UI must not have a Webxdc with the same integration open twice.
 *
 * Example:
 *
 * ~~~
 * // Define a .xdc file to be used as maps integration
 * dc_set_webxdc_integration(context, path_to_maps_xdc);
 *
 * // Integrate the map to a chat, the map will show locations for this chat then:
 * uint32_t webxdc_instance = dc_init_webxdc_integration(context, any_chat_id);
 *
 * // Or use the Webxdc as a global map, showing locations of all chats:
 * uint32_t webxdc_instance = dc_init_webxdc_integration(context, 0);
 * ~~~
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat to get the integration for.
 * @return ID of the message that refers to the Webxdc instance.
 *     UI can open a Webxdc as usual with this instance.
 */
uint32_t        dc_init_webxdc_integration    (dc_context_t* context, uint32_t chat_id);


/**
 * Start an outgoing call.
 * This sends a message of type #DC_MSG_CALL with all relevant information to the callee,
 * who will get informed by an #DC_EVENT_INCOMING_CALL event and rings.
 *
 * Possible actions during ringing:
 *
 * - caller cancels the call using dc_end_call():
 *   callee receives #DC_EVENT_CALL_ENDED and has a "Missed call"
 *
 * - callee accepts using dc_accept_incoming_call():
 *   caller receives #DC_EVENT_OUTGOING_CALL_ACCEPTED.
 *   callee's devices receive #DC_EVENT_INCOMING_CALL_ACCEPTED, call starts
 *
 * - callee declines using dc_end_call():
 *   caller receives #DC_EVENT_CALL_ENDED and has a "Declinced Call".
 *   callee's other devices receive #DC_EVENT_CALL_ENDED and have a "Canceled Call",
 *
 * - callee is already in a call:
 *   what to do depends on the capabilities of UI to handle calls.
 *   if UI cannot handle multiple calls, an easy approach would be to decline the new call automatically
 *   and make that visble to the user in the call, e.g. by a notification
 *
 * - timeout:
 *   after 1 minute without action,
 *   caller and callee receive #DC_EVENT_CALL_ENDED
 *   to prevent endless ringing of callee
 *   in case caller got offline without being able to send cancellation message.
 *   for caller, this is a "Canceled call";
 *   for callee, this is a "Missed call"
 *
 * Actions during the call:
 *
 * - caller ends the call using dc_end_call():
 *   callee receives #DC_EVENT_CALL_ENDED
 *
 * - callee ends the call using dc_end_call():
 *   caller receives #DC_EVENT_CALL_ENDED
 *
 * Contact request handling:
 *
 * - placing or accepting calls implies accepting contact requests
 *
 * - ending a call does not accept a contact request;
 *   instead, the call will timeout on all affected devices.
 *
 * Note, that the events are for updating the call screen,
 * possible status messages are added and updated as usual, including the known events.
 * In the UI, the sorted chatlist is used as an overview about calls as well as messages.
 * To place a call with a contact that has no chat yet, use dc_create_chat_by_contact_id() first.
 *
 * UI will usually allow only one call at the same time,
 * this has to be tracked by UI across profile, the core does not track this.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat to place a call for.
 *     This needs to be a one-to-one chat.
 * @param place_call_info any data that other devices receive
 *     in #DC_EVENT_INCOMING_CALL.
 * @param has_video Whether the call has video initially.
 *     This allows the recipient's client to adjust incoming call UX.
 *     A call can be upgraded to include video later.
 * @return ID of the system message announcing the call.
 */
uint32_t        dc_place_outgoing_call       (dc_context_t* context, uint32_t chat_id, const char* place_call_info, int has_video);


/**
 * Accept incoming call.
 *
 * This implicitly accepts the contact request, if not yet done.
 * All affected devices will receive
 * either #DC_EVENT_OUTGOING_CALL_ACCEPTED or #DC_EVENT_INCOMING_CALL_ACCEPTED.
 *
 * If the call is already accepted or ended, nothing happens.
 * If the chat is a contact request, it is accepted implicitly.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The ID of the call to accept.
 *     This is the ID reported by #DC_EVENT_INCOMING_CALL
 *     and equals to the ID of the corresponding info message.
 * @param accept_call_info any data that other devices receive
 *     in #DC_EVENT_OUTGOING_CALL_ACCEPTED.
 * @return 1=success, 0=error
 */
 int            dc_accept_incoming_call      (dc_context_t* context, uint32_t msg_id, const char* accept_call_info);


 /**
  * End incoming or outgoing call.
  *
  * For unaccepted calls ended by the caller, this is a "cancellation".
  * Unaccepted calls ended by the callee are a "decline".
  * If the call was accepted, this is a "hangup".
  *
  * All participant devices get informed about the ended call via #DC_EVENT_CALL_ENDED unless they are contact requests.
  * For contact requests, the call times out on all other affected devices.
  *
  * If the message ID is wrong or does not exist for whatever reasons, nothing happens.
  * Therefore, and for resilience, UI should remove the call UI directly when calling
  * this function and not only on the event.
  *
  * If the call is already ended, nothing happens.
  *
  * @memberof dc_context_t
  * @param context The context object.
  * @param msg_id the ID of the call.
  * @return 1=success, 0=error
  */
 int            dc_end_call                  (dc_context_t* context, uint32_t msg_id);


/**
 * Save a draft for a chat in the database.
 *
 * The UI should call this function if the user has prepared a message
 * and exits the compose window without clicking the "send" button before.
 * When the user later opens the same chat again,
 * the UI can load the draft using dc_get_draft()
 * allowing the user to continue editing and sending.
 *
 * Drafts are considered when sorting messages
 * and are also returned e.g. by dc_chatlist_get_summary().
 *
 * Each chat can have its own draft but only one draft per chat is possible.
 *
 * If the draft is modified, an #DC_EVENT_MSGS_CHANGED will be sent.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to save the draft for.
 * @param msg The message to save as a draft.
 *     Existing draft will be overwritten.
 *     NULL deletes the existing draft, if any, without sending it.
 */
void            dc_set_draft                 (dc_context_t* context, uint32_t chat_id, dc_msg_t* msg);


/**
 * Add a message to the device-chat.
 * Device-messages usually contain update information
 * and some hints that are added during the program runs, multi-device etc.
 * The device-message may be defined by a label;
 * if a message with the same label was added or skipped before,
 * the message is not added again, even if the message was deleted in between.
 * If needed, the device-chat is created before.
 *
 * Sends the event #DC_EVENT_MSGS_CHANGED on success.
 * To check, if a given chat is a device-chat, see dc_chat_is_device_talk()
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param label A unique name for the message to add.
 *     The label is typically not displayed to the user and
 *     must be created from the characters `A-Z`, `a-z`, `0-9`, `_` or `-`.
 *     If you pass NULL here, the message is added unconditionally.
 * @param msg The message to be added to the device-chat.
 *     The message appears to the user as an incoming message.
 *     If you pass NULL here, only the given label will be added
 *     and block adding messages with that label in the future.
 * @return The ID of the just added message,
 *     if the message was already added or no message to add is given, 0 is returned.
 *
 * Example:
 * ~~~
 * dc_msg_t* welcome_msg = dc_msg_new(DC_MSG_TEXT);
 * dc_msg_set_text(welcome_msg, "great that you give this app a try!");
 *
 * dc_msg_t* changelog_msg = dc_msg_new(DC_MSG_TEXT);
 * dc_msg_set_text(changelog_msg, "we have added 3 new emojis :)");
 *
 * if (dc_add_device_msg(context, "welcome", welcome_msg)) {
 *     // do not add the changelog on a new installations -
 *     // not now and not when this code is executed again
 *     dc_add_device_msg(context, "update-123", NULL);
 * } else {
 *     // welcome message was not added now, this is an older installation,
 *     // add a changelog
 *     dc_add_device_msg(context, "update-123", changelog_msg);
 * }
 *
 * dc_msg_unref(changelog_msg);
 * dc_msg_unref(welome_msg);
 * ~~~
 */
uint32_t        dc_add_device_msg            (dc_context_t* context, const char* label, dc_msg_t* msg);

/**
 * Check if a device-message with a given label was ever added.
 * Device-messages can be added with dc_add_device_msg().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param label The label of the message to check.
 * @return 1=A message with this label was added at some point,
 *     0=A message with this label was never added.
 */
int             dc_was_device_msg_ever_added (dc_context_t* context, const char* label);


/**
 * Get draft for a chat, if any.
 * See dc_set_draft() for more details about drafts.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to get the draft for.
 * @return Message object.
 *     Can be passed directly to dc_send_msg().
 *     Must be freed using dc_msg_unref() after usage.
 *     If there is no draft, NULL is returned.
 */
dc_msg_t*       dc_get_draft                 (dc_context_t* context, uint32_t chat_id);


#define         DC_GCM_ADDDAYMARKER          0x01
#define         DC_GCM_INFO_ONLY             0x02


/**
 * Get all message IDs belonging to a chat.
 *
 * The list is already sorted and starts with the oldest message.
 * Clients should not try to re-sort the list as this would be an expensive action
 * and would result in inconsistencies between clients.
 *
 * Optionally, some special markers added to the ID array may help to
 * implement virtual lists.
 *
 * To get the concrete time of the message, use dc_array_get_timestamp().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID of which the messages IDs should be queried.
 * @param flags If set to DC_GCM_ADDDAYMARKER, the marker DC_MSG_ID_DAYMARKER will
 *     be added before each day (regarding the local timezone). Set this to 0 if you do not want this behaviour.
 *     The day marker timestamp is the midnight one for the corresponding (following) day in the local timezone.
 *     If set to DC_GCM_INFO_ONLY, only system messages will be returned, can be combined with DC_GCM_ADDDAYMARKER.
 * @param marker1before Deprecated, set this to 0.
 * @return Array of message IDs, must be dc_array_unref()'d when no longer used.
 */
dc_array_t*     dc_get_chat_msgs             (dc_context_t* context, uint32_t chat_id, uint32_t flags, uint32_t marker1before);


/**
 * Get the total number of messages in a chat.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to count the messages for.
 * @return Number of total messages in the given chat. 0 for errors or empty chats.
 */
int             dc_get_msg_cnt               (dc_context_t* context, uint32_t chat_id);


/**
 * Get the number of _fresh_ messages in a chat.
 * Typically used to implement a badge with a number in the chatlist.
 *
 * As muted archived chats are not unarchived automatically,
 * a similar information is needed for the @ref dc_get_chatlist() "archive link" as well:
 * here, the number of archived chats containing fresh messages is returned.
 *
 * If the specified chat is muted or the @ref dc_get_chatlist() "archive link",
 * the UI should show the badge counter "less obtrusive",
 * e.g. using "gray" instead of "red" color.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to count the messages for.
 * @return Number of fresh messages in the given chat. 0 for errors or if there are no fresh messages.
 */
int             dc_get_fresh_msg_cnt         (dc_context_t* context, uint32_t chat_id);


/**
 * Returns a list of similar chats.
 *
 * @warning This is an experimental API which may change or be removed in the future.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat for which to find similar chats.
 * @return The list of similar chats.
 *     On errors, NULL is returned.
 *     Must be freed using dc_chatlist_unref() when no longer used.
 */
dc_chatlist_t*     dc_get_similar_chatlist   (dc_context_t* context, uint32_t chat_id);


/**
 * Estimate the number of messages that will be deleted
 * by the dc_set_config()-options `delete_device_after` or `delete_server_after`.
 * This is typically used to show the estimated impact to the user
 * before actually enabling deletion of old messages.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param from_server 1=Estimate deletion count for server, 0=Estimate deletion count for device
 * @param seconds Count messages older than the given number of seconds.
 * @return Number of messages that are older than the given number of seconds.
 *     This includes e-mails downloaded due to the `show_emails` option.
 *     Messages in the "saved messages" folder are not counted as they will not be deleted automatically.
 */
int             dc_estimate_deletion_cnt    (dc_context_t* context, int from_server, int64_t seconds);


/**
 * Returns the message IDs of all _fresh_ messages of any chat.
 * Typically used for implementing notification summaries
 * or badge counters e.g. on the app icon.
 * The list is already sorted and starts with the most recent fresh message.
 *
 * Messages belonging to muted chats or to the contact requests are not returned;
 * these messages should not be notified
 * and also badge counters should not include these messages.
 *
 * To get the number of fresh messages for a single chat, muted or not,
 * use dc_get_fresh_msg_cnt().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @return An array of message IDs, must be dc_array_unref()'d when no longer used.
 *     On errors, the list is empty. NULL is never returned.
 */
dc_array_t*     dc_get_fresh_msgs            (dc_context_t* context);


/**
 * Returns the message IDs of all messages of any chat
 * with a database ID higher than `last_msg_id` config value.
 *
 * This function is intended for use by bots.
 * Self-sent messages, device messages,
 * messages from contact requests
 * and muted chats are included,
 * but messages from explicitly blocked contacts
 * and chats are ignored.
 *
 * This function may be called as a part of event loop
 * triggered by DC_EVENT_INCOMING_MSG if you are only interested
 * in the incoming messages.
 * Otherwise use a separate message processing loop
 * calling dc_wait_next_msgs() in a separate thread.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @return An array of message IDs, must be dc_array_unref()'d when no longer used.
 *     On errors, the list is empty. NULL is never returned.
 */
dc_array_t*     dc_get_next_msgs             (dc_context_t* context);


/**
 * Waits for notification of new messages
 * and returns an array of new message IDs.
 * See the documentation for dc_get_next_msgs()
 * for the details of return value.
 *
 * This function waits for internal notification of
 * a new message in the database and returns afterwards.
 * Notification is also sent when I/O is started
 * to allow processing new messages
 * and when I/O is stopped using dc_stop_io() or dc_accounts_stop_io()
 * to allow for manual interruption of the message processing loop.
 * The function may return an empty array if there are
 * no messages after notification,
 * which may happen on start or if the message is quickly deleted
 * after adding it to the database.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @return An array of message IDs, must be dc_array_unref()'d when no longer used.
 *     On errors, the list is empty. NULL is never returned.
 */
dc_array_t*     dc_wait_next_msgs            (dc_context_t* context);


/**
 * Mark all messages in a chat as _noticed_.
 * _Noticed_ messages are no longer _fresh_ and do not count as being unseen
 * but are still waiting for being marked as "seen" using dc_markseen_msgs()
 * (read receipts aren't sent for noticed messages).
 *
 * Calling this function usually results in the event #DC_EVENT_MSGS_NOTICED.
 * See also dc_markseen_msgs().
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The chat ID of which all messages should be marked as being noticed.
 */
void            dc_marknoticed_chat          (dc_context_t* context, uint32_t chat_id);


/**
 * Returns all message IDs of the given types in a given chat or any chat.
 * Typically used to show a gallery.
 * The result must be dc_array_unref()'d
 *
 * The list is already sorted and starts with the oldest message.
 * Clients should not try to re-sort the list as this would be an expensive action
 * and would result in inconsistencies between clients.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id >0: get messages with media from this chat ID.
 *    0: get messages with media from any chat of the currently used account.
 * @param msg_type Specify a message type to query here, one of the @ref DC_MSG constants.
 * @param msg_type2 Alternative message type to search for. 0 to skip.
 * @param msg_type3 Alternative message type to search for. 0 to skip.
 * @return An array with messages from the given chat ID that have the wanted message types.
 */
dc_array_t*     dc_get_chat_media            (dc_context_t* context, uint32_t chat_id, int msg_type, int msg_type2, int msg_type3);


/**
 * Set chat visibility to pinned, archived or normal.
 *
 * Calling this function usually results in the event #DC_EVENT_MSGS_CHANGED
 * See @ref DC_CHAT_VISIBILITY for detailed information about the visibilities.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to change the visibility for.
 * @param visibility one of @ref DC_CHAT_VISIBILITY
 */
void            dc_set_chat_visibility       (dc_context_t* context, uint32_t chat_id, int visibility);


/**
 * Delete a chat.
 *
 * Messages are deleted from the device and the chat database entry is deleted.
 * After that, the event #DC_EVENT_MSGS_CHANGED is posted.
 * Messages are deleted from the server in background.
 *
 * Things that are _not_ done implicitly:
 *
 * - The chat or the contact is **not blocked**, so new messages from the user/the group may appear
 *   and the user may create the chat again.
 * - **Groups are not left** - this would
 *   be unexpected as (1) deleting a normal chat also does not prevent new mails
 *   from arriving, (2) leaving a group requires sending a message to
 *   all group members - especially for groups not used for a longer time, this is
 *   really unexpected when deletion results in contacting all members again,
 *   (3) only leaving groups is also a valid usecase.
 *
 * To leave a chat explicitly, use dc_remove_contact_from_chat() with
 * chat_id=DC_CONTACT_ID_SELF)
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to delete.
 */
void            dc_delete_chat               (dc_context_t* context, uint32_t chat_id);

/**
 * Block a chat.
 *
 * Blocking 1:1 chats blocks the corresponding contact. Blocking
 * mailing lists creates a pseudo-contact in the list of blocked
 * contacts, so blocked mailing lists can be discovered and unblocked
 * the same way as the contacts. Blocking group chats deletes the
 * chat without blocking any contacts, so it may pop up again later.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to block.
 */
void            dc_block_chat                (dc_context_t* context, uint32_t chat_id);

/**
 * Accept a contact request chat.
 *
 * Use it to accept "contact request" chats as indicated by dc_chat_is_contact_request().
 *
 * If the dc_set_config()-option `bot` is set,
 * all chats are accepted automatically and calling this function has no effect.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to accept.
 */
void            dc_accept_chat               (dc_context_t* context, uint32_t chat_id);

/**
 * Get the contact IDs belonging to a chat.
 *
 * - for normal chats, the function always returns exactly one contact,
 *   DC_CONTACT_ID_SELF is returned only for SELF-chats.
 *
 * - for group chats all members are returned, DC_CONTACT_ID_SELF is returned
 *   explicitly as it may happen that oneself gets removed from a still existing
 *   group
 *
 * - for broadcasts, all recipients are returned, DC_CONTACT_ID_SELF is not included
 *
 * - for mailing lists, the behavior is not documented currently, we will decide on that later.
 *   for now, the UI should not show the list for mailing lists.
 *   (we do not know all members and there is not always a global mailing list address,
 *   so we could return only SELF or the known members; this is not decided yet)
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to get the belonging contact IDs for.
 * @return An array of contact IDs belonging to the chat; must be freed using dc_array_unref() when done.
 */
dc_array_t*     dc_get_chat_contacts         (dc_context_t* context, uint32_t chat_id);

/**
 * Get encryption info for a chat.
 * Get a multi-line encryption info, containing encryption preferences of all members.
 * Can be used to find out why messages sent to group are not encrypted.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The ID of the chat to get the encryption info for.
 * @return Multi-line text, must be released using dc_str_unref() after usage.
 */
char*           dc_get_chat_encrinfo (dc_context_t* context, uint32_t chat_id);

/**
 * Get the chat's ephemeral message timer.
 * The ephemeral message timer is set by dc_set_chat_ephemeral_timer()
 * on this or any other device participating in the chat.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID.
 *
 * @return ephemeral timer value in seconds, 0 if the timer is disabled or if there is an error
 */
uint32_t dc_get_chat_ephemeral_timer (dc_context_t* context, uint32_t chat_id);

/**
 * Search messages containing the given query string.
 * Searching can be done globally (chat_id=0) or in a specified chat only (chat_id set).
 *
 * Global chat results are typically displayed using dc_msg_get_summary(), chat
 * search results may just hilite the corresponding messages and present a
 * prev/next button.
 *
 * For global search, result is limited to 1000 messages,
 * this allows incremental search done fast.
 * So, when getting exactly 1000 results, the result may be truncated;
 * the UIs may display sth. as "1000+ messages found" in this case.
 * Chat search (if a chat_id is set) is not limited.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to search messages in.
 *     Set this to 0 for a global search.
 * @param query The query to search for.
 * @return An array of message IDs. Must be freed using dc_array_unref() when no longer needed.
 *     If nothing can be found, the function returns NULL.
 */
dc_array_t*     dc_search_msgs               (dc_context_t* context, uint32_t chat_id, const char* query);


/**
 * Get a chat object by a chat ID.
 *
 * @memberof dc_context_t
 * @param context The context object as returned from dc_context_new().
 * @param chat_id The ID of the chat to get the chat object for.
 * @return A chat object of the type dc_chat_t,
 *     must be freed using dc_chat_unref() when done.
 *     On errors, NULL is returned.
 */
dc_chat_t*      dc_get_chat                  (dc_context_t* context, uint32_t chat_id);


// handle group chats

/**
 * Create a new group chat.
 *
 * After creation,
 * the group has one member with the ID DC_CONTACT_ID_SELF
 * and is in _unpromoted_ state.
 * This means, you can add or remove members, change the name,
 * the group image and so on without messages being sent to all group members.
 *
 * This changes as soon as the first message is sent to the group members
 * and the group becomes _promoted_.
 * After that, all changes are synced with all group members
 * by sending status message.
 *
 * To check, if a chat is still unpromoted, you dc_chat_is_unpromoted().
 * This may be useful if you want to show some help for just created groups.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param protect Deprecated 2025-08-31, ignored.
 * @param name The name of the group chat to create.
 *     The name may be changed later using dc_set_chat_name().
 *     To find out the name of a group later, see dc_chat_get_name()
 * @return The chat ID of the new group chat, 0 on errors.
 */
uint32_t        dc_create_group_chat         (dc_context_t* context, int protect, const char* name);


/**
 * Create a new broadcast list.
 *
 * Broadcast lists are similar to groups on the sending device,
 * however, recipients get the messages in a read-only chat
 * and will see who the other members are.
 *
 * For historical reasons, this function does not take a name directly,
 * instead you have to set the name using dc_set_chat_name()
 * after creating the broadcast list.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return The chat ID of the new broadcast list, 0 on errors.
 */
uint32_t        dc_create_broadcast_list     (dc_context_t* context);


/**
 * Check if a given contact ID is a member of a group chat.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to check.
 * @param contact_id The contact ID to check. To check if yourself is member
 *     of the chat, pass DC_CONTACT_ID_SELF (1) here.
 * @return 1=contact ID is member of chat ID, 0=contact is not in chat
 */
int             dc_is_contact_in_chat        (dc_context_t* context, uint32_t chat_id, uint32_t contact_id);


/**
 * Add a member to a group.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * all group members are informed by a special status message that is sent automatically by this function.
 *
 * If the group has group protection enabled, only verified contacts can be added to the group.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to add the contact to. Must be a group chat.
 * @param contact_id The contact ID to add to the chat.
 * @return 1=member added to group, 0=error
 */
int             dc_add_contact_to_chat       (dc_context_t* context, uint32_t chat_id, uint32_t contact_id);


/**
 * Remove a member from a group.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * all group members are informed by a special status message that is sent automatically by this function.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to remove the contact from. Must be a group chat.
 * @param contact_id The contact ID to remove from the chat.
 * @return 1=member removed from group, 0=error
 */
int             dc_remove_contact_from_chat  (dc_context_t* context, uint32_t chat_id, uint32_t contact_id);


/**
 * Set the name of a group or broadcast channel.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * or if this is a brodacast channel,
 * all members are informed by a special status message that is sent automatically by this function.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * @memberof dc_context_t
 * @param chat_id The chat ID to set the name for. Must be a group chat or broadcast channel.
 * @param name New name of the group.
 * @param context The context object.
 * @return 1=success, 0=error
 */
int             dc_set_chat_name             (dc_context_t* context, uint32_t chat_id, const char* name);

/**
 * Set the chat's ephemeral message timer.
 *
 * This timer is applied to all messages in a chat and starts when the message is read.
 * For outgoing messages, the timer starts once the message is sent,
 * for incoming messages, the timer starts once dc_markseen_msgs() is called.
 *
 * The setting is synchronized to all clients
 * participating in a chat.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to set the ephemeral message timer for.
 * @param timer The timer value in seconds or 0 to disable the timer.
 *
 * @return 1=success, 0=error
 */
int dc_set_chat_ephemeral_timer (dc_context_t* context, uint32_t chat_id, uint32_t timer);

/**
 * Set group or broadcast channel profile image.
 *
 * If the group is already _promoted_ (any message was sent to the group),
 * or if this is a brodacast channel,
 * all members are informed by a special status message that is sent automatically by this function.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
 *
 * To find out the profile image of a chat, use dc_chat_get_profile_image()
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to set the image for.  Must be a group chat or broadcast channel.
 * @param image Full path of the image to use as the group image. The image will immediately be copied to the 
 *     `blobdir`; the original image will not be needed anymore.
 *      If you pass NULL here, the group image is deleted (for promoted groups, all members are informed about 
 *      this change anyway).
 * @return 1=success, 0=error
 */
int             dc_set_chat_profile_image    (dc_context_t* context, uint32_t chat_id, const char* image);



/**
 * Set mute duration of a chat.
 *
 * The UI can then call dc_chat_is_muted() when receiving a new message
 * to decide whether it should trigger an notification.
 *
 * Muted chats should not sound or vibrate
 * and should not show a visual notification in the system area.
 * Moreover, muted chats should be excluded from global badge counter
 * (dc_get_fresh_msgs() skips muted chats therefore)
 * and the in-app, per-chat badge counter should use a less obtrusive color.
 *
 * Sends out #DC_EVENT_CHAT_MODIFIED.
 *
 * @memberof dc_context_t
 * @param chat_id The chat ID to set the mute duration.
 * @param duration The duration (0 for no mute, -1 for forever mute,
 *      everything else is is the relative mute duration from now in seconds)
 * @param context The context object.
 * @return 1=success, 0=error
 */
int             dc_set_chat_mute_duration             (dc_context_t* context, uint32_t chat_id, int64_t duration);

// handle messages

/**
 * Get an informational text for a single message. The text is multiline and may
 * contain e.g. the raw text of the message.
 *
 * The max. text returned is typically longer (about 100000 characters) than the
 * max. text returned by dc_msg_get_text() (about 30000 characters).
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The message ID for which information should be generated.
 * @return Text string, must be released using dc_str_unref() after usage
 */
char*           dc_get_msg_info              (dc_context_t* context, uint32_t msg_id);


/**
 * Get uncut message, if available.
 *
 * Delta Chat tries to break the message in simple parts as plain text or images
 * that are retrieved using dc_msg_get_viewtype(), dc_msg_get_text(), dc_msg_get_file() and so on.
 * This works totally fine for Delta Chat to Delta Chat communication,
 * however, when the counterpart uses another E-Mail-client, this has limits:
 *
 * - even if we do some good job on removing quotes,
 *   sometimes one needs to see them
 * - HTML-only messages might lose information on conversion to text,
 *   esp. when there are lots of embedded images
 * - even if there is some plain text part for a HTML-message,
 *   this is often poor and not nicely usable due to long links
 *
 * In these cases, dc_msg_has_html() returns 1
 * and you can ask dc_get_msg_html() for some HTML-code
 * that shows the uncut text (which is close to the original)
 * For simplicity, the function _always_ returns HTML-code,
 * this removes the need for the UI
 * to deal with different formatting options of PLAIN-parts.
 *
 * As the title of the full-message-view, you can use the subject (see dc_msg_get_subject()).
 *
 * **Note:** The returned HTML-code may contain scripts,
 * external images that may be misused as hidden read-receipts and so on.
 * Taking care of these parts
 * while maintaining compatibility with the then generated HTML-code
 * is not easily doable, if at all.
 * E.g. taking care of tags and attributes is not sufficient,
 * we would have to deal with linked content (e.g. script, css),
 * text (e.g. script-blocks) and values (e.g. javascript-protocol) as well;
 * on this level, we have to deal with encodings, browser peculiarities and so on -
 * and would still risk to oversee something and to break things.
 *
 * To avoid starting this cat-and-mouse game,
 * and to close this issue in a sustainable way,
 * it is up to the UI to display the HTML-code in an **appropriate sandbox environment** -
 * that may e.g. be an external browser or a WebView with scripting disabled.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The message ID for which the uncut text should be loaded.
 * @return Uncut text as HTML.
 *     In case of errors, NULL is returned.
 *     The result must be released using dc_str_unref().
 */
char*           dc_get_msg_html              (dc_context_t* context, uint32_t msg_id);


/**
  * Asks the core to start downloading a message fully.
  * This function is typically called when the user hits the "Download" button
  * that is shown by the UI in case dc_msg_get_download_state()
  * returns @ref DC_DOWNLOAD_AVAILABLE or @ref DC_DOWNLOAD_FAILURE.
  *
  * On success, the @ref DC_MSG "view type of the message" may change
  * or the message may be replaced completely by one or more messages with other message IDs.
  * That may happen e.g. in cases where the message was encrypted
  * and the type could not be determined without fully downloading.
  * Downloaded content can be accessed as usual after download,
  * e.g. using dc_msg_get_file().
  *
  * To reflect these changes a @ref DC_EVENT_MSGS_CHANGED event will be emitted.
  *
  * @memberof dc_context_t
  * @param context The context object.
  * @param msg_id The message ID to download the content for.
  */
void dc_download_full_msg (dc_context_t* context, int msg_id);


/**
 * Delete messages. The messages are deleted on all devices and
 * on the IMAP server.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_ids An array of uint32_t containing all message IDs that should be deleted.
 * @param msg_cnt The number of messages IDs in the msg_ids array.
 */
void            dc_delete_msgs               (dc_context_t* context, const uint32_t* msg_ids, int msg_cnt);


/**
 * Forward messages to another chat.
 *
 * All types of messages can be forwarded,
 * however, they will be flagged as such (dc_msg_is_forwarded() is set).
 *
 * Original sender, info-state and webxdc updates are not forwarded on purpose.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_ids An array of uint32_t containing all message IDs that should be forwarded.
 * @param msg_cnt The number of messages IDs in the msg_ids array.
 * @param chat_id The destination chat ID.
 */
void            dc_forward_msgs              (dc_context_t* context, const uint32_t* msg_ids, int msg_cnt, uint32_t chat_id);


/**
 * Save a copy of messages in "Saved Messages".
 *
 * In contrast to forwarding messages,
 * information as author, date and origin are preserved.
 * The action completes locally, so "Saved Messages" do not show sending errors in case one is offline.
 * Still, a sync message is emitted, so that other devices will save the same message,
 * as long as not deleted before.
 *
 * To check if a message was saved, use dc_msg_get_saved_msg_id(),
 * UI may show an indicator and offer an "Unsave" instead of a "Save" button then.
 *
 * The other way round, from inside the "Saved Messages" chat,
 * UI may show the indicator and "Unsave" button checking dc_msg_get_original_msg_id()
 * and offer a button to go the original message.
 *
 * "Unsave" is done by deleting the saved message.
 * Webxdc updates are not copied on purpose.
 *
 * For performance reasons, esp. when saving lots of messages,
 * UI should call this function from a background thread.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_ids An array of uint32_t containing all message IDs that should be saved.
 * @param msg_cnt The number of messages IDs in the msg_ids array.
 */
void            dc_save_msgs                 (dc_context_t* context, const uint32_t* msg_ids, int msg_cnt);


/**
 * Resend messages and make information available for newly added chat members.
 * Resending sends out the original message, however, recipients and webxdc-status may differ.
 * Clients that already have the original message can still ignore the resent message as
 * they have tracked the state by dedicated updates.
 *
 * Some messages cannot be resent, eg. info-messages, drafts, already pending messages or messages that are not sent by SELF.
 * In this case, the return value indicates an error and the error string from dc_get_last_error() should be shown to the user.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_ids An array of uint32_t containing all message IDs that should be resend.
 *     All messages must belong to the same chat.
 * @param msg_cnt The number of messages IDs in the msg_ids array.
 * @return 1=all messages are queued for resending, 0=error
 */
int             dc_resend_msgs               (dc_context_t* context, const uint32_t* msg_ids, int msg_cnt);


/**
 * Mark messages as presented to the user.
 * Typically, UIs call this function on scrolling through the message list,
 * when the messages are presented at least for a little moment.
 * The concrete action depends on the type of the chat and on the users settings
 * (dc_msgs_presented() may be a better name therefore, but well. :)
 *
 * - For normal chats, the IMAP state is updated, MDN is sent
 *   (if dc_set_config()-options `mdns_enabled` is set)
 *   and the internal state is changed to @ref DC_STATE_IN_SEEN to reflect these actions.
 *
 * - For contact requests, no IMAP or MDNs is done
 *   and the internal state is not changed therefore.
 *   See also dc_marknoticed_chat().
 *
 * Moreover, timer is started for incoming ephemeral messages.
 * This also happens for contact requests chats.
 *
 * This function updates last_msg_id configuration value
 * to the maximum of the current value and IDs passed to this function.
 * Bots which mark messages as seen can rely on this side effect
 * to avoid updating last_msg_id value manually.
 *
 * One #DC_EVENT_MSGS_NOTICED event is emitted per modified chat.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_ids An array of uint32_t containing all the messages IDs that should be marked as seen.
 * @param msg_cnt The number of message IDs in msg_ids.
 */
void            dc_markseen_msgs             (dc_context_t* context, const uint32_t* msg_ids, int msg_cnt);


/**
 * Get a single message object of the type dc_msg_t.
 * For a list of messages in a chat, see dc_get_chat_msgs()
 * For a list or chats, see dc_get_chatlist()
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The message ID for which the message object should be created.
 * @return A dc_msg_t message object.
 *     On errors, NULL is returned.
 *     When done, the object must be freed using dc_msg_unref().
 */
dc_msg_t*       dc_get_msg                   (dc_context_t* context, uint32_t msg_id);


// handle contacts

/**
 * Rough check if a string may be a valid e-mail address.
 * The function checks if the string contains a minimal amount of characters
 * before and after the `@` and `.` characters.
 *
 * To check if a given address is a contact in the contact database
 * use dc_lookup_contact_id_by_addr().
 *
 * @memberof dc_context_t
 * @param addr The e-mail address to check.
 * @return 1=address may be a valid e-mail address,
 *     0=address won't be a valid e-mail address
 */
int             dc_may_be_valid_addr         (const char* addr);


/**
 * Looks up a known and unblocked contact with a given e-mail address.
 * To get a list of all known and unblocked contacts, use dc_get_contacts().
 *
 * **POTENTIAL SECURITY ISSUE**: If there are multiple contacts with this address
 * (e.g. an address-contact and a key-contact),
 * this looks up the most recently seen contact,
 * i.e. which contact is returned depends on which contact last sent a message.
 * If the user just clicked on a mailto: link, then this is the best thing you can do.
 * But **DO NOT** internally represent contacts by their email address
 * and do not use this function to look them up;
 * otherwise this function will sometimes look up the wrong contact.
 * Instead, you should internally represent contacts by their ids.
 *
 * To validate an e-mail address independently of the contact database
 * use dc_may_be_valid_addr().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param addr The e-mail address to check.
 * @return The contact ID of the contact belonging to the e-mail address
 *     or 0 if there is no contact that is or was introduced by an accepted contact.
 */
uint32_t        dc_lookup_contact_id_by_addr (dc_context_t* context, const char* addr);


/**
 * Add a single contact as a result of an _explicit_ user action.
 *
 * We assume, the contact name, if any, is entered by the user and is used "as is" therefore,
 * normalize() is _not_ called for the name. If the contact is blocked, it is unblocked.
 *
 * To add a number of contacts, see dc_add_address_book() which is much faster for adding
 * a bunch of addresses.
 *
 * This will always create or look up an address-contact,
 * i.e. a contact identified by an email address,
 * with all messages sent to and from this contact being unencrypted.
 * If the user just clicked on an email address,
 * you should first check `lookup_contact_id_by_addr`,
 * and only if there is no contact yet, call this function here.
 *
 * May result in a #DC_EVENT_CONTACTS_CHANGED event.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param name The name of the contact to add. If you do not know the name belonging
 *     to the address, you can give NULL here.
 * @param addr The e-mail address of the contact to add. If the e-mail address
 *     already exists, the name is updated and the origin is increased to
 *     "manually created".
 * @return The contact ID of the created or reused contact.
 */
uint32_t        dc_create_contact            (dc_context_t* context, const char* name, const char* addr);


#define         DC_GCL_ADD_SELF              0x02
#define         DC_GCL_ADDRESS               0x04


/**
 * Add a number of contacts.
 *
 * Typically used to add the whole address book from the OS. As names here are typically not
 * well formatted, we call normalize() for each name given.
 *
 * No e-mail address is added twice.
 * Trying to add e-mail addresses that are already in the contact list,
 * results in updating the name unless the name was changed manually by the user.
 * If any e-mail address or any name is really updated,
 * the event #DC_EVENT_CONTACTS_CHANGED is sent.
 *
 * To add a single contact entered by the user, you should prefer dc_create_contact(),
 * however, for adding a bunch of addresses, this function is _much_ faster.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param addr_book A multi-line string in the format
 *     `Name one\nAddress one\nName two\nAddress two`.
 *      If an e-mail address already exists, the name is updated
 *      unless it was edited manually by dc_create_contact() before.
 * @return The number of modified or added contacts.
 */
int             dc_add_address_book          (dc_context_t* context, const char* addr_book);


/**
 * Make a vCard.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param contact_id The ID of the contact to make the vCard of.
 * @return vCard, must be released using dc_str_unref() after usage.
 */
char*           dc_make_vcard                (dc_context_t* context, uint32_t contact_id);


/**
 * Import a vCard.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param vcard vCard contents.
 * @return Returns the IDs of the contacts in the order they appear in the vCard.
 *         Must be dc_array_unref()'d after usage.
 */
dc_array_t*     dc_import_vcard              (dc_context_t* context, const char* vcard);


/**
 * Returns known and unblocked contacts.
 *
 * To get information about a single contact, see dc_get_contact().
 * By default, key-contacts are listed.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param flags A combination of flags:
 *     - DC_GCL_ADD_SELF: SELF is added to the list unless filtered by other parameters
 *     - DC_GCL_ADDRESS: List address-contacts instead of key-contacts.
 * @param query A string to filter the list. Typically used to implement an
 *     incremental search. NULL for no filtering.
 * @return An array containing all contact IDs. Must be dc_array_unref()'d
 *     after usage.
 */
dc_array_t*     dc_get_contacts              (dc_context_t* context, uint32_t flags, const char* query);


/**
 * Get blocked contacts.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return An array containing all blocked contact IDs. Must be dc_array_unref()'d
 *     after usage.
 */
dc_array_t*     dc_get_blocked_contacts      (dc_context_t* context);


/**
 * Block or unblock a contact.
 * May result in a #DC_EVENT_CONTACTS_CHANGED event.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param contact_id The ID of the contact to block or unblock.
 * @param block 1=block contact, 0=unblock contact
 */
void            dc_block_contact             (dc_context_t* context, uint32_t contact_id, int block);


/**
 * Get encryption info for a contact.
 * Get a multi-line encryption info, containing your fingerprint and the
 * fingerprint of the contact, used e.g. to compare the fingerprints for a simple out-of-band verification.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param contact_id The ID of the contact to get the encryption info for.
 * @return Multi-line text, must be released using dc_str_unref() after usage.
 */
char*           dc_get_contact_encrinfo      (dc_context_t* context, uint32_t contact_id);


/**
 * Delete a contact so that it disappears from the corresponding lists.
 * Depending on whether there are ongoing chats, deletion is done by physical deletion or hiding.
 * The contact is deleted from the local device.
 *
 * May result in a #DC_EVENT_CONTACTS_CHANGED event.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param contact_id The ID of the contact to delete.
 * @return 1=success, 0=error
 */
int             dc_delete_contact            (dc_context_t* context, uint32_t contact_id);


/**
 * Get a single contact object. For a list, see e.g. dc_get_contacts().
 *
 * For contact DC_CONTACT_ID_SELF (1), the function returns sth.
 * like "Me" in the selected language and the e-mail address
 * defined by dc_set_config().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param contact_id The ID of the contact to get the object for.
 * @return The contact object, must be freed using dc_contact_unref() when no
 *     longer used. NULL on errors.
 */
dc_contact_t*   dc_get_contact               (dc_context_t* context, uint32_t contact_id);


// import/export and tools

#define         DC_IMEX_EXPORT_SELF_KEYS      1 // param1 is a directory where the keys are written to
#define         DC_IMEX_IMPORT_SELF_KEYS      2 // param1 is a directory where the keys are searched in and read from
#define         DC_IMEX_EXPORT_BACKUP        11 // param1 is a directory where the backup is written to, param2 is a passphrase to encrypt the backup
#define         DC_IMEX_IMPORT_BACKUP        12 // param1 is the file with the backup to import, param2 is the backup's passphrase


/**
 * Import/export things.
 *
 * What to do is defined by the _what_ parameter which may be one of the following:
 *
 * - **DC_IMEX_EXPORT_BACKUP** (11) - Export a backup to the directory given as `param1`
 *   encrypted with the passphrase given as `param2`. If `param2` is NULL or empty string,
 *   the backup is not encrypted.
 *   The backup contains all contacts, chats, images and other data and device independent settings.
 *   The backup does not contain device dependent settings as ringtones or LED notification settings.
 *   The name of the backup is `delta-chat-backup-<day>-<number>-<addr>.tar`.
 *
 * - **DC_IMEX_IMPORT_BACKUP** (12) - `param1` is the file (not: directory) to import. `param2` is the passphrase.
 *   The file is normally created by DC_IMEX_EXPORT_BACKUP and detected by dc_imex_has_backup(). Importing a backup
 *   is only possible as long as the context is not configured or used in another way.
 *
 * - **DC_IMEX_EXPORT_SELF_KEYS** (1) - Export all private keys and all public keys of the user to the
 *   directory given as `param1`. The default key is written to the files `public-key-default.asc`
 *   and `private-key-default.asc`, if there are more keys, they are written to files as
 *   `public-key-<id>.asc` and `private-key-<id>.asc`
 *
 * - **DC_IMEX_IMPORT_SELF_KEYS** (2) - Import private keys found in the directory given as `param1`.
 *   The last imported key is made the default keys unless its name contains the string `legacy`. Public keys are not imported.
 *   If `param1` is a filename, import the private key from the file and make it the default.
 *
 * While dc_imex() returns immediately, the started job may take a while,
 * you can stop it using dc_stop_ongoing_process(). During execution of the job,
 * some events are sent out:
 *
 * - A number of #DC_EVENT_IMEX_PROGRESS events are sent and may be used to create
 *   a progress bar or stuff like that. Moreover, you will be informed when the imex-job is done.
 *
 * - For each file written on export, the function sends #DC_EVENT_IMEX_FILE_WRITTEN
 *
 * Only one import-/export-progress can run at the same time.
 * To cancel an import-/export-progress, use dc_stop_ongoing_process().
 *
 * @memberof dc_context_t
 * @param context The context.
 * @param what One of the DC_IMEX_* constants.
 * @param param1 Meaning depends on the DC_IMEX_* constants. If this parameter is a directory, it should not end with
 *     a slash (otherwise you will get double slashes when receiving #DC_EVENT_IMEX_FILE_WRITTEN). Set to NULL if not used.
 * @param param2 Meaning depends on the DC_IMEX_* constants. Set to NULL if not used.
 */
void            dc_imex                      (dc_context_t* context, int what, const char* param1, const char* param2);


/**
 * Check if there is a backup file.
 * May only be used on fresh installations (e.g. dc_is_configured() returns 0).
 *
 * Example:
 *
 * ~~~
 * char dir[] = "/dir/to/search/backups/in";
 *
 * void ask_user_for_credentials()
 * {
 *     // - ask the user for e-mail and password
 *     // - save them using dc_set_config()
 * }
 *
 * int ask_user_whether_to_import()
 * {
 *     // - inform the user that we've found a backup
 *     // - ask if he want to import it
 *     // - return 1 to import, 0 to skip
 *     return 1;
 * }
 *
 * if (!dc_is_configured(context))
 * {
 *     char* file = NULL;
 *     if ((file=dc_imex_has_backup(context, dir))!=NULL && ask_user_whether_to_import())
 *     {
 *         dc_imex(context, DC_IMEX_IMPORT_BACKUP, file, NULL);
 *         // connect
 *     }
 *     else
 *     {
 *         do {
 *             ask_user_for_credentials();
 *         }
 *         while (!configure_succeeded())
 *     }
 *     dc_str_unref(file);
 * }
 * ~~~
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param dir The directory to search backups in.
 * @return String with the backup file, typically given to dc_imex(),
 *     returned strings must be released using dc_str_unref().
 *     The function returns NULL if no backup was found.
 */
char*           dc_imex_has_backup           (dc_context_t* context, const char* dir);


/**
 * Initiate Autocrypt Setup Transfer.
 * Before starting the setup transfer with this function, the user should be asked:
 *
 * ~~~
 * "An 'Autocrypt Setup Message' securely shares your end-to-end setup with other Autocrypt-compliant apps.
 * The setup will be encrypted by a setup code which is displayed here and must be typed on the other device.
 * ~~~
 *
 * After that, this function should be called to send the Autocrypt Setup Message.
 * The function creates the setup message and adds it to outgoing message queue.
 * The message is sent asynchronously.
 *
 * The required setup code is returned in the following format:
 *
 * ~~~
 * 1234-1234-1234-1234-1234-1234-1234-1234-1234
 * ~~~
 *
 * The setup code should be shown to the user then:
 *
 * ~~~
 * "Your key has been sent to yourself. Switch to the other device and
 * open the setup message. You should be prompted for a setup code. Type
 * the following digits into the prompt:
 *
 * 1234 - 1234 - 1234 -
 * 1234 - 1234 - 1234 -
 * 1234 - 1234 - 1234
 *
 * Once you're done, your other device will be ready to use Autocrypt."
 * ~~~
 *
 * On the _other device_ you will call dc_continue_key_transfer() then
 * for setup messages identified by dc_msg_is_setupmessage().
 *
 * For more details about the Autocrypt setup process, please refer to
 * https://autocrypt.org/en/latest/level1.html#autocrypt-setup-message
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return The setup code. Must be released using dc_str_unref() after usage.
 *     On errors, e.g. if the message could not be sent, NULL is returned.
 */
char*           dc_initiate_key_transfer     (dc_context_t* context);


/**
 * Continue the Autocrypt Key Transfer on another device.
 *
 * If you have started the key transfer on another device using dc_initiate_key_transfer()
 * and you've detected a setup message with dc_msg_is_setupmessage(), you should prompt the
 * user for the setup code and call this function then.
 *
 * You can use dc_msg_get_setupcodebegin() to give the user a hint about the code (useful if the user
 * has created several messages and should not enter the wrong code).
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param msg_id The ID of the setup message to decrypt.
 * @param setup_code The setup code entered by the user. This is the same setup code as returned from
 *     dc_initiate_key_transfer() on the other device.
 *     There is no need to format the string correctly, the function will remove all spaces and other characters and
 *     insert the `-` characters at the correct places.
 * @return 1=key successfully decrypted and imported; both devices will use the same key now;
 *     0=key transfer failed e.g. due to a bad setup code.
 */
int             dc_continue_key_transfer     (dc_context_t* context, uint32_t msg_id, const char* setup_code);


/**
 * Signal an ongoing process to stop.
 *
 * After that, dc_stop_ongoing_process() returns _without_ waiting
 * for the ongoing process to return.
 *
 * The ongoing process will return ASAP then, however, it may
 * still take a moment.
 *
 * Typical ongoing processes are started by dc_configure()
 * or dc_imex(). As there is always at most only
 * one onging process at the same time, there is no need to define _which_ process to exit.
 *
 * @memberof dc_context_t
 * @param context The context object.
 */
void            dc_stop_ongoing_process      (dc_context_t* context);


// out-of-band verification

#define         DC_QR_ASK_VERIFYCONTACT      200 // id=contact
#define         DC_QR_ASK_VERIFYGROUP        202 // text1=groupname
#define         DC_QR_ASK_VERIFYBROADCAST    204 // text1=broadcast name
#define         DC_QR_FPR_OK                 210 // id=contact
#define         DC_QR_FPR_MISMATCH           220 // id=contact
#define         DC_QR_FPR_WITHOUT_ADDR       230 // test1=formatted fingerprint
#define         DC_QR_ACCOUNT                250 // text1=domain
#define         DC_QR_BACKUP2                252
#define         DC_QR_BACKUP_TOO_NEW         255
#define         DC_QR_PROXY                  271 // text1=address (e.g. "127.0.0.1:9050")
#define         DC_QR_ADDR                   320 // id=contact
#define         DC_QR_TEXT                   330 // text1=text
#define         DC_QR_URL                    332 // text1=URL
#define         DC_QR_ERROR                  400 // text1=error string
#define         DC_QR_WITHDRAW_VERIFYCONTACT 500
#define         DC_QR_WITHDRAW_VERIFYGROUP   502 // text1=groupname
#define         DC_QR_WITHDRAW_JOINBROADCAST 504 // text1=broadcast name
#define         DC_QR_REVIVE_VERIFYCONTACT   510
#define         DC_QR_REVIVE_VERIFYGROUP     512 // text1=groupname
#define         DC_QR_REVIVE_JOINBROADCAST   514 // text1=broadcast name
#define         DC_QR_LOGIN                  520 // text1=email_address

/**
 * Check a scanned QR code.
 * The function takes the raw text scanned and checks what can be done with it.
 *
 * The UI is supposed to show the result to the user.
 * In case there are further actions possible,
 * the UI has to ask the user before doing further steps.
 *
 * The QR code state is returned in dc_lot_t::state as:
 *
 * - DC_QR_ASK_VERIFYCONTACT with dc_lot_t::id=Contact ID:
 *   ask whether to verify the contact;
 *   if so, start the protocol with dc_join_securejoin().
 *
 * - DC_QR_ASK_VERIFYGROUP or DC_QR_ASK_VERIFYBROADCAST
 *   with dc_lot_t::text1=Group name:
 *   ask whether to join the chat;
 *   if so, start the protocol with dc_join_securejoin().
 *
 * - DC_QR_FPR_OK with dc_lot_t::id=Contact ID:
 *   contact fingerprint verified,
 *   ask the user if they want to start chatting;
 *   if so, call dc_create_chat_by_contact_id().
 *
 * - DC_QR_FPR_MISMATCH with dc_lot_t::id=Contact ID:
 *   scanned fingerprint does not match last seen fingerprint.
 *
 * - DC_QR_FPR_WITHOUT_ADDR with dc_lot_t::text1=Formatted fingerprint
 *   the scanned QR code contains a fingerprint but no e-mail address;
 *   suggest the user to establish an encrypted connection first.
 *
 * - DC_QR_ACCOUNT dc_lot_t::text1=domain:
 *   ask the user if they want to create an account on the given domain,
 *   if so, call dc_set_config_from_qr() and then dc_configure().
 *
 * - DC_QR_BACKUP2:
 *   ask the user if they want to set up a new device.
 *   If so, pass the qr-code to dc_receive_backup().
 *
 * - DC_QR_BACKUP_TOO_NEW:
 *   show a hint to the user that this backup comes from a newer Delta Chat version
 *   and this device needs an update
 *
 * - DC_QR_PROXY with dc_lot_t::text1=address:
 *   ask the user if they want to use the given proxy.
 *   if so, call dc_set_config_from_qr() and restart I/O.
 *   On success, dc_get_config(context, "proxy_url")
 *   will contain the new proxy in normalized form as the first element.
 *
 * - DC_QR_ADDR with dc_lot_t::id=Contact ID:
 *   e-mail address scanned, optionally, a draft message could be set in
 *   dc_lot_t::text1 in which case dc_lot_t::text1_meaning will be DC_TEXT1_DRAFT;
 *   ask the user if they want to start chatting;
 *   if so, call dc_create_chat_by_contact_id().
 *
 * - DC_QR_TEXT with dc_lot_t::text1=Text:
 *   Text scanned,
 *   ask the user e.g. if they want copy to clipboard.
 *
 * - DC_QR_URL with dc_lot_t::text1=URL:
 *   URL scanned,
 *   ask the user e.g. if they want to open a browser or copy to clipboard.
 *
 * - DC_QR_ERROR with dc_lot_t::text1=Error string:
 *   show the error to the user.
 *
 * - DC_QR_WITHDRAW_VERIFYCONTACT:
 *   ask the user if they want to withdraw the their own qr-code;
 *   if so, call dc_set_config_from_qr().
 *
 * - DC_QR_WITHDRAW_VERIFYGROUP with text1=groupname:
 *   ask the user if they want to withdraw the group-invite code;
 *   if so, call dc_set_config_from_qr().
 *
 * - DC_QR_REVIVE_VERIFYCONTACT:
 *   ask the user if they want to revive their withdrawn qr-code;
 *   if so, call dc_set_config_from_qr().
 *
 * - DC_QR_REVIVE_VERIFYGROUP with text1=groupname:
 *   ask the user if they want to revive the withdrawn group-invite code;
 *   if so, call dc_set_config_from_qr().
 *
 * - DC_QR_LOGIN with dc_lot_t::text1=email_address:
 *   ask the user if they want to login with the email_address,
 *   if so, call dc_set_config_from_qr() and then dc_configure().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param qr The text of the scanned QR code.
 * @return The parsed QR code as an dc_lot_t object. The returned object must be
 *     freed using dc_lot_unref() after usage.
 */
dc_lot_t*       dc_check_qr                  (dc_context_t* context, const char* qr);


/**
 * Get QR code text that will offer an Setup-Contact or Verified-Group invitation.
 *
 * The scanning device will pass the scanned content to dc_check_qr() then;
 * if dc_check_qr() returns
 * DC_QR_ASK_VERIFYCONTACT, DC_QR_ASK_VERIFYGROUP or DC_QR_ASK_VERIFYBROADCAST
 * an out-of-band-verification can be joined using dc_join_securejoin()
 *
 * The returned text will also work as a normal https:-link,
 * so that the QR code is useful also without Delta Chat being installed
 * or can be passed to contacts through other channels.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id If set to a group-chat-id,
 *     the Verified-Group-Invite protocol is offered in the QR code;
 *     works for protected groups as well as for normal groups.
 *     If set to 0, the Setup-Contact protocol is offered in the QR code.
 *     See https://securejoin.delta.chat/
 *     for details about both protocols.
 * @return The text that should go to the QR code,
 *     On errors, an empty QR code is returned, NULL is never returned.
 *     The returned string must be released using dc_str_unref() after usage.
 */
char*           dc_get_securejoin_qr         (dc_context_t* context, uint32_t chat_id);


/**
 * Get QR code image from the QR code text generated by dc_get_securejoin_qr().
 * See dc_get_securejoin_qr() for details about the contained QR code.
 *
 * @deprecated 2024-10 use dc_create_qr_svg(dc_get_securejoin_qr()) instead.
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id group-chat-id for secure-join or 0 for setup-contact,
 *     see dc_get_securejoin_qr() for details.
 * @return SVG-Image with the QR code.
 *     On errors, an empty string is returned.
 *     The returned string must be released using dc_str_unref() after usage.
 */
char*           dc_get_securejoin_qr_svg         (dc_context_t* context, uint32_t chat_id);

/**
 * Continue a Setup-Contact or Verified-Group-Invite protocol
 * started on another device with dc_get_securejoin_qr().
 * This function is typically called when dc_check_qr() returns
 * lot.state=DC_QR_ASK_VERIFYCONTACT, lot.state=DC_QR_ASK_VERIFYGROUP or lot.state=DC_QR_ASK_VERIFYBROADCAST
 *
 * The function returns immediately and the handshake runs in background,
 * sending and receiving several messages.
 * During the handshake, info messages are added to the chat,
 * showing progress, success or errors.
 *
 * Subsequent calls of dc_join_securejoin() will abort previous, unfinished handshakes.
 *
 * See https://securejoin.delta.chat/ for details about both protocols.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param qr The text of the scanned QR code. Typically, the same string as given
 *     to dc_check_qr().
 * @return The chat ID of the joined chat, the UI may redirect to the this chat.
 *     On errors, 0 is returned, however, most errors will happen during handshake later on.
 *     A returned chat ID does not guarantee that the chat is protected or the belonging contact is verified.
 */
uint32_t        dc_join_securejoin           (dc_context_t* context, const char* qr);


// location streaming


/**
 * Enable or disable location streaming for a chat.
 * Locations are sent to all members of the chat for the given number of seconds;
 * after that, location streaming is automatically disabled for the chat.
 * The current location streaming state of a chat
 * can be checked using dc_is_sending_locations_to_chat().
 *
 * The locations that should be sent to the chat can be set using
 * dc_set_location().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to enable location streaming for.
 * @param seconds >0: enable location streaming for the given number of seconds;
 *     0: disable location streaming.
 */
void        dc_send_locations_to_chat       (dc_context_t* context, uint32_t chat_id, int seconds);


/**
 * Check if location streaming is enabled.
 * Location stream can be enabled or disabled using dc_send_locations_to_chat().
 * If you have already a dc_chat_t object,
 * dc_chat_is_sending_locations() may be more handy.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id >0: Check if location streaming is enabled for the given chat.
 *     0: Check of location streaming is enabled for any chat.
 * @return 1: location streaming is enabled for the given chat(s);
 *     0: location streaming is disabled for the given chat(s).
 */
int         dc_is_sending_locations_to_chat (dc_context_t* context, uint32_t chat_id);


/**
 * Set current location.
 * The location is sent to all chats where location streaming is enabled
 * using dc_send_locations_to_chat().
 *
 * Typically results in the event #DC_EVENT_LOCATION_CHANGED with
 * contact_id set to DC_CONTACT_ID_SELF.
 *
 * The UI should call this function on all location changes.
 * The locations set by this function are not sent immediately,
 * instead a message with the last locations is sent out every some minutes
 * or when the user sends out a normal message,
 * the last locations are attached.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param latitude A north-south position of the location.
 *     Set to 0.0 if the latitude is not known.
 * @param longitude East-west position of the location.
 *     Set to 0.0 if the longitude is not known.
 * @param accuracy Estimated accuracy of the location, radial, in meters.
 *     Set to 0.0 if the accuracy is not known.
 * @return 1: location streaming is still enabled for at least one chat,
 *     this dc_set_location() should be called as soon as the location changes;
 *     0: location streaming is no longer needed,
 *     dc_is_sending_locations_to_chat() is false for all chats.
 */
int         dc_set_location                 (dc_context_t* context, double latitude, double longitude, double accuracy);


/**
 * Get shared locations from the database.
 * The locations can be filtered by the chat ID, the contact ID,
 * and by a timespan.
 *
 * The number of returned locations can be retrieved using dc_array_get_cnt().
 * To get information for each location,
 * use dc_array_get_latitude(), dc_array_get_longitude(),
 * dc_array_get_accuracy(), dc_array_get_timestamp(), dc_array_get_contact_id()
 * and dc_array_get_msg_id().
 * The latter returns 0 if there is no message bound to the location.
 *
 * Note that only if dc_array_is_independent() returns 0,
 * the location is the current or a past position of the user.
 * If dc_array_is_independent() returns 1,
 * the location is any location on earth that is marked by the user.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to get location information for.
 *     0 to get locations independently of the chat.
 * @param contact_id The contact ID to get location information for.
 *     If also a chat ID is given, this should be a member of the given chat.
 *     0 to get locations independently of the contact.
 * @param timestamp_begin The start of timespan to return.
 *     Must be given in number of seconds since 00:00 hours, Jan 1, 1970 UTC.
 *     0 for "start from the beginning".
 * @param timestamp_end The end of timespan to return.
 *     Must be given in number of seconds since 00:00 hours, Jan 1, 1970 UTC.
 *     0 for "all up to now".
 * @return An array of locations, NULL is never returned.
 *     The array is sorted descending;
 *     the first entry in the array is the location with the newest timestamp.
 *     Note that this is only related to the recent position of the user
 *     if dc_array_is_independent() returns 0.
 *     The returned array must be freed using dc_array_unref().
 *
 * Examples:
 * ~~~
 * // get locations from the last hour for a global map
 * dc_array_t* loc = dc_get_locations(context, 0, 0, time(NULL)-60*60, 0);
 * for (int i=0; i<dc_array_get_cnt(); i++) {
 *     double lat = dc_array_get_latitude(loc, i);
 *     ...
 * }
 * dc_array_unref(loc);
 *
 * // get locations from a contact for a global map
 * dc_array_t* loc = dc_get_locations(context, 0, contact_id, 0, 0);
 * ...
 *
 * // get all locations known for a given chat
 * dc_array_t* loc = dc_get_locations(context, chat_id, 0, 0, 0);
 * ...
 *
 * // get locations from a single contact for a given chat
 * dc_array_t* loc = dc_get_locations(context, chat_id, contact_id, 0, 0);
 * ...
 * ~~~
 */
dc_array_t* dc_get_locations                (dc_context_t* context, uint32_t chat_id, uint32_t contact_id, int64_t timestamp_begin, int64_t timestamp_end);


/**
 * Delete all locations on the current device.
 * Locations already sent cannot be deleted.
 *
 * Typically results in the event #DC_EVENT_LOCATION_CHANGED
 * with contact_id set to 0.
 *
 * @memberof dc_context_t
 * @param context The context object.
 */
void        dc_delete_all_locations         (dc_context_t* context);


// misc

/**
 * Create a QR code from any input data.
 *
 * The QR code is returned as a square SVG image.
 *
 * @memberof dc_context_t
 * @param payload The content for the QR code.
 * @return SVG image with the QR code.
 *     On errors, an empty string is returned.
 *     The returned string must be released using dc_str_unref() after usage.
 */
char*           dc_create_qr_svg             (const char* payload);


/**
 * Get last error string.
 *
 * This is the same error string as logged via #DC_EVENT_ERROR,
 * however, using this function avoids race conditions
 * if the failing function is called in another thread than dc_get_next_event().
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @return Last error or an empty string if there is no last error.
 *     NULL is never returned.
 *     The returned value must be released using dc_str_unref() after usage.
 */
char* dc_get_last_error (dc_context_t* context);


/**
 * Release a string returned by another deltachat-core function.
 * - Strings returned by any deltachat-core-function
 *   MUST NOT be released by the standard free() function;
 *   always use dc_str_unref() for this purpose.
 * - dc_str_unref() MUST NOT be called for strings not returned by deltachat-core.
 * - dc_str_unref() MUST NOT be called for other objects returned by deltachat-core.
 *
 * @memberof dc_context_t
 * @param str The string to release.
 *     If NULL is given, nothing is done.
 */
void dc_str_unref (char* str);


/**
 * @class dc_backup_provider_t
 *
 * Set up another device.
 */

/**
 * Creates an object for sending a backup to another device.
 *
 * The backup is sent to through a peer-to-peer channel which is bootstrapped
 * by a QR-code.  The backup contains the entire state of the account
 * including credentials.  This can be used to setup a new device.
 *
 * This is a blocking call as some preparations are made like e.g. exporting
 * the database.  Once this function returns, the backup is being offered to
 * remote devices.  To wait until one device received the backup, use
 * dc_backup_provider_wait().  Alternatively abort the operation using
 * dc_stop_ongoing_process().
 *
 * During execution of the job #DC_EVENT_IMEX_PROGRESS is sent out to indicate
 * state and progress.
 *
 * @memberof dc_backup_provider_t
 * @param context The context.
 * @return Opaque object for sending the backup.
 *    On errors, NULL is returned and dc_get_last_error() returns an error that
 *    should be shown to the user.
 */
dc_backup_provider_t* dc_backup_provider_new (dc_context_t* context);


/**
 * Returns the QR code text that will offer the backup to other devices.
 *
 * The QR code contains a ticket which will validate the backup and provide
 * authentication for both the provider and the recipient.
 *
 * The scanning device should call the scanned text to dc_check_qr().  If
 * dc_check_qr() returns DC_QR_BACKUP, the backup transfer can be started using
 * dc_get_backup().
 *
 * @memberof dc_backup_provider_t
 * @param backup_provider The backup provider object as created by
 *    dc_backup_provider_new().
 * @return The text that should be put in the QR code.
 *    On errors an empty string is returned, NULL is never returned.
 *    the returned string must be released using dc_str_unref() after usage.
 */
char* dc_backup_provider_get_qr (const dc_backup_provider_t* backup_provider);


/**
 * Returns the QR code SVG image that will offer the backup to other devices.
 *
 * This works like dc_backup_provider_qr() but returns the text of a rendered
 * SVG image containing the QR code.
 *
 * @deprecated 2024-10 use dc_create_qr_svg(dc_backup_provider_get_qr()) instead.
 * @memberof dc_backup_provider_t
 * @param backup_provider The backup provider object as created by
 *    dc_backup_provider_new().
 * @return The QR code rendered as SVG.
 *    On errors an empty string is returned, NULL is never returned.
 *    the returned string must be released using dc_str_unref() after usage.
 */
char* dc_backup_provider_get_qr_svg (const dc_backup_provider_t* backup_provider);

/**
 * Waits for the sending to finish.
 *
 * This is a blocking call and should only be called once.
 *
 * @memberof dc_backup_provider_t
 * @param backup_provider The backup provider object as created by
 *    dc_backup_provider_new().  If NULL is given nothing is done.
 */
void dc_backup_provider_wait (dc_backup_provider_t* backup_provider);

/**
 * Frees a dc_backup_provider_t object.
 *
 * If the provider has not yet finished, as indicated by
 * dc_backup_provider_wait() or the #DC_EVENT_IMEX_PROGRESS event with value
 * of 0 (failed) or 1000 (succeeded), this will also abort any in-progress
 * transfer.  If this aborts the provider a #DC_EVENT_IMEX_PROGRESS event with
 * value 0 (failed) will be emitted.
 *
 * @memberof dc_backup_provider_t
 * @param backup_provider The backup provider object as created by
 *    dc_backup_provider_new().
 */
void dc_backup_provider_unref (dc_backup_provider_t* backup_provider);

/**
 * Gets a backup offered by a dc_backup_provider_t object on another device.
 *
 * This function is called on a device that scanned the QR code offered by
 * dc_backup_provider_get_qr().  Typically this is a
 * different device than that which provides the backup.
 *
 * This call will block while the backup is being transferred and only
 * complete on success or failure.  Use dc_stop_ongoing_process() to abort it
 * early.
 *
 * During execution of the job #DC_EVENT_IMEX_PROGRESS is sent out to indicate
 * state and progress.  The process is finished when the event emits either 0
 * or 1000, 0 means it failed and 1000 means it succeeded.  These events are
 * for showing progress and informational only, success and failure is also
 * shown in the return code of this function.
 *
 * @memberof dc_context_t
 * @param context The context.
 * @param qr The qr code text, dc_check_qr() must have returned DC_QR_BACKUP
 *    on this text.
 * @return 0=failure, 1=success.
 */
int dc_receive_backup (dc_context_t* context, const char* qr);

/**
 * @class dc_accounts_t
 *
 * This class provides functionality that can be used to
 * manage several dc_context_t objects running at the same time.
 * The account manager takes a directory where all
 * context-databases are created in.
 *
 * You can add, remove, import account to the account manager,
 * all context-databases are persisted and stay available once the
 * account manager is created again for the same directory.
 *
 * All accounts may receive messages at the same time (e.g. by #DC_EVENT_INCOMING_MSG),
 * and all accounts may be accessed by their own dc_context_t object.
 *
 * To make this possible, some dc_context_t functions must not be called
 * when using the account manager:
 * - use dc_accounts_add_account() and dc_accounts_get_account() instead of dc_context_new()
 * - use dc_accounts_add_closed_account() instead of dc_context_new_closed()
 * - use dc_accounts_start_io() and dc_accounts_stop_io() instead of dc_start_io() and dc_stop_io()
 * - use dc_accounts_maybe_network() instead of dc_maybe_network()
 * - use dc_accounts_get_event_emitter() instead of dc_get_event_emitter()
 *
 * Additionally, there are functions to list, import and migrate accounts
 * and to handle a "selected" account, see below.
 */

/**
 * Create a new account manager.
 * The account manager takes a directory
 * where all context-databases are placed in.
 * To add a context to the account manager,
 * use dc_accounts_add_account() or dc_accounts_migrate_account().
 * All account information are persisted.
 * To remove a context from the account manager,
 * use dc_accounts_remove_account().
 *
 * @memberof dc_accounts_t
 * @param dir The directory to create the context-databases in.
 *     If the directory does not exist,
 *     dc_accounts_new() will try to create it.
 * @param writable Whether the returned account manager is writable, i.e. calling these functions on
 *     it is possible: dc_accounts_add_account(), dc_accounts_add_closed_account(),
 *     dc_accounts_migrate_account(), dc_accounts_remove_account(), dc_accounts_select_account().
 * @return An account manager object.
 *     The object must be passed to the other account manager functions
 *     and must be freed using dc_accounts_unref() after usage.
 *     On errors, NULL is returned.
 */
dc_accounts_t* dc_accounts_new                  (const char* dir, int writable);

/**
 * Create a new account manager with an existing events channel,
 * which allows you to see events emitted during startup.
 * 
 * The account manager takes a directory
 * where all context-databases are placed in.
 * To add a context to the account manager,
 * use dc_accounts_add_account() or dc_accounts_migrate_account().
 * All account information are persisted.
 * To remove a context from the account manager,
 * use dc_accounts_remove_account().
 *
 * @memberof dc_accounts_t
 * @param dir The directory to create the context-databases in.
 *     If the directory does not exist,
 *     dc_accounts_new_with_event_channel() will try to create it.
 * @param writable Whether the returned account manager is writable, i.e. calling these functions on
 *     it is possible: dc_accounts_add_account(), dc_accounts_add_closed_account(),
 *     dc_accounts_migrate_account(), dc_accounts_remove_account(), dc_accounts_select_account().
 * @param dc_event_channel_t Events Channel to be used for this accounts manager, 
 *      create one with dc_event_channel_new().
 *      This channel is consumed by this method and can not be used again afterwards,
 *      so be sure to call `dc_event_channel_get_event_emitter` before.
 * @return An account manager object.
 *     The object must be passed to the other account manager functions
 *     and must be freed using dc_accounts_unref() after usage.
 *     On errors, NULL is returned.
 */
dc_accounts_t* dc_accounts_new_with_event_channel(const char* dir, int writable, dc_event_channel_t* events_channel);

/**
 * Free an account manager object.
 *
 * @memberof dc_accounts_t
 * @param accounts Account manager as created by dc_accounts_new().
 */
void           dc_accounts_unref                (dc_accounts_t* accounts);


/**
 * Add a new account to the account manager.
 * Internally, dc_context_new() is called using a unique database name
 * in the directory specified at dc_accounts_new().
 *
 * If the function succeeds,
 * dc_accounts_get_all() will return one more account
 * and you can access the newly created account using dc_accounts_get_account().
 * Moreover, the newly created account will be the selected one.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @return The account ID, use dc_accounts_get_account() to get the context object.
 *     On errors, 0 is returned.
 */
uint32_t       dc_accounts_add_account          (dc_accounts_t* accounts);

/**
 * Add a new closed account to the account manager.
 * Internally, dc_context_new_closed() is called using a unique database-name
 * in the directory specified at dc_accounts_new().
 *
 * If the function succeeds,
 * dc_accounts_get_all() will return one more account
 * and you can access the newly created account using dc_accounts_get_account().
 * Moreover, the newly created account will be the selected one.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @return The account ID, use dc_accounts_get_account() to get the context object.
 *     On errors, 0 is returned.
 */
uint32_t       dc_accounts_add_closed_account   (dc_accounts_t* accounts);

/**
 * Migrate independent accounts into accounts managed by the account manager.
 * This will _move_ the database-file and all blob files to the directory managed
 * by the account manager.
 * (To save disk space on small devices, the files are not _copied_.
 * Once the migration is done, the original file is no longer existent.)
 * Moreover, the newly created account will be the selected one.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @param dbfile The unmanaged database file that was created at some point using dc_context_new().
 * @return The account ID, use dc_accounts_get_account() to get the context object.
 *     On errors, 0 is returned.
 */
uint32_t       dc_accounts_migrate_account      (dc_accounts_t* accounts, const char* dbfile);


/**
 * Remove an account from the account manager.
 * This also removes the database-file and all blobs physically.
 * If the removed account is the selected account,
 * one of the other accounts will be selected.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @param account_id The account ID as returned e.g. by dc_accounts_add_account().
 * @return 1=success, 0=error
 */
int            dc_accounts_remove_account       (dc_accounts_t* accounts, uint32_t account_id);


/**
 * List all accounts.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @return An array containing all account IDs,
 *     use dc_array_get_id() to get the IDs.
 */
dc_array_t*    dc_accounts_get_all              (dc_accounts_t* accounts);


/**
 * Get an account context from an account ID.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @param account_id The account ID as returned e.g. by dc_accounts_get_all() or dc_accounts_add_account().
 * @return The account context, this can be used most similar as a normal,
 *     unmanaged account context as created by dc_context_new().
 *     Once you do no longer need the context-object, you have to call dc_context_unref() on it,
 *     which, however, will not close the account but only decrease a reference counter.
 */
dc_context_t*  dc_accounts_get_account          (dc_accounts_t* accounts, uint32_t account_id);


/**
 * Get the currently selected account.
 * If there is at least one account in the account manager,
 * there is always a selected one.
 * To change the selected account, use dc_accounts_select_account();
 * also adding/importing/migrating accounts may change the selection.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @return The account context, this can be used most similar as a normal,
 *     unmanaged account context as created by dc_context_new().
 *     Once you do no longer need the context-object, you have to call dc_context_unref() on it,
 *     which, however, will not close the account but only decrease a reference counter.
 *     If there is no selected account, NULL is returned.
 */
dc_context_t*  dc_accounts_get_selected_account (dc_accounts_t* accounts);


/**
 * Change the selected account.
 *
 * @memberof dc_accounts_t
 * @param accounts Account manager as created by dc_accounts_new().
 * @param account_id The account ID as returned e.g. by dc_accounts_get_all() or dc_accounts_add_account().
 * @return 1=success, 0=error
 */
int            dc_accounts_select_account       (dc_accounts_t* accounts, uint32_t account_id);


/**
 * Start job and IMAP/SMTP tasks for all accounts managed by the account manager.
 * If IO is already running, nothing happens.
 * This is similar to dc_start_io(), which, however,
 * must not be called for accounts handled by the account manager.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 */
void           dc_accounts_start_io             (dc_accounts_t* accounts);


/**
 * Stop job and IMAP/SMTP tasks for all accounts and return when they are finished.
 * This is similar to dc_stop_io(), which, however,
 * must not be called for accounts handled by the account manager.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 */
void           dc_accounts_stop_io              (dc_accounts_t* accounts);


/**
 * This function should be called when there is a hint
 * that the network is available again.
 * This is similar to dc_maybe_network(), which, however,
 * must not be called for accounts handled by the account manager.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 */
void           dc_accounts_maybe_network        (dc_accounts_t* accounts);


/**
 * This function can be called when there is a hint that the network is lost.
 * This is similar to dc_accounts_maybe_network(), however,
 * it does not retry job processing.
 *
 * dc_accounts_maybe_network_lost() is needed only on systems
 * where the core cannot find out the connectivity loss on its own, e.g. iOS.
 * The function is not needed on Android, MacOS, Windows or Linux.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 */
void           dc_accounts_maybe_network_lost    (dc_accounts_t* accounts);


/**
 * Perform a background fetch for all accounts in parallel with a timeout.
 * Pauses the scheduler, fetches messages from imap and then resumes the scheduler.
 *
 * dc_accounts_background_fetch() was created for the iOS Background fetch.
 *
 * The `DC_EVENT_ACCOUNTS_BACKGROUND_FETCH_DONE` event is emitted at the end
 * even in case of timeout, unless the function fails and returns 0.
 * Process all events until you get this one and you can safely return to the background
 * without forgetting to create notifications caused by timing race conditions.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @param timeout The timeout in seconds
 * @return Return 1 if DC_EVENT_ACCOUNTS_BACKGROUND_FETCH_DONE was emitted and 0 otherwise.
 */
int            dc_accounts_background_fetch    (dc_accounts_t* accounts, uint64_t timeout);


/**
 * Stop ongoing background fetch.
 *
 * Calling this function allows to stop dc_accounts_background_fetch() early.
 * dc_accounts_background_fetch() will then return immediately
 * and emit DC_EVENT_ACCOUNTS_BACKGROUND_FETCH_DONE unless
 * if it has failed and returned 0.
 *
 * If there is no ongoing dc_accounts_background_fetch() call,
 * calling this function does nothing.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 */
void           dc_accounts_stop_background_fetch (dc_accounts_t *accounts);


/**
 * Sets device token for Apple Push Notification service.
 * Returns immediately.
 *
 * @memberof dc_accounts_t
 * @param token Hexadecimal device token
 */
void           dc_accounts_set_push_device_token (dc_accounts_t* accounts, const char *token);

/**
 * Create the event emitter that is used to receive events.
 *
 * The library will emit various @ref DC_EVENT events as "new message", "message read" etc.
 * To get these events, you have to create an event emitter using this function
 * and call dc_get_next_event() on the emitter.
 *
 * This is similar to dc_get_event_emitter(), which, however,
 * must not be called for accounts handled by the account manager.
 *
 * @memberof dc_accounts_t
 * @param accounts The account manager as created by dc_accounts_new().
 * @return Returns the event emitter, NULL on errors.
 *     Must be freed using dc_event_emitter_unref() after usage.
 *
 * Note: Use only one event emitter per account manager.
 * The result of having multiple event emitters is unspecified.
 * Currently events are broadcasted to all existing event emitters,
 * but previous versions delivered events to only one event emitter
 * and this behavior may change again in the future.
 * Events emitted before creation of event emitter
 * are not available to event emitter.
 */
dc_event_emitter_t* dc_accounts_get_event_emitter (dc_accounts_t* accounts);


/**
 * @class dc_array_t
 *
 * An object containing a simple array.
 * This object is used in several places where functions need to return an array.
 * The items of the array are typically IDs.
 * To free an array object, use dc_array_unref().
 */


/**
 * Free an array object. Does not free any data items.
 *
 * @memberof dc_array_t
 * @param array The array object to free,
 *     created e.g. by dc_get_chatlist(), dc_get_contacts() and so on.
 *     If NULL is given, nothing is done.
 */
void             dc_array_unref              (dc_array_t* array);


/**
 * Find out the number of items in an array.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @return Returns the number of items in a dc_array_t object. 0 on errors or if the array is empty.
 */
size_t           dc_array_get_cnt            (const dc_array_t* array);


/**
 * Get the item at the given index as an ID.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item to get. Must be between 0 and dc_array_get_cnt()-1.
 * @return Returns the item at the given index. Returns 0 on errors or if the array is empty.
 */
uint32_t         dc_array_get_id             (const dc_array_t* array, size_t index);


/**
 * Return the latitude of the item at the given index.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return Latitude of the item at the given index.
 *     0.0 if there is no latitude bound to the given item,
 */
double           dc_array_get_latitude       (const dc_array_t* array, size_t index);


/**
 * Return the longitude of the item at the given index.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return Latitude of the item at the given index.
 *     0.0 if there is no longitude bound to the given item,
 */
double           dc_array_get_longitude      (const dc_array_t* array, size_t index);


/**
 * Return the accuracy of the item at the given index.
 * See dc_set_location() for more information about the accuracy.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return Accuracy of the item at the given index.
 *     0.0 if there is no longitude bound to the given item,
 */
double           dc_array_get_accuracy       (const dc_array_t* array, size_t index);


/**
 * Return the timestamp of the item at the given index.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return Timestamp of the item at the given index.
 *     0 if there is no timestamp bound to the given item,
 */
int64_t           dc_array_get_timestamp      (const dc_array_t* array, size_t index);


/**
 * Return the chat ID of the item at the given index.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return The chat ID of the item at the given index.
 *     0 if there is no chat ID bound to the given item,
 */
uint32_t         dc_array_get_chat_id        (const dc_array_t* array, size_t index);


/**
 * Return the contact ID of the item at the given index.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return The contact ID of the item at the given index.
 *     0 if there is no contact ID bound to the given item,
 */
uint32_t         dc_array_get_contact_id     (const dc_array_t* array, size_t index);


/**
 * Return the message ID of the item at the given index.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return The message ID of the item at the given index.
 *     0 if there is no message ID bound to the given item.
 */
uint32_t         dc_array_get_msg_id         (const dc_array_t* array, size_t index);


/**
 * Return the marker-character of the item at the given index.
 * Marker-character are typically bound to locations
 * returned by dc_get_locations()
 * and are typically created by on-character-messages
 * which can also be an emoticon. :)
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return Marker-character of the item at the given index.
 *     NULL if there is no marker-character bound to the given item.
 *     The returned value must be released using dc_str_unref() after usage.
 */
char*            dc_array_get_marker         (const dc_array_t* array, size_t index);


/**
 * Return the independent-state of the location at the given index.
 * Independent locations do not belong to the track of the user.
 *
 * @memberof dc_array_t
 * @param array The array object.
 * @param index The index of the item. Must be between 0 and dc_array_get_cnt()-1.
 * @return 0=Location belongs to the track of the user,
 *     1=Location was reported independently.
 */
int              dc_array_is_independent     (const dc_array_t* array, size_t index);


/**
 * Check if a given ID is present in an array.
 *
 * @private @memberof dc_array_t
 * @param array The array object to search in.
 * @param needle The ID to search for.
 * @param[out] ret_index If set, this will receive the index. Set to NULL if you're not interested in the index.
 * @return 1=ID is present in array, 0=ID not found.
 */
int              dc_array_search_id          (const dc_array_t* array, uint32_t needle, size_t* ret_index);


/**
 * @class dc_chatlist_t
 *
 * An object representing a single chatlist in memory.
 * Chatlist objects contain chat IDs
 * and, if possible, message IDs belonging to them.
 * The chatlist object is not updated;
 * if you want an update, you have to recreate the object.
 *
 * For a **typical chat overview**,
 * the idea is to get the list of all chats via dc_get_chatlist()
 * without any listflags (see below)
 * and to implement a "virtual list" or so
 * (the count of chats is known by dc_chatlist_get_cnt()).
 *
 * Only for the items that are in view
 * (the list may have several hundreds chats),
 * the UI should call dc_chatlist_get_summary() then.
 * dc_chatlist_get_summary() provides all elements needed for painting the item.
 *
 * On a click of such an item,
 * the UI should change to the chat view
 * and get all messages from this view via dc_get_chat_msgs().
 * Again, a "virtual list" is created
 * (the count of messages is known)
 * and for each messages that is scrolled into view, dc_get_msg() is called then.
 *
 * Why no listflags?
 * Without listflags, dc_get_chatlist() adds
 * the archive "link" automatically as needed.
 * The UI can just render these items differently then.
 */


/**
 * Free a chatlist object.
 *
 * @memberof dc_chatlist_t
 * @param chatlist The chatlist object to free, created e.g. by dc_get_chatlist(), dc_search_msgs().
 *     If NULL is given, nothing is done.
 */
void             dc_chatlist_unref           (dc_chatlist_t* chatlist);


/**
 * Find out the number of chats in a chatlist.
 *
 * @memberof dc_chatlist_t
 * @param chatlist The chatlist object as created e.g. by dc_get_chatlist().
 * @return Returns the number of items in a dc_chatlist_t object. 0 on errors or if the list is empty.
 */
size_t           dc_chatlist_get_cnt         (const dc_chatlist_t* chatlist);


/**
 * Get a single chat ID of a chatlist.
 *
 * To get the message object from the message ID, use dc_get_chat().
 *
 * @memberof dc_chatlist_t
 * @param chatlist The chatlist object as created e.g. by dc_get_chatlist().
 * @param index The index to get the chat ID for.
 * @return Returns the chat ID of the item at the given index. Index must be between
 *     0 and dc_chatlist_get_cnt()-1.
 */
uint32_t         dc_chatlist_get_chat_id     (const dc_chatlist_t* chatlist, size_t index);


/**
 * Get a single message ID of a chatlist.
 *
 * To get the message object from the message ID, use dc_get_msg().
 *
 * @memberof dc_chatlist_t
 * @param chatlist The chatlist object as created e.g. by dc_get_chatlist().
 * @param index The index to get the chat ID for.
 * @return Returns the message_id of the item at the given index. Index must be between
 *     0 and dc_chatlist_get_cnt()-1. If there is no message at the given index (e.g. the chat may be empty), 0 is returned.
 */
uint32_t         dc_chatlist_get_msg_id      (const dc_chatlist_t* chatlist, size_t index);


/**
 * Get a summary for a chatlist index.
 *
 * The summary is returned by a dc_lot_t object with the following fields:
 *
 * - dc_lot_t::text1: contains the username or the strings "Me", "Draft" and so on.
 *   The string may be colored by having a look at text1_meaning.
 *   If there is no such name or it should not be displayed, the element is NULL.
 *
 * - dc_lot_t::text1_meaning: one of DC_TEXT1_USERNAME, DC_TEXT1_SELF or DC_TEXT1_DRAFT.
 *   Typically used to show dc_lot_t::text1 with different colors. 0 if not applicable.
 *
 * - dc_lot_t::text2: contains an excerpt of the message text or strings as
 *   "No messages". May be NULL of there is no such text (e.g. for the archive link)
 *
 * - dc_lot_t::timestamp: the timestamp of the message. 0 if not applicable.
 *
 * - dc_lot_t::state: The state of the message as one of the @ref DC_STATE constants. 0 if not applicable.
 *
 * @memberof dc_chatlist_t
 * @param chatlist The chatlist to query as returned e.g. from dc_get_chatlist().
 * @param index The index to query in the chatlist.
 * @param chat To speed up things, pass an already available chat object here.
 *     If the chat object is not yet available, it is faster to pass NULL.
 * @return The summary as an dc_lot_t object. Must be freed using dc_lot_unref(). NULL is never returned.
 */
dc_lot_t*        dc_chatlist_get_summary     (const dc_chatlist_t* chatlist, size_t index, dc_chat_t* chat);


/**
 * Create a chatlist summary item when the chatlist object is already unref()'d.
 *
 * This function is similar to dc_chatlist_get_summary(), however,
 * it takes the chat ID and the message ID as returned by dc_chatlist_get_chat_id() and dc_chatlist_get_msg_id()
 * as arguments. The chatlist object itself is not needed directly.
 *
 * This maybe useful if you convert the complete object into a different representation
 * as done e.g. in the node-bindings.
 * If you have access to the chatlist object in some way, using this function is not recommended,
 * use dc_chatlist_get_summary() in this case instead.
 *
 * @memberof dc_context_t
 * @param context The context object.
 * @param chat_id The chat ID to get a summary for.
 * @param msg_id The message ID to get a summary for.
 * @return The summary as an dc_lot_t object, see dc_chatlist_get_summary() for details.
 *     Must be freed using dc_lot_unref(). NULL is never returned.
 */
dc_lot_t*        dc_chatlist_get_summary2    (dc_context_t* context, uint32_t chat_id, uint32_t msg_id);


/**
 * Helper function to get the associated context object.
 *
 * @memberof dc_chatlist_t
 * @param chatlist The chatlist object to empty.
 * @return The context object associated with the chatlist. NULL if none or on errors.
 */
dc_context_t*    dc_chatlist_get_context     (dc_chatlist_t* chatlist);


/**
 * Get info summary for a chat, in JSON format.
 *
 * The returned JSON string has the following key/values:
 *
 * id: chat id
 * name: chat/group name
 * color: color of this chat
 * last-message-from: who sent the last message
 * last-message-text: message (truncated)
 * last-message-state: @ref DC_STATE constant
 * last-message-date:
 * avatar-path: path-to-blobfile
 * is_verified: yes/no
 * @return a UTF8-encoded JSON string containing all requested info. Must be freed using dc_str_unref(). NULL is never returned.
 */
char*            dc_chat_get_info_json       (dc_context_t* context, size_t chat_id);

/**
 * @class dc_chat_t
 *
 * An object representing a single chat in memory.
 * Chat objects are created using e.g. dc_get_chat()
 * and are not updated on database changes;
 * if you want an update, you have to recreate the object.
 */


#define         DC_CHAT_ID_TRASH             3 // messages that should be deleted get this chat ID; the messages are deleted from the working thread later then. This is also needed as rfc724_mid should be preset as long as the message is not deleted on the server (otherwise it is downloaded again)
#define         DC_CHAT_ID_ARCHIVED_LINK     6 // only an indicator in a chatlist
#define         DC_CHAT_ID_ALLDONE_HINT      7 // only an indicator in a chatlist
#define         DC_CHAT_ID_LAST_SPECIAL      9 // larger chat IDs are "real" chats, their messages are "real" messages


/**
 * Free a chat object.
 *
 * @memberof dc_chat_t
 * @param chat Chat object are returned e.g. by dc_get_chat().
 *     If NULL is given, nothing is done.
 */
void            dc_chat_unref                (dc_chat_t* chat);


/**
 * Get the chat ID. The chat ID is the ID under which the chat is filed in the database.
 *
 * Special IDs:
 * - DC_CHAT_ID_ARCHIVED_LINK    (6) - A link at the end of the chatlist, if present the UI should show the button "Archived chats"-
 *
 * "Normal" chat IDs are larger than these special IDs (larger than DC_CHAT_ID_LAST_SPECIAL).
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return The chat ID. 0 on errors.
 */
uint32_t        dc_chat_get_id               (const dc_chat_t* chat);


/**
 * Get chat type as one of the @ref DC_CHAT_TYPE constants.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return The chat type.
 */
int             dc_chat_get_type             (const dc_chat_t* chat);


/**
 * Returns the address where messages are sent to if the chat is a mailing list.
 * If you just want to know if a mailing list can be written to,
 * use dc_chat_can_send() instead.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return The mailing list address. Must be released using dc_str_unref() after usage.
 *     If there is no such address, an empty string is returned, NULL is never returned.
 */
char*           dc_chat_get_mailinglist_addr (const dc_chat_t* chat);


/**
 * Get name of a chat. For one-to-one chats, this is the name of the contact.
 * For group chats, this is the name given e.g. to dc_create_group_chat() or
 * received by a group-creation message.
 *
 * To change the name, use dc_set_chat_name()
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return The chat name as a string. Must be released using dc_str_unref() after usage. Never NULL.
 */
char*           dc_chat_get_name             (const dc_chat_t* chat);


/**
 * Get the chat's profile image.
 * For groups, this is the image set by any group member
 * using dc_set_chat_profile_image().
 * For normal chats, this is the image set by each remote user on their own
 * using dc_set_config(context, "selfavatar", image).
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Path and file of the profile image, if any.
 *     NULL otherwise.
 *     Must be released using dc_str_unref() after usage.
 */
char*           dc_chat_get_profile_image    (const dc_chat_t* chat);


/**
 * Get a color for the chat.
 * For 1:1 chats, the color is calculated from the contact's e-mail address.
 * Otherwise, the chat name is used.
 * The color can be used for an fallback avatar with white initials
 * as well as for headlines in bubbles of group chats.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return The color as 0x00rrggbb with rr=red, gg=green, bb=blue
 *     each in the range 0-255.
 */
uint32_t        dc_chat_get_color            (const dc_chat_t* chat);


/**
 * Get visibility of chat.
 * See @ref DC_CHAT_VISIBILITY for detailed information about the visibilities.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return One of @ref DC_CHAT_VISIBILITY
 */
int             dc_chat_get_visibility       (const dc_chat_t* chat);


/**
 * Check if a chat is a contact request chat.
 *
 * UI should display such chats with a [New] badge in the chatlist.
 *
 * When such chat is opened, user should be presented with a set of
 * options instead of the message composition area, for example:
 * - Accept chat (dc_accept_chat())
 * - Block chat (dc_block_chat())
 * - Delete chat (dc_delete_chat())
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is a contact request chat,
 *     0=chat is not a contact request chat.
 */
int             dc_chat_is_contact_request   (const dc_chat_t* chat);


/**
 * Check if a group chat is still unpromoted.
 *
 * After the creation with dc_create_group_chat() the chat is usually unpromoted
 * until the first call to dc_send_text_msg() or another sending function.
 *
 * With unpromoted chats, members can be added
 * and settings can be modified without the need of special status messages being sent.
 *
 * While the core takes care of the unpromoted state on its own,
 * checking the state from the UI side may be useful to decide whether a hint as
 * "Send the first message to allow others to reply within the group"
 * should be shown to the user or not.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is still unpromoted, no message was ever send to the chat,
 *     0=chat is not unpromoted, messages were send and/or received
 *     or the chat is not group chat.
 */
int             dc_chat_is_unpromoted        (const dc_chat_t* chat);


/**
 * Check if a chat is a self talk. Self talks are normal chats with
 * the only contact DC_CONTACT_ID_SELF.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is self talk, 0=chat is no self talk.
 */
int             dc_chat_is_self_talk         (const dc_chat_t* chat);


/**
 * Check if a chat is a device-talk.
 * Device-talks contain update information
 * and some hints that are added during the program runs, multi-device etc.
 *
 * From the UI view, device-talks are not very special,
 * the user can delete and forward messages, archive the chat, set notifications etc.
 *
 * Messages can be added to the device-talk using dc_add_device_msg()
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is device talk, 0=chat is no device talk.
 */
int             dc_chat_is_device_talk       (const dc_chat_t* chat);


/**
 * Check if messages can be sent to a given chat.
 * This is not true e.g. for contact requests or for the device-talk, cmp. dc_chat_is_device_talk().
 *
 * Calling dc_send_msg() for these chats will fail
 * and the UI may decide to hide input controls therefore.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is writable, 0=chat is not writable.
 */
int             dc_chat_can_send              (const dc_chat_t* chat);


/**
 * Deprecated, always returns 0.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return Always 0.
 * @deprecated 2025-09-09
 */
int             dc_chat_is_protected         (const dc_chat_t* chat);


/**
 * Check if the chat is encrypted.
 *
 * 1:1 chats with key-contacts and group chats with key-contacts
 * are encrypted.
 * 1:1 chats with emails contacts and ad-hoc groups
 * created for email threads are not encrypted.
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=chat is encrypted, 0=chat is not encrypted.
 */
int             dc_chat_is_encrypted         (const dc_chat_t *chat);


/**
 * Check if locations are sent to the chat
 * at the time the object was created using dc_get_chat().
 * To check if locations are sent to _any_ chat,
 * use dc_is_sending_locations_to_chat().
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=locations are sent to chat, 0=no locations are sent to chat.
 */
int             dc_chat_is_sending_locations (const dc_chat_t* chat);


/**
 * Check whether the chat is currently muted (can be changed by dc_set_chat_mute_duration()).
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 1=muted, 0=not muted
 */
int             dc_chat_is_muted (const dc_chat_t* chat);


/**
 * Get the exact state of the mute of a chat
 *
 * @memberof dc_chat_t
 * @param chat The chat object.
 * @return 0=not muted, -1=forever muted, (x>0)=remaining seconds until the mute is lifted.
 */
int64_t          dc_chat_get_remaining_mute_duration (const dc_chat_t* chat);


/**
 * @class dc_msg_t
 *
 * An object representing a single message in memory.
 * The message object is not updated.
 * If you want an update, you have to recreate the object.
 */


#define         DC_MSG_ID_MARKER1            1 // this is used by iOS to mark things in the message list
#define         DC_MSG_ID_DAYMARKER          9
#define         DC_MSG_ID_LAST_SPECIAL       9


/**
 * Create new message object. Message objects are needed e.g. for sending messages using
 * dc_send_msg(). Moreover, they are returned e.g. from dc_get_msg(),
 * set up with the current state of a message. The message object is not updated;
 * to achieve this, you have to recreate it.
 *
 * @memberof dc_msg_t
 * @param context The context that should be stored in the message object.
 * @param viewtype The type to the message object to create,
 *     one of the @ref DC_MSG constants.
 * @return The created message object.
 */
dc_msg_t*       dc_msg_new                    (dc_context_t* context, int viewtype);


/**
 * Free a message object. Message objects are created e.g. by dc_get_msg().
 *
 * @memberof dc_msg_t
 * @param msg The message object to free.
 *     If NULL is given, nothing is done.
 */
void            dc_msg_unref                  (dc_msg_t* msg);


/**
 * Get the ID of the message.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The ID of the message.
 *     0 if the given message object is invalid.
 */
uint32_t        dc_msg_get_id                 (const dc_msg_t* msg);


/**
 * Get the ID of the contact who wrote the message.
 *
 * If the ID is equal to DC_CONTACT_ID_SELF (1), the message is an outgoing
 * message that is typically shown on the right side of the chat view.
 *
 * Otherwise, the message is an incoming message; to get details about the sender,
 * pass the returned ID to dc_get_contact().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The ID of the contact who wrote the message, DC_CONTACT_ID_SELF (1)
 *     if this is an outgoing message, 0 on errors.
 */
uint32_t        dc_msg_get_from_id            (const dc_msg_t* msg);


/**
 * Get the ID of the chat the message belongs to.
 * To get details about the chat, pass the returned ID to dc_get_chat().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The ID of the chat the message belongs to, 0 on errors.
 */
uint32_t        dc_msg_get_chat_id            (const dc_msg_t* msg);


/**
 * Get the type of the message.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return One of the @ref DC_MSG constants.
 *     0 if the given message object is invalid.
 */
int             dc_msg_get_viewtype           (const dc_msg_t* msg);


/**
 * Get the state of a message.
 *
 * Incoming message states:
 * - @ref DC_STATE_IN_FRESH - Incoming _fresh_ message.
 *   Fresh messages are neither noticed nor seen and are typically shown in notifications.
 *   Use dc_get_fresh_msgs() to get all fresh messages.
 * - @ref DC_STATE_IN_NOTICED - Incoming _noticed_ message.
 *   E.g. chat opened but message not yet read.
 *   Noticed messages are not counted as unread but were not marked as read nor resulted in MDNs.
 *   Use dc_marknoticed_chat() to mark messages as being noticed.
 * - @ref DC_STATE_IN_SEEN - Incoming message, really _seen_ by the user.
 *   Marked as read on IMAP and MDN may be sent. Use dc_markseen_msgs() to mark messages as being seen.
 *
 * Outgoing message states:
 * - @ref DC_STATE_OUT_PREPARING - For files which need time to be prepared before they can be sent,
 *   the message enters this state before @ref DC_STATE_OUT_PENDING. Deprecated.
 * - @ref DC_STATE_OUT_DRAFT - Message saved as draft using dc_set_draft()
 * - @ref DC_STATE_OUT_PENDING - The user has pressed the "send" button but the
 *   message is not yet sent and is pending in some way. Maybe we're offline (no checkmark).
 * - @ref DC_STATE_OUT_FAILED - _Unrecoverable_ error (_recoverable_ errors result in pending messages),
 *   you will receive the event #DC_EVENT_MSG_FAILED.
 * - @ref DC_STATE_OUT_DELIVERED - Outgoing message successfully delivered to server (one checkmark).
 *   Note, that already delivered messages may get into the state @ref DC_STATE_OUT_FAILED if we get such a hint from the server.
 *   If a sent message changes to this state, you will receive the event #DC_EVENT_MSG_DELIVERED.
 * - @ref DC_STATE_OUT_MDN_RCVD - Outgoing message read by the recipient
 *   (two checkmarks; this requires goodwill on the receiver's side)
 *   If a sent message changes to this state, you will receive the event #DC_EVENT_MSG_READ.
 *   Also messages already read by some recipients
 *   may get into the state @ref DC_STATE_OUT_FAILED at a later point,
 *   e.g. when in a group, delivery fails for some recipients.
 *
 * If you just want to check if a message is sent or not, please use dc_msg_is_sent() which regards all states accordingly.
 *
 * The state of just created message objects is @ref DC_STATE_UNDEFINED.
 * The state is always set by the core library, users of the library cannot set the state directly, but it is changed implicitly e.g.
 * when calling dc_marknoticed_chat() or dc_markseen_msgs().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The state of the message.
 */
int             dc_msg_get_state              (const dc_msg_t* msg);


/**
 * Get the message sending time.
 * The sending time is returned as a unix timestamp in seconds.
 *
 * Note that the message lists returned e.g. by dc_get_chat_msgs()
 * are not sorted by the _sending_ time but by the _receiving_ time.
 * This ensures newly received messages always pop up at the end of the list,
 * however, for delayed messages, the correct sending time will be displayed.
 *
 * To display detailed information about the times to the user,
 * the UI can use dc_get_msg_info().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The time of the message.
 */
int64_t          dc_msg_get_timestamp          (const dc_msg_t* msg);


/**
 * Get the message receive time.
 * The receive time is returned as a unix timestamp in seconds.
 *
 * To get the sending time, use dc_msg_get_timestamp().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The receiving time of the message.
 *     For outgoing messages, 0 is returned.
 */
int64_t          dc_msg_get_received_timestamp (const dc_msg_t* msg);


/**
 * Get the message time used for sorting.
 * This function returns the timestamp that is used for sorting the message
 * into lists as returned e.g. by dc_get_chat_msgs().
 * This may be the received time, the sending time or another time.
 *
 * To get the receiving time, use dc_msg_get_received_timestamp().
 * To get the sending time, use dc_msg_get_timestamp().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The time used for ordering.
 */
int64_t          dc_msg_get_sort_timestamp     (const dc_msg_t* msg);


/**
 * Get the text of the message.
 * If there is no text associated with the message, an empty string is returned.
 * NULL is never returned.
 *
 * The returned text is plain text, HTML is stripped.
 * The returned text is truncated to a max. length of currently about 30000 characters,
 * it does not make sense to show more text in the message list and typical controls
 * will have problems with showing much more text.
 * This max. length is to avoid passing _lots_ of data to the frontend which may
 * result e.g. from decoding errors (assume some bytes missing in a mime structure, forcing
 * an attachment to be plain text).
 *
 * To get information about the message and more/raw text, use dc_get_msg_info().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The message text. The result must be released using dc_str_unref(). Never returns NULL.
 */
char*           dc_msg_get_text               (const dc_msg_t* msg);


/**
 * Get the subject of the e-mail.
 * If there is no subject associated with the message, an empty string is returned.
 * NULL is never returned.
 *
 * You usually don't need this; if the core thinks that the subject might contain important
 * information, it automatically prepends it to the message text.
 *
 * This function was introduced so that you can use the subject as the title for the 
 * full-message-view (see dc_get_msg_html()).
 *
 * For outgoing messages, the subject is not stored and an empty string is returned.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The subject. The result must be released using dc_str_unref(). Never returns NULL.
 */
char*           dc_msg_get_subject            (const dc_msg_t* msg);


/**
 * Find out full path of the file associated with a message.
 *
 * Typically files are associated with images, videos, audios, documents.
 * Plain text messages do not have a file.
 * File name may be mangled. To obtain the original attachment filename use dc_msg_get_filename().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The full path (with file name and extension) of the file associated with the message.
 *     If there is no file associated with the message, an empty string is returned.
 *     NULL is never returned and the returned value must be released using dc_str_unref().
 */
char*           dc_msg_get_file               (const dc_msg_t* msg);


/**
 * Save file copy at the user-provided path.
 *
 * Fails if file already exists at the provided path.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param path Destination file path with filename and extension.
 * @return 0 on failure, 1 on success.
 */
int             dc_msg_save_file              (const dc_msg_t* msg, const char* path);


/**
 * Get an original attachment filename, with extension but without the path. To get the full path,
 * use dc_msg_get_file().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The attachment filename. If there is no file associated with the message, an empty string
 *     is returned. The returned value must be released using dc_str_unref().
 */
char*           dc_msg_get_filename           (const dc_msg_t* msg);


/**
 * Get the MIME type of a file. If there is no file, an empty string is returned.
 * If there is no associated MIME type with the file, the function guesses on; if
 * in doubt, `application/octet-stream` is returned. NULL is never returned.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return A string containing the MIME type.
 *     Must be released using dc_str_unref() after usage. NULL is never returned.
 */
char*           dc_msg_get_filemime           (const dc_msg_t* msg);


/**
 * Return a file from inside a webxdc message.
 *
 * @memberof dc_msg_t
 * @param msg The webxdc instance.
 * @param filename The name inside the archive.
 *     Can be given as an absolute path (`/file.png`)
 *     or as a relative path (`file.png`, no leading slash).
 * @param ret_bytes A pointer to a size_t. The size of the blob will be written here.
 * @return The blob must be released using dc_str_unref() after usage.
 *     NULL if there is no such file in the archive or on errors.
 */
char*             dc_msg_get_webxdc_blob      (const dc_msg_t* msg, const char* filename, size_t* ret_bytes);


/**
 * Get info from a webxdc message, in JSON format.
 * The returned JSON string has the following key/values:
 *
 * - name: The name of the app.
 *   Defaults to the filename if not set in the manifest.
 * - icon: App icon file name.
 *   Defaults to an standard icon if nothing is set in the manifest.
 *   To get the file, use dc_msg_get_webxdc_blob().
 *   App icons should should be square,
 *   the implementations will add round corners etc. as needed.
 * - document: if the Webxdc represents a document, this is the name of the document,
 *   otherwise, this is an empty string.
 * - summary: short string describing the state of the app,
 *   sth. as "2 votes", "Highscore: 123",
 *   can be changed by the apps and defaults to an empty string.
 * - source_code_url:
 *   URL where the source code of the Webxdc and other information can be found;
 *   defaults to an empty string.
 *   Implementations may offer an menu or a button to open this URL.
 * - internet_access:
 *   true if the Webxdc should get internet access;
 *   this is the case i.e. for experimental maps integration.
 * - self_addr: address to be used for `window.webxdc.selfAddr` in JS land.
 * - send_update_interval: Milliseconds to wait before calling `sendUpdate()` again since the last call.
 *   Should be exposed to `webxdc.sendUpdateInterval` in JS land.
 * - send_update_max_size: Maximum number of bytes accepted for a serialized update object.
 *   Should be exposed to `webxdc.sendUpdateMaxSize` in JS land.
 *
 * @memberof dc_msg_t
 * @param msg The webxdc instance.
 * @return A UTF8 encoded JSON string containing all requested info.
 *     Must be freed using dc_str_unref().
 *     NULL is never returned.
 */
char*             dc_msg_get_webxdc_info      (const dc_msg_t* msg);


/**
 * Get the size of the file. Returns the size of the file associated with a
 * message, if applicable.
 * If message is a pre-message, then this returns the size of the file to be downloaded.
 *
 * Typically, this is used to show the size of document files, e.g. a PDF.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The file size in bytes, 0 if not applicable or on errors.
 */
uint64_t        dc_msg_get_filebytes          (const dc_msg_t* msg);


/**
 * Get the width of an image or a video. The width is returned in pixels.
 * If the width is unknown or if the associated file is no image or video file,
 * 0 is returned.
 *
 * Often the aspect ratio is the more interesting thing. You can calculate
 * this using dc_msg_get_width() / dc_msg_get_height().
 *
 * See also dc_msg_get_duration().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The width in pixels, if applicable. 0 otherwise or if unknown.
 */
int             dc_msg_get_width              (const dc_msg_t* msg);


/**
 * Get the height of an image or a video. The height is returned in pixels.
 * If the height is unknown or if the associated file is no image or video file,
 * 0 is returned.
 *
 * Often the aspect ratio is the more interesting thing. You can calculate
 * this using dc_msg_get_width() / dc_msg_get_height().
 *
 * See also dc_msg_get_duration().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The height in pixels, if applicable. 0 otherwise or if unknown.
 */
int             dc_msg_get_height             (const dc_msg_t* msg);


/**
 * Get the duration of audio or video. The duration is returned in milliseconds (ms).
 * If the duration is unknown or if the associated file is no audio or video file,
 * 0 is returned.
 *
 * See also dc_msg_get_width() and dc_msg_get_height().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The duration in milliseconds, if applicable. 0 otherwise or if unknown.
 */
int             dc_msg_get_duration           (const dc_msg_t* msg);


/**
 * Check if message was correctly encrypted and signed.
 *
 * Historically, UIs showed a small padlock on the message then.
 * Today, the UIs should instead
 * show a small email-icon on the message if the message is not encrypted or signed,
 * and nothing otherwise.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message correctly encrypted and signed, no need to show anything; 0=show email-icon beside the message.
 */
int             dc_msg_get_showpadlock        (const dc_msg_t* msg);

/**
 * Check if an incoming message is a bot message, i.e. automatically submitted.
 *
 * Return value for outgoing messages is unspecified.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message is submitted automatically, 0=message is not automatically submitted.
 */
int             dc_msg_is_bot                 (const dc_msg_t* msg); 

/**
 * Get the ephemeral timer duration for a message.
 * This is the value of dc_get_chat_ephemeral_timer() in the moment the message was sent.
 *
 * To check if the timer is started and calculate remaining time,
 * use dc_msg_get_ephemeral_timestamp().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The duration in seconds, or 0 if no timer is set.
 */
uint32_t        dc_msg_get_ephemeral_timer    (const dc_msg_t* msg);

/**
 * Get the timestamp of the ephemeral message removal.
 *
 * If returned value is non-zero, you can calculate the * fraction of
 * time remaining by divinding the difference between the current timestamp
 * and this timestamp by dc_msg_get_ephemeral_timer().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The time of the message removal, 0 if the timer is not yet started.
 *     (The timer starts on sending messages or when dc_markseen_msgs() is called.)
 */
int64_t          dc_msg_get_ephemeral_timestamp (const dc_msg_t* msg);


/**
 * Get a summary for a message.
 *
 * The summary is returned by a dc_lot_t object with the following fields:
 *
 * - dc_lot_t::text1: contains the username or the string "Me".
 *   The string may be colored by having a look at text1_meaning.
 *   If the name should not be displayed, the element is NULL.
 * - dc_lot_t::text1_meaning: one of DC_TEXT1_USERNAME or DC_TEXT1_SELF.
 *   Typically used to show dc_lot_t::text1 with different colors. 0 if not applicable.
 * - dc_lot_t::text2: contains an excerpt of the message text.
 * - dc_lot_t::timestamp: the timestamp of the message.
 * - dc_lot_t::state: The state of the message as one of the @ref DC_STATE constants.
 *
 * Typically used to display a search result. See also dc_chatlist_get_summary() to display a list of chats.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param chat The chat object. To speed up things, pass an already available chat object here.
 *     If the chat object is not yet available, it is faster to pass NULL.
 * @return The summary as an dc_lot_t object. Must be freed using dc_lot_unref(). NULL is never returned.
 */
dc_lot_t*       dc_msg_get_summary            (const dc_msg_t* msg, const dc_chat_t* chat);


/**
 * Get a message summary as a single line of text. Typically used for
 * notifications.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param approx_characters A rough length of the expected string.
 * @return A summary for the given messages.
 *     The returned string must be released using dc_str_unref().
 *     Returns an empty string on errors, never returns NULL.
 */
char*           dc_msg_get_summarytext        (const dc_msg_t* msg, int approx_characters);


/**
 * Get the name that should be shown over the message (in a group chat) instead of the contact
 * display name, or NULL.
 *
 * If this returns non-NULL, put a `~` before the override-sender-name and show the
 * override-sender-name and the sender's avatar even in 1:1 chats.
 *
 * In mailing lists, sender display name and sender address do not always belong together.
 * In this case, this function gives you the name that should actually be shown over the message.
 *
 * Also, sometimes, we need to indicate a different sender in 1:1 chats:
 * Suppose that our user writes an e-mail to support@delta.chat, which forwards to 
 * Bob <bob@delta.chat>, and Bob replies.
 * 
 * Then, Bob's reply is shown in our 1:1 chat with support@delta.chat and the override-sender-name is
 * set to `Bob`. The UI should show the sender name as `~Bob` and show the avatar, just
 * as in group messages. If the user then taps on the avatar, they can see that this message
 * comes from bob@delta.chat.
 * 
 * You should show a `~` before the override-sender-name in chats, so that the user can
 * see that this isn't the sender's actual name.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The name to show over this message or NULL.
 *     If this returns NULL, call `dc_contact_get_display_name()`.
 *     The returned string must be released using dc_str_unref().
 */
char*           dc_msg_get_override_sender_name(const dc_msg_t* msg);



/**
 * Check if a message has a deviating timestamp.
 * A message has a deviating timestamp
 * when it is sent on another day as received/sorted by.
 *
 * When the UI displays normally only the time beside the message and the full day as headlines,
 * the UI should display the full date directly beside the message if the timestamp is deviating.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=Timestamp is deviating, the UI should display the full date beside the message,
 *     0=Timestamp is not deviating and belongs to the same date as the date headers,
 *     displaying the time only is sufficient in this case.
 */
int             dc_msg_has_deviating_timestamp(const dc_msg_t* msg);


/**
 * Check if a message has a POI location bound to it.
 * These locations are also returned by dc_get_locations()
 * The UI may decide to display a special icon beside such messages.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=Message has location bound to it, 0=No location bound to message.
 */
int             dc_msg_has_location           (const dc_msg_t* msg);


/**
 * Check if a message was sent successfully.
 *
 * Currently, "sent" messages are messages that are in the state "delivered" or "mdn received",
 * see dc_msg_get_state().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message sent successfully, 0=message not yet sent or message is an incoming message.
 */
int             dc_msg_is_sent                (const dc_msg_t* msg);


/**
 * Check if the message is a forwarded message.
 *
 * Forwarded messages may not be created by the contact given as "from".
 *
 * Typically, the UI shows a little text for a symbol above forwarded messages.
 *
 * For privacy reasons, we do not provide the name or the e-mail address of the
 * original author (in a typical GUI, you select the messages text and click on
 * "forwarded"; you won't expect other data to be send to the new recipient,
 * esp. as the new recipient may not be in any relationship to the original author)
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message is a forwarded message, 0=message not forwarded.
 */
int             dc_msg_is_forwarded           (const dc_msg_t* msg);


/**
 * Check if the message was edited.
 *
 * Edited messages should be marked by the UI as such,
 * e.g. by the text "Edited" beside the time.
 * To edit messages, use dc_send_edit_request().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message is edited, 0=message not edited.
 */
 int             dc_msg_is_edited             (const dc_msg_t* msg);


/**
 * Check if the message is an informational message, created by the
 * device or by another users. Such messages are not "typed" by the user but
 * created due to other actions,
 * e.g. dc_set_chat_name(), dc_set_chat_profile_image(),
 * or dc_add_contact_to_chat().
 *
 * These messages are typically shown in the center of the chat view,
 * dc_msg_get_text() returns a descriptive text about what is going on.
 *
 * For informational messages created by Webxdc apps,
 * dc_msg_get_parent() usually returns the Webxdc instance;
 * UIs can use that to scroll to the Webxdc app when the info is tapped.
 *
 * There is no need to perform any action when seeing such a message - this is already done by the core.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message is a system command, 0=normal message.
 */
int             dc_msg_is_info                (const dc_msg_t* msg);


/**
 * Get the type of an informational message.
 * If dc_msg_is_info() returns 1, this function returns the type of the informational message.
 * UIs can display e.g. an icon based upon the type.
 *
 * Currently, the following types are defined:
 * - DC_INFO_GROUP_NAME_CHANGED (2) - "Group name changd from OLD to BY by CONTACT"
 * - DC_INFO_GROUP_IMAGE_CHANGED (3) - "Group image changd by CONTACT"
 * - DC_INFO_MEMBER_ADDED_TO_GROUP (4) - "Member CONTACT added by OTHER_CONTACT"
 * - DC_INFO_MEMBER_REMOVED_FROM_GROUP (5) - "Member CONTACT removed by OTHER_CONTACT"
 * - DC_INFO_EPHEMERAL_TIMER_CHANGED (10) - "Disappearing messages CHANGED_TO by CONTACT"
 * - DC_INFO_PROTECTION_ENABLED (11) - Info-message for "Chat is protected"
 * - DC_INFO_INVALID_UNENCRYPTED_MAIL (13) - Info-message for "Provider requires end-to-end encryption which is not setup yet",
 *   the UI should change the corresponding string using #DC_STR_INVALID_UNENCRYPTED_MAIL
 *   and also offer a way to fix the encryption, eg. by a button offering a QR scan
 * - DC_INFO_WEBXDC_INFO_MESSAGE (32) - Info-message created by webxdc app sending `update.info`
 * - DC_INFO_CHAT_E2EE (50) - Info-message for "Chat is end-to-end-encrypted"
 *
 * For the messages that refer to a CONTACT,
 * dc_msg_get_info_contact_id() returns the contact ID.
 * The UI should open the contact's profile when tapping the info message.
 *
 * Even when you display an icon,
 * you should still display the text of the informational message using dc_msg_get_text()
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return One of the DC_INFO* constants.
 *     0 or other values indicate unspecified types
 *     or that the message is not an info-message.
 */
int             dc_msg_get_info_type          (const dc_msg_t* msg);


/**
 * Return the contact ID of the profile to open when tapping the info message.
 *
 * - For DC_INFO_MEMBER_ADDED_TO_GROUP and DC_INFO_MEMBER_REMOVED_FROM_GROUP,
 *   this is the contact being added/removed.
 *   The contact that did the adding/removal is usually only a tap away
 *   (as introducer and/or atop of the memberlist),
 *   and usually more known anyways.
 * - For DC_INFO_GROUP_NAME_CHANGED, DC_INFO_GROUP_IMAGE_CHANGED and DC_INFO_EPHEMERAL_TIMER_CHANGED
 *   this is the contact who did the change.
 *
 * No need to check additionally for dc_msg_get_info_type(),
 * unless you e.g. want to show the info message in another style.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return If the info message refers to a contact,
 *     this contact ID or DC_CONTACT_ID_SELF is returned.
 *     Otherwise 0.
 */
uint32_t        dc_msg_get_info_contact_id    (const dc_msg_t* msg);


// DC_INFO* uses the same values as SystemMessage in rust-land
#define         DC_INFO_UNKNOWN                    0
#define         DC_INFO_GROUP_NAME_CHANGED         2
#define         DC_INFO_GROUP_IMAGE_CHANGED        3
#define         DC_INFO_MEMBER_ADDED_TO_GROUP      4
#define         DC_INFO_MEMBER_REMOVED_FROM_GROUP  5
#define         DC_INFO_AUTOCRYPT_SETUP_MESSAGE    6
#define         DC_INFO_SECURE_JOIN_MESSAGE        7
#define         DC_INFO_LOCATIONSTREAMING_ENABLED  8
#define         DC_INFO_LOCATION_ONLY              9
#define         DC_INFO_EPHEMERAL_TIMER_CHANGED   10
#define         DC_INFO_PROTECTION_ENABLED        11
#define         DC_INFO_INVALID_UNENCRYPTED_MAIL  13
#define         DC_INFO_WEBXDC_INFO_MESSAGE       32
#define         DC_INFO_CHAT_E2EE                 50


/**
 * Get link attached to an webxdc info message.
 * The info message needs to be of type DC_INFO_WEBXDC_INFO_MESSAGE.
 *
 * Typically, this is used to set `document.location.href` in JS land.
 *
 * Webxdc apps can define the link by setting `update.href` when sending and update,
 * see dc_send_webxdc_status_update().
 *
 * @memberof dc_msg_t
 * @param msg The info message object.
 *     Not: the webxdc instance.
 * @return The link to be set to `document.location.href` in JS land.
 *     Returns NULL if there is no link attached to the info message and on errors.
 */
char*           dc_msg_get_webxdc_href        (const dc_msg_t* msg);


/**
 * Check if the message is an Autocrypt Setup Message.
 *
 * Setup messages should be shown in an unique way e.g. using a different text color.
 * On a click or another action, the user should be prompted for the setup code
 * which is forwarded to dc_continue_key_transfer() then.
 *
 * Setup message are typically generated by dc_initiate_key_transfer() on another device.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 1=message is a setup message, 0=no setup message.
 *     For setup messages, dc_msg_get_viewtype() returns #DC_MSG_FILE.
 */
int             dc_msg_is_setupmessage        (const dc_msg_t* msg);


/**
 * Get the first characters of the setup code.
 *
 * Typically, this is used to pre-fill the first entry field of the setup code.
 * If the user has several setup messages, he can be sure typing in the correct digits.
 *
 * To check, if a message is a setup message, use dc_msg_is_setupmessage().
 * To decrypt a secret key from a setup message, use dc_continue_key_transfer().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return Typically the first two digits of the setup code or an empty string if unknown.
 *     NULL is never returned. Must be released using dc_str_unref() when done.
 */
char*           dc_msg_get_setupcodebegin     (const dc_msg_t* msg);


/**
 * Gets the error status of the message.
 * If there is no error associated with the message, NULL is returned.
 *
 * A message can have an associated error status if something went wrong when sending or
 * receiving message itself. The error status is free-form text and should not be further parsed,
 * rather it's presence is meant to indicate *something* went wrong with the message and the
 * text of the error is detailed information on what.
 * 
 * Some common reasons error can be associated with messages are:
 * * Lack of valid signature on an e2ee message, usually for received messages.
 * * Failure to decrypt an e2ee message, usually for received messages.
 * * When a message could not be delivered to one or more recipients the non-delivery
 *   notification text can be stored in the error status.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return An error or NULL. The result must be released using dc_str_unref().
 */
char*           dc_msg_get_error               (const dc_msg_t* msg);


/**
 * Checks if the message has a full HTML version.
 *
 * Messages have a full HTML version
 * if the original message _may_ contain important parts
 * that are removed by some heuristics
 * or if the message is just too long or too complex
 * to get displayed properly by just using plain text.
 * If so, the UI should offer a button as
 * "Show full message" that shows the uncut message using dc_get_msg_html().
 *
 * Even if a "Show full message" button is recommended,
 * the UI should display the text in the bubble
 * using the normal dc_msg_get_text() function -
 * which will still be fine in many cases.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return 0=Message as displayed using dc_msg_get_text() is just fine;
 *     1=Message has a full HTML version,
 *     should be displayed using dc_msg_get_text()
 *     and a button to show the full version should be offered
 */
int dc_msg_has_html (dc_msg_t* msg);


/**
  * Check if the message is completely downloaded
  * or if some further action is needed.
  *
  * Messages may be not fully downloaded
  * if they are larger than the limit set by the dc_set_config()-option `download_limit`.
  *
  * The function returns one of:
  * - @ref DC_DOWNLOAD_DONE           - The message does not need any further download action
  *                                     and should be rendered as usual.
  * - @ref DC_DOWNLOAD_AVAILABLE      - There is additional content to download.
  *                                     In addition to the usual message rendering,
  *                                     the UI shall show a download button that calls dc_download_full_msg()
  * - @ref DC_DOWNLOAD_IN_PROGRESS    - Download was started with dc_download_full_msg() and is still in progress.
  *                                     If the download fails or succeeds,
  *                                     the event @ref DC_EVENT_MSGS_CHANGED is emitted.
  *
  * - @ref DC_DOWNLOAD_UNDECIPHERABLE - The message does not need any further download action.
  *                                     It was fully downloaded, but we failed to decrypt it.
  * - @ref DC_DOWNLOAD_FAILURE        - Download error, the user may start over calling dc_download_full_msg() again.
  *
  * @memberof dc_msg_t
  * @param msg The message object.
  * @return One of the @ref DC_DOWNLOAD values.
  */
int dc_msg_get_download_state (const dc_msg_t* msg);


/**
 * Set the text of a message object.
 * This does not alter any information in the database; this may be done by dc_send_msg() later.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param text The message text.
 */
void            dc_msg_set_text               (dc_msg_t* msg, const char* text);


/**
 * Set the HTML part of a message object.
 * As for all other dc_msg_t setters,
 * this is only useful if the message is sent using dc_send_msg() later.
 *
 * Please note, that Delta Chat clients show the plain text set with
 * dc_msg_set_text() at the first place;
 * the HTML part is not shown instead of this text.
 * However, for messages with HTML parts,
 * on the receiver's device, dc_msg_has_html() will return 1
 * and a button "Show full message" is typically shown.
 *
 * So adding a HTML part might be useful e.g. for bots,
 * that want to add rich content to a message, e.g. a website;
 * this HTML part is similar to an attachment then.
 *
 * **dc_msg_set_html() is currently not meant for sending a message,
 * a "normal user" has typed in!**
 * Use dc_msg_set_text() for that purpose.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param html HTML to send.
 */
void            dc_msg_set_html               (dc_msg_t* msg, const char* html);


/**
 * Sets the email's subject. If it's empty, a default subject
 * will be used (e.g. `Message from Alice` or `Re: <last subject>`).
 * This does not alter any information in the database.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param subject The new subject.
 */
void            dc_msg_set_subject            (dc_msg_t* msg, const char* subject);


/**
 * Set different sender name for a message.
 * This overrides the name set by the dc_set_config()-option `displayname`.
 *
 * Usually, this function is not needed
 * when implementing pure messaging functions.
 * However, it might be useful for bots e.g. building bridges to other networks.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param name The name to send along with the message.
 */
void            dc_msg_set_override_sender_name(dc_msg_t* msg, const char* name);


/**
 * Sets the file associated with a message.
 *
 * If `name` is non-null, it is used as the file name
 * and the actual current name of the file is ignored.
 *
 * If the source file is already in the blobdir, it will be renamed,
 * otherwise it will be copied to the blobdir first.
 *
 * In order to deduplicate files that contain the same data,
 * the file will be named `<hash>.<extension>`, e.g. `ce940175885d7b78f7b7e9f1396611f.jpg`.
 *
 * NOTE:
 * - This function will rename the file. To get the new file path, call `get_file()`.
 * - The file must not be modified after this function was called.
 *
 * @memberof dc_msg_t
 * @param msg The message object. Must not be NULL.
 * @param file The path of the file to attach. Must not be NULL.
 * @param name The original filename of the attachment. If NULL, the current name of `file` will be used instead.
 * @param filemime The MIME type of the file. NULL if you don't know or don't care.
 */
void            dc_msg_set_file_and_deduplicate(dc_msg_t* msg, const char* file, const char* name, const char* filemime);


/**
 * Set the dimensions associated with message object.
 * Typically this is the width and the height of an image or video associated using dc_msg_set_file_and_deduplicate().
 * This does not alter any information in the database; this may be done by dc_send_msg() later.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param width The width in pixels, if known. 0 if you don't know or don't care.
 * @param height The height in pixels, if known. 0 if you don't know or don't care.
 */
void            dc_msg_set_dimension          (dc_msg_t* msg, int width, int height);


/**
 * Set the duration associated with message object.
 * Typically this is the duration of an audio or video associated using dc_msg_set_file_and_deduplicate().
 * This does not alter any information in the database; this may be done by dc_send_msg() later.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param duration The duration in milliseconds. 0 if you don't know or don't care.
 */
void            dc_msg_set_duration           (dc_msg_t* msg, int duration);


/**
 * Set any location that should be bound to the message object.
 * The function is useful to add a marker to the map
 * at a position different from the self-location.
 * You should not call this function
 * if you want to bind the current self-location to a message;
 * this is done by dc_set_location() and dc_send_locations_to_chat().
 *
 * Typically results in the event #DC_EVENT_LOCATION_CHANGED with
 * contact ID set to DC_CONTACT_ID_SELF.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param latitude A north-south position of the location.
 * @param longitude An east-west position of the location.
 */
void            dc_msg_set_location           (dc_msg_t* msg, double latitude, double longitude);


/**
 * Late filing information to a message.
 * In contrast to the dc_msg_set_*() functions, this function really stores the information in the database.
 *
 * Sometimes, the core cannot find out the width, the height or the duration
 * of an image, an audio or a video.
 *
 * If, in these cases, the frontend can provide the information, it can save
 * them together with the message object for later usage.
 *
 * This function should only be used if dc_msg_get_width(), dc_msg_get_height() or dc_msg_get_duration()
 * do not provide the expected values.
 *
 * To get the stored values later, use dc_msg_get_width(), dc_msg_get_height() or dc_msg_get_duration().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @param width The new width to store in the message object. 0 if you don't want to change the width.
 * @param height The new height to store in the message object. 0 if you don't want to change the height.
 * @param duration The new duration to store in the message object. 0 if you don't want to change it.
 */
void            dc_msg_latefiling_mediasize   (dc_msg_t* msg, int width, int height, int duration);


/**
 * Set the message replying to.
 * This allows optionally to reply to an explicit message
 * instead of replying implicitly to the end of the chat.
 *
 * dc_msg_set_quote() copies some basic data from the quoted message object
 * so that dc_msg_get_quoted_text() will always work.
 * dc_msg_get_quoted_msg() gets back the quoted message only if it is _not_ deleted.
 *
 * @memberof dc_msg_t
 * @param msg The message object to set the reply to.
 * @param quote The quote to set for the message object given as `msg`.
 *     NULL removes an previously set quote.
 */
void             dc_msg_set_quote             (dc_msg_t* msg, const dc_msg_t* quote);


/**
 * Get quoted text, if any.
 * You can use this function also check if there is a quote for a message.
 *
 * The text is a summary of the original text,
 * similar to what is shown in the chatlist.
 *
 * If available, you can get the whole quoted message object using dc_msg_get_quoted_msg().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The quoted text or NULL if there is no quote.
 *     Returned strings must be released using dc_str_unref().
 */
char*           dc_msg_get_quoted_text        (const dc_msg_t* msg);


/**
 * Get quoted message, if available.
 * UIs might use this information to offer "jumping back" to the quoted message
 * or to enrich displaying the quote.
 *
 * If this function returns NULL,
 * this does not mean there is no quote for the message -
 * it might also mean that a quote exist but the quoted message is deleted meanwhile.
 * Therefore, do not use this function to check if there is a quote for a message.
 * To check if a message has a quote, use dc_msg_get_quoted_text().
 *
 * To display the quote in the chat, use dc_msg_get_quoted_text() as a primary source,
 * however, one might add information from the message object (e.g. an image).
 *
 * It is not guaranteed that the message belong to the same chat.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The quoted message or NULL.
 *     Must be freed using dc_msg_unref() after usage.
 */
dc_msg_t*       dc_msg_get_quoted_msg         (const dc_msg_t* msg);

/**
 * Get parent message, if available.
 *
 * Used for Webxdc-info-messages
 * to jump to the corresponding instance that created the info message.
 *
 * For quotes, please use the more specialized
 * dc_msg_get_quoted_text() and dc_msg_get_quoted_msg().
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 * @return The parent message or NULL.
 *     Must be freed using dc_msg_unref() after usage.
 */
dc_msg_t*       dc_msg_get_parent             (const dc_msg_t* msg);


/**
 * Get original message ID for a saved message from the "Saved Messages" chat.
 *
 * Can be used by UI to show a button to go the original message
 * and an option to "Unsave" the message.
 *
 * @memberof dc_msg_t
 * @param msg The message object. Usually, this refers to a a message inside "Saved Messages".
 * @return The message ID of the original message.
 *     0 if the given message object is not a "Saved Message"
 *     or if the original message does no longer exist.
 */
uint32_t        dc_msg_get_original_msg_id    (const dc_msg_t* msg);


/**
 * Check if a message was saved and return its ID inside "Saved Messages".
 *
 * Deleting the returned message will un-save the message.
 * The state "is saved" can be used to show some icon to indicate that a message was saved.
 *
 * @memberof dc_msg_t
 * @param msg The message object. Usually, this refers to a a message outside "Saved Messages".
 * @return The message ID inside "Saved Messages", if any.
 *     0 if the given message object is not saved.
 */
uint32_t        dc_msg_get_saved_msg_id     (const dc_msg_t* msg);


/**
 * Force the message to be sent in plain text.
 *
 * This API is for bots, there is no need to expose it in the UI.
 *
 * @memberof dc_msg_t
 * @param msg The message object.
 */
void            dc_msg_force_plaintext        (dc_msg_t* msg);

/**
 * @class dc_contact_t
 *
 * An object representing a single contact in memory.
 * The contact object is not updated.
 * If you want an update, you have to recreate the object.
 *
 * The library makes sure
 * only to use names _authorized_ by the contact in `To:` or `Cc:`.
 * _Given-names _as "Daddy" or "Honey" are not used there.
 * For this purpose, internally, two names are tracked -
 * authorized-name and given-name.
 * By default, these names are equal,
 * but functions working with contact names
 * (e.g. dc_contact_get_name(), dc_contact_get_display_name(),
 * dc_contact_get_name_n_addr(),
 * dc_create_contact() or dc_add_address_book())
 * only affect the given-name.
 */


#define         DC_CONTACT_ID_SELF           1
#define         DC_CONTACT_ID_INFO           2 // centered messages as "member added", used in all chats
#define         DC_CONTACT_ID_DEVICE         5 // messages "update info" in the device-chat
#define         DC_CONTACT_ID_LAST_SPECIAL   9


/**
 * Free a contact object.
 *
 * @memberof dc_contact_t
 * @param contact The contact object as created e.g. by dc_get_contact().
 *     If NULL is given, nothing is done.
 */
void            dc_contact_unref             (dc_contact_t* contact);


/**
 * Get the ID of a contact.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return The ID of the contact, 0 on errors.
 */
uint32_t        dc_contact_get_id            (const dc_contact_t* contact);


/**
 * Get the e-mail address of a contact. The e-mail address is always set for a contact.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return A string with the e-mail address,
 *     must be released using dc_str_unref(). Never returns NULL.
 */
char*           dc_contact_get_addr          (const dc_contact_t* contact);


/**
 * Get the edited contact name.
 * This is the name as given or modified by the local user using dc_create_contact().
 * If there is no such name for the contact, an empty string is returned.
 * The function does not return the contact name as received from the network.
 *
 * This name is typically used in a form where the user can edit the name of a contact.
 * To get a fine name to display in lists etc., use dc_contact_get_display_name() or dc_contact_get_name_n_addr().
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return A string with the name to display, must be released using dc_str_unref().
 *     Empty string if unset, never returns NULL.
 */
char*           dc_contact_get_name          (const dc_contact_t* contact);


/**
 * Get original contact name.
 * This is the name of the contact as defined by the contact themself.
 * If the contact themself does not define such a name,
 * an empty string is returned.
 *
 * This function is typically only needed for the controls that
 * allow the local user to edit the name,
 * e.g. you want to show the original name somewhere in the edit dialog
 * (you cannot use dc_contact_get_display_name() for that as
 * this would return previously set edited names).
 *
 * In most other situations than the name-edit-dialog,
 * as lists, messages etc. use dc_contact_get_display_name().
 *
 * @memberof dc_contact_t
 * @return A string with the original name, must be released using dc_str_unref().
 *     Empty string if unset, never returns NULL.
 */
char*           dc_contact_get_auth_name     (const dc_contact_t* contact);


/**
 * Get display name. This is the name as defined by the contact himself,
 * modified by the user or, if both are unset, the e-mail address.
 *
 * This name is typically used in lists.
 * To get the name editable in a formular, use dc_contact_get_name().
 *
 * In a group, you should show the sender's name over a message. To get it, call dc_msg_get_override_sender_name()
 * first and if it returns NULL, call dc_contact_get_display_name().
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return A string with the name to display, must be released using dc_str_unref().
 *     Never returns NULL.
 */
char*           dc_contact_get_display_name  (const dc_contact_t* contact);


// dc_contact_get_first_name is removed,
// the following define is to make upgrading more smoothly.
#define         dc_contact_get_first_name    dc_contact_get_display_name


/**
 * Get a summary of name and address.
 *
 * The returned string is either "Name (email@domain.com)" or just
 * "email@domain.com" if the name is unset.
 *
 * The summary is typically used when asking the user something about the contact.
 * The attached e-mail address makes the question unique, e.g. "Chat with Alan Miller (am@uniquedomain.com)?"
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return A summary string, must be released using dc_str_unref().
 *     Never returns NULL.
 */
char*           dc_contact_get_name_n_addr   (const dc_contact_t* contact);


/**
 * Get the contact's profile image.
 * This is the image set by each remote user on their own
 * using dc_set_config(context, "selfavatar", image).
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return The path and the file of the profile image, if any.
 *     NULL otherwise.
 *     Must be released using dc_str_unref() after usage.
 */
char*           dc_contact_get_profile_image (const dc_contact_t* contact);


/**
 * Get a color for the contact.
 * The color is calculated from the contact's e-mail address
 * and can be used for an fallback avatar with white initials
 * as well as for headlines in bubbles of group chats.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return A color as 0x00rrggbb with rr=red, gg=green, bb=blue
 *     each in the range 0-255.
 */
uint32_t        dc_contact_get_color         (const dc_contact_t* contact);


/**
 * Get the contact's status.
 *
 * Status is the last signature received in a message from this contact.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return The contact status, if any.
 *     Empty string otherwise.
 *     Must be released by using dc_str_unref() after usage.
 */
char*           dc_contact_get_status        (const dc_contact_t* contact);

/**
 * Get the contact's last seen timestamp.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return The last seen timestamp.
 *     0 on error or if the contact was never seen.
 */
int64_t         dc_contact_get_last_seen     (const dc_contact_t* contact);


/**
 * Check if the contact was seen recently.
 *
 * The UI may highlight these contacts,
 * eg. draw a little green dot on the avatars of the users recently seen.
 * DC_CONTACT_ID_SELF and other special contact IDs are defined as never seen recently (they should not get a dot).
 * To get the time a contact was seen, use dc_contact_get_last_seen().
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return 1=contact seen recently, 0=contact not seen recently.
 */
int             dc_contact_was_seen_recently (const dc_contact_t* contact);


/**
 * Check if a contact is blocked.
 *
 * To block or unblock a contact, use dc_block_contact().
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return 1=contact is blocked, 0=contact is not blocked.
 */
int             dc_contact_is_blocked        (const dc_contact_t* contact);


/**
 * Check if the contact
 * can be added to protected chats.
 *
 * See dc_contact_get_verifier_id() for a guidance how to display these information.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return 0: contact is not verified.
 *    2: SELF and contact have verified their fingerprints in both directions.
 */
int             dc_contact_is_verified       (dc_contact_t* contact);

/**
 * Returns whether contact is a bot.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return 0 if the contact is not a bot, 1 otherwise.
 */
int             dc_contact_is_bot            (dc_contact_t* contact);


/**
 * Returns whether contact is a key-contact,
 * i.e. it is identified by the public key
 * rather than the email address.
 *
 * If so, all messages to and from this contact are encrypted.
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return 1 if the contact is a key-contact, 0 if it is an address-contact.
 */
int             dc_contact_is_key_contact    (dc_contact_t* contact);


/**
 * Return the contact ID that verified a contact.
 *
 * As verifier may be unknown,
 * use dc_contact_is_verified() to check if a contact can be added to a protected chat.
 *
 * UI should display the information in the contact's profile as follows:
 *
 * - If dc_contact_get_verifier_id() != 0,
 *   display text "Introduced by ..."
 *   with the name of the contact
 *   formatted by dc_contact_get_name().
 *   Prefix the text by a green checkmark.
 *
 * - If dc_contact_get_verifier_id() == 0 and dc_contact_is_verified() != 0,
 *   display "Introduced" prefixed by a green checkmark.
 *
 * - if dc_contact_get_verifier_id() == 0 and dc_contact_is_verified() == 0,
 *   display nothing
 *
 * @memberof dc_contact_t
 * @param contact The contact object.
 * @return 
 *    The contact ID of the verifier. If it is DC_CONTACT_ID_SELF,
 *    we verified the contact ourself. If it is 0, we don't have verifier information or 
 *    the contact is not verified.
 */
uint32_t       dc_contact_get_verifier_id      (dc_contact_t* contact);


/**
 * @class dc_provider_t
 *
 * Opaque object containing information about one single e-mail provider.
 */


/**
 * Create a provider struct for the given e-mail address by local lookup.
 *
 * Lookup is done from the local database by extracting the domain from the e-mail address.
 * Therefore the provider for custom domains cannot be identified.
 *
 * @memberof dc_provider_t
 * @param context The context object.
 * @param email The user's e-mail address to extract the provider info form.
 * @return A dc_provider_t struct which can be used with the dc_provider_get_*
 *     accessor functions. If no provider info is found, NULL will be
 *     returned.
 */
dc_provider_t*  dc_provider_new_from_email            (const dc_context_t* context, const char* email);


/**
 * Create a provider struct for the given e-mail address by local lookup.
 *
 * DNS lookup is not used anymore and this function is deprecated.
 *
 * @memberof dc_provider_t
 * @param context The context object.
 * @param email The user's e-mail address to extract the provider info form.
 * @return A dc_provider_t struct which can be used with the dc_provider_get_*
 *     accessor functions. If no provider info is found, NULL will be
 *     returned.
 * @deprecated 2025-10-17 use dc_provider_new_from_email() instead.
 */
dc_provider_t*  dc_provider_new_from_email_with_dns    (const dc_context_t* context, const char* email);


/**
 * URL of the overview page.
 *
 * This URL allows linking to the providers page on providers.delta.chat.
 *
 * @memberof dc_provider_t
 * @param provider The dc_provider_t struct.
 * @return A string with a fully-qualified URL,
 *     if there is no such URL, an empty string is returned, NULL is never returned.
 *     The returned value must be released using dc_str_unref().
 */
char*           dc_provider_get_overview_page         (const dc_provider_t* provider);


/**
 * Get hints to be shown to the user on the login screen.
 * Depending on the @ref DC_PROVIDER_STATUS returned by dc_provider_get_status(),
 * the UI may want to highlight the hint.
 *
 * Moreover, the UI should display a "More information" link
 * that forwards to the URL returned by dc_provider_get_overview_page().
 *
 * @memberof dc_provider_t
 * @param provider The dc_provider_t struct.
 * @return A string with the hint to show to the user, may contain multiple lines,
 *     if there is no such hint, an empty string is returned, NULL is never returned.
 *     The returned value must be released using dc_str_unref().
 */
char*           dc_provider_get_before_login_hint     (const dc_provider_t* provider);


/**
 * Whether DC works with this provider.
 *
 * Can be one of #DC_PROVIDER_STATUS_OK,
 * #DC_PROVIDER_STATUS_PREPARATION or #DC_PROVIDER_STATUS_BROKEN.
 *
 * @memberof dc_provider_t
 * @param provider The dc_provider_t struct.
 * @return The status as a constant number.
 */
int             dc_provider_get_status                (const dc_provider_t* provider);


/**
 * Free the provider info struct.
 *
 * @memberof dc_provider_t
 * @param provider The dc_provider_t struct.
 */
void            dc_provider_unref                     (dc_provider_t* provider);


/**
 * @class dc_lot_t
 *
 * An object containing a set of values.
 * The meaning of the values is defined by the function returning the object.
 * Lot objects are created
 * e.g. by dc_chatlist_get_summary() or dc_msg_get_summary().
 *
 * NB: _Lot_ is used in the meaning _heap_ here.
 */


#define         DC_TEXT1_DRAFT     1
#define         DC_TEXT1_USERNAME  2
#define         DC_TEXT1_SELF      3


/**
 * Frees an object containing a set of parameters.
 * If the set object contains strings, the strings are also freed with this function.
 * Set objects are created e.g. by dc_chatlist_get_summary() or dc_msg_get_summary().
 *
 * @memberof dc_lot_t
 * @param lot The object to free.
 *     If NULL is given, nothing is done.
 */
void            dc_lot_unref             (dc_lot_t* lot);


/**
 * Get first string. The meaning of the string is defined by the creator of the object and may be roughly described by dc_lot_get_text1_meaning().
 *
 * @memberof dc_lot_t
 * @param lot The lot object.
 * @return A string, the string may be empty
 *     and the returned value must be released using dc_str_unref().
 *     NULL if there is no such string.
 */
char*           dc_lot_get_text1         (const dc_lot_t* lot);


/**
 * Get second string. The meaning of the string is defined by the creator of the object.
 *
 * @memberof dc_lot_t
 * @param lot The lot object.
 * @return A string, the string may be empty.
 *     and the returned value must be released using dc_str_unref().
 *     NULL if there is no such string.
 */
char*           dc_lot_get_text2         (const dc_lot_t* lot);


/**
 * Get the meaning of the first string. Possible meanings of the string are defined by the creator of the object and may be returned e.g.
 * as DC_TEXT1_DRAFT, DC_TEXT1_USERNAME or DC_TEXT1_SELF.
 *
 * @memberof dc_lot_t
 * @param lot The lot object.
 * @return Returns the meaning of the first string, possible meanings are defined by the creator of the object.
 *    0 if there is no concrete meaning or on errors.
 */
int             dc_lot_get_text1_meaning (const dc_lot_t* lot);


/**
 * Get the associated state. The meaning of the state is defined by the creator of the object.
 *
 * @memberof dc_lot_t
 * @param lot The lot object.
 * @return The state as defined by the creator of the object. 0 if there is not state or on errors.
 */
int             dc_lot_get_state         (const dc_lot_t* lot);


/**
 * Get the associated ID. The meaning of the ID is defined by the creator of the object.
 *
 * @memberof dc_lot_t
 * @param lot The lot object.
 * @return The state as defined by the creator of the object. 0 if there is not state or on errors.
 */
uint32_t        dc_lot_get_id            (const dc_lot_t* lot);


/**
 * Get the associated timestamp.
 * The timestamp is returned as a unix timestamp in seconds.
 * The meaning of the timestamp is defined by the creator of the object.
 *
 * @memberof dc_lot_t
 * @param lot The lot object.
 * @return The timestamp as defined by the creator of the object. 0 if there is not timestamp or on errors.
 */
int64_t         dc_lot_get_timestamp     (const dc_lot_t* lot);


/**
 * @defgroup DC_MSG DC_MSG
 *
 * With these constants the type of a message is defined.
 *
 * From the view of the library,
 * all types are primary types of the same level,
 * e.g. the library does not regard #DC_MSG_GIF as a subtype for #DC_MSG_IMAGE
 * and it is up to the UI to decide whether a GIF is shown
 * e.g. in an image or in a video container.
 *
 * If you want to define the type of a dc_msg_t object for sending,
 * use dc_msg_new().
 * Depending on the type, you will set more properties using e.g.
 * dc_msg_set_text() or dc_msg_set_file_and_deduplicate().
 * To finally send the message, use dc_send_msg().
 *
 * To get the types of dc_msg_t objects received, use dc_msg_get_viewtype().
 *
 * @addtogroup DC_MSG
 * @{
 */


/**
 * Text message.
 * The text of the message is set using dc_msg_set_text()
 * and retrieved with dc_msg_get_text().
 */
#define DC_MSG_TEXT      10


/**
 * Image message.
 * If the image is an animated GIF, the type #DC_MSG_GIF should be used.
 * File, width, and height are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_dimension()
 * and retrieved via dc_msg_get_file(), dc_msg_get_width(), and dc_msg_get_height().
 *
 * Before sending, the image is recoded to an reasonable size,
 * see dc_set_config()-option `media_quality`.
 * If you do not want images to be recoded,
 * send them as #DC_MSG_FILE.
 */
#define DC_MSG_IMAGE     20


/**
 * Animated GIF message.
 * File, width, and height are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_dimension()
 * and retrieved via dc_msg_get_file(), dc_msg_get_width(), and dc_msg_get_height().
 */
#define DC_MSG_GIF       21


/**
 * Message containing a sticker, similar to image.
 * NB: When sending, the message viewtype may be changed to `Image` by some heuristics like checking
 * for transparent pixels.
 * If possible, the UI should display the image without borders in a transparent way.
 * A click on a sticker will offer to install the sticker set in some future.
 */
#define DC_MSG_STICKER     23


/**
 * Message containing an audio file.
 * File and duration are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_duration()
 * and retrieved via dc_msg_get_file(), and dc_msg_get_duration().
 */
#define DC_MSG_AUDIO     40


/**
 * A voice message that was directly recorded by the user.
 * For all other audio messages, the type #DC_MSG_AUDIO should be used.
 * File and duration are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_duration()
 * and retrieved via dc_msg_get_file(), and dc_msg_get_duration().
 */
#define DC_MSG_VOICE     41


/**
 * Video messages.
 * File, width, height, and duration
 * are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_dimension(), dc_msg_set_duration()
 * and retrieved via
 * dc_msg_get_file(), dc_msg_get_width(),
 * dc_msg_get_height(), and dc_msg_get_duration().
 */
#define DC_MSG_VIDEO     50


/**
 * Message containing any file, e.g. a PDF.
 * The file is set via dc_msg_set_file_and_deduplicate()
 * and retrieved via dc_msg_get_file().
 */
#define DC_MSG_FILE      60


/**
 * Message indicating an incoming or outgoing call.
 *
 * These messages are created by dc_place_outgoing_call()
 * and should be rendered by UI similar to text messages,
 * maybe with some "phone icon" at the side.
 *
 * The message text is updated as needed
 * and UI will be informed via #DC_EVENT_MSGS_CHANGED as usual.
 *
 * Do not start ringing when seeing this message;
 * the mesage may belong e.g. to an old missed call.
 *
 * Instead, ringing should start on the event #DC_EVENT_INCOMING_CALL
 */
#define DC_MSG_CALL 71


/**
 * The message is a webxdc instance.
 *
 * To send data to a webxdc instance, use dc_send_webxdc_status_update().
 */
#define DC_MSG_WEBXDC    80

/**
 * Message containing shared contacts represented as a vCard (virtual contact file)
 * with email addresses and possibly other fields.
 */
#define DC_MSG_VCARD     90

/**
 * @}
 */


/**
  * @defgroup DC_STATE DC_STATE
  *
  * These constants describe the state of a message.
  * The state can be retrieved using dc_msg_get_state()
  * and may change by various actions reported by various events
  *
  * @addtogroup DC_STATE
  * @{
  */

/**
 * Message just created. See dc_msg_get_state() for details.
 */
#define         DC_STATE_UNDEFINED           0

/**
 * Incoming fresh message. See dc_msg_get_state() for details.
 */
#define         DC_STATE_IN_FRESH            10

/**
 * Incoming noticed message. See dc_msg_get_state() for details.
 */
#define         DC_STATE_IN_NOTICED          13

/**
 * Incoming seen message. See dc_msg_get_state() for details.
 */
#define         DC_STATE_IN_SEEN             16

/**
 * Outgoing message being prepared. See dc_msg_get_state() for details.
 *
 * @deprecated 2024-12-07
 */
#define         DC_STATE_OUT_PREPARING       18

/**
 * Outgoing message drafted. See dc_msg_get_state() for details.
 */
#define         DC_STATE_OUT_DRAFT           19

/**
 * Outgoing message waiting to be sent. See dc_msg_get_state() for details.
 */
#define         DC_STATE_OUT_PENDING         20

/**
 * Outgoing message failed sending. See dc_msg_get_state() for details.
 */
#define         DC_STATE_OUT_FAILED          24

/**
 * Outgoing message sent. To check if a mail was actually sent, use dc_msg_is_sent().
 * See dc_msg_get_state() for details.
 */
#define         DC_STATE_OUT_DELIVERED       26

/**
 * Outgoing message sent and seen by recipients(s). See dc_msg_get_state() for details.
 */
#define         DC_STATE_OUT_MDN_RCVD        28

/**
 * @}
 */


/**
 * @defgroup DC_CHAT_TYPE DC_CHAT_TYPE
 *
 * These constants describe the type of a chat.
 * The chat type can be retrieved using dc_chat_get_type()
 * and the type does not change during the chat's lifetime.
 *
 * @addtogroup DC_CHAT_TYPE
 * @{
 */

/**
 * Undefined chat type.
 * Normally, this type is not returned.
 */
#define         DC_CHAT_TYPE_UNDEFINED       0

/**
 * A one-to-one chat with a single contact.
 *
 * dc_get_chat_contacts() contains one record for the user.
 * DC_CONTACT_ID_SELF is added _only_ for a self talk.
 * These chats are created by dc_create_chat_by_contact_id().
 */
#define         DC_CHAT_TYPE_SINGLE          100

/**
 * A group chat.
 *
 * dc_get_chat_contacts() contain all group members,
 * including DC_CONTACT_ID_SELF.
 * Groups are created by dc_create_group_chat().
 */
#define         DC_CHAT_TYPE_GROUP           120

/**
 * A mailing list.
 *
 * This is similar to groups,
 * however, the member list cannot be retrieved completely
 * and cannot be changed using an API from this library.
 * Mailing lists are created as needed by incoming messages
 * and usually require some special server;
 * they cannot be created by a function call as the other chat types.
 */
#define         DC_CHAT_TYPE_MAILINGLIST     140

/**
 * Outgoing broadcast channel, called "Channel" in the UI.
 *
 * The user can send into this chat,
 * and all recipients will receive messages
 * in a `DC_CHAT_TYPE_IN_BROADCAST`.
 *
 * Called `broadcast` here rather than `channel`,
 * because the word "channel" already appears a lot in the code,
 * which would make it hard to grep for it.
 */
#define         DC_CHAT_TYPE_OUT_BROADCAST   160

/**
 * Incoming broadcast channel, called "Channel" in the UI.
 *
 * This chat is read-only,
 * and we do not know who the other recipients are.
 *
 * This is similar to `DC_CHAT_TYPE_MAILINGLIST`,
 * with the main difference being that
 * broadcasts are encrypted.
 *
 * Called `broadcast` here rather than `channel`,
 * because the word "channel" already appears a lot in the code,
 * which would make it hard to grep for it.
 */
#define         DC_CHAT_TYPE_IN_BROADCAST    165

/**
 * @}
 */


/**
 * @defgroup DC_SOCKET DC_SOCKET
 *
 * These constants configure socket security.
 * To set socket security, use dc_set_config() with the keys "mail_security" and/or "send_security".
 * If no socket-configuration is explicitly specified, #DC_SOCKET_AUTO is used.
 *
 * @addtogroup DC_SOCKET
 * @{
 */

/**
 * Choose socket security automatically.
 */
#define DC_SOCKET_AUTO 0


/**
 * Connect via SSL/TLS.
 */
#define DC_SOCKET_SSL 1


/**
 * Connect via STARTTLS.
 */
#define DC_SOCKET_STARTTLS 2


/**
 * Connect unencrypted, this should not be used.
 */
#define DC_SOCKET_PLAIN 3

/**
 * @}
 */


/**
 * @defgroup DC_LP DC_LP
 *
 * Flags for configuring IMAP and SMTP servers.
 * These flags are optional
 * and may be set together with the username, password etc.
 * via dc_set_config() using the key "server_flags".
 *
 * @addtogroup DC_LP
 * @{
 */


/**
 * Force OAuth2 authorization. This flag does not skip automatic configuration.
 * Before calling dc_configure() with DC_LP_AUTH_OAUTH2 set,
 * the user has to confirm access at the URL returned by dc_get_oauth2_url().
 */
#define DC_LP_AUTH_OAUTH2                0x2


/**
 * Force NORMAL authorization, this is the default.
 * If this flag is set, automatic configuration is skipped.
 */
#define DC_LP_AUTH_NORMAL                0x4


/**
 * @}
 */

#define DC_LP_AUTH_FLAGS        (DC_LP_AUTH_OAUTH2|DC_LP_AUTH_NORMAL) // if none of these flags are set, the default is chosen

/**
 * @defgroup DC_CERTCK DC_CERTCK
 *
 * These constants configure TLS certificate checks for IMAP and SMTP connections.
 *
 * These constants are set via dc_set_config()
 * using keys "imap_certificate_checks" and "smtp_certificate_checks".
 *
 * @addtogroup DC_CERTCK
 * @{
 */

/**
 * Configure certificate checks automatically.
 */
#define DC_CERTCK_AUTO 0

/**
 * Strictly check TLS certificates;
 * requires that both the certificate and the hostname are valid.
 */
#define DC_CERTCK_STRICT 1

/**
 * Accept certificates that are expired, self-signed
 * or not valid for the server hostname.
 */
#define DC_CERTCK_ACCEPT_INVALID 2

/**
 * For API compatibility only: Treat this as DC_CERTCK_ACCEPT_INVALID on reading.
 * Must not be written.
 */
#define DC_CERTCK_ACCEPT_INVALID_CERTIFICATES 3

/**
 * @}
 */


/**
 * @class dc_jsonrpc_instance_t
 *
 * Opaque object for using the json rpc api from the cffi bindings.
 */

/**
 * Create the jsonrpc instance that is used to call the jsonrpc.
 *
 * @memberof dc_accounts_t
 * @param account_manager The accounts object as created by dc_accounts_new().
 * @return Returns the jsonrpc instance, NULL on errors.
 *     Must be freed using dc_jsonrpc_unref() after usage.
 *
 */
dc_jsonrpc_instance_t* dc_jsonrpc_init(dc_accounts_t* account_manager);

/**
 * Free a jsonrpc instance.
 *
 * @memberof dc_jsonrpc_instance_t
 * @param jsonrpc_instance jsonrpc instance as returned from dc_jsonrpc_init().
 *     If NULL is given, nothing is done and an error is logged.
 */
void dc_jsonrpc_unref(dc_jsonrpc_instance_t* jsonrpc_instance);

/**
 * Makes an asynchronous jsonrpc request,
 * returns immediately and once the result is ready it can be retrieved via dc_jsonrpc_next_response()
 * the jsonrpc specification defines an invocation id that can then be used to match request and response.
 *
 * An overview of JSON-RPC calls is available at
 * <https://js.jsonrpc.delta.chat/classes/RawClient.html>.
 * Note that the page describes only the rough methods.
 * Calling convention, casing etc. does vary, this is a known flaw,
 * and at some point we will get to improve that :)
 *
 * Also, note that most calls are more high-level than this CFFI, require more database calls and are slower.
 * They're more suitable for an environment that is totally async and/or cannot use CFFI, which might not be true for native apps.
 *
 * Notable exceptions that exist only as JSON-RPC and probably never get a CFFI counterpart:
 * - getMessageReactions(), sendReaction()
 * - getHttpResponse()
 * - draftSelfReport()
 * - getAccountFileSize()
 * - importVcard(), parseVcard(), makeVcard()
 * - sendWebxdcRealtimeData, sendWebxdcRealtimeAdvertisement(), leaveWebxdcRealtime()
 *
 * @memberof dc_jsonrpc_instance_t
 * @param jsonrpc_instance jsonrpc instance as returned from dc_jsonrpc_init().
 * @param request JSON-RPC request as string
 */
void dc_jsonrpc_request(dc_jsonrpc_instance_t* jsonrpc_instance, const char* request);

/**
 * Get the next json_rpc response, blocks until there is a new event, so call this in a loop from a thread.
 *
 * @memberof dc_jsonrpc_instance_t
 * @param jsonrpc_instance jsonrpc instance as returned from dc_jsonrpc_init().
 * @return JSON-RPC response as string, must be freed using dc_str_unref() after usage.
 *     If NULL is returned, the accounts_t belonging to the jsonrpc instance is unref'd and no more events will come;
 *     in this case, free the jsonrpc instance using dc_jsonrpc_unref().
 */
char* dc_jsonrpc_next_response(dc_jsonrpc_instance_t* jsonrpc_instance);

/**
 * Make a JSON-RPC call and return a response.
 *
 * See dc_jsonrpc_request() for an overview of possible calls and for more information.
 *
 * @memberof dc_jsonrpc_instance_t
 * @param jsonrpc_instance jsonrpc instance as returned from dc_jsonrpc_init().
 * @param input JSON-RPC request.
 * @return JSON-RPC response as string, must be freed using dc_str_unref() after usage.
 *     If there is no response, NULL is returned.
 */
char* dc_jsonrpc_blocking_call(dc_jsonrpc_instance_t* jsonrpc_instance, const char *input);

/**
 * @class dc_event_channel_t
 *
 * Opaque object that is used to create an event emitter which can be used log events during startup of an accounts manger.
 * Only used for dc_accounts_new_with_event_channel().
 * To use it:
 *   1. create an events channel with `dc_event_channel_new()`.
 *   2. get an event emitter for it with `dc_event_channel_get_event_emitter()`.
 *   3. use it to create your account manager with `dc_accounts_new_with_event_channel()`, which consumes the channel.
 *   4. free the empty channel wrapper object with `dc_event_channel_unref()`.
 */

 /**
  * Create a new event channel.
  *
  * @memberof dc_event_channel_t
  * @return An event channel wrapper object (dc_event_channel_t).
  */
 dc_event_channel_t* dc_event_channel_new();
 
 /**
  * Release/free the events channel structure.
  * This function releases the memory of the `dc_event_channel_t` structure.
  *
  * you can call it after calling dc_accounts_new_with_event_channel,
  * which took the events channel out of it already, so this just frees the underlying option.
  * 
  * @memberof dc_event_channel_t
  */
void dc_event_channel_unref(dc_event_channel_t* event_channel);

/**
 * Create the event emitter that is used to receive events.
 * 
 * The library will emit various @ref DC_EVENT events, such as "new message", "message read" etc.
 * To get these events, you have to create an event emitter using this function
 * and call dc_get_next_event() on the emitter.
 *
 * This is similar to dc_get_event_emitter(), which, however,
 * must not be called for accounts handled by the account manager.
 * 
 * @memberof dc_event_channel_t
 * @param The event channel.
 * @return Returns the event emitter, NULL on errors.
 *     Must be freed using dc_event_emitter_unref() after usage.
 * 
 * Note: Use only one event emitter per account manager / event channel.
 * The result of having multiple event emitters is unspecified.
 * Currently events are broadcasted to all existing event emitters,
 * but previous versions delivered events to only one event emitter
 * and this behavior may change again in the future.
 * Events emitted before creation of event emitter
 * are not available to event emitter.
 */
dc_event_emitter_t* dc_event_channel_get_event_emitter(dc_event_channel_t* event_channel);

/**
 * @class dc_event_emitter_t
 *
 * Opaque object that is used to get events from a single context.
 * You can get an event emitter from a context using dc_get_event_emitter()
 * or dc_accounts_get_event_emitter().
 */

/**
 * Get the next event from a context event emitter object.
 *
 * @memberof dc_event_emitter_t
 * @param emitter Event emitter object as returned from dc_get_event_emitter().
 * @return An event as an dc_event_t object.
 *     You can query the event for information using dc_event_get_id(), dc_event_get_data1_int() and so on;
 *     if you are done with the event, you have to free the event using dc_event_unref().
 *     If NULL is returned, the context belonging to the event emitter is unref'd and no more events will come;
 *     in this case, free the event emitter using dc_event_emitter_unref().
 */
dc_event_t* dc_get_next_event(dc_event_emitter_t* emitter);

// Alias for backwards compatibility, use dc_get_next_event instead.
#define dc_accounts_get_next_event dc_get_next_event

/**
 * Free a context event emitter object.
 *
 * @memberof dc_event_emitter_t
 * @param emitter Event emitter object as returned from dc_get_event_emitter().
 *     If NULL is given, nothing is done and an error is logged.
 */
void  dc_event_emitter_unref(dc_event_emitter_t* emitter);

// Alias for backwards compatibility, use dc_event_emtitter_unref instead.
#define dc_accounts_event_emitter_unref dc_event_emitter_unref

/**
 * @class dc_event_t
 *
 * Opaque object describing a single event.
 * To get events, call dc_get_next_event() on an event emitter created by dc_get_event_emitter().
 */

/**
 * Get the event ID from an event object.
 * The event ID is one of the @ref DC_EVENT constants.
 * There may be additional data belonging to an event,
 * to get them, use dc_event_get_data1_int(), dc_event_get_data2_int() and dc_event_get_data2_str().
 *
 * @memberof dc_event_t
 * @param event Event object as returned from dc_get_next_event().
 * @return once of the @ref DC_EVENT constants.
 *     0 on errors.
 */
int dc_event_get_id(dc_event_t* event);


/**
 * Get data associated with an event object.
 * The meaning of the data depends on the event ID
 * returned as @ref DC_EVENT constants by dc_event_get_id().
 * See also dc_event_get_data2_int() and dc_event_get_data2_str().
 *
 * @memberof dc_event_t
 * @param event Event object as returned from dc_get_next_event().
 * @return "data1" as a signed integer, at least 32bit,
 *     the meaning depends on the event type associated with this event.
 */
int dc_event_get_data1_int(dc_event_t* event);


/**
 * Get data associated with an event object.
 * The meaning of the data depends on the event ID
 * returned as @ref DC_EVENT constants by dc_event_get_id().
 * See also dc_event_get_data2_int() and dc_event_get_data2_str().
 *
 * @memberof dc_event_t
 * @param event Event object as returned from dc_get_next_event().
 * @return "data2" as a signed integer, at least 32bit,
 *     the meaning depends on the event type associated with this event.
 */
int dc_event_get_data2_int(dc_event_t* event);


/**
 * Get data associated with an event object.
 * The meaning of the data depends on the event ID returned as @ref DC_EVENT constants.
 *
 * @memberof dc_event_t
 * @param event Event object as returned from dc_get_next_event().
 * @return "data1" string or NULL.
 *     The meaning depends on the event type associated with this event.
 *     Must be freed using dc_str_unref().
 */
char* dc_event_get_data1_str(dc_event_t* event);


/**
 * Get data associated with an event object.
 * The meaning of the data depends on the event ID returned as @ref DC_EVENT constants.
 *
 * @memberof dc_event_t
 * @param event Event object as returned from dc_get_next_event().
 * @return "data2" string or NULL.
 *     The meaning depends on the event type associated with this event.
 *     Must be freed using dc_str_unref().
 */
char* dc_event_get_data2_str(dc_event_t* event);


/**
 * Get the account ID this event belongs to.
 * The account ID is of interest only when using the dc_accounts_t account manager.
 * To get the context object belonging to the event, use dc_accounts_get_account().
 *
 * @memberof dc_event_t
 * @param event The event object as returned from dc_get_next_event().
 * @return The account ID belonging to the event, 0 for account manager errors.
 */
uint32_t dc_event_get_account_id(dc_event_t* event);


/**
 * Free memory used by an event object.
 * If you forget to do this for an event, this will result in memory leakage.
 *
 * @memberof dc_event_t
 * @param event Event object as returned from dc_get_next_event().
 */
void dc_event_unref(dc_event_t* event);


/**
 * @defgroup DC_EVENT DC_EVENT
 *
 * These constants are used as event ID
 * in events returned by dc_get_next_event().
 *
 * Events typically come with some additional data,
 * use dc_event_get_data1_int(), dc_event_get_data2_int() and dc_event_get_data2_str() to read this data.
 * The meaning of the data depends on the event.
 *
 * @addtogroup DC_EVENT
 * @{
 */

/**
 * The library-user may write an informational string to the log.
 *
 * This event should not be reported to the end-user using a popup or something like that.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_INFO                     100


/**
 * Emitted when SMTP connection is established and login was successful.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_SMTP_CONNECTED           101


/**
 * Emitted when IMAP connection is established and login was successful.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_IMAP_CONNECTED           102

/**
 * Emitted when a message was successfully sent to the SMTP server.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_SMTP_MESSAGE_SENT        103

/**
 * Emitted when a message was successfully marked as deleted on the IMAP server.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_IMAP_MESSAGE_DELETED   104

/**
 * Emitted when a message was successfully moved on IMAP.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_IMAP_MESSAGE_MOVED   105

/**
 * Emitted before going into IDLE on the Inbox folder.
 *
 * @param data1 0
 * @param data2 0
 */
#define DC_EVENT_IMAP_INBOX_IDLE 106

/**
 * Emitted when a new blob file was successfully written
 *
 * @param data1 0
 * @param data2 (char*) Path name
 */
#define DC_EVENT_NEW_BLOB_FILE 150

/**
 * Emitted when a blob file was successfully deleted
 *
 * @param data1 0
 * @param data2 (char*) Path name
 */
#define DC_EVENT_DELETED_BLOB_FILE 151

/**
 * The library-user should write a warning string to the log.
 *
 * This event should not be reported to the end-user using a popup or something like that.
 *
 * @param data1 0
 * @param data2 (char*) Warning string in English language.
 */
#define DC_EVENT_WARNING                  300


/**
 * The library-user should report an error to the end-user.
 *
 * As most things are asynchronous, things may go wrong at any time and the user
 * should not be disturbed by a dialog or so. Instead, use a bubble or so.
 *
 * However, for ongoing processes (e.g. dc_configure())
 * or for functions that are expected to fail (e.g. dc_continue_key_transfer())
 * it might be better to delay showing these events until the function has really
 * failed (returned false). It should be sufficient to report only the _last_ error
 * in a message box then.
 *
 * @param data1 0
 * @param data2 (char*) Error string, always set, never NULL.
 *     Some error strings are taken from dc_set_stock_translation(),
 *     however, most error strings will be in English language.
 */
#define DC_EVENT_ERROR                    400


/**
 * An action cannot be performed because the user is not in the group.
 * Reported e.g. after a call to
 * dc_set_chat_name(), dc_set_chat_profile_image(),
 * dc_add_contact_to_chat(), dc_remove_contact_from_chat(),
 * dc_send_text_msg() or another sending function.
 *
 * @param data1 0
 * @param data2 (char*) Info string in English language.
 */
#define DC_EVENT_ERROR_SELF_NOT_IN_GROUP  410


/**
 * Messages or chats changed. One or more messages or chats changed for various
 * reasons in the database:
 * - Messages have been sent, received or removed.
 * - Chats have been created, deleted or archived.
 * - A draft has been set.
 *
 * @param data1 (int) chat_id if only a single chat is affected by the changes, otherwise 0.
 * @param data2 (int) msg_id if only a single message is affected by the changes, otherwise 0.
 */
#define DC_EVENT_MSGS_CHANGED             2000


/**
 * Message reactions changed.
 *
 * @param data1 (int) chat_id ID of the chat affected by the changes.
 * @param data2 (int) msg_id ID of the message for which reactions were changed.
 */
#define DC_EVENT_REACTIONS_CHANGED        2001


/**
 * A reaction to one's own sent message received.
 * Typically, the UI will show a notification for that.
 *
 * In addition to this event, DC_EVENT_REACTIONS_CHANGED is emitted.
 *
 * @param data1 (int) contact_id ID of the contact sending this reaction.
 * @param data2 (int) msg_id + (char*) reaction.
 *      ID of the message for which a reaction was received in dc_event_get_data2_int(),
 *      and the reaction as dc_event_get_data2_str().
 *      string must be passed to dc_str_unref() afterwards.
 */
#define DC_EVENT_INCOMING_REACTION        2002



/**
 * A webxdc wants an info message or a changed summary to be notified.
 *
 * @param data1 (int) contact_id ID _and_ (char*) href.
 *      - dc_event_get_data1_int() returns contact_id of the sending contact.
 *      - dc_event_get_data1_str() returns the href as set to `update.href`.
 * @param data2 (int) msg_id _and_ (char*) text_to_notify.
 *      - dc_event_get_data2_int() returns the msg_id,
 *        referring to the webxdc-info-message, if there is any.
 *        Sometimes no webxdc-info-message is added to the chat
 *        and yet a notification is sent; in this case the msg_id
 *        of the webxdc instance is returned.
 *      - dc_event_get_data2_str() returns text_to_notify,
 *        the text that shall be shown in the notification.
 *        string must be passed to dc_str_unref() afterwards.
 */
#define DC_EVENT_INCOMING_WEBXDC_NOTIFY   2003


/**
 * There is a fresh message. Typically, the user will show an notification
 * when receiving this message.
 *
 * There is no extra #DC_EVENT_MSGS_CHANGED event send together with this event.
 *
 * If the message is a webxdc info message,
 * dc_msg_get_parent() returns the webxdc instance the notification belongs to.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) msg_id
 */
#define DC_EVENT_INCOMING_MSG             2005

/**
 * Downloading a bunch of messages just finished. This is an
 * event to allow the UI to only show one notification per message bunch,
 * instead of cluttering the user with many notifications.
 * UI may store #DC_EVENT_INCOMING_MSG events
 * and display notifications for all messages at once
 * when this event arrives.
 * 
 * @param data1 0
 * @param data2 0
 */
#define DC_EVENT_INCOMING_MSG_BUNCH       2006


/**
 * Messages were marked noticed or seen.
 * The UI may update badge counters or stop showing a chatlist-item with a bold font.
 *
 * This event is emitted e.g. when calling dc_markseen_msgs() or dc_marknoticed_chat()
 * or when a chat is answered on another device.
 * Do not try to derive the state of an item from just the fact you received the event;
 * use e.g. dc_msg_get_state() or dc_get_fresh_msg_cnt() for this purpose.
 *
 * @param data1 (int) chat_id
 * @param data2 0
 */
#define DC_EVENT_MSGS_NOTICED             2008


/**
 * A single message is sent successfully. State changed from @ref DC_STATE_OUT_PENDING to
 * @ref DC_STATE_OUT_DELIVERED.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) msg_id
 */
#define DC_EVENT_MSG_DELIVERED            2010


/**
 * A single message could not be sent.
 * State changed from @ref DC_STATE_OUT_PENDING, @ref DC_STATE_OUT_DELIVERED or @ref DC_STATE_OUT_MDN_RCVD
 * to @ref DC_STATE_OUT_FAILED.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) msg_id
 */
#define DC_EVENT_MSG_FAILED               2012


/**
 * A single message is read by the receiver. State changed from @ref DC_STATE_OUT_DELIVERED to
 * @ref DC_STATE_OUT_MDN_RCVD.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) msg_id
 */
#define DC_EVENT_MSG_READ                 2015


/**
 * A single message is deleted.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) msg_id
 */
#define DC_EVENT_MSG_DELETED              2016


/**
 * Chat changed. The name or the image of a chat group was changed or members were added or removed.
 * See dc_set_chat_name(), dc_set_chat_profile_image(), dc_add_contact_to_chat()
 * and dc_remove_contact_from_chat().
 *
 * @param data1 (int) chat_id
 * @param data2 0
 */
#define DC_EVENT_CHAT_MODIFIED            2020

/**
 * Chat ephemeral timer changed.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) The timer value in seconds or 0 for disabled timer.
 */
#define DC_EVENT_CHAT_EPHEMERAL_TIMER_MODIFIED 2021


/**
 * Chat was deleted.
 * This event is emitted in response to dc_delete_chat()
 * called on this or another device.
 * The event is a good place to remove notifications or homescreen shortcuts.
 *
 * @param data1 (int) chat_id
 * @param data2 (int) 0
 */
#define DC_EVENT_CHAT_DELETED             2023


/**
 * Contact(s) created, renamed, verified, blocked or deleted.
 *
 * @param data1 (int) contact_id of the changed contact or 0 on batch-changes or deletion.
 * @param data2 0
 */
#define DC_EVENT_CONTACTS_CHANGED         2030



/**
 * Location of one or more contact has changed.
 *
 * @param data1 (int) contact_id of the contact for which the location has changed.
 *     If the locations of several contacts have been changed,
 *     e.g. after calling dc_delete_all_locations(), this parameter is set to 0.
 * @param data2 0
 */
#define DC_EVENT_LOCATION_CHANGED         2035


/**
 * Inform about the configuration progress started by dc_configure().
 *
 * @param data1 (int) 0=error, 1-999=progress in permille, 1000=success and done.
 * @param data2 (char*) A progress comment, error message or NULL if not applicable.
 */
#define DC_EVENT_CONFIGURE_PROGRESS       2041


/**
 * Inform about the import/export progress started by dc_imex().
 *
 * @param data1 (int) 0=error, 1-999=progress in permille, 1000=success and done
 * @param data2 0
 */
#define DC_EVENT_IMEX_PROGRESS            2051


/**
 * A file has been exported. A file has been written by dc_imex().
 * This event may be sent multiple times by a single call to dc_imex().
 *
 * A typical purpose for a handler of this event may be to make the file public to some system
 * services.
 *
 * @param data1 0
 * @param data2 (char*) The path and the file name.
 */
#define DC_EVENT_IMEX_FILE_WRITTEN        2052


/**
 * Progress information of a secure-join handshake from the view of the inviter
 * (Alice, the person who shows the QR code).
 *
 * These events are typically sent after a joiner has scanned the QR code
 * generated by dc_get_securejoin_qr().
 *
 * @param data1 (int) The ID of the contact that wants to join.
 * @param data2 (int) The progress, always 1000.
 */
#define DC_EVENT_SECUREJOIN_INVITER_PROGRESS      2060


/**
 * Progress information of a secure-join handshake from the view of the joiner
 * (Bob, the person who scans the QR code).
 *
 * The events are typically sent while dc_join_securejoin(), which
 * may take some time, is executed.
 *
 * @param data1 (int) The ID of the inviting contact.
 * @param data2 (int) The progress as:
 *     400=vg-/vc-request-with-auth sent, typically shown as "alice@addr verified, introducing myself."
 *     (Bob has verified alice and waits until Alice does the same for him)
 *     1000=vg-member-added/vc-contact-confirm received
 */
#define DC_EVENT_SECUREJOIN_JOINER_PROGRESS       2061


/**
 * The connectivity to the server changed.
 * This means that you should refresh the connectivity view
 * and possibly the connectivtiy HTML; see dc_get_connectivity() and
 * dc_get_connectivity_html() for details.
 *
 * @param data1 0
 * @param data2 0
 */
#define DC_EVENT_CONNECTIVITY_CHANGED             2100


/**
 * The user's avatar changed.
 * You can get the new avatar file with `dc_get_config(context, "selfavatar")`.
 */
#define DC_EVENT_SELFAVATAR_CHANGED               2110


/**
 * A multi-device synced config value changed. Maybe the app needs to refresh smth. For uniformity
 * this is emitted on the source device too. The value isn't reported, otherwise it would be logged
 * which might not be good for privacy. You can get the new value with
 * `dc_get_config(context, data2)`.
 *
 * @param data1 0
 * @param data2 (char*) Configuration key.
 */
#define DC_EVENT_CONFIG_SYNCED                    2111


/**
 * Webxdc status update received.
 * To get the received status update, use dc_get_webxdc_status_updates() with
 * `serial` set to the last known update
 * (in case of special bots, `status_update_serial` from `data2`
 * may help to calculate the last known update for dc_get_webxdc_status_updates();
 * UIs must not peek at this parameter to avoid races in the status replication
 * eg. when events arrive while initial updates are played back).
 *
 * To send status updates, use dc_send_webxdc_status_update().
 *
 * @param data1 (int) msg_id
 * @param data2 (int) status_update_serial - must not be used by UI implementations.
 */
#define DC_EVENT_WEBXDC_STATUS_UPDATE             2120

/**
 * Message deleted which contained a webxdc instance.
 *
 * @param data1 (int) msg_id
 */

#define DC_EVENT_WEBXDC_INSTANCE_DELETED          2121

/**
 * Data received over an ephemeral peer channel.
 *
 * @param data1 (int) msg_id
 * @param data2 (int) + (char*) binary data.
 *     length is returned as integer with dc_event_get_data2_int()
 *     and binary data is returned as dc_event_get_data2_str().
 *     Binary data must be passed to dc_str_unref() afterwards.
 */

#define DC_EVENT_WEBXDC_REALTIME_DATA             2150

/**
 * Advertisement for ephemeral peer channel communication received.
 * This can be used by bots to initiate peer-to-peer communication from their side.
 * @param data1 (int) msg_id
 * @param data2 0
 */

#define DC_EVENT_WEBXDC_REALTIME_ADVERTISEMENT    2151

/**
 * Tells that the Background fetch was completed (or timed out).
 *
 * This event acts as a marker, when you reach this event you can be sure
 * that all events emitted during the background fetch were processed.
 * 
 * This event is only emitted by the account manager
 */

#define DC_EVENT_ACCOUNTS_BACKGROUND_FETCH_DONE   2200

/**
 * Inform that set of chats or the order of the chats in the chatlist has changed.
 *
 * Sometimes this is emitted together with `DC_EVENT_CHATLIST_ITEM_CHANGED`.
 */

#define DC_EVENT_CHATLIST_CHANGED              2300

/**
 * Inform that all or a single chat list item changed and needs to be rerendered
 * If `chat_id` is set to 0, then all currently visible chats need to be rerendered, and all not-visible items need to be cleared from cache if the UI has a cache.
 * 
 * @param data1 (int) chat_id chat id of chatlist item to be rerendered, if chat_id = 0 all (cached & visible) items need to be rerendered
 */

#define DC_EVENT_CHATLIST_ITEM_CHANGED         2301

/**
 * Inform that the list of accounts has changed (an account removed or added or (not yet implemented) the account order changes)
 *
 * This event is only emitted by the account manager.
 */

#define DC_EVENT_ACCOUNTS_CHANGED              2302

/**
 * Inform that an account property that might be shown in the account list changed, namely:
 * - is_configured (see dc_is_configured())
 * - displayname
 * - selfavatar
 * - private_tag
 * 
 * This event is emitted from the account whose property changed.
 */

#define DC_EVENT_ACCOUNTS_ITEM_CHANGED         2303

/**
 * Inform that some events have been skipped due to event channel overflow.
 *
 * @param data1 (int) number of events that have been skipped
 */
#define DC_EVENT_CHANNEL_OVERFLOW              2400



/**
 * Incoming call.
 * UI will usually start ringing,
 * or show a notification if there is already a call in some profile.
 *
 * Together with this event,
 * a message of type #DC_MSG_CALL is added to the corresponding chat;
 * this message is announced and updated by the usual event as #DC_EVENT_MSGS_CHANGED,
 * there is usually no need to take care of this message from any of the CALL events.
 *
 * If user takes action, dc_accept_incoming_call() or dc_end_call() should be called.
 *
 * Otherwise, ringing should end on #DC_EVENT_CALL_ENDED
 * or #DC_EVENT_INCOMING_CALL_ACCEPTED
 *
 * @param data1 (int) msg_id ID of the message referring to the call.
 * @param data2 (char*) place_call_info, text passed to dc_place_outgoing_call()
 * @param data2 (int) 1 if incoming call is a video call, 0 otherwise
 */
#define DC_EVENT_INCOMING_CALL                            2550

/**
 * The callee accepted an incoming call on this or another device using dc_accept_incoming_call().
 * The caller gets the event #DC_EVENT_OUTGOING_CALL_ACCEPTED at the same time.
 *
 * UI usually only takes action in case call UI was opened before, otherwise the event should be ignored.
 *
 * @param data1 (int) msg_id ID of the message referring to the call
 */
 #define DC_EVENT_INCOMING_CALL_ACCEPTED                  2560

/**
 * A call placed using dc_place_outgoing_call() was accepted by the callee using dc_accept_incoming_call().
 *
 * UI usually only takes action in case call UI was opened before, otherwise the event should be ignored.
 *
 * @param data1 (int) msg_id ID of the message referring to the call
 * @param data2 (char*) accept_call_info, text passed to dc_accept_incoming_call()
 */
#define DC_EVENT_OUTGOING_CALL_ACCEPTED                   2570

/**
 * An incoming or outgoing call was ended using dc_end_call() on this or another device, by caller or callee.
 * Moreover, the event is sent when the call was not accepted within 1 minute timeout.
 *
 * UI usually only takes action in case call UI was opened before, otherwise the event should be ignored.
 *
 * @param data1 (int) msg_id ID of the message referring to the call
 */
#define DC_EVENT_CALL_ENDED                               2580

/**
 * Transport relay added/deleted or default has changed.
 * UI should update the list.
 *
 * The event is emitted when the transports are modified on another device
 * using the JSON-RPC calls `add_or_update_transport`, `add_transport_from_qr`, `delete_transport`
 * or `set_config(configured_addr)`.
 */
#define DC_EVENT_TRANSPORTS_MODIFIED           2600


/**
 * @}
 */


#define DC_EVENT_DATA1_IS_STRING(e)  0    // not used anymore 
#define DC_EVENT_DATA2_IS_STRING(e)  ((e)==DC_EVENT_CONFIGURE_PROGRESS || (e)==DC_EVENT_IMEX_FILE_WRITTEN || ((e)>=100 && (e)<=499))


/*
 * Values for dc_get|set_config("show_emails")
 */
#define DC_SHOW_EMAILS_OFF               0
#define DC_SHOW_EMAILS_ACCEPTED_CONTACTS 1
#define DC_SHOW_EMAILS_ALL               2


/*
 * Values for dc_get|set_config("media_quality")
 */
#define DC_MEDIA_QUALITY_BALANCED 0
#define DC_MEDIA_QUALITY_WORSE    1


/**
 * @defgroup DC_PROVIDER_STATUS DC_PROVIDER_STATUS
 *
 * These constants are used as return values for dc_provider_get_status().
 *
 * @addtogroup DC_PROVIDER_STATUS
 * @{
 */

/**
 * Provider works out-of-the-box.
 * This provider status is returned for provider where the login
 * works by just entering the name or the e-mail address.
 *
 * - There is no need for the user to do any special things
 *   (enable IMAP or so) in the provider's web interface or at other places.
 * - There is no need for the user to enter advanced settings;
 *   server, port etc. are known by the core.
 *
 * The status is returned by dc_provider_get_status().
 */
#define         DC_PROVIDER_STATUS_OK           1

/**
 * Provider works, but there are preparations needed.
 *
 * - The user has to do some special things as "Enable IMAP in the web interface",
 *   what exactly, is described in the string returned by dc_provider_get_before_login_hints()
 *   and, typically more detailed, in the page linked by dc_provider_get_overview_page().
 * - There is no need for the user to enter advanced settings;
 *   server, port etc. should be known by the core.
 *
 * The status is returned by dc_provider_get_status().
 */
#define         DC_PROVIDER_STATUS_PREPARATION  2

/**
 * Provider is not working.
 * This provider status is returned for providers
 * that are known to not work with Delta Chat.
 * The UI should block logging in with this provider.
 *
 * More information about that is typically provided
 * in the string returned by dc_provider_get_before_login_hints()
 * and in the page linked by dc_provider_get_overview_page().
 *
 * The status is returned by dc_provider_get_status().
 */
#define         DC_PROVIDER_STATUS_BROKEN       3

/**
 * @}
 */


/**
 * @defgroup DC_CHAT_VISIBILITY DC_CHAT_VISIBILITY
 *
 * These constants describe the visibility of a chat.
 * The chat visibility can be get using dc_chat_get_visibility()
 * and set using dc_set_chat_visibility().
 *
 * @addtogroup DC_CHAT_VISIBILITY
 * @{
 */

/**
 * Chats with normal visibility are not archived and are shown below all pinned chats.
 * Archived chats, that receive new messages automatically become normal chats.
 */
#define         DC_CHAT_VISIBILITY_NORMAL      0

/**
 * Archived chats are not included in the default chatlist returned by dc_get_chatlist().
 * Instead, if there are _any_ archived chats, the pseudo-chat
 * with the chat ID DC_CHAT_ID_ARCHIVED_LINK will be added at the end of the chatlist.
 *
 * The UI typically shows a little icon or chats beside archived chats in the chatlist,
 * this is needed as e.g. the search will also return archived chats.
 *
 * If archived chats receive new messages, they become normal chats again.
 *
 * To get a list of archived chats, use dc_get_chatlist() with the flag DC_GCL_ARCHIVED_ONLY.
 */
#define         DC_CHAT_VISIBILITY_ARCHIVED    1

/**
 * Pinned chats are included in the default chatlist. moreover,
 * they are always the first items, whether they have fresh messages or not.
 */
#define         DC_CHAT_VISIBILITY_PINNED      2

/**
 * @}
 */


/**
  * @defgroup DC_DOWNLOAD DC_DOWNLOAD
  *
  * These constants describe the download state of a message.
  * The download state can be retrieved using dc_msg_get_download_state()
  * and usually changes after calling dc_download_full_msg().
  *
  * @addtogroup DC_DOWNLOAD
  * @{
  */

/**
 * Download not needed, see dc_msg_get_download_state() for details.
 */
#define DC_DOWNLOAD_DONE           0

/**
 * Download available, see dc_msg_get_download_state() for details.
 */
#define DC_DOWNLOAD_AVAILABLE      10

/**
 * Download failed, see dc_msg_get_download_state() for details.
 */
#define DC_DOWNLOAD_FAILURE        20

/**
 * Download not needed, see dc_msg_get_download_state() for details.
 */
#define DC_DOWNLOAD_UNDECIPHERABLE 30

/**
 * Download in progress, see dc_msg_get_download_state() for details.
 */
#define DC_DOWNLOAD_IN_PROGRESS    1000



/**
 * @}
 */


/**
 * @defgroup DC_STR DC_STR
 *
 * These constants are used to define strings using dc_set_stock_translation().
 * This allows localisation of the texts used by the core,
 * you have to call dc_set_stock_translation()
 * for every @ref DC_STR string you want to translate.
 *
 * Some strings contain some placeholders as `%1$s` or `%2$s` -
 * these will be replaced by some content defined in the @ref DC_STR description below.
 * As a synonym for `%1$s` you can also use `%1$d` or `%1$@`; same for `%2$s`.
 *
 * If you do not call dc_set_stock_translation() for a concrete @ref DC_STR constant,
 * a default string will be used.
 *
 * @addtogroup DC_STR
 * @{
 */

/// "No messages."
///
/// Used in summaries.
#define DC_STR_NOMESSAGES                 1

/// "Me"
///
/// Used as the sender name for oneself.
#define DC_STR_SELF                       2

/// "Draft"
///
/// Used in summaries.
#define DC_STR_DRAFT                      3

/// "Voice message"
///
/// Used in summaries.
#define DC_STR_VOICEMESSAGE               7

/// "Image"
///
/// Used in summaries.
#define DC_STR_IMAGE                      9

/// "Video"
///
/// Used in summaries.
#define DC_STR_VIDEO                      10

/// "Audio"
///
/// Used in summaries.
#define DC_STR_AUDIO                      11

/// "File"
///
/// Used in summaries.
#define DC_STR_FILE                       12

/// "GIF"
///
/// Used in summaries.
#define DC_STR_GIF                        23

/// "End-to-end encryption available."
///
/// @deprecated 2026-01-23
#define DC_STR_E2E_AVAILABLE              25

/// "No encryption."
///
/// Used to build the string returned by dc_get_contact_encrinfo().
#define DC_STR_ENCR_NONE                  28

/// "Fingerprints"
///
/// Used to build the string returned by dc_get_contact_encrinfo().
#define DC_STR_FINGERPRINTS               30

/// "%1$s verified"
///
/// Used in status messages.
/// - %1$s will be replaced by the name of the verified contact
#define DC_STR_CONTACT_VERIFIED           35

/// "Archived chats"
///
/// Used as the name for the corresponding chatlist entry.
#define DC_STR_ARCHIVEDCHATS              40

/// "Cannot login as %1$s."
///
/// Used in error strings.
/// - %1$s will be replaced by the failing login name
#define DC_STR_CANNOT_LOGIN               60

/// "Location streaming enabled."
///
/// Used in status messages.
#define DC_STR_MSGLOCATIONENABLED         64

/// "Location streaming disabled."
///
/// Used in status messages.
#define DC_STR_MSGLOCATIONDISABLED        65

/// "Location"
///
/// Used in summaries.
#define DC_STR_LOCATION                   66

/// "Sticker"
///
/// Used in summaries.
#define DC_STR_STICKER                    67

/// "Device messages"
///
/// Used as the name for the corresponding chat.
#define DC_STR_DEVICE_MESSAGES            68

/// "Saved messages"
///
/// Used as the name for the corresponding chat.
#define DC_STR_SAVED_MESSAGES             69

/// "Messages in this chat are generated locally by your Delta Chat app."
///
/// Used as message text for the message added to a newly created device chat.
#define DC_STR_DEVICE_MESSAGES_HINT       70

/// "Welcome to Delta Chat! Delta Chat looks and feels like other popular messenger apps ..."
///
/// Used as message text for the message added to the device chat after successful login.
#define DC_STR_WELCOME_MESSAGE            71

/// "Message from %1$s"
///
/// Used in subjects of outgoing messages in one-to-one chats.
/// - %1$s will be replaced by the name of the sender,
///   this is the dc_set_config()-option `displayname` or `addr`
#define DC_STR_SUBJECT_FOR_NEW_CONTACT    73

/// "Failed to send message to %1$s."
///
/// Unused. Was used in group chat status messages.
/// - %1$s will be replaced by the name of the contact the message cannot be sent to
#define DC_STR_FAILED_SENDING_TO          74

/// "Error: %1$s"
///
/// Used in error strings.
/// - %1$s will be replaced by the concrete error
#define DC_STR_CONFIGURATION_FAILED       84

/// "Date or time of your device seem to be inaccurate (%1$s). Adjust your clock to ensure your messages are received correctly."
///
/// Used as device message if a wrong date or time was detected.
/// - %1$s will be replaced by a date/time string as YY-mm-dd HH:MM:SS
#define DC_STR_BAD_TIME_MSG_BODY          85

/// "Your Delta Chat version might be outdated, check https://get.delta.chat for updates."
///
/// Used as device message if the used version is probably outdated.
#define DC_STR_UPDATE_REMINDER_MSG_BODY   86

/// "No network."
///
/// Used in error strings.
#define DC_STR_ERROR_NO_NETWORK           87

/// "Reply"
///
/// Used in summaries.
/// Note: the string has to be a noun, not a verb (not: "to reply").
#define DC_STR_REPLY_NOUN                 90

/// "You deleted the 'Saved messages' chat..."
///
/// Used as device message text.
#define DC_STR_SELF_DELETED_MSG_BODY      91

/// "Forwarded"
///
/// Used in message summary text for notifications and chatlist.
#define DC_STR_FORWARDED                  97

/// "Quota exceeding, already %1$s%% used."
///
/// Used as device message text.
///
/// `%1$s` will be replaced by the percentage used
#define DC_STR_QUOTA_EXCEEDING_MSG_BODY   98

/// "Multi Device Synchronization"
///
/// Used in subjects of outgoing sync messages.
#define DC_STR_SYNC_MSG_SUBJECT           101

/// "This message is used to synchronize data between your devices."
///
///
/// Used as message text of outgoing sync messages.
/// The text is visible in non-dc-muas or in outdated Delta Chat versions,
/// the default text therefore adds the following hint:
/// "If you see this message in Delta Chat,
/// please update your Delta Chat apps on all devices."
#define DC_STR_SYNC_MSG_BODY              102

/// "Incoming Messages"
///
/// Used as a headline in the connectivity view.
#define DC_STR_INCOMING_MESSAGES          103

/// "Outgoing Messages"
///
/// Used as a headline in the connectivity view.
#define DC_STR_OUTGOING_MESSAGES          104

/// "Connected"
///
/// Used as status in the connectivity view.
#define DC_STR_CONNECTED                  107

/// "Connecting…"
///
/// Used as status in the connectivity view.
#define DC_STR_CONNTECTING                108

/// "Updating…"
///
/// Used as status in the connectivity view.
#define DC_STR_UPDATING                   109

/// "Sending…"
///
/// Used as status in the connectivity view.
#define DC_STR_SENDING                    110

/// "Your last message was sent successfully."
///
/// Used as status in the connectivity view.
#define DC_STR_LAST_MSG_SENT_SUCCESSFULLY 111

/// "Error: %1$s"
///
/// Used as status in the connectivity view.
///
/// `%1$s` will be replaced by a possibly more detailed, typically english, error description.
#define DC_STR_ERROR                      112

/// "Not supported by your provider."
///
/// Used in the connectivity view.
#define DC_STR_NOT_SUPPORTED_BY_PROVIDER  113

/// "Messages"
///
/// Used as a subtitle in quota context; can be plural always.
#define DC_STR_MESSAGES                   114

/// "Broadcast List"
///
/// Used as the default name for broadcast lists; a number may be added.
#define DC_STR_BROADCAST_LIST             115

/// "%1$s of %2$s used"
///
/// Used for describing resource usage, resulting string will be e.g. "1.2 GiB of 3 GiB used".
#define DC_STR_PART_OF_TOTAL_USED         116

/// "%1$s invited you to join this group. Waiting for the device of %2$s to reply…"
///
/// Added as an info-message directly after scanning a QR code for joining a group.
/// May be followed by the info-messages
/// #DC_STR_SECURE_JOIN_REPLIES, #DC_STR_CONTACT_VERIFIED and #DC_STR_MSGADDMEMBER.
///
/// `%1$s` and `%2$s` will be replaced by name of the inviter.
#define DC_STR_SECURE_JOIN_STARTED        117

/// "%1$s replied, waiting for being added to the group…"
///
/// Info-message on scanning a QR code for joining a group.
/// Added after #DC_STR_SECURE_JOIN_STARTED.
/// If the handshake allows to skip a step and go for #DC_STR_CONTACT_VERIFIED directly,
/// this info-message is skipped.
///
/// `%1$s` will be replaced by the name of the inviter.
#define DC_STR_SECURE_JOIN_REPLIES        118

/// "Scan to chat with %1$s"
///
/// Subtitle for verification qrcode svg image generated by the core.
///
/// `%1$s` will be replaced by name of the inviter.
#define DC_STR_SETUP_CONTACT_QR_DESC      119

/// "Scan to join %1$s"
///
/// Subtitle for group join qrcode svg image generated by the core.
///
/// `%1$s` will be replaced with the group name.
#define DC_STR_SECURE_JOIN_GROUP_QR_DESC  120

/// "Not connected"
///
/// Used as status in the connectivity view.
#define DC_STR_NOT_CONNECTED              121

/// "You changed group name from \"%1$s\" to \"%2$s\"."
///
/// `%1$s` will be replaced by the old group name.
/// `%2$s` will be replaced by the new group name.
#define DC_STR_GROUP_NAME_CHANGED_BY_YOU 124

/// "Group name changed from \"%1$s\" to \"%2$s\" by %3$s."
///
/// `%1$s` will be replaced by the old group name.
/// `%2$s` will be replaced by the new group name.
/// `%3$s` will be replaced by name of the contact who did the action.
#define DC_STR_GROUP_NAME_CHANGED_BY_OTHER 125

/// "You changed the group image."
#define DC_STR_GROUP_IMAGE_CHANGED_BY_YOU 126

/// "Group image changed by %1$s."
///
/// `%1$s` will be replaced by name of the contact who did the action.
#define DC_STR_GROUP_IMAGE_CHANGED_BY_OTHER 127

/// "You added member %1$s."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the added member's name.
#define DC_STR_ADD_MEMBER_BY_YOU 128

/// "Member %1$s added by %2$s."
///
/// `%1$s` will be replaced by name of the contact added to the group.
/// `%2$s` will be replaced by name of the contact who did the action.
///
/// Used in status messages.
#define DC_STR_ADD_MEMBER_BY_OTHER 129

/// "You removed member %1$s."
///
/// `%1$s` will be replaced by name of the contact removed from the group.
///
/// Used in status messages.
#define DC_STR_REMOVE_MEMBER_BY_YOU 130

/// "Member %1$s removed by %2$s."
///
/// `%1$s` will be replaced by name of the contact removed from the group.
/// `%2$s` will be replaced by name of the contact who did the action.
///
/// Used in status messages.
#define DC_STR_REMOVE_MEMBER_BY_OTHER 131

/// "You left the group."
///
/// Used in status messages.
#define DC_STR_GROUP_LEFT_BY_YOU 132

/// "Group left by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_GROUP_LEFT_BY_OTHER 133

/// "You deleted the group image."
///
/// Used in status messages.
#define DC_STR_GROUP_IMAGE_DELETED_BY_YOU 134

/// "Group image deleted by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_GROUP_IMAGE_DELETED_BY_OTHER 135

/// "You enabled location streaming."
///
/// Used in status messages.
#define DC_STR_LOCATION_ENABLED_BY_YOU 136

/// "Location streaming enabled by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_LOCATION_ENABLED_BY_OTHER 137

/// "You disabled message deletion timer."
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_DISABLED_BY_YOU 138

/// "Message deletion timer is disabled by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_DISABLED_BY_OTHER 139

/// "You set message deletion timer to %1$s s."
///
/// `%1$s` will be replaced by the number of seconds (always >1) the timer is set to.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_SECONDS_BY_YOU 140

/// "Message deletion timer is set to %1$s s by %2$s."
///
/// `%1$s` will be replaced by the number of seconds (always >1) the timer is set to.
/// `%2$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_SECONDS_BY_OTHER 141

/// "You set message deletion timer to 1 hour."
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_HOUR_BY_YOU 144

/// "Message deletion timer is set to 1 hour by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_HOUR_BY_OTHER 145

/// "You set message deletion timer to 1 day."
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_DAY_BY_YOU 146

/// "Message deletion timer is set to 1 day by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_DAY_BY_OTHER 147

/// "You set message deletion timer to 1 week."
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_WEEK_BY_YOU 148

/// "Message deletion timer is set to 1 week by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_WEEK_BY_OTHER 149

/// "You set message deletion timer to %1$s minutes."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of minutes (always >1) the timer is set to.
#define DC_STR_EPHEMERAL_TIMER_MINUTES_BY_YOU 150

/// "Message deletion timer is set to %1$s minutes by %2$s."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of minutes (always >1) the timer is set to.
/// `%2$s` will be replaced by name of the contact.
#define DC_STR_EPHEMERAL_TIMER_MINUTES_BY_OTHER 151

/// "You set message deletion timer to %1$s hours."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of hours (always >1) the timer is set to.
#define DC_STR_EPHEMERAL_TIMER_HOURS_BY_YOU 152

/// "Message deletion timer is set to %1$s hours by %2$s."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of hours (always >1) the timer is set to.
/// `%2$s` will be replaced by name of the contact.
#define DC_STR_EPHEMERAL_TIMER_HOURS_BY_OTHER 153

/// "You set message deletion timer to %1$s days."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of days (always >1) the timer is set to.
#define DC_STR_EPHEMERAL_TIMER_DAYS_BY_YOU 154

/// "Message deletion timer is set to %1$s days by %2$s."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of days (always >1) the timer is set to.
/// `%2$s` will be replaced by name of the contact.
#define DC_STR_EPHEMERAL_TIMER_DAYS_BY_OTHER 155

/// "You set message deletion timer to %1$s weeks."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of weeks (always >1) the timer is set to.
#define DC_STR_EPHEMERAL_TIMER_WEEKS_BY_YOU 156

/// "Message deletion timer is set to %1$s weeks by %2$s."
///
/// Used in status messages.
///
/// `%1$s` will be replaced by the number of weeks (always >1) the timer is set to.
/// `%2$s` will be replaced by name of the contact.
#define DC_STR_EPHEMERAL_TIMER_WEEKS_BY_OTHER 157

/// "You set message deletion timer to 1 year."
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_YEAR_BY_YOU 158

/// "Message deletion timer is set to 1 year by %1$s."
///
/// `%1$s` will be replaced by name of the contact.
///
/// Used in status messages.
#define DC_STR_EPHEMERAL_TIMER_1_YEAR_BY_OTHER 159

/// "Scan to set up second device for %1$s"
///
/// `%1$s` will be replaced by name of the account.
#define DC_STR_BACKUP_TRANSFER_QR 162

/// "Account transferred to your second device."
///
/// Used as a device message after a successful backup transfer.
#define DC_STR_BACKUP_TRANSFER_MSG_BODY 163

/// "Messages are end-to-end encrypted."
///
/// Used in info messages.
#define DC_STR_CHAT_PROTECTION_ENABLED 170

/// "Others will only see this group after you sent a first message."
///
/// Used as the first info messages in newly created groups.
#define DC_STR_NEW_GROUP_SEND_FIRST_MESSAGE 172

/// "Member %1$s added."
///
/// Used as info messages.
///
/// `%1$s` will be replaced by the added member's name.
#define DC_STR_MESSAGE_ADD_MEMBER 173

/// "Your email provider %1$s requires end-to-end encryption which is not setup yet."
///
/// Used as info messages when a message cannot be sent because it cannot be encrypted.
///
/// `%1$s` will be replaced by the provider's domain.
#define DC_STR_INVALID_UNENCRYPTED_MAIL 174

/// "You reacted %1$s to '%2$s'"
///
/// `%1$s` will be replaced by the reaction, usually an emoji
/// `%2$s` will be replaced by the summary of the message the reaction refers to
///
/// Used in summaries.
#define DC_STR_YOU_REACTED 176

/// "%1$s reacted %2$s to '%3$s'"
///
/// `%1$s` will be replaced by the name the contact who reacted
/// `%2$s` will be replaced by the reaction, usually an emoji
/// `%3$s` will be replaced by the summary of the message the reaction refers to
///
/// Used in summaries.
#define DC_STR_REACTED_BY 177

/// "Member %1$s removed."
///
/// `%1$s` will be replaced by name of the removed contact.
#define DC_STR_REMOVE_MEMBER 178

/// "Establishing connection, please wait…"
///
/// Used as info message.
#define DC_STR_SECUREJOIN_WAIT 190

/// "❤️ Seems you're enjoying Delta Chat!"… (donation request device message)
#define DC_STR_DONATION_REQUEST 193

/// "Declined call"
#define DC_STR_DECLINED_CALL 196

/// "Canceled call"
#define DC_STR_CANCELED_CALL 197

/// "Missed call"
#define DC_STR_MISSED_CALL 198

/// "You left the channel."
///
/// Used in status messages.
#define DC_STR_CHANNEL_LEFT_BY_YOU 200

/// "Scan to join channel %1$s"
///
/// Subtitle for channel join qrcode svg image generated by the core.
///
/// `%1$s` will be replaced with the channel name.
#define DC_STR_SECURE_JOIN_CHANNEL_QR_DESC 201

/// "You joined the channel."
#define DC_STR_MSG_YOU_JOINED_CHANNEL 202

/// "%1$s invited you to join this channel. Waiting for the device of %2$s to reply…"
///
/// Added as an info-message directly after scanning a QR code for joining a broadcast channel.
///
/// `%1$s` and `%2$s` will both be replaced by the name of the inviter.
#define DC_STR_SECURE_JOIN_CHANNEL_STARTED 203

/// "The attachment contains anonymous usage statistics, which help us improve Delta Chat. Thank you!"
///
/// Used as the message body for statistics sent out.
#define DC_STR_STATS_MSG_BODY 210

/// "Proxy Enabled"
///
/// Title for proxy section in connectivity view.
#define DC_STR_PROXY_ENABLED  220

/// "You are using a proxy. If you're having trouble connecting, try a different proxy."
///
/// Description in connectivity view when proxy is enabled.
#define DC_STR_PROXY_ENABLED_DESCRIPTION  221

/// "Messages in this chat use classic email and are not encrypted."
///
/// Used as the first info messages in newly created classic email threads.
#define DC_STR_CHAT_UNENCRYPTED_EXPLANATON 230

/// "Outgoing audio call"
#define DC_STR_OUTGOING_AUDIO_CALL 232

/// "Outgoing video call"
#define DC_STR_OUTGOING_VIDEO_CALL 233

/// "Incoming audio call"
#define DC_STR_INCOMING_AUDIO_CALL 234

/// "Incoming video call"
#define DC_STR_INCOMING_VIDEO_CALL 235

/// "You changed the chat description."
#define DC_STR_GROUP_DESCRIPTION_CHANGED_BY_YOU 240

/// "Chat description changed by %1$s."
#define DC_STR_GROUP_DESCRIPTION_CHANGED_BY_OTHER 241

/**
 * @}
 */


#ifdef PY_CFFI_INC
/* Helper utility to locate the header file when building python bindings. */
char* _dc_header_file_location(void) {
    return __FILE__;
}
#endif


#ifdef __cplusplus
}
#endif
#endif // __DELTACHAT_H__
