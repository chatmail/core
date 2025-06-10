use deltachat_contact_tools::may_be_valid_addr;

use super::*;
use crate::chat::{get_chat_contacts, send_text_msg, Chat};
use crate::chatlist::Chatlist;
use crate::receive_imf::receive_imf;
use crate::test_utils::{self, TestContext, TestContextManager, TimeShiftFalsePositiveNote};

#[test]
fn test_contact_id_values() {
    // Some FFI users need to have the values of these fixed, how naughty.  But let's
    // make sure we don't modify them anyway.
    assert_eq!(ContactId::UNDEFINED.to_u32(), 0);
    assert_eq!(ContactId::SELF.to_u32(), 1);
    assert_eq!(ContactId::INFO.to_u32(), 2);
    assert_eq!(ContactId::DEVICE.to_u32(), 5);
    assert_eq!(ContactId::LAST_SPECIAL.to_u32(), 9);
}

#[test]
fn test_may_be_valid_addr() {
    assert_eq!(may_be_valid_addr(""), false);
    assert_eq!(may_be_valid_addr("user@domain.tld"), true);
    assert_eq!(may_be_valid_addr("uuu"), false);
    assert_eq!(may_be_valid_addr("dd.tt"), false);
    assert_eq!(may_be_valid_addr("tt.dd@uu"), true);
    assert_eq!(may_be_valid_addr("u@d"), true);
    assert_eq!(may_be_valid_addr("u@d."), false);
    assert_eq!(may_be_valid_addr("u@d.t"), true);
    assert_eq!(may_be_valid_addr("u@d.tt"), true);
    assert_eq!(may_be_valid_addr("u@.tt"), true);
    assert_eq!(may_be_valid_addr("@d.tt"), false);
    assert_eq!(may_be_valid_addr("<da@d.tt"), false);
    assert_eq!(may_be_valid_addr("sk <@d.tt>"), false);
    assert_eq!(may_be_valid_addr("as@sd.de>"), false);
    assert_eq!(may_be_valid_addr("ask dkl@dd.tt"), false);
    assert_eq!(may_be_valid_addr("user@domain.tld."), false);
}

#[test]
fn test_normalize_addr() {
    assert_eq!(addr_normalize("mailto:john@doe.com"), "john@doe.com");
    assert_eq!(addr_normalize("  hello@world.com   "), "hello@world.com");
    assert_eq!(addr_normalize("John@Doe.com"), "john@doe.com");
}

#[test]
fn test_split_address_book() {
    let book = "Name one\nAddress one\nName two\nAddress two\nrest name";
    let list = split_address_book(book);
    assert_eq!(
        list,
        vec![("Name one", "Address one"), ("Name two", "Address two")]
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_contacts() -> Result<()> {
    let context = TestContext::new().await;

    assert!(context.get_all_self_addrs().await?.is_empty());

    // Bob is not in the contacts yet.
    let contacts = Contact::get_all(&context.ctx, 0, Some("bob")).await?;
    assert_eq!(contacts.len(), 0);

    let (id, _modified) = Contact::add_or_lookup(
        &context.ctx,
        "bob",
        &ContactAddress::new("user@example.org")?,
        Origin::IncomingReplyTo,
    )
    .await?;
    assert_ne!(id, ContactId::UNDEFINED);

    let contact = Contact::get_by_id(&context.ctx, id).await.unwrap();
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_authname(), "bob");
    assert_eq!(contact.get_display_name(), "bob");

    // Search by name.
    let contacts = Contact::get_all(&context.ctx, 0, Some("bob")).await?;
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts.first(), Some(&id));

    // Search by address.
    let contacts = Contact::get_all(&context.ctx, 0, Some("user")).await?;
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts.first(), Some(&id));

    let contacts = Contact::get_all(&context.ctx, 0, Some("alice")).await?;
    assert_eq!(contacts.len(), 0);

    // Set Bob name to "someone" manually.
    let (contact_bob_id, modified) = Contact::add_or_lookup(
        &context.ctx,
        "someone",
        &ContactAddress::new("user@example.org")?,
        Origin::ManuallyCreated,
    )
    .await?;
    assert_eq!(contact_bob_id, id);
    assert_eq!(modified, Modifier::Modified);
    let contact = Contact::get_by_id(&context.ctx, id).await.unwrap();
    assert_eq!(contact.get_name(), "someone");
    assert_eq!(contact.get_authname(), "bob");
    assert_eq!(contact.get_display_name(), "someone");

    // Not searchable by authname, because it is not displayed.
    let contacts = Contact::get_all(&context.ctx, 0, Some("bob")).await?;
    assert_eq!(contacts.len(), 0);

    // Search by display name (same as manually set name).
    let contacts = Contact::get_all(&context.ctx, 0, Some("someone")).await?;
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts.first(), Some(&id));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_is_self_addr() -> Result<()> {
    let t = TestContext::new().await;
    assert_eq!(t.is_self_addr("me@me.org").await?, false);

    t.configure_addr("you@you.net").await;
    assert_eq!(t.is_self_addr("me@me.org").await?, false);
    assert_eq!(t.is_self_addr("you@you.net").await?, true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_or_lookup() {
    // add some contacts, this also tests add_address_book()
    let t = TestContext::new().await;
    let book = concat!(
        "  Name one  \n one@eins.org \n",
        "Name two\ntwo@deux.net\n",
        "Invalid\n+1234567890\n", // invalid, should be ignored
        "\nthree@drei.sam\n",
        "Name two\ntwo@deux.net\n", // should not be added again
        "\nWonderland, Alice <alice@w.de>\n",
    );
    assert_eq!(Contact::add_address_book(&t, book).await.unwrap(), 4);

    // check first added contact, this modifies authname because it is empty
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "bla foo",
        &ContactAddress::new("one@eins.org").unwrap(),
        Origin::IncomingUnknownTo,
    )
    .await
    .unwrap();
    assert!(!contact_id.is_special());
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_id(), contact_id);
    assert_eq!(contact.get_name(), "Name one");
    assert_eq!(contact.get_authname(), "bla foo");
    assert_eq!(contact.get_display_name(), "Name one");
    assert_eq!(contact.get_addr(), "one@eins.org");
    assert_eq!(contact.get_name_n_addr(), "Name one (one@eins.org)");

    // modify first added contact
    let (contact_id_test, sth_modified) = Contact::add_or_lookup(
        &t,
        "Real one",
        &ContactAddress::new(" one@eins.org  ").unwrap(),
        Origin::ManuallyCreated,
    )
    .await
    .unwrap();
    assert_eq!(contact_id, contact_id_test);
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "Real one");
    assert_eq!(contact.get_addr(), "one@eins.org");
    assert!(!contact.is_blocked());

    // check third added contact (contact without name)
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "",
        &ContactAddress::new("three@drei.sam").unwrap(),
        Origin::IncomingUnknownTo,
    )
    .await
    .unwrap();
    assert!(!contact_id.is_special());
    assert_eq!(sth_modified, Modifier::None);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "three@drei.sam");
    assert_eq!(contact.get_addr(), "three@drei.sam");
    assert_eq!(contact.get_name_n_addr(), "three@drei.sam");

    // add name to third contact from incoming message (this becomes authorized name)
    let (contact_id_test, sth_modified) = Contact::add_or_lookup(
        &t,
        "m. serious",
        &ContactAddress::new("three@drei.sam").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    assert_eq!(contact_id, contact_id_test);
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name_n_addr(), "m. serious (three@drei.sam)");
    assert!(!contact.is_blocked());

    // manually edit name of third contact (does not changed authorized name)
    let (contact_id_test, sth_modified) = Contact::add_or_lookup(
        &t,
        "schnucki",
        &ContactAddress::new("three@drei.sam").unwrap(),
        Origin::ManuallyCreated,
    )
    .await
    .unwrap();
    assert_eq!(contact_id, contact_id_test);
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "m. serious");
    assert_eq!(contact.get_name_n_addr(), "schnucki (three@drei.sam)");
    assert!(!contact.is_blocked());

    // Fourth contact:
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "",
        &ContactAddress::new("alice@w.de").unwrap(),
        Origin::IncomingUnknownTo,
    )
    .await
    .unwrap();
    assert!(!contact_id.is_special());
    assert_eq!(sth_modified, Modifier::None);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "Wonderland, Alice");
    assert_eq!(contact.get_display_name(), "Wonderland, Alice");
    assert_eq!(contact.get_addr(), "alice@w.de");
    assert_eq!(contact.get_name_n_addr(), "Wonderland, Alice (alice@w.de)");

    // check SELF
    let contact = Contact::get_by_id(&t, ContactId::SELF).await.unwrap();
    assert_eq!(contact.get_name(), stock_str::self_msg(&t).await);
    assert_eq!(contact.get_addr(), ""); // we're not configured
    assert!(!contact.is_blocked());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_contact_name_changes() -> Result<()> {
    let t = TestContext::new_alice().await;

    // first message creates contact and one-to-one-chat without name set
    receive_imf(
        &t,
        b"From: f@example.org\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <1234-1@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 29 May 2022 08:37:57 +0000\n\
                 \n\
                 hello one\n",
        false,
    )
    .await?;
    let chat_id = t.get_last_msg().await.get_chat_id();
    chat_id.accept(&t).await?;
    assert_eq!(Chat::load_from_db(&t, chat_id).await?.name, "f@example.org");
    let chatlist = Chatlist::try_load(&t, 0, Some("f@example.org"), None).await?;
    assert_eq!(chatlist.len(), 1);
    let contacts = get_chat_contacts(&t, chat_id).await?;
    let contact_id = contacts.first().unwrap();
    let contact = Contact::get_by_id(&t, *contact_id).await?;
    assert_eq!(contact.get_authname(), "");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "f@example.org");
    assert_eq!(contact.get_name_n_addr(), "f@example.org");
    let contacts = Contact::get_all(&t, 0, Some("f@example.org")).await?;
    assert_eq!(contacts.len(), 1);

    // second message inits the name
    receive_imf(
        &t,
        b"From: Flobbyfoo <f@example.org>\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <1234-2@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 29 May 2022 08:38:57 +0000\n\
                 \n\
                 hello two\n",
        false,
    )
    .await?;
    let chat_id = t.get_last_msg().await.get_chat_id();
    assert_eq!(Chat::load_from_db(&t, chat_id).await?.name, "Flobbyfoo");
    let chatlist = Chatlist::try_load(&t, 0, Some("flobbyfoo"), None).await?;
    assert_eq!(chatlist.len(), 1);
    let contact = Contact::get_by_id(&t, *contact_id).await?;
    assert_eq!(contact.get_authname(), "Flobbyfoo");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "Flobbyfoo");
    assert_eq!(contact.get_name_n_addr(), "Flobbyfoo (f@example.org)");
    let contacts = Contact::get_all(&t, 0, Some("f@example.org")).await?;
    assert_eq!(contacts.len(), 1);
    let contacts = Contact::get_all(&t, 0, Some("flobbyfoo")).await?;
    assert_eq!(contacts.len(), 1);

    // third message changes the name
    receive_imf(
        &t,
        b"From: Foo Flobby <f@example.org>\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <1234-3@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 29 May 2022 08:39:57 +0000\n\
                 \n\
                 hello three\n",
        false,
    )
    .await?;
    let chat_id = t.get_last_msg().await.get_chat_id();
    assert_eq!(Chat::load_from_db(&t, chat_id).await?.name, "Foo Flobby");
    let chatlist = Chatlist::try_load(&t, 0, Some("Flobbyfoo"), None).await?;
    assert_eq!(chatlist.len(), 0);
    let chatlist = Chatlist::try_load(&t, 0, Some("Foo Flobby"), None).await?;
    assert_eq!(chatlist.len(), 1);
    let contact = Contact::get_by_id(&t, *contact_id).await?;
    assert_eq!(contact.get_authname(), "Foo Flobby");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "Foo Flobby");
    assert_eq!(contact.get_name_n_addr(), "Foo Flobby (f@example.org)");
    let contacts = Contact::get_all(&t, 0, Some("f@example.org")).await?;
    assert_eq!(contacts.len(), 1);
    let contacts = Contact::get_all(&t, 0, Some("flobbyfoo")).await?;
    assert_eq!(contacts.len(), 0);
    let contacts = Contact::get_all(&t, 0, Some("Foo Flobby")).await?;
    assert_eq!(contacts.len(), 1);

    // change name manually
    let test_id = Contact::create(&t, "Falk", "f@example.org").await?;
    assert_eq!(*contact_id, test_id);
    assert_eq!(Chat::load_from_db(&t, chat_id).await?.name, "Falk");
    let chatlist = Chatlist::try_load(&t, 0, Some("Falk"), None).await?;
    assert_eq!(chatlist.len(), 1);
    let contact = Contact::get_by_id(&t, *contact_id).await?;
    assert_eq!(contact.get_authname(), "Foo Flobby");
    assert_eq!(contact.get_name(), "Falk");
    assert_eq!(contact.get_display_name(), "Falk");
    assert_eq!(contact.get_name_n_addr(), "Falk (f@example.org)");
    let contacts = Contact::get_all(&t, 0, Some("f@example.org")).await?;
    assert_eq!(contacts.len(), 1);
    let contacts = Contact::get_all(&t, 0, Some("falk")).await?;
    assert_eq!(contacts.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete() -> Result<()> {
    let alice = TestContext::new_alice().await;

    assert!(Contact::delete(&alice, ContactId::SELF).await.is_err());

    // Create Bob contact
    let (contact_id, _) = Contact::add_or_lookup(
        &alice,
        "Bob",
        &ContactAddress::new("bob@example.net")?,
        Origin::ManuallyCreated,
    )
    .await?;
    let chat = alice
        .create_chat_with_contact("Bob", "bob@example.net")
        .await;
    assert_eq!(
        Contact::get_all(&alice, 0, Some("bob@example.net"))
            .await?
            .len(),
        1
    );

    // If a contact has ongoing chats, contact is only hidden on deletion
    Contact::delete(&alice, contact_id).await?;
    let contact = Contact::get_by_id(&alice, contact_id).await?;
    assert_eq!(contact.origin, Origin::Hidden);
    assert_eq!(
        Contact::get_all(&alice, 0, Some("bob@example.net"))
            .await?
            .len(),
        0
    );

    // Delete chat.
    chat.get_id().delete(&alice).await?;

    // Can delete contact physically now
    Contact::delete(&alice, contact_id).await?;
    assert!(Contact::get_by_id(&alice, contact_id).await.is_err());
    assert_eq!(
        Contact::get_all(&alice, 0, Some("bob@example.net"))
            .await?
            .len(),
        0
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_and_recreate_contact() -> Result<()> {
    let t = TestContext::new_alice().await;

    // test recreation after physical deletion
    let contact_id1 = Contact::create(&t, "Foo", "foo@bar.de").await?;
    assert_eq!(Contact::get_all(&t, 0, Some("foo@bar.de")).await?.len(), 1);
    Contact::delete(&t, contact_id1).await?;
    assert!(Contact::get_by_id(&t, contact_id1).await.is_err());
    assert_eq!(Contact::get_all(&t, 0, Some("foo@bar.de")).await?.len(), 0);
    let contact_id2 = Contact::create(&t, "Foo", "foo@bar.de").await?;
    assert_ne!(contact_id2, contact_id1);
    assert_eq!(Contact::get_all(&t, 0, Some("foo@bar.de")).await?.len(), 1);

    // test recreation after hiding
    t.create_chat_with_contact("Foo", "foo@bar.de").await;
    Contact::delete(&t, contact_id2).await?;
    let contact = Contact::get_by_id(&t, contact_id2).await?;
    assert_eq!(contact.origin, Origin::Hidden);
    assert_eq!(Contact::get_all(&t, 0, Some("foo@bar.de")).await?.len(), 0);

    let contact_id3 = Contact::create(&t, "Foo", "foo@bar.de").await?;
    let contact = Contact::get_by_id(&t, contact_id3).await?;
    assert_eq!(contact.origin, Origin::ManuallyCreated);
    assert_eq!(contact_id3, contact_id2);
    assert_eq!(Contact::get_all(&t, 0, Some("foo@bar.de")).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_authnames() {
    let t = TestContext::new().await;

    // incoming mail `From: bob1 <bob@example.org>` - this should init authname
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "bob1",
        &ContactAddress::new("bob@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    assert!(!contact_id.is_special());
    assert_eq!(sth_modified, Modifier::Created);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "bob1");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "bob1");

    // incoming mail `From: bob2 <bob@example.org>` - this should update authname
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "bob2",
        &ContactAddress::new("bob@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    assert!(!contact_id.is_special());
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "bob2");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "bob2");

    // manually edit name to "bob3" - authname should be still be "bob2" as given in `From:` above
    let contact_id = Contact::create(&t, "bob3", "bob@example.org")
        .await
        .unwrap();
    assert!(!contact_id.is_special());
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "bob2");
    assert_eq!(contact.get_name(), "bob3");
    assert_eq!(contact.get_display_name(), "bob3");

    // incoming mail `From: bob4 <bob@example.org>` - this should update authname, manually given name is still "bob3"
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "bob4",
        &ContactAddress::new("bob@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    assert!(!contact_id.is_special());
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "bob4");
    assert_eq!(contact.get_name(), "bob3");
    assert_eq!(contact.get_display_name(), "bob3");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_authnames_create_empty() {
    let t = TestContext::new().await;

    // manually create "claire@example.org" without a given name
    let contact_id = Contact::create(&t, "", "claire@example.org").await.unwrap();
    assert!(!contact_id.is_special());
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "claire@example.org");

    // incoming mail `From: claire1 <claire@example.org>` - this should update authname
    let (contact_id_same, sth_modified) = Contact::add_or_lookup(
        &t,
        "claire1",
        &ContactAddress::new("claire@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    assert_eq!(contact_id, contact_id_same);
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "claire1");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "claire1");

    // incoming mail `From: claire2 <claire@example.org>` - this should update authname
    let (contact_id_same, sth_modified) = Contact::add_or_lookup(
        &t,
        "claire2",
        &ContactAddress::new("claire@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    assert_eq!(contact_id, contact_id_same);
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "claire2");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "claire2");
}

/// Regression test.
///
/// In the past, "Not Bob" name was stuck until "Bob" changed the name to "Not Bob" and back in
/// the "From:" field or user set the name to empty string manually.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_authnames_update_to() -> Result<()> {
    let t = TestContext::new().await;

    // Incoming message from Bob.
    let (contact_id, sth_modified) = Contact::add_or_lookup(
        &t,
        "Bob",
        &ContactAddress::new("bob@example.org")?,
        Origin::IncomingUnknownFrom,
    )
    .await?;
    assert_eq!(sth_modified, Modifier::Created);
    let contact = Contact::get_by_id(&t, contact_id).await?;
    assert_eq!(contact.get_display_name(), "Bob");

    // Incoming message from someone else with "Not Bob" <bob@example.org> in the "To:" field.
    let (contact_id_same, sth_modified) = Contact::add_or_lookup(
        &t,
        "Not Bob",
        &ContactAddress::new("bob@example.org")?,
        Origin::IncomingUnknownTo,
    )
    .await?;
    assert_eq!(contact_id, contact_id_same);
    assert_eq!(sth_modified, Modifier::Modified);
    let contact = Contact::get_by_id(&t, contact_id).await?;
    assert_eq!(contact.get_display_name(), "Not Bob");

    // Incoming message from Bob, changing the name back.
    let (contact_id_same, sth_modified) = Contact::add_or_lookup(
        &t,
        "Bob",
        &ContactAddress::new("bob@example.org")?,
        Origin::IncomingUnknownFrom,
    )
    .await?;
    assert_eq!(contact_id, contact_id_same);
    assert_eq!(sth_modified, Modifier::Modified); // This was None until the bugfix
    let contact = Contact::get_by_id(&t, contact_id).await?;
    assert_eq!(contact.get_display_name(), "Bob");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remote_authnames_edit_empty() {
    let t = TestContext::new().await;

    // manually create "dave@example.org"
    let contact_id = Contact::create(&t, "dave1", "dave@example.org")
        .await
        .unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "");
    assert_eq!(contact.get_name(), "dave1");
    assert_eq!(contact.get_display_name(), "dave1");

    // incoming mail `From: dave2 <dave@example.org>` - this should update authname
    Contact::add_or_lookup(
        &t,
        "dave2",
        &ContactAddress::new("dave@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "dave2");
    assert_eq!(contact.get_name(), "dave1");
    assert_eq!(contact.get_display_name(), "dave1");

    // manually clear the name
    Contact::create(&t, "", "dave@example.org").await.unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_authname(), "dave2");
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "dave2");
}

#[test]
fn test_addr_cmp() {
    assert!(addr_cmp("AA@AA.ORG", "aa@aa.ORG"));
    assert!(addr_cmp(" aa@aa.ORG ", "AA@AA.ORG"));
    assert!(addr_cmp(" mailto:AA@AA.ORG", "Aa@Aa.orG"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_name_in_address() {
    let t = TestContext::new().await;

    let contact_id = Contact::create(&t, "", "<dave@example.org>").await.unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_addr(), "dave@example.org");

    let contact_id = Contact::create(&t, "", "Mueller, Dave <dave@example.org>")
        .await
        .unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "Mueller, Dave");
    assert_eq!(contact.get_addr(), "dave@example.org");

    let contact_id = Contact::create(&t, "name1", "name2 <dave@example.org>")
        .await
        .unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "name1");
    assert_eq!(contact.get_addr(), "dave@example.org");

    assert!(Contact::create(&t, "", "<dskjfdslk@sadklj.dk")
        .await
        .is_err());
    assert!(Contact::create(&t, "", "<dskjf>dslk@sadklj.dk>")
        .await
        .is_err());
    assert!(Contact::create(&t, "", "dskjfdslksadklj.dk").await.is_err());
    assert!(Contact::create(&t, "", "dskjfdslk@sadklj.dk>")
        .await
        .is_err());
    assert!(Contact::create(&t, "", "dskjf dslk@d.e").await.is_err());
    assert!(Contact::create(&t, "", "<dskjf dslk@sadklj.dk")
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lookup_id_by_addr() {
    let t = TestContext::new().await;

    let id = Contact::lookup_id_by_addr(&t.ctx, "the.other@example.net", Origin::Unknown)
        .await
        .unwrap();
    assert!(id.is_none());

    let other_id = Contact::create(&t.ctx, "The Other", "the.other@example.net")
        .await
        .unwrap();
    let id = Contact::lookup_id_by_addr(&t.ctx, "the.other@example.net", Origin::Unknown)
        .await
        .unwrap();
    assert_eq!(id, Some(other_id));

    let alice = TestContext::new_alice().await;

    let id = Contact::lookup_id_by_addr(&alice.ctx, "alice@example.org", Origin::Unknown)
        .await
        .unwrap();
    assert_eq!(id, Some(ContactId::SELF));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_contact_get_color() -> Result<()> {
    let t = TestContext::new().await;
    let contact_id = Contact::create(&t, "name", "name@example.net").await?;
    let color1 = Contact::get_by_id(&t, contact_id).await?.get_color();
    assert_eq!(color1, 0xA739FF);

    let t = TestContext::new().await;
    let contact_id = Contact::create(&t, "prename name", "name@example.net").await?;
    let color2 = Contact::get_by_id(&t, contact_id).await?.get_color();
    assert_eq!(color2, color1);

    let t = TestContext::new().await;
    let contact_id = Contact::create(&t, "Name", "nAme@exAmple.NET").await?;
    let color3 = Contact::get_by_id(&t, contact_id).await?.get_color();
    assert_eq!(color3, color1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_contact_get_encrinfo() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Return error for special IDs
    let encrinfo = Contact::get_encrinfo(&alice, ContactId::SELF).await;
    assert!(encrinfo.is_err());
    let encrinfo = Contact::get_encrinfo(&alice, ContactId::DEVICE).await;
    assert!(encrinfo.is_err());

    let (contact_bob_id, _modified) = Contact::add_or_lookup(
        &alice,
        "Bob",
        &ContactAddress::new("bob@example.net")?,
        Origin::ManuallyCreated,
    )
    .await?;

    let encrinfo = Contact::get_encrinfo(&alice, contact_bob_id).await?;
    assert_eq!(encrinfo, "No encryption");
    let contact = Contact::get_by_id(&alice, contact_bob_id).await?;
    assert!(!contact.e2ee_avail(&alice).await?);

    let bob = TestContext::new_bob().await;
    let chat_alice = bob
        .create_chat_with_contact("Alice", "alice@example.org")
        .await;
    send_text_msg(&bob, chat_alice.id, "Hello".to_string()).await?;
    let msg = bob.pop_sent_msg().await;
    alice.recv_msg(&msg).await;

    let encrinfo = Contact::get_encrinfo(&alice, contact_bob_id).await?;
    assert_eq!(
        encrinfo,
        "End-to-end encryption preferred.
Fingerprints:

Me (alice@example.org):
2E6F A2CB 23B5 32D7 2863
4B58 64B0 8F61 A9ED 9443

Bob (bob@example.net):
CCCB 5AA9 F6E1 141C 9431
65F1 DB18 B18C BCF7 0487"
    );
    let contact = Contact::get_by_id(&alice, contact_bob_id).await?;
    assert!(contact.e2ee_avail(&alice).await?);
    Ok(())
}

/// Tests that status is synchronized when sending encrypted BCC-self messages and not
/// synchronized when the message is not encrypted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_synchronize_status() -> Result<()> {
    // Alice has two devices.
    let alice1 = TestContext::new_alice().await;
    let alice2 = TestContext::new_alice().await;

    // Bob has one device.
    let bob = TestContext::new_bob().await;

    let default_status = alice1.get_config(Config::Selfstatus).await?;

    alice1
        .set_config(Config::Selfstatus, Some("New status"))
        .await?;
    let chat = alice1
        .create_chat_with_contact("Bob", "bob@example.net")
        .await;

    // Alice sends a message to Bob from the first device.
    send_text_msg(&alice1, chat.id, "Hello".to_string()).await?;
    let sent_msg = alice1.pop_sent_msg().await;

    // Message is not encrypted.
    let message = sent_msg.load_from_db().await;
    assert!(!message.get_showpadlock());

    // Alice's second devices receives a copy of outgoing message.
    alice2.recv_msg(&sent_msg).await;

    // Bob receives message.
    bob.recv_msg(&sent_msg).await;

    // Message was not encrypted, so status is not copied.
    assert_eq!(alice2.get_config(Config::Selfstatus).await?, default_status);

    // Bob replies.
    let chat = bob
        .create_chat_with_contact("Alice", "alice@example.org")
        .await;

    send_text_msg(&bob, chat.id, "Reply".to_string()).await?;
    let sent_msg = bob.pop_sent_msg().await;
    alice1.recv_msg(&sent_msg).await;
    alice2.recv_msg(&sent_msg).await;

    // Alice sends second message.
    send_text_msg(&alice1, chat.id, "Hello".to_string()).await?;
    let sent_msg = alice1.pop_sent_msg().await;

    // Second message is encrypted.
    let message = sent_msg.load_from_db().await;
    assert!(message.get_showpadlock());

    // Alice's second devices receives a copy of second outgoing message.
    alice2.recv_msg(&sent_msg).await;

    assert_eq!(
        alice2.get_config(Config::Selfstatus).await?,
        Some("New status".to_string())
    );

    Ok(())
}

/// Tests that DC_EVENT_SELFAVATAR_CHANGED is emitted on avatar changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_changed_event() -> Result<()> {
    // Alice has two devices.
    let alice1 = TestContext::new_alice().await;
    let alice2 = TestContext::new_alice().await;

    // Bob has one device.
    let bob = TestContext::new_bob().await;

    assert_eq!(alice1.get_config(Config::Selfavatar).await?, None);

    let avatar_src = alice1.get_blobdir().join("avatar.png");
    tokio::fs::write(&avatar_src, test_utils::AVATAR_900x900_BYTES).await?;

    alice1
        .set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
        .await?;

    alice1
        .evtracker
        .get_matching(|e| matches!(e, EventType::SelfavatarChanged))
        .await;

    // Bob sends a message so that Alice can encrypt to him.
    let chat = bob
        .create_chat_with_contact("Alice", "alice@example.org")
        .await;

    send_text_msg(&bob, chat.id, "Reply".to_string()).await?;
    let sent_msg = bob.pop_sent_msg().await;
    alice1.recv_msg(&sent_msg).await;
    alice2.recv_msg(&sent_msg).await;

    // Alice sends a message.
    let alice1_chat_id = alice1.get_last_msg().await.chat_id;
    alice1_chat_id.accept(&alice1).await?;
    send_text_msg(&alice1, alice1_chat_id, "Hello".to_string()).await?;
    let sent_msg = alice1.pop_sent_msg().await;

    // The message is encrypted.
    let message = sent_msg.load_from_db().await;
    assert!(message.get_showpadlock());

    // Alice's second device receives a copy of the outgoing message.
    alice2.recv_msg(&sent_msg).await;

    // Alice's second device applies the selfavatar.
    assert!(alice2.get_config(Config::Selfavatar).await?.is_some());
    alice2
        .evtracker
        .get_matching(|e| matches!(e, EventType::SelfavatarChanged))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_last_seen() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let (contact_id, _) = Contact::add_or_lookup(
        &alice,
        "Bob",
        &ContactAddress::new("bob@example.net")?,
        Origin::ManuallyCreated,
    )
    .await?;
    let contact = Contact::get_by_id(&alice, contact_id).await?;
    assert_eq!(contact.last_seen(), 0);

    let mime = br#"Subject: Hello
Message-ID: message@example.net
To: Alice <alice@example.org>
From: Bob <bob@example.net>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Chat-Version: 1.0
Date: Sun, 22 Mar 2020 22:37:55 +0000

Hi."#;
    receive_imf(&alice, mime, false).await?;
    let msg = alice.get_last_msg().await;

    let timestamp = msg.get_timestamp();
    assert!(timestamp > 0);
    let contact = Contact::get_by_id(&alice, contact_id).await?;
    assert_eq!(contact.last_seen(), timestamp);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_was_seen_recently() -> Result<()> {
    let _n = TimeShiftFalsePositiveNote;

    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let chat = alice.create_chat(&bob).await;
    let sent_msg = alice.send_text(chat.id, "moin").await;

    let chat = bob.create_chat(&alice).await;
    let contacts = chat::get_chat_contacts(&bob, chat.id).await?;
    let contact = Contact::get_by_id(&bob, *contacts.first().unwrap()).await?;
    assert!(!contact.was_seen_recently());

    bob.recv_msg(&sent_msg).await;
    let contact = Contact::get_by_id(&bob, *contacts.first().unwrap()).await?;

    assert!(contact.was_seen_recently());

    let self_contact = Contact::get_by_id(&bob, ContactId::SELF).await?;
    assert!(!self_contact.was_seen_recently());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_was_seen_recently_event() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let recently_seen_loop = RecentlySeenLoop::new(bob.ctx.clone());
    let chat = bob.create_chat(&alice).await;
    let contacts = chat::get_chat_contacts(&bob, chat.id).await?;

    for _ in 0..2 {
        let chat = alice.create_chat(&bob).await;
        let sent_msg = alice.send_text(chat.id, "moin").await;
        let contact = Contact::get_by_id(&bob, *contacts.first().unwrap()).await?;
        assert!(!contact.was_seen_recently());
        bob.evtracker.clear_events();
        bob.recv_msg(&sent_msg).await;
        let contact = Contact::get_by_id(&bob, *contacts.first().unwrap()).await?;
        assert!(contact.was_seen_recently());
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::ContactsChanged { .. }))
            .await;
        recently_seen_loop
            .interrupt(contact.id, contact.last_seen)
            .await;

        // Wait for `was_seen_recently()` to turn off.
        bob.evtracker.clear_events();
        SystemTime::shift(Duration::from_secs(SEEN_RECENTLY_SECONDS as u64 * 2));
        recently_seen_loop.interrupt(ContactId::UNDEFINED, 0).await;
        let contact = Contact::get_by_id(&bob, *contacts.first().unwrap()).await?;
        assert!(!contact.was_seen_recently());
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::ContactsChanged { .. }))
            .await;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verified_by_none() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let contact_id = Contact::create(&alice, "Bob", "bob@example.net").await?;
    let contact = Contact::get_by_id(&alice, contact_id).await?;
    assert!(contact.get_verifier_id(&alice).await?.is_none());

    // Receive a message from Bob to create a peerstate.
    let chat = bob.create_chat(&alice).await;
    let sent_msg = bob.send_text(chat.id, "moin").await;
    alice.recv_msg(&sent_msg).await;

    let contact = Contact::get_by_id(&alice, contact_id).await?;
    assert!(contact.get_verifier_id(&alice).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_create() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    Contact::create(alice0, "Bob", "bob@example.net").await?;
    test_utils::sync(alice0, alice1).await;
    let a1b_contact_id =
        Contact::lookup_id_by_addr(alice1, "bob@example.net", Origin::ManuallyCreated)
            .await?
            .unwrap();
    let a1b_contact = Contact::get_by_id(alice1, a1b_contact_id).await?;
    assert_eq!(a1b_contact.name, "Bob");

    Contact::create(alice0, "Bob Renamed", "bob@example.net").await?;
    test_utils::sync(alice0, alice1).await;
    let id = Contact::lookup_id_by_addr(alice1, "bob@example.net", Origin::ManuallyCreated)
        .await?
        .unwrap();
    assert_eq!(id, a1b_contact_id);
    let a1b_contact = Contact::get_by_id(alice1, a1b_contact_id).await?;
    assert_eq!(a1b_contact.name, "Bob Renamed");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_make_n_import_vcard() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    bob.set_config(Config::Displayname, Some("Bob")).await?;
    bob.set_config(Config::Selfstatus, Some("It's me, bob"))
        .await?;
    let avatar_path = bob.dir.path().join("avatar.png");
    let avatar_bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    let avatar_base64 = base64::engine::general_purpose::STANDARD.encode(avatar_bytes);
    tokio::fs::write(&avatar_path, avatar_bytes).await?;
    bob.set_config(Config::Selfavatar, Some(avatar_path.to_str().unwrap()))
        .await?;
    let bob_addr = bob.get_config(Config::Addr).await?.unwrap();
    let bob_biography = bob.get_config(Config::Selfstatus).await?.unwrap();
    let chat = bob.create_chat(alice).await;
    let sent_msg = bob.send_text(chat.id, "moin").await;
    alice.recv_msg(&sent_msg).await;
    let bob_id = Contact::create(alice, "Some Bob", &bob_addr).await?;
    let key_base64 = Peerstate::from_addr(alice, &bob_addr)
        .await?
        .unwrap()
        .peek_key(false)
        .unwrap()
        .to_base64();
    let fiona_id = Contact::create(alice, "Fiona", "fiona@example.net").await?;

    assert_eq!(make_vcard(alice, &[]).await?, "".to_string());

    let t0 = time();
    let vcard = make_vcard(alice, &[bob_id, fiona_id]).await?;
    let t1 = time();
    // Just test that it's parsed as expected, `deltachat_contact_tools` crate has tests on the
    // exact format.
    let contacts = contact_tools::parse_vcard(&vcard);
    assert_eq!(contacts.len(), 2);
    assert_eq!(contacts[0].addr, bob_addr);
    assert_eq!(contacts[0].authname, "Bob".to_string());
    assert_eq!(*contacts[0].key.as_ref().unwrap(), key_base64);
    assert_eq!(*contacts[0].profile_image.as_ref().unwrap(), avatar_base64);
    assert_eq!(*contacts[0].biography.as_ref().unwrap(), bob_biography);
    let timestamp = *contacts[0].timestamp.as_ref().unwrap();
    assert!(t0 <= timestamp && timestamp <= t1);
    assert_eq!(contacts[1].addr, "fiona@example.net".to_string());
    assert_eq!(contacts[1].authname, "".to_string());
    assert_eq!(contacts[1].key, None);
    assert_eq!(contacts[1].profile_image, None);
    assert_eq!(contacts[1].biography, None);
    let timestamp = *contacts[1].timestamp.as_ref().unwrap();
    assert!(t0 <= timestamp && timestamp <= t1);

    let alice = &TestContext::new_alice().await;
    alice.evtracker.clear_events();
    let contact_ids = import_vcard(alice, &vcard).await?;
    assert_eq!(contact_ids.len(), 2);
    for _ in 0..contact_ids.len() {
        alice
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::ContactsChanged(Some(_))))
            .await;
    }

    let vcard = make_vcard(alice, &[contact_ids[0], contact_ids[1]]).await?;
    // This should be the same vCard except timestamps, check that roughly.
    let contacts = contact_tools::parse_vcard(&vcard);
    assert_eq!(contacts.len(), 2);
    assert_eq!(contacts[0].addr, bob_addr);
    assert_eq!(contacts[0].authname, "Bob".to_string());
    assert_eq!(*contacts[0].key.as_ref().unwrap(), key_base64);
    assert_eq!(*contacts[0].profile_image.as_ref().unwrap(), avatar_base64);
    assert_eq!(*contacts[0].biography.as_ref().unwrap(), bob_biography);
    assert!(contacts[0].timestamp.is_ok());
    assert_eq!(contacts[1].addr, "fiona@example.net".to_string());

    let chat_id = ChatId::create_for_contact(alice, contact_ids[0]).await?;
    let sent_msg = alice.send_text(chat_id, "moin").await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert!(msg.get_showpadlock());

    // Bob only actually imports Fiona, though `ContactId::SELF` is also returned.
    bob.evtracker.clear_events();
    let contact_ids = import_vcard(bob, &vcard).await?;
    bob.emit_event(EventType::Test);
    assert_eq!(contact_ids.len(), 2);
    assert_eq!(contact_ids[0], ContactId::SELF);
    let ev = bob
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ContactsChanged { .. }))
        .await;
    assert_eq!(ev, EventType::ContactsChanged(Some(contact_ids[1])));
    let ev = bob
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ContactsChanged { .. } | EventType::Test))
        .await;
    assert_eq!(ev, EventType::Test);
    let vcard = make_vcard(bob, &[contact_ids[1]]).await?;
    let contacts = contact_tools::parse_vcard(&vcard);
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].addr, "fiona@example.net");
    assert_eq!(contacts[0].authname, "".to_string());
    assert_eq!(contacts[0].key, None);
    assert_eq!(contacts[0].profile_image, None);
    assert_eq!(contacts[0].biography, None);
    assert!(contacts[0].timestamp.is_ok());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_vcard_updates_only_key() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    let bob = &TestContext::new_bob().await;
    let bob_addr = &bob.get_config(Config::Addr).await?.unwrap();
    bob.set_config(Config::Displayname, Some("Bob")).await?;
    let vcard = make_vcard(bob, &[ContactId::SELF]).await?;
    alice.evtracker.clear_events();
    let alice_bob_id = import_vcard(alice, &vcard).await?[0];
    let ev = alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ContactsChanged { .. }))
        .await;
    assert_eq!(ev, EventType::ContactsChanged(Some(alice_bob_id)));
    let chat_id = ChatId::create_for_contact(alice, alice_bob_id).await?;
    let sent_msg = alice.send_text(chat_id, "moin").await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert!(msg.get_showpadlock());

    let bob = &TestContext::new().await;
    bob.configure_addr(bob_addr).await;
    bob.set_config(Config::Displayname, Some("Not Bob")).await?;
    let avatar_path = bob.dir.path().join("avatar.png");
    let avatar_bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&avatar_path, avatar_bytes).await?;
    bob.set_config(Config::Selfavatar, Some(avatar_path.to_str().unwrap()))
        .await?;
    SystemTime::shift(Duration::from_secs(1));
    let vcard1 = make_vcard(bob, &[ContactId::SELF]).await?;
    assert_eq!(import_vcard(alice, &vcard1).await?, vec![alice_bob_id]);
    let alice_bob_contact = Contact::get_by_id(alice, alice_bob_id).await?;
    assert_eq!(alice_bob_contact.get_authname(), "Bob");
    assert_eq!(alice_bob_contact.get_profile_image(alice).await?, None);
    let msg = alice.get_last_msg_in(chat_id).await;
    assert!(msg.is_info());
    assert_eq!(
        msg.get_text(),
        stock_str::contact_setup_changed(alice, bob_addr).await
    );
    let sent_msg = alice.send_text(chat_id, "moin").await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert!(msg.get_showpadlock());

    // The old vCard is imported, but doesn't change Bob's key for Alice.
    import_vcard(alice, &vcard).await?.first().unwrap();
    let sent_msg = alice.send_text(chat_id, "moin").await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert!(msg.get_showpadlock());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reset_encryption() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let msg = tcm.send_recv_accept(bob, alice, "Hi!").await;
    assert_eq!(msg.get_showpadlock(), true);

    let alice_bob_chat_id = msg.chat_id;
    let alice_bob_contact_id = msg.from_id;

    alice_bob_contact_id.reset_encryption(alice).await?;

    let sent = alice.send_text(alice_bob_chat_id, "Unencrypted").await;
    let msg = bob.recv_msg(&sent).await;
    assert_eq!(msg.get_showpadlock(), false);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reset_verified_encryption() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.execute_securejoin(bob, alice).await;

    let msg = tcm.send_recv(bob, alice, "Encrypted").await;
    assert_eq!(msg.get_showpadlock(), true);

    let alice_bob_chat_id = msg.chat_id;
    let alice_bob_contact_id = msg.from_id;

    alice_bob_contact_id.reset_encryption(alice).await?;

    // Check that the contact is still verified after resetting encryption.
    let alice_bob_contact = Contact::get_by_id(alice, alice_bob_contact_id).await?;
    assert_eq!(alice_bob_contact.is_verified(alice).await?, true);

    // 1:1 chat and profile is no longer verified.
    assert_eq!(alice_bob_contact.is_profile_verified(alice).await?, false);

    let info_msg = alice.get_last_msg_in(alice_bob_chat_id).await;
    assert_eq!(
        info_msg.text,
        "bob@example.net sent a message from another device."
    );

    let sent = alice.send_text(alice_bob_chat_id, "Unencrypted").await;
    let msg = bob.recv_msg(&sent).await;
    assert_eq!(msg.get_showpadlock(), false);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_self_is_verified() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;

    let contact = Contact::get_by_id(&alice, ContactId::SELF).await?;
    assert_eq!(contact.is_verified(&alice).await?, true);
    assert!(contact.is_profile_verified(&alice).await?);
    assert!(contact.get_verifier_id(&alice).await?.is_none());

    let chat_id = ChatId::get_for_contact(&alice, ContactId::SELF).await?;
    assert!(chat_id.is_protected(&alice).await.unwrap() == ProtectionStatus::Protected);

    Ok(())
}
