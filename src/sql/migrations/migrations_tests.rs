use super::*;
use crate::chat;
use crate::chat::ChatId;
use crate::config::Config;
use crate::contact::Contact;
use crate::contact::Origin;
use crate::test_utils::bob_keypair;
use crate::test_utils::TestContext;
use crate::tools;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_clear_config_cache() -> anyhow::Result<()> {
    // Some migrations change the `config` table in SQL.
    // This test checks that the config cache is invalidated in `execute_migration()`.

    let t = TestContext::new().await;
    assert_eq!(t.get_config_bool(Config::IsChatmail).await?, false);

    t.sql
        .execute_migration(
            "INSERT INTO config (keyname, value) VALUES ('is_chatmail', '1')",
            1000,
        )
        .await?;
    assert_eq!(t.get_config_bool(Config::IsChatmail).await?, true);
    assert_eq!(t.sql.get_raw_config_int(VERSION_CFG).await?.unwrap(), 1000);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pgp_contacts_migration() -> Result<()> {
    let t = STOP_MIGRATIONS_AT
        .scope(131, async move { TestContext::new_alice().await })
        .await;

    t.sql.call_write(|conn| Ok(conn.execute_batch(r#"
            INSERT INTO acpeerstates VALUES(1,'bob@example.net',0,0,NULL,1,1745589039,X'c6c04d045e30c757010800cec0b4bfc4277c88a0d652cc937d5cd66f2f9918a3e96a63d3bdd8f41858277f4075101680e7ffcf8c0cdb2b988a8a8e903449996a0cc93e45cf07225c0084549b44f5eada83b42bf19be1fddd8117a478bf5d639e270f64a210134aa52db113b4a4525e0ef3e2313990ac498762858349005f0aba3065dbe730095b27d26360e9e070c793c5cd23c663ece6cd7bc850bed4e5aee1fc160b250cdf0cb527374a4dc0d6af2ad292f9a015d52a27ba490e4d47153b7ec7db6f4252b7ba7f415e2470bf4bb4cc34ae23c7831ff7512c0e142fd3eaeaf9899816a67b504fb04d4f03b573793489476a28257313ea8d80987f0f3d47d192fdce896ba1ecb339152a470011010001cd113c626f62406578616d706c652e6e65743ec2c08b0410010800350219010502680b932f021b03040b090807061508090a0b02031602010127162104cccb5aa9f6e1141c943165f1db18b18cbcf70487000a0910db18b18cbcf70487069707ff53fae1e7d40cf1b2b0ea22c1cadd735b16fbdc4c0571fc88b9c489bb2023fce8e197880c4d579d67fa75124ae696fecc17cd5815362e00601e9240d10e0a46bfc0567b88312a41e56bedb045482de61279eb7d10cf15b23e56dc254084401eeaac0780f7ca912f6f9e3d4e4b3f82b1a0fc3ee6600e5367549dbc83242743dee435287c1ba1db604f4d7416780a5d43fe8047338866715a9081285797b96cb9340822d04331121646188e3c9e9bf209611fe9f72bf5df3f0cfdf46d698566ae5ef75e8fa05f5d760e22e592c61e2a48dffeff8cec2f425a5c04951df78f68362f475ba9a8f15e4f588d85f8738815d92d8ccd876833c1683927dd28f5ede9da8ecec04d045e30c757010800a207812db22369e2482375b6a71b2ef9212eb1090957291b1980edab25d5f970598ac638184d244dac0ae66a9287eac3aaab82c438185814539c667010aa219e3d8d1bbe698dfc953e160c51d26defe61ad68885bd9960aeb3a3d5bb637afab9df216d42894c37e5f6a12f2695ff634b32323c2783c499353758316800138370720320754ddd300dd14fa78f278bcab37f219979889cbc9971ef862739a8dada59c8ff2f88f4bb269aa88e808f0771b987d68779a929d58e17290684c4035e582c8124484dc2d344395129434b711583f20ebb71579cb97bbf4850fe35f2bfcf1ec9c7e949f15c6cc1e8b7d56d2784c83c8a125fb0d0fae53649724a899364550011010001c2c0760418010800200502680b932f021b0c162104cccb5aa9f6e1141c943165f1db18b18cbcf70487000a0910db18b18cbcf704873c3807fd1e3e54a16fc879fc006af060de9216a761188b73fcaa617383feb632b80bcbbf362ea4381bd15e58cffa5ec03da0cd50e4adf37be5c81a66d6a22b9835cbb9c219ecd7426547e6a8ec35839d76795aa448a544bc4a5ecfea0284c1ee576a3dc9fdd41beb54f3f60283451b1d292bddda076e1c02b82d957708dcea5f6fb4faf72f69bdff01ed89468e9870e1a081dac09ccc0b9590ac12e7b85008838e8f9aafcfb2bdcc63085a70819c4f6b8b77cff5716af43c834d114a22745eea504b90c431abadb06ba979021726de29fa09523254ff88d3a9a94ba22c46ba5eb4919ca3c8d1f58b1349c5dd1747afb88067dd2ee258b07b8eb0e09235da2469fcc08c79',NULL,'CCCB5AA9F6E1141C943165F1DB18B18CBCF70487',NULL,NULL,'',NULL,NULL,'',NULL);
            INSERT INTO contacts VALUES(10,'','bob@example.net',16384,0,0,'','',1745589041,'',0);
            INSERT INTO chats VALUES(10,100,'bob@example.net',0,'',0,'','',0,0,0,0,0,1745589039,0,NULL,0);
            INSERT INTO chats_contacts VALUES(10,10,0,0);"#,
    )?)).await?;
    t.sql.run_migrations(&t).await?;

    //std::thread::sleep(std::time::Duration::from_secs(1000));
    let email_bob_id = Contact::lookup_id_by_addr(&t, "bob@example.net", Origin::Hidden)
        .await?
        .unwrap();
    let email_bob = Contact::get_by_id(&t, email_bob_id).await?;
    assert_eq!(email_bob.origin, Origin::Hidden); // Email bob is in no chats, so, contact is hidden
    assert_eq!(email_bob.e2ee_avail(&t).await?, false);
    assert_eq!(email_bob.fingerprint(), None);
    assert_eq!(email_bob.get_verifier_id(&t).await?, None);

    let bob_chat_contacts = chat::get_chat_contacts(&t, ChatId::new(10)).await?;
    let pgp_bob_id = tools::single_value(bob_chat_contacts).unwrap();
    let pgp_bob = Contact::get_by_id(&t, pgp_bob_id).await?;
    assert_eq!(pgp_bob.origin, Origin::OutgoingTo);
    assert_eq!(pgp_bob.e2ee_avail(&t).await?, true);
    assert_eq!(
        pgp_bob.fingerprint().unwrap(),
        pgp_bob.public_key(&t).await?.unwrap().dc_fingerprint()
    );
    assert_eq!(pgp_bob.get_verifier_id(&t).await?, None);

    Ok(())
}
