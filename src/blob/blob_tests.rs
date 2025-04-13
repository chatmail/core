use std::time::Duration;

use super::*;
use crate::message::{Message, Viewtype};
use crate::param::Param;
use crate::sql;
use crate::test_utils::{self, TestContext};
use crate::tools::SystemTime;

fn check_image_size(path: impl AsRef<Path>, width: u32, height: u32) -> image::DynamicImage {
    tokio::task::block_in_place(move || {
        let img = ImageReader::open(path)
            .expect("failed to open image")
            .with_guessed_format()
            .expect("failed to guess format")
            .decode()
            .expect("failed to decode image");
        assert_eq!(img.width(), width, "invalid width");
        assert_eq!(img.height(), height, "invalid height");
        img
    })
}

const FILE_BYTES: &[u8] = b"hello";
const FILE_DEDUPLICATED: &str = "ea8f163db38682925e4491c5e58d4bb.txt";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create() {
    let t = TestContext::new().await;
    let blob = BlobObject::create_and_deduplicate_from_bytes(&t, FILE_BYTES, "foo.txt").unwrap();
    let fname = t.get_blobdir().join(FILE_DEDUPLICATED);
    let data = fs::read(fname).await.unwrap();
    assert_eq!(data, FILE_BYTES);
    assert_eq!(blob.as_name(), format!("$BLOBDIR/{FILE_DEDUPLICATED}"));
    assert_eq!(blob.to_abs_path(), t.get_blobdir().join(FILE_DEDUPLICATED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lowercase_ext() {
    let t = TestContext::new().await;
    let blob = BlobObject::create_and_deduplicate_from_bytes(&t, FILE_BYTES, "foo.TXT").unwrap();
    assert!(
        blob.as_name().ends_with(".txt"),
        "Blob {blob:?} should end with .txt"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_suffix() {
    let t = TestContext::new().await;
    let blob = BlobObject::create_and_deduplicate_from_bytes(&t, FILE_BYTES, "foo.txt").unwrap();
    assert_eq!(blob.suffix(), Some("txt"));
    let blob = BlobObject::create_and_deduplicate_from_bytes(&t, FILE_BYTES, "bar").unwrap();
    assert_eq!(blob.suffix(), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_dup() {
    let t = TestContext::new().await;
    BlobObject::create_and_deduplicate_from_bytes(&t, FILE_BYTES, "foo.txt").unwrap();
    let foo_path = t.get_blobdir().join(FILE_DEDUPLICATED);
    assert!(foo_path.exists());
    BlobObject::create_and_deduplicate_from_bytes(&t, b"world", "foo.txt").unwrap();
    let mut dir = fs::read_dir(t.get_blobdir()).await.unwrap();
    while let Ok(Some(dirent)) = dir.next_entry().await {
        let fname = dirent.file_name();
        if fname == foo_path.file_name().unwrap() {
            assert_eq!(fs::read(&foo_path).await.unwrap(), FILE_BYTES);
        } else {
            let name = fname.to_str().unwrap();
            assert!(name.ends_with(".txt"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_double_ext() {
    let t = TestContext::new().await;
    BlobObject::create_and_deduplicate_from_bytes(&t, FILE_BYTES, "foo.tar.gz").unwrap();
    let foo_path = t.get_blobdir().join(FILE_DEDUPLICATED).with_extension("gz");
    assert!(foo_path.exists());
    BlobObject::create_and_deduplicate_from_bytes(&t, b"world", "foo.tar.gz").unwrap();
    let mut dir = fs::read_dir(t.get_blobdir()).await.unwrap();
    while let Ok(Some(dirent)) = dir.next_entry().await {
        let fname = dirent.file_name();
        if fname == foo_path.file_name().unwrap() {
            assert_eq!(fs::read(&foo_path).await.unwrap(), FILE_BYTES);
        } else {
            let name = fname.to_str().unwrap();
            println!("{name}");
            assert_eq!(name.starts_with("foo"), false);
            assert_eq!(name.ends_with(".tar.gz"), false);
            assert!(name.ends_with(".gz"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_long_names() {
    let t = TestContext::new().await;
    let s = format!("file.{}", "a".repeat(100));
    let blob = BlobObject::create_and_deduplicate_from_bytes(&t, b"data", &s).unwrap();
    let blobname = blob.as_name().split('/').next_back().unwrap();
    assert!(blobname.len() < 70);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_from_name_long() {
    let t = TestContext::new().await;
    let src_ext = t.dir.path().join("autocrypt-setup-message-4137848473.html");
    fs::write(&src_ext, b"boo").await.unwrap();
    let blob = BlobObject::create_and_deduplicate(&t, &src_ext, &src_ext).unwrap();
    assert_eq!(
        blob.as_name(),
        "$BLOBDIR/06f010b24d1efe57ffab44a8ad20c54.html"
    );
}

#[test]
fn test_is_blob_name() {
    assert!(BlobObject::is_acceptible_blob_name("foo"));
    assert!(BlobObject::is_acceptible_blob_name("foo.txt"));
    assert!(BlobObject::is_acceptible_blob_name(&"f".repeat(128)));
    assert!(!BlobObject::is_acceptible_blob_name("foo/bar"));
    assert!(!BlobObject::is_acceptible_blob_name("foo\\bar"));
    assert!(!BlobObject::is_acceptible_blob_name("foo\x00bar"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_white_bg() {
    let t = TestContext::new().await;
    let bytes0 = include_bytes!("../../test-data/image/logo.png").as_slice();
    let bytes1 = include_bytes!("../../test-data/image/avatar900x900.png").as_slice();
    for (bytes, color) in [
        (bytes0, [255u8, 255, 255, 255]),
        (bytes1, [253u8, 198, 0, 255]),
    ] {
        let avatar_src = t.dir.path().join("avatar.png");
        fs::write(&avatar_src, bytes).await.unwrap();

        let mut blob = BlobObject::create_and_deduplicate(&t, &avatar_src, &avatar_src).unwrap();
        let img_wh = 128;
        let maybe_sticker = &mut false;
        let strict_limits = true;
        blob.recode_to_size(&t, None, maybe_sticker, img_wh, 20_000, strict_limits)
            .unwrap();
        tokio::task::block_in_place(move || {
            let img = ImageReader::open(blob.to_abs_path())
                .unwrap()
                .with_guessed_format()
                .unwrap()
                .decode()
                .unwrap();
            assert!(img.width() == img_wh);
            assert!(img.height() == img_wh);
            assert_eq!(img.get_pixel(0, 0), Rgba(color));
        });
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_outside_blobdir() {
    async fn file_size(path_buf: &Path) -> u64 {
        fs::metadata(path_buf).await.unwrap().len()
    }

    let t = TestContext::new().await;
    let avatar_src = t.dir.path().join("avatar.jpg");
    let avatar_bytes = include_bytes!("../../test-data/image/avatar1000x1000.jpg");
    fs::write(&avatar_src, avatar_bytes).await.unwrap();
    t.set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
        .await
        .unwrap();
    let avatar_blob = t.get_config(Config::Selfavatar).await.unwrap().unwrap();
    let avatar_path = Path::new(&avatar_blob);
    assert!(
        avatar_blob.ends_with("1e08d1c9398297c21dd3820f7db2324.jpg"),
        "The avatar filename should be its hash, put instead it's {avatar_blob}"
    );
    let scaled_avatar_size = file_size(avatar_path).await;
    assert!(scaled_avatar_size < avatar_bytes.len() as u64);

    check_image_size(avatar_src, 1000, 1000);
    check_image_size(
        &avatar_blob,
        constants::BALANCED_AVATAR_SIZE,
        constants::BALANCED_AVATAR_SIZE,
    );

    let mut blob = BlobObject::create_and_deduplicate(&t, avatar_path, avatar_path).unwrap();
    let maybe_sticker = &mut false;
    let strict_limits = true;
    blob.recode_to_size(&t, None, maybe_sticker, 1000, 3000, strict_limits)
        .unwrap();
    let new_file_size = file_size(&blob.to_abs_path()).await;
    assert!(new_file_size <= 3000);
    assert!(new_file_size > 2000);
    // The new file should be smaller:
    assert!(new_file_size < scaled_avatar_size);
    // And the original file should not be touched:
    assert_eq!(file_size(avatar_path).await, scaled_avatar_size);
    tokio::task::block_in_place(move || {
        let img = ImageReader::open(blob.to_abs_path())
            .unwrap()
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        assert!(img.width() > 130);
        assert_eq!(img.width(), img.height());
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_in_blobdir() {
    let t = TestContext::new().await;
    let avatar_src = t.get_blobdir().join("avatar.png");
    fs::write(&avatar_src, test_utils::AVATAR_900x900_BYTES)
        .await
        .unwrap();

    check_image_size(&avatar_src, 900, 900);

    t.set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
        .await
        .unwrap();
    let avatar_cfg = t.get_config(Config::Selfavatar).await.unwrap().unwrap();
    assert!(
        avatar_cfg.ends_with("ec054c444a5755adf2b0aaea40209f2.png"),
        "Avatar file name {avatar_cfg} should end with its hash"
    );

    check_image_size(
        avatar_cfg,
        constants::BALANCED_AVATAR_SIZE,
        constants::BALANCED_AVATAR_SIZE,
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_copy_without_recode() {
    let t = TestContext::new().await;
    let avatar_src = t.dir.path().join("avatar.png");
    let avatar_bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    fs::write(&avatar_src, avatar_bytes).await.unwrap();
    let avatar_blob = t.get_blobdir().join("e9b6c7a78aa2e4f415644f55a553e73.png");
    assert!(!avatar_blob.exists());
    t.set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
        .await
        .unwrap();
    assert!(avatar_blob.exists());
    assert_eq!(
        fs::metadata(&avatar_blob).await.unwrap().len(),
        avatar_bytes.len() as u64
    );
    let avatar_cfg = t.get_config(Config::Selfavatar).await.unwrap();
    assert_eq!(avatar_cfg, avatar_blob.to_str().map(|s| s.to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recode_image_1() {
    let bytes = include_bytes!("../../test-data/image/avatar1000x1000.jpg");
    SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "0",
        bytes,
        extension: "jpg",
        has_exif: true,
        original_width: 1000,
        original_height: 1000,
        compressed_width: 1000,
        compressed_height: 1000,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
    SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "1",
        bytes,
        extension: "jpg",
        has_exif: true,
        original_width: 1000,
        original_height: 1000,
        compressed_width: 1000,
        compressed_height: 1000,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recode_image_2() {
    // The "-rotated" files are rotated by 270 degrees using the Exif metadata
    let bytes = include_bytes!("../../test-data/image/rectangle2000x1800-rotated.jpg");
    let img_rotated = SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "0",
        bytes,
        extension: "jpg",
        has_exif: true,
        original_width: 2000,
        original_height: 1800,
        orientation: 270,
        compressed_width: 1800,
        compressed_height: 2000,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
    assert_correct_rotation(&img_rotated);

    let mut buf = Cursor::new(vec![]);
    img_rotated.write_to(&mut buf, ImageFormat::Jpeg).unwrap();
    let bytes = buf.into_inner();

    let img_rotated = SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "1",
        bytes: &bytes,
        extension: "jpg",
        original_width: 1800,
        original_height: 2000,
        compressed_width: 1800,
        compressed_height: 2000,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
    assert_correct_rotation(&img_rotated);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recode_image_balanced_png() {
    let bytes = include_bytes!("../../test-data/image/screenshot.png");

    SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "0",
        bytes,
        extension: "png",
        original_width: 1920,
        original_height: 1080,
        compressed_width: 1920,
        compressed_height: 1080,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();

    SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "1",
        bytes,
        extension: "png",
        original_width: 1920,
        original_height: 1080,
        compressed_width: constants::WORSE_IMAGE_SIZE,
        compressed_height: constants::WORSE_IMAGE_SIZE * 1080 / 1920,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();

    SendImageCheckMediaquality {
        viewtype: Viewtype::File,
        media_quality_config: "1",
        bytes,
        extension: "png",
        original_width: 1920,
        original_height: 1080,
        compressed_width: 1920,
        compressed_height: 1080,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();

    SendImageCheckMediaquality {
        viewtype: Viewtype::File,
        media_quality_config: "1",
        bytes,
        extension: "png",
        original_width: 1920,
        original_height: 1080,
        compressed_width: 1920,
        compressed_height: 1080,
        set_draft: true,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();

    // This will be sent as Image, see [`BlobObject::maybe_sticker`] for explanation.
    SendImageCheckMediaquality {
        viewtype: Viewtype::Sticker,
        media_quality_config: "0",
        bytes,
        extension: "png",
        original_width: 1920,
        original_height: 1080,
        compressed_width: 1920,
        compressed_height: 1080,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
}

/// Tests that RGBA PNG can be recoded into JPEG
/// by dropping alpha channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recode_image_rgba_png_to_jpeg() {
    let bytes = include_bytes!("../../test-data/image/screenshot-rgba.png");

    SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "1",
        bytes,
        extension: "png",
        original_width: 1920,
        original_height: 1080,
        compressed_width: constants::WORSE_IMAGE_SIZE,
        compressed_height: constants::WORSE_IMAGE_SIZE * 1080 / 1920,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recode_image_huge_jpg() {
    let bytes = include_bytes!("../../test-data/image/screenshot.jpg");
    SendImageCheckMediaquality {
        viewtype: Viewtype::Image,
        media_quality_config: "0",
        bytes,
        extension: "jpg",
        has_exif: true,
        original_width: 1920,
        original_height: 1080,
        compressed_width: constants::BALANCED_IMAGE_SIZE,
        compressed_height: constants::BALANCED_IMAGE_SIZE * 1080 / 1920,
        ..Default::default()
    }
    .test()
    .await
    .unwrap();
}

fn assert_correct_rotation(img: &DynamicImage) {
    // The test images are black in the bottom left corner after correctly applying
    // the EXIF orientation

    let [luma] = img.get_pixel(10, 10).to_luma().0;
    assert_eq!(luma, 255);
    let [luma] = img.get_pixel(img.width() - 10, 10).to_luma().0;
    assert_eq!(luma, 255);
    let [luma] = img
        .get_pixel(img.width() - 10, img.height() - 10)
        .to_luma()
        .0;
    assert_eq!(luma, 255);
    let [luma] = img.get_pixel(10, img.height() - 10).to_luma().0;
    assert_eq!(luma, 0);
}

#[derive(Default)]
struct SendImageCheckMediaquality<'a> {
    pub(crate) viewtype: Viewtype,
    pub(crate) media_quality_config: &'a str,
    pub(crate) bytes: &'a [u8],
    pub(crate) extension: &'a str,
    pub(crate) has_exif: bool,
    pub(crate) original_width: u32,
    pub(crate) original_height: u32,
    pub(crate) orientation: i32,
    pub(crate) compressed_width: u32,
    pub(crate) compressed_height: u32,
    pub(crate) set_draft: bool,
}

impl SendImageCheckMediaquality<'_> {
    pub(crate) async fn test(self) -> anyhow::Result<DynamicImage> {
        let viewtype = self.viewtype;
        let media_quality_config = self.media_quality_config;
        let bytes = self.bytes;
        let extension = self.extension;
        let has_exif = self.has_exif;
        let original_width = self.original_width;
        let original_height = self.original_height;
        let orientation = self.orientation;
        let compressed_width = self.compressed_width;
        let compressed_height = self.compressed_height;
        let set_draft = self.set_draft;

        let alice = TestContext::new_alice().await;
        let bob = TestContext::new_bob().await;
        alice
            .set_config(Config::MediaQuality, Some(media_quality_config))
            .await?;
        let file = alice.get_blobdir().join("file").with_extension(extension);
        let file_name = format!("file.{extension}");

        fs::write(&file, &bytes)
            .await
            .context("failed to write file")?;
        check_image_size(&file, original_width, original_height);

        let (_, exif) = image_metadata(&std::fs::File::open(&file)?)?;
        if has_exif {
            let exif = exif.unwrap();
            assert_eq!(exif_orientation(&exif, &alice), orientation);
        } else {
            assert!(exif.is_none());
        }

        let mut msg = Message::new(viewtype);
        msg.set_file_and_deduplicate(&alice, &file, Some(&file_name), None)?;
        let chat = alice.create_chat(&bob).await;
        if set_draft {
            chat.id.set_draft(&alice, Some(&mut msg)).await.unwrap();
            msg = chat.id.get_draft(&alice).await.unwrap().unwrap();
            assert_eq!(msg.get_viewtype(), Viewtype::File);
        }
        let sent = alice.send_msg(chat.id, &mut msg).await;
        let alice_msg = alice.get_last_msg().await;
        assert_eq!(alice_msg.get_width() as u32, compressed_width);
        assert_eq!(alice_msg.get_height() as u32, compressed_height);
        let file_saved = alice
            .get_blobdir()
            .join("saved-".to_string() + &alice_msg.get_filename().unwrap());
        alice_msg.save_file(&alice, &file_saved).await?;
        check_image_size(file_saved, compressed_width, compressed_height);

        if original_width == compressed_width {
            assert_extension(&alice, alice_msg, extension);
        } else {
            assert_extension(&alice, alice_msg, "jpg");
        }

        let bob_msg = bob.recv_msg(&sent).await;
        assert_eq!(bob_msg.get_viewtype(), Viewtype::Image);
        assert_eq!(bob_msg.get_width() as u32, compressed_width);
        assert_eq!(bob_msg.get_height() as u32, compressed_height);
        let file_saved = bob
            .get_blobdir()
            .join("saved-".to_string() + &bob_msg.get_filename().unwrap());
        bob_msg.save_file(&bob, &file_saved).await?;
        if viewtype == Viewtype::File {
            assert_eq!(file_saved.extension().unwrap(), extension);
            let bytes1 = fs::read(&file_saved).await?;
            assert_eq!(&bytes1, bytes);
        }

        let (_, exif) = image_metadata(&std::fs::File::open(&file_saved)?)?;
        assert!(exif.is_none());

        let img = check_image_size(file_saved, compressed_width, compressed_height);

        if original_width == compressed_width {
            assert_extension(&bob, bob_msg, extension);
        } else {
            assert_extension(&bob, bob_msg, "jpg");
        }

        Ok(img)
    }
}

fn assert_extension(context: &TestContext, msg: Message, extension: &str) {
    assert!(msg
        .param
        .get(Param::File)
        .unwrap()
        .ends_with(&format!(".{extension}")));
    assert!(msg
        .param
        .get(Param::Filename)
        .unwrap()
        .ends_with(&format!(".{extension}")));
    assert!(msg
        .get_filename()
        .unwrap()
        .ends_with(&format!(".{extension}")));
    assert_eq!(
        msg.get_file(context)
            .unwrap()
            .extension()
            .unwrap()
            .to_str()
            .unwrap(),
        extension
    );
    assert_eq!(
        msg.param
            .get_file_blob(context)
            .unwrap()
            .unwrap()
            .suffix()
            .unwrap(),
        extension
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_big_gif_as_image() -> Result<()> {
    let bytes = include_bytes!("../../test-data/image/screenshot.gif");
    let (width, height) = (1920u32, 1080u32);
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    alice
        .set_config(
            Config::MediaQuality,
            Some(&(MediaQuality::Worse as i32).to_string()),
        )
        .await?;
    let file = alice.get_blobdir().join("file").with_extension("gif");
    fs::write(&file, &bytes)
        .await
        .context("failed to write file")?;
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_and_deduplicate(&alice, &file, Some("file.gif"), None)?;
    let chat = alice.create_chat(&bob).await;
    let sent = alice.send_msg(chat.id, &mut msg).await;
    let bob_msg = bob.recv_msg(&sent).await;
    // DC must detect the image as GIF and send it w/o reencoding.
    assert_eq!(bob_msg.get_viewtype(), Viewtype::Gif);
    assert_eq!(bob_msg.get_width() as u32, width);
    assert_eq!(bob_msg.get_height() as u32, height);
    let file_saved = bob
        .get_blobdir()
        .join("saved-".to_string() + &bob_msg.get_filename().unwrap());
    bob_msg.save_file(&bob, &file_saved).await?;
    let (file_size, _) = image_metadata(&std::fs::File::open(&file_saved)?)?;
    assert_eq!(file_size, bytes.len() as u64);
    check_image_size(file_saved, width, height);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_gif_as_sticker() -> Result<()> {
    let bytes = include_bytes!("../../test-data/image/image100x50.gif");
    let alice = &TestContext::new_alice().await;
    let file = alice.get_blobdir().join("file").with_extension("gif");
    fs::write(&file, &bytes)
        .await
        .context("failed to write file")?;
    let mut msg = Message::new(Viewtype::Sticker);
    msg.set_file_and_deduplicate(alice, &file, None, None)?;
    let chat = alice.get_self_chat().await;
    let sent = alice.send_msg(chat.id, &mut msg).await;
    let msg = Message::load_from_db(alice, sent.sender_msg_id).await?;
    // Message::force_sticker() wasn't used, still Viewtype::Sticker is preserved because of the
    // extension.
    assert_eq!(msg.get_viewtype(), Viewtype::Sticker);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_and_deduplicate() -> Result<()> {
    let t = TestContext::new().await;

    let path = t.get_blobdir().join("anyfile.dat");
    fs::write(&path, b"bla").await?;
    let blob = BlobObject::create_and_deduplicate(&t, &path, &path)?;
    assert_eq!(blob.name, "$BLOBDIR/ce940175885d7b78f7b7e9f1396611f.dat");
    assert_eq!(path.exists(), false);

    assert_eq!(fs::read(&blob.to_abs_path()).await?, b"bla");

    fs::write(&path, b"bla").await?;
    let blob2 = BlobObject::create_and_deduplicate(&t, &path, &path)?;
    assert_eq!(blob2.name, blob.name);

    let path_outside_blobdir = t.dir.path().join("anyfile.dat");
    fs::write(&path_outside_blobdir, b"bla").await?;
    let blob3 =
        BlobObject::create_and_deduplicate(&t, &path_outside_blobdir, &path_outside_blobdir)?;
    assert!(path_outside_blobdir.exists());
    assert_eq!(blob3.name, blob.name);

    fs::write(&path, b"blabla").await?;
    let blob4 = BlobObject::create_and_deduplicate(&t, &path, &path)?;
    assert_ne!(blob4.name, blob.name);

    fs::remove_dir_all(t.get_blobdir()).await?;
    let blob5 =
        BlobObject::create_and_deduplicate(&t, &path_outside_blobdir, &path_outside_blobdir)?;
    assert_eq!(blob5.name, blob.name);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_and_deduplicate_from_bytes() -> Result<()> {
    let t = TestContext::new().await;

    fs::remove_dir(t.get_blobdir()).await?;
    let blob = BlobObject::create_and_deduplicate_from_bytes(&t, b"bla", "file")?;
    assert_eq!(blob.name, "$BLOBDIR/ce940175885d7b78f7b7e9f1396611f");

    assert_eq!(fs::read(&blob.to_abs_path()).await?, b"bla");
    let modified1 = blob.to_abs_path().metadata()?.modified()?;

    // Test that the modification time of the file is updated when a new file is created
    // so that it's not deleted during housekeeping.
    // We can't use SystemTime::shift() here because file creation uses the actual OS time,
    // which we can't mock from our code.
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let blob2 = BlobObject::create_and_deduplicate_from_bytes(&t, b"bla", "file")?;
    assert_eq!(blob2.name, blob.name);

    let modified2 = blob.to_abs_path().metadata()?.modified()?;
    assert_ne!(modified1, modified2);
    sql::housekeeping(&t).await?;
    assert!(blob2.to_abs_path().exists());

    // If we do shift the time by more than 1h, the blob file will be deleted during housekeeping:
    SystemTime::shift(Duration::from_secs(65 * 60));
    sql::housekeeping(&t).await?;
    assert_eq!(blob2.to_abs_path().exists(), false);

    let blob3 = BlobObject::create_and_deduplicate_from_bytes(&t, b"blabla", "file")?;
    assert_ne!(blob3.name, blob.name);

    {
        // If something goes wrong and the blob file is overwritten,
        // the correct content should be restored:
        fs::write(blob3.to_abs_path(), b"bloblo").await?;

        let blob4 = BlobObject::create_and_deduplicate_from_bytes(&t, b"blabla", "file")?;
        let blob4_content = fs::read(blob4.to_abs_path()).await?;
        assert_eq!(blob4_content, b"blabla");
    }

    Ok(())
}
