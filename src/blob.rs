//! # Blob directory management.

use std::cmp::max;
use std::io::{Cursor, Seek};
use std::iter::FusedIterator;
use std::mem;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure, format_err};
use base64::Engine as _;
use futures::StreamExt;
use image::ImageReader;
use image::codecs::jpeg::JpegEncoder;
use image::{DynamicImage, GenericImage, GenericImageView, ImageFormat, Pixel, Rgba};
use num_traits::FromPrimitive;
use tokio::{fs, task};
use tokio_stream::wrappers::ReadDirStream;

use crate::config::Config;
use crate::constants::{self, MediaQuality};
use crate::context::Context;
use crate::events::EventType;
use crate::log::{LogExt, warn};
use crate::message::Viewtype;
use crate::tools::sanitize_filename;

/// Represents a file in the blob directory.
///
/// The object has a name, which will always be valid UTF-8.  Having a
/// blob object does not imply the respective file exists, however
/// when using one of the `create*()` methods a unique file is
/// created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobObject<'a> {
    blobdir: &'a Path,

    /// The name of the file on the disc.
    /// Note that this is NOT the user-visible filename,
    /// which is only stored in Param::Filename on the message.
    name: String,
}

#[derive(Debug, Clone)]
enum ImageOutputFormat {
    Png,
    Jpeg { quality: u8 },
}

impl<'a> BlobObject<'a> {
    /// Creates a blob object by copying or renaming an existing file.
    /// If the source file is already in the blobdir, it will be renamed,
    /// otherwise it will be copied to the blobdir first.
    ///
    /// In order to deduplicate files that contain the same data,
    /// the file will be named `<hash>.<extension>`, e.g. `ce940175885d7b78f7b7e9f1396611f.jpg`.
    /// The `original_name` param is only used to get the extension.
    ///
    /// This is done in a in way which avoids race-conditions when multiple files are
    /// concurrently created.
    pub fn create_and_deduplicate(
        context: &'a Context,
        src: &Path,
        original_name: &Path,
    ) -> Result<BlobObject<'a>> {
        // `create_and_deduplicate{_from_bytes}()` do blocking I/O, but can still be called
        // from an async context thanks to `block_in_place()`.
        // Tokio's "async" I/O functions are also just thin wrappers around the blocking I/O syscalls,
        // so we are doing essentially the same here.
        task::block_in_place(|| {
            let temp_path;
            let src_in_blobdir: &Path;
            let blobdir = context.get_blobdir();

            if src.starts_with(blobdir) {
                src_in_blobdir = src;
            } else {
                info!(
                    context,
                    "Source file not in blobdir. Copying instead of moving in order to prevent moving a file that was still needed."
                );
                temp_path = blobdir.join(format!("tmp-{}", rand::random::<u64>()));
                if std::fs::copy(src, &temp_path).is_err() {
                    // Maybe the blobdir didn't exist
                    std::fs::create_dir_all(blobdir).log_err(context).ok();
                    std::fs::copy(src, &temp_path).context("Copying new blobfile failed")?;
                };
                src_in_blobdir = &temp_path;
            }

            let hash = file_hash(src_in_blobdir)?.to_hex();
            let hash = hash.as_str();
            let hash = hash.get(0..31).unwrap_or(hash);
            let new_file =
                if let Some(extension) = original_name.extension().filter(|e| e.len() <= 32) {
                    let extension = extension.to_string_lossy().to_lowercase();
                    let extension = sanitize_filename(&extension);
                    format!("$BLOBDIR/{hash}.{extension}")
                } else {
                    format!("$BLOBDIR/{hash}")
                };

            let blob = BlobObject {
                blobdir,
                name: new_file,
            };
            let new_path = blob.to_abs_path();

            // This will also replace an already-existing file.
            // Renaming is atomic, so this will avoid race conditions.
            std::fs::rename(src_in_blobdir, &new_path)?;

            context.emit_event(EventType::NewBlobFile(blob.as_name().to_string()));
            Ok(blob)
        })
    }

    /// Creates a new blob object with the file contents in `data`.
    /// In order to deduplicate files that contain the same data,
    /// the file will be named `<hash>.<extension>`, e.g. `ce940175885d7b78f7b7e9f1396611f.jpg`.
    /// The `original_name` param is only used to get the extension.
    ///
    /// The `data` will be written into the file without race-conditions.
    ///
    /// This function does blocking I/O, but it can still be called from an async context
    /// because `block_in_place()` is used to leave the async runtime if necessary.
    pub fn create_and_deduplicate_from_bytes(
        context: &'a Context,
        data: &[u8],
        original_name: &str,
    ) -> Result<BlobObject<'a>> {
        task::block_in_place(|| {
            let blobdir = context.get_blobdir();
            let temp_path = blobdir.join(format!("tmp-{}", rand::random::<u64>()));
            if std::fs::write(&temp_path, data).is_err() {
                // Maybe the blobdir didn't exist
                std::fs::create_dir_all(blobdir).log_err(context).ok();
                std::fs::write(&temp_path, data).context("writing new blobfile failed")?;
            };

            BlobObject::create_and_deduplicate(context, &temp_path, Path::new(original_name))
        })
    }

    /// Returns a [BlobObject] for an existing blob from a path.
    ///
    /// The path must designate a file directly in the blobdir and
    /// must use a valid blob name.  That is after sanitisation the
    /// name must still be the same, that means it must be valid UTF-8
    /// and not have any special characters in it.
    pub fn from_path(context: &'a Context, path: &Path) -> Result<BlobObject<'a>> {
        let rel_path = path
            .strip_prefix(context.get_blobdir())
            .with_context(|| format!("wrong blobdir: {}", path.display()))?;
        let name = rel_path.to_str().context("wrong name")?;
        if !BlobObject::is_acceptible_blob_name(name) {
            return Err(format_err!("bad blob name: {}", rel_path.display()));
        }
        BlobObject::from_name(context, name)
    }

    /// Returns a [BlobObject] for an existing blob.
    ///
    /// The `name` may optionally be prefixed with the `$BLOBDIR/`
    /// prefixed, as returned by [BlobObject::as_name].  This is how
    /// you want to create a [BlobObject] for a filename read from the
    /// database.
    pub fn from_name(context: &'a Context, name: &str) -> Result<BlobObject<'a>> {
        let name = match name.starts_with("$BLOBDIR/") {
            true => name.splitn(2, '/').last().unwrap(),
            false => name,
        };
        if !BlobObject::is_acceptible_blob_name(name) {
            return Err(format_err!("not an acceptable blob name: {name}"));
        }
        Ok(BlobObject {
            blobdir: context.get_blobdir(),
            name: format!("$BLOBDIR/{name}"),
        })
    }

    /// Returns the absolute path to the blob in the filesystem.
    pub fn to_abs_path(&self) -> PathBuf {
        let fname = Path::new(&self.name).strip_prefix("$BLOBDIR/").unwrap();
        self.blobdir.join(fname)
    }

    /// Returns the blob name, as stored in the database.
    ///
    /// This returns the blob in the `$BLOBDIR/<name>` format used in
    /// the database.  Do not use this unless you're about to store
    /// this string in the database or [Params].  Eventually even
    /// those conversions should be handled by the type system.
    ///
    /// Note that this is NOT the user-visible filename,
    /// which is only stored in Param::Filename on the message.
    ///
    #[allow(rustdoc::private_intra_doc_links)]
    /// [Params]: crate::param::Params
    pub fn as_name(&self) -> &str {
        &self.name
    }

    /// Returns the extension of the blob.
    ///
    /// If a blob's filename has an extension, it is always guaranteed
    /// to be lowercase.
    pub fn suffix(&self) -> Option<&str> {
        let ext = self.name.rsplit('.').next();
        if ext == Some(&self.name) { None } else { ext }
    }

    /// Checks whether a name is a valid blob name.
    ///
    /// This is slightly less strict than stanitise_name, presumably
    /// someone already created a file with such a name so we just
    /// ensure it's not actually a path in disguise.
    ///
    /// Acceptible blob name always have to be valid utf-8.
    fn is_acceptible_blob_name(name: &str) -> bool {
        if name.find('/').is_some() {
            return false;
        }
        if name.find('\\').is_some() {
            return false;
        }
        if name.find('\0').is_some() {
            return false;
        }
        true
    }

    /// Returns path to the stored Base64-decoded blob.
    ///
    /// If `data` represents an image of known format, this adds the corresponding extension.
    ///
    /// Even though this function is not async, it's OK to call it from an async context.
    ///
    /// Returns an error if there is an I/O problem,
    /// but in case of a failure to decode base64 returns `Ok(None)`.
    pub(crate) fn store_from_base64(context: &Context, data: &str) -> Result<Option<String>> {
        let Ok(buf) = base64::engine::general_purpose::STANDARD.decode(data) else {
            return Ok(None);
        };
        let name = if let Ok(format) = image::guess_format(&buf) {
            if let Some(ext) = format.extensions_str().first() {
                format!("file.{ext}")
            } else {
                String::new()
            }
        } else {
            String::new()
        };
        let blob = BlobObject::create_and_deduplicate_from_bytes(context, &buf, &name)?;
        Ok(Some(blob.as_name().to_string()))
    }

    /// Recode image to avatar size.
    pub async fn recode_to_avatar_size(&mut self, context: &Context) -> Result<()> {
        let (max_wh, max_bytes) =
            match MediaQuality::from_i32(context.get_config_int(Config::MediaQuality).await?)
                .unwrap_or_default()
            {
                MediaQuality::Balanced => (
                    constants::BALANCED_AVATAR_SIZE,
                    constants::BALANCED_AVATAR_BYTES,
                ),
                MediaQuality::Worse => {
                    (constants::WORSE_AVATAR_SIZE, constants::WORSE_AVATAR_BYTES)
                }
            };

        let viewtype = &mut Viewtype::Image;
        let is_avatar = true;
        self.check_or_recode_to_size(
            context, None, // The name of an avatar doesn't matter
            viewtype, max_wh, max_bytes, is_avatar,
        )?;

        Ok(())
    }

    /// Checks or recodes an image pointed by the [BlobObject] so that it fits into limits on the
    /// image width, height and file size specified by the config.
    ///
    /// Recoding is only done for [`Viewtype::Image`]. For [`Viewtype::File`], if it's a correct
    /// image, `*viewtype` is set to [`Viewtype::Image`].
    ///
    /// On some platforms images are passed to Core as [`Viewtype::Sticker`]. We recheck if the
    /// image is a true sticker assuming that it must have at least one fully transparent corner,
    /// otherwise `*viewtype` is set to [`Viewtype::Image`].
    pub async fn check_or_recode_image(
        &mut self,
        context: &Context,
        name: Option<String>,
        viewtype: &mut Viewtype,
    ) -> Result<String> {
        let (max_wh, max_bytes) =
            match MediaQuality::from_i32(context.get_config_int(Config::MediaQuality).await?)
                .unwrap_or_default()
            {
                MediaQuality::Balanced => (
                    constants::BALANCED_IMAGE_SIZE,
                    constants::BALANCED_IMAGE_BYTES,
                ),
                MediaQuality::Worse => (constants::WORSE_IMAGE_SIZE, constants::WORSE_IMAGE_BYTES),
            };
        let is_avatar = false;
        self.check_or_recode_to_size(context, name, viewtype, max_wh, max_bytes, is_avatar)
    }

    /// Checks or recodes the image so that it fits into limits on width/height and/or byte size.
    ///
    /// If `!is_avatar`, then if `max_bytes` is exceeded, reduces the image to `max_wh` and proceeds
    /// with the result (even if `max_bytes` is still exceeded).
    ///
    /// If `is_avatar`, the resolution will be reduced in a loop until the image fits `max_bytes`.
    ///
    /// This modifies the blob object in-place.
    ///
    /// Additionally, if you pass the user-visible filename as `name`
    /// then the updated user-visible filename will be returned;
    /// this may be necessary because the format may be changed to JPG,
    /// i.e. "image.png" -> "image.jpg".
    #[expect(clippy::arithmetic_side_effects)]
    fn check_or_recode_to_size(
        &mut self,
        context: &Context,
        name: Option<String>,
        viewtype: &mut Viewtype,
        max_wh: u32,
        max_bytes: usize,
        is_avatar: bool,
    ) -> Result<String> {
        // Add white background only to avatars to spare the CPU.
        let mut add_white_bg = is_avatar;
        let mut no_exif = false;
        let no_exif_ref = &mut no_exif;
        let mut name = name.unwrap_or_else(|| self.name.clone());
        let original_name = name.clone();
        let vt = &mut *viewtype;
        let res: Result<String> = tokio::task::block_in_place(move || {
            let mut file = std::fs::File::open(self.to_abs_path())?;
            let (nr_bytes, exif) = image_metadata(&file)?;
            *no_exif_ref = exif.is_none();
            // It's strange that BufReader modifies a file position while it takes a non-mut
            // reference. Ok, just rewind it.
            file.rewind()?;
            let imgreader = ImageReader::new(std::io::BufReader::new(&file)).with_guessed_format();
            let imgreader = match imgreader {
                Ok(ir) => ir,
                _ => {
                    file.rewind()?;
                    ImageReader::with_format(
                        std::io::BufReader::new(&file),
                        ImageFormat::from_path(self.to_abs_path())?,
                    )
                }
            };
            let fmt = imgreader.format().context("Unknown format")?;
            if *vt == Viewtype::File {
                *vt = Viewtype::Image;
                return Ok(name);
            }
            let mut img = imgreader.decode().context("image decode failure")?;
            let orientation = exif.as_ref().map(|exif| exif_orientation(exif, context));
            let mut encoded = Vec::new();

            if *vt == Viewtype::Sticker {
                let x_max = img.width().saturating_sub(1);
                let y_max = img.height().saturating_sub(1);
                if !img.in_bounds(x_max, y_max)
                    || !(img.get_pixel(0, 0).0[3] == 0
                        || img.get_pixel(x_max, 0).0[3] == 0
                        || img.get_pixel(0, y_max).0[3] == 0
                        || img.get_pixel(x_max, y_max).0[3] == 0)
                {
                    *vt = Viewtype::Image;
                } else {
                    // Core doesn't auto-assign `Viewtype::Sticker` to messages and stickers coming
                    // from UIs shouldn't contain sensitive Exif info.
                    return Ok(name);
                }
            }

            img = match orientation {
                Some(90) => img.rotate90(),
                Some(180) => img.rotate180(),
                Some(270) => img.rotate270(),
                _ => img,
            };

            // max_wh is the maximum image width and height, i.e. the resolution-limit.
            // target_wh target-resolution for resizing the image.
            let exceeds_wh = img.width() > max_wh || img.height() > max_wh;
            let mut target_wh = if exceeds_wh {
                max_wh
            } else {
                max(img.width(), img.height())
            };
            let exceeds_max_bytes = nr_bytes > max_bytes as u64;

            let jpeg_quality = 75;
            let ofmt = match fmt {
                ImageFormat::Png if !exceeds_max_bytes => ImageOutputFormat::Png,
                ImageFormat::Jpeg => {
                    add_white_bg = false;
                    ImageOutputFormat::Jpeg {
                        quality: jpeg_quality,
                    }
                }
                _ => ImageOutputFormat::Jpeg {
                    quality: jpeg_quality,
                },
            };
            // We need to rewrite images with Exif to remove metadata such as location,
            // camera model, etc.
            //
            // TODO: Fix lost animation and transparency when recoding using the `image` crate. And
            // also `Viewtype::Gif` (maybe renamed to `Animation`) should be used for animated
            // images.
            let do_scale = exceeds_max_bytes
                || is_avatar
                    && (exceeds_wh
                        || exif.is_some() && {
                            if mem::take(&mut add_white_bg) {
                                self::add_white_bg(&mut img);
                            }
                            encoded_img_exceeds_bytes(
                                context,
                                &img,
                                ofmt.clone(),
                                max_bytes,
                                &mut encoded,
                            )?
                        });

            if do_scale {
                loop {
                    if mem::take(&mut add_white_bg) {
                        self::add_white_bg(&mut img);
                    }

                    // resize() results in often slightly better quality,
                    // however, comes at high price of being 4+ times slower than thumbnail().
                    // for a typical camera image that is sent, this may be a change from "instant" (500ms) to "long time waiting" (3s).
                    // as we do not have recoding in background while chat has already a preview,
                    // we vote for speed.
                    // exception is the avatar image: this is far more often sent than recoded,
                    // usually has less pixels by cropping, UI that needs to wait anyways,
                    // and also benefits from slightly better (5%) encoding of Triangle-filtered images.
                    let new_img = if is_avatar {
                        img.resize(target_wh, target_wh, image::imageops::FilterType::Triangle)
                    } else {
                        img.thumbnail(target_wh, target_wh)
                    };

                    if encoded_img_exceeds_bytes(
                        context,
                        &new_img,
                        ofmt.clone(),
                        max_bytes,
                        &mut encoded,
                    )? && is_avatar
                    {
                        if target_wh < 20 {
                            return Err(format_err!(
                                "Failed to scale image to below {max_bytes}B.",
                            ));
                        }

                        target_wh = target_wh * 2 / 3;
                    } else {
                        info!(
                            context,
                            "Final scaled-down image size: {}B ({}px).",
                            encoded.len(),
                            target_wh
                        );
                        break;
                    }
                }
            }

            if do_scale || exif.is_some() {
                // The file format is JPEG/PNG now, we may have to change the file extension
                if !matches!(fmt, ImageFormat::Jpeg)
                    && matches!(ofmt, ImageOutputFormat::Jpeg { .. })
                {
                    name = Path::new(&name)
                        .with_extension("jpg")
                        .to_string_lossy()
                        .into_owned();
                }

                if encoded.is_empty() {
                    if mem::take(&mut add_white_bg) {
                        self::add_white_bg(&mut img);
                    }
                    encode_img(&img, ofmt, &mut encoded)?;
                }

                self.name = BlobObject::create_and_deduplicate_from_bytes(context, &encoded, &name)
                    .context("failed to write recoded blob to file")?
                    .name;
            }

            Ok(name)
        });
        match res {
            Ok(_) => res,
            Err(err) => {
                if !is_avatar && no_exif {
                    error!(
                        context,
                        "Cannot check/recode image, using original data: {err:#}.",
                    );
                    *viewtype = Viewtype::File;
                    Ok(original_name)
                } else {
                    Err(err)
                }
            }
        }
    }
}

fn file_hash(src: &Path) -> Result<blake3::Hash> {
    ensure!(
        !src.starts_with("$BLOBDIR/"),
        "Use `get_abs_path()` to get the absolute path of the blobfile"
    );
    let mut hasher = blake3::Hasher::new();
    let mut src_file = std::fs::File::open(src)
        .with_context(|| format!("Failed to open file {}", src.display()))?;
    hasher
        .update_reader(&mut src_file)
        .context("update_reader")?;
    let hash = hasher.finalize();
    Ok(hash)
}

/// Returns image file size and Exif.
fn image_metadata(file: &std::fs::File) -> Result<(u64, Option<exif::Exif>)> {
    let len = file.metadata()?.len();
    let mut bufreader = std::io::BufReader::new(file);
    let exif = exif::Reader::new()
        .continue_on_error(true)
        .read_from_container(&mut bufreader)
        .or_else(|e| e.distill_partial_result(|_errors| {}))
        .ok();
    Ok((len, exif))
}

fn exif_orientation(exif: &exif::Exif, context: &Context) -> i32 {
    if let Some(orientation) = exif.get_field(exif::Tag::Orientation, exif::In::PRIMARY) {
        // possible orientation values are described at http://sylvana.net/jpegcrop/exif_orientation.html
        // we only use rotation, in practise, flipping is not used.
        match orientation.value.get_uint(0) {
            Some(3) => return 180,
            Some(6) => return 90,
            Some(8) => return 270,
            other => warn!(context, "Exif orientation value ignored: {other:?}."),
        }
    }
    0
}

/// All files in the blobdir.
///
/// This exists so we can have a [`BlobDirIter`] which needs something to own the data of
/// it's `&Path`.  Use [`BlobDirContents::iter`] to create the iterator.
///
/// Additionally pre-allocating this means we get a length for progress report.
pub(crate) struct BlobDirContents<'a> {
    inner: Vec<PathBuf>,
    context: &'a Context,
}

impl<'a> BlobDirContents<'a> {
    pub(crate) async fn new(context: &'a Context) -> Result<BlobDirContents<'a>> {
        let readdir = fs::read_dir(context.get_blobdir()).await?;
        let inner = ReadDirStream::new(readdir)
            .filter_map(|entry| async move {
                match entry {
                    Ok(entry) => Some(entry),
                    Err(err) => {
                        error!(context, "Failed to read blob file: {err}.");
                        None
                    }
                }
            })
            .filter_map(|entry| async move {
                match entry.file_type().await.ok()?.is_file() {
                    true => Some(entry.path()),
                    false => {
                        warn!(
                            context,
                            "Export: Found blob dir entry {} that is not a file, ignoring.",
                            entry.path().display()
                        );
                        None
                    }
                }
            })
            .collect()
            .await;
        Ok(Self { inner, context })
    }

    pub(crate) fn iter(&self) -> BlobDirIter<'_> {
        BlobDirIter::new(self.context, self.inner.iter())
    }
}

/// A iterator over all the [`BlobObject`]s in the blobdir.
pub(crate) struct BlobDirIter<'a> {
    iter: std::slice::Iter<'a, PathBuf>,
    context: &'a Context,
}

impl<'a> BlobDirIter<'a> {
    fn new(context: &'a Context, iter: std::slice::Iter<'a, PathBuf>) -> BlobDirIter<'a> {
        Self { iter, context }
    }
}

impl<'a> Iterator for BlobDirIter<'a> {
    type Item = BlobObject<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        for path in self.iter.by_ref() {
            // In theory this can error but we'd have corrupted filenames in the blobdir, so
            // silently skipping them is fine.
            match BlobObject::from_path(self.context, path) {
                Ok(blob) => return Some(blob),
                Err(err) => warn!(self.context, "{err}"),
            }
        }
        None
    }
}

impl FusedIterator for BlobDirIter<'_> {}

fn encode_img(
    img: &DynamicImage,
    fmt: ImageOutputFormat,
    encoded: &mut Vec<u8>,
) -> anyhow::Result<()> {
    encoded.clear();
    let mut buf = Cursor::new(encoded);
    match fmt {
        ImageOutputFormat::Png => img.write_to(&mut buf, ImageFormat::Png)?,
        ImageOutputFormat::Jpeg { quality } => {
            let encoder = JpegEncoder::new_with_quality(&mut buf, quality);
            // Convert image into RGB8 to avoid the error
            // "The encoder or decoder for Jpeg does not support the color type Rgba8"
            // (<https://github.com/image-rs/image/issues/2211>).
            img.clone().into_rgb8().write_with_encoder(encoder)?;
        }
    }
    Ok(())
}

fn encoded_img_exceeds_bytes(
    context: &Context,
    img: &DynamicImage,
    fmt: ImageOutputFormat,
    max_bytes: usize,
    encoded: &mut Vec<u8>,
) -> anyhow::Result<bool> {
    encode_img(img, fmt, encoded)?;
    if encoded.len() > max_bytes {
        info!(
            context,
            "Image size {}B ({}x{}px) exceeds {}B, need to scale down.",
            encoded.len(),
            img.width(),
            img.height(),
            max_bytes,
        );
        return Ok(true);
    }
    Ok(false)
}

/// Removes transparency from an image using a white background.
fn add_white_bg(img: &mut DynamicImage) {
    for y in 0..img.height() {
        for x in 0..img.width() {
            let mut p = Rgba([255u8, 255, 255, 255]);
            p.blend(&img.get_pixel(x, y));
            img.put_pixel(x, y, p);
        }
    }
}

#[cfg(test)]
mod blob_tests;
