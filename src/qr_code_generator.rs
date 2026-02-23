//! # QR code generation module.

use anyhow::{Result, bail};
use base64::Engine as _;
use qrcodegen::{QrCode, QrCodeEcc};

use crate::blob::BlobObject;
use crate::chat::{Chat, ChatId};
use crate::color::color_int_to_hex_string;
use crate::config::Config;
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::qr::{self, Qr};
use crate::securejoin;
use crate::stock_str::{self, backup_transfer_qr};

/// Create a QR code from any input data.
#[expect(clippy::arithmetic_side_effects)]
pub fn create_qr_svg(qrcode_content: &str) -> Result<String> {
    let all_size = 512.0;
    let qr_code_size = 416.0;
    let logo_size = 96.0;

    let qr = QrCode::encode_text(qrcode_content, QrCodeEcc::Medium)?;
    let mut svg = String::with_capacity(28000);
    let mut w = tagger::new(&mut svg);

    w.elem("svg", |d| {
        d.attr("xmlns", "http://www.w3.org/2000/svg")?;
        d.attr("viewBox", format_args!("0 0 {all_size} {all_size}"))?;
        d.attr("xmlns:xlink", "http://www.w3.org/1999/xlink")?; // required for enabling xlink:href on browsers
        Ok(())
    })?
    .build(|w| {
        // background
        w.single("rect", |d| {
            d.attr("x", 0)?;
            d.attr("y", 0)?;
            d.attr("width", all_size)?;
            d.attr("height", all_size)?;
            d.attr("style", "fill:#ffffff")?;
            Ok(())
        })?;
        // QR code
        w.elem("g", |d| {
            d.attr(
                "transform",
                format!(
                    "translate({},{})",
                    (all_size - qr_code_size) / 2.0,
                    ((all_size - qr_code_size) / 2.0)
                ),
            )
        })?
        .build(|w| {
            w.single("path", |d| {
                let mut path_data = String::with_capacity(0);
                let scale = qr_code_size / qr.size() as f32;

                for y in 0..qr.size() {
                    for x in 0..qr.size() {
                        if qr.get_module(x, y) {
                            path_data += &format!("M{x},{y}h1v1h-1z");
                        }
                    }
                }

                d.attr("style", "fill:#000000")?;
                d.attr("d", path_data)?;
                d.attr("transform", format!("scale({scale})"))
            })
        })?;
        w.elem("g", |d| {
            d.attr(
                "transform",
                format!(
                    "translate({},{}) scale(2)", // data in qr_overlay_delta.svg-part are 48 x 48, scaling by 2 results in desired logo_size of 96
                    (all_size - logo_size) / 2.0,
                    (all_size - logo_size) / 2.0
                ),
            )
        })?
        .build(|w| w.put_raw_escapable(include_str!("../assets/qr_overlay_delta.svg-part")))
    })?;

    Ok(svg)
}

/// Returns SVG of the QR code to join the group or verify contact.
///
/// If `chat_id` is `None`, returns verification QR code.
/// Otherwise, returns secure join QR code.
pub async fn get_securejoin_qr_svg(context: &Context, chat_id: Option<ChatId>) -> Result<String> {
    if let Some(chat_id) = chat_id {
        generate_join_group_qr_code(context, chat_id).await
    } else {
        generate_verification_qr(context).await
    }
}

async fn generate_join_group_qr_code(context: &Context, chat_id: ChatId) -> Result<String> {
    let chat = Chat::load_from_db(context, chat_id).await?;

    let avatar = match chat.get_profile_image(context).await? {
        Some(path) => {
            let avatar_blob = BlobObject::from_path(context, &path)?;
            Some(tokio::fs::read(avatar_blob.to_abs_path()).await?)
        }
        None => None,
    };

    let qrcode_description = match chat.typ {
        crate::constants::Chattype::Group => {
            stock_str::secure_join_group_qr_description(context, &chat).await
        }
        crate::constants::Chattype::OutBroadcast => {
            stock_str::secure_join_broadcast_qr_description(context, &chat).await
        }
        _ => bail!("Unexpected chat type {}", chat.typ),
    };

    inner_generate_secure_join_qr_code(
        &qrcode_description,
        &securejoin::get_securejoin_qr(context, Some(chat_id)).await?,
        &color_int_to_hex_string(chat.get_color(context).await?),
        avatar,
        chat.get_name().chars().next().unwrap_or('#'),
    )
}

async fn generate_verification_qr(context: &Context) -> Result<String> {
    let (avatar, displayname, addr, color) = self_info(context).await?;

    inner_generate_secure_join_qr_code(
        &stock_str::setup_contact_qr_description(context, &displayname, &addr).await,
        &securejoin::get_securejoin_qr(context, None).await?,
        &color,
        avatar,
        displayname.chars().next().unwrap_or('#'),
    )
}

/// Renders a [`Qr::Backup2`] QR code as an SVG image.
pub async fn generate_backup_qr(context: &Context, qr: &Qr) -> Result<String> {
    let content = qr::format_backup(qr)?;
    let (avatar, displayname, _addr, color) = self_info(context).await?;
    let description = backup_transfer_qr(context).await?;

    inner_generate_secure_join_qr_code(
        &description,
        &content,
        &color,
        avatar,
        displayname.chars().next().unwrap_or('#'),
    )
}

/// Returns `(avatar, displayname, addr, color) of the configured account.
async fn self_info(context: &Context) -> Result<(Option<Vec<u8>>, String, String, String)> {
    let contact = Contact::get_by_id(context, ContactId::SELF).await?;

    let avatar = match contact.get_profile_image(context).await? {
        Some(path) => {
            let avatar_blob = BlobObject::from_path(context, &path)?;
            Some(tokio::fs::read(avatar_blob.to_abs_path()).await?)
        }
        None => None,
    };

    let displayname = match context.get_config(Config::Displayname).await? {
        Some(name) => name,
        None => contact.get_addr().to_string(),
    };
    let addr = contact.get_addr().to_string();
    let color = color_int_to_hex_string(contact.get_color());
    Ok((avatar, displayname, addr, color))
}

#[expect(clippy::arithmetic_side_effects)]
fn inner_generate_secure_join_qr_code(
    qrcode_description: &str,
    qrcode_content: &str,
    color: &str,
    avatar: Option<Vec<u8>>,
    avatar_letter: char,
) -> Result<String> {
    // config
    let width = 515.0;
    let height = 630.0;
    let logo_offset = 28.0;
    let qr_code_size = 400.0;
    let qr_translate_up = 40.0;
    let text_y_pos = ((height - qr_code_size) / 2.0) + qr_code_size;
    let avatar_border_size = 9.0;
    let card_border_size = 2.0;
    let card_roundness = 40.0;

    let qr = QrCode::encode_text(qrcode_content, QrCodeEcc::Medium)?;
    let mut svg = String::with_capacity(28000);
    let mut w = tagger::new(&mut svg);

    w.elem("svg", |d| {
        d.attr("xmlns", "http://www.w3.org/2000/svg")?;
        d.attr("viewBox", format_args!("0 0 {width} {height}"))?;
        d.attr("xmlns:xlink", "http://www.w3.org/1999/xlink")?; // required for enabling xlink:href on browsers
        Ok(())
    })?
    .build(|w| {
        // White Background appears like a card
        w.single("rect", |d| {
            d.attr("x", card_border_size)?;
            d.attr("y", card_border_size)?;
            d.attr("rx", card_roundness)?;
            d.attr("stroke", "#c6c6c6")?;
            d.attr("stroke-width", card_border_size)?;
            d.attr("width", width - (card_border_size * 2.0))?;
            d.attr("height", height - (card_border_size * 2.0))?;
            d.attr("style", "fill:#f2f2f2")?;
            Ok(())
        })?;
        // Qrcode
        w.elem("g", |d| {
            d.attr(
                "transform",
                format!(
                    "translate({},{})",
                    (width - qr_code_size) / 2.0,
                    ((height - qr_code_size) / 2.0) - qr_translate_up
                ),
            )
            // If the qr code should be in the wrong place,
            // we could also translate and scale the points in the path already,
            // but that would make the resulting svg way bigger in size and might bring up rounding issues,
            // so better avoid doing it manually if possible
        })?
        .build(|w| {
            w.single("path", |d| {
                let mut path_data = String::with_capacity(0);
                let scale = qr_code_size / qr.size() as f32;

                for y in 0..qr.size() {
                    for x in 0..qr.size() {
                        if qr.get_module(x, y) {
                            path_data += &format!("M{x},{y}h1v1h-1z");
                        }
                    }
                }

                d.attr("style", "fill:#000000")?;
                d.attr("d", path_data)?;
                d.attr("transform", format!("scale({scale})"))
            })
        })?;

        // Text
        const BIG_TEXT_CHARS_PER_LINE: usize = 32;
        const SMALL_TEXT_CHARS_PER_LINE: usize = 38;
        let chars_per_line = if qrcode_description.len() > SMALL_TEXT_CHARS_PER_LINE * 2 {
            SMALL_TEXT_CHARS_PER_LINE
        } else {
            BIG_TEXT_CHARS_PER_LINE
        };
        let lines = textwrap::fill(qrcode_description, chars_per_line);
        let (text_font_size, text_y_shift) = if lines.split('\n').count() <= 2 {
            (27.0, 0.0)
        } else {
            (19.0, -10.0)
        };
        for (count, line) in lines.split('\n').enumerate() {
            w.elem("text", |d| {
                d.attr(
                    "y",
                    (count as f32 * (text_font_size * 1.2)) + text_y_pos + text_y_shift,
                )?;
                d.attr("x", width / 2.0)?;
                d.attr("text-anchor", "middle")?;
                d.attr(
                    "style",
                    format!(
                        "font-family:sans-serif;\
                        font-weight:bold;\
                        font-size:{text_font_size}px;\
                        fill:#000000;\
                        stroke:none"
                    ),
                )
            })?
            .build(|w| w.put_raw(line))?;
        }
        // contact avatar in middle of qrcode
        const LOGO_SIZE: f32 = 94.4;
        const HALF_LOGO_SIZE: f32 = LOGO_SIZE / 2.0;
        let logo_position_in_qr = (qr_code_size / 2.0) - HALF_LOGO_SIZE;
        let logo_position_x = ((width - qr_code_size) / 2.0) + logo_position_in_qr;
        let logo_position_y =
            ((height - qr_code_size) / 2.0) - qr_translate_up + logo_position_in_qr;

        w.single("circle", |d| {
            d.attr("cx", logo_position_x + HALF_LOGO_SIZE)?;
            d.attr("cy", logo_position_y + HALF_LOGO_SIZE)?;
            d.attr("r", HALF_LOGO_SIZE + avatar_border_size)?;
            d.attr("style", "fill:#f2f2f2")
        })?;

        if let Some(img) = avatar {
            w.elem("defs", tagger::no_attr())?.build(|w| {
                w.elem("clipPath", |d| d.attr("id", "avatar-cut"))?
                    .build(|w| {
                        w.single("circle", |d| {
                            d.attr("cx", logo_position_x + HALF_LOGO_SIZE)?;
                            d.attr("cy", logo_position_y + HALF_LOGO_SIZE)?;
                            d.attr("r", HALF_LOGO_SIZE)
                        })
                    })
            })?;

            w.single("image", |d| {
                d.attr("x", logo_position_x)?;
                d.attr("y", logo_position_y)?;
                d.attr("width", HALF_LOGO_SIZE * 2.0)?;
                d.attr("height", HALF_LOGO_SIZE * 2.0)?;
                d.attr("preserveAspectRatio", "none")?;
                d.attr("clip-path", "url(#avatar-cut)")?;
                d.attr(
                    "xlink:href", /* xlink:href is needed otherwise it won't even display in inkscape not to mention qt's QSvgHandler */
                    format!(
                        "data:image/jpeg;base64,{}",
                        base64::engine::general_purpose::STANDARD.encode(img)
                    ),
                )
            })?;
        } else {
            w.single("circle", |d| {
                d.attr("cx", logo_position_x + HALF_LOGO_SIZE)?;
                d.attr("cy", logo_position_y + HALF_LOGO_SIZE)?;
                d.attr("r", HALF_LOGO_SIZE)?;
                d.attr("style", format!("fill:{}", &color))
            })?;

            let avatar_font_size = LOGO_SIZE * 0.65;
            let font_offset = avatar_font_size * 0.1;
            w.elem("text", |d| {
                d.attr("y", logo_position_y + HALF_LOGO_SIZE + font_offset)?;
                d.attr("x", logo_position_x + HALF_LOGO_SIZE)?;
                d.attr("text-anchor", "middle")?;
                d.attr("dominant-baseline", "central")?;
                d.attr("alignment-baseline", "middle")?;
                d.attr(
                    "style",
                    format!(
                        "font-family:sans-serif;\
                            font-weight:400;\
                            font-size:{avatar_font_size}px;\
                            fill:#ffffff;"
                    ),
                )
            })?
            .build(|w| w.put_raw(avatar_letter.to_uppercase()))?;
        }

        // Footer logo
        const FOOTER_HEIGHT: f32 = 35.0;
        const FOOTER_WIDTH: f32 = 198.0;
        w.elem("g", |d| {
            d.attr(
                "transform",
                format!(
                    "translate({},{})",
                    (width - FOOTER_WIDTH) / 2.0,
                    height - logo_offset - FOOTER_HEIGHT - text_y_shift
                ),
            )
        })?
        .build(|w| w.put_raw(include_str!("../assets/qrcode_logo_footer.svg")))
    })?;

    Ok(svg)
}

#[cfg(test)]
mod tests {
    use testdir::testdir;

    use crate::imex::BackupProvider;
    use crate::qr::format_backup;
    use crate::test_utils::TestContextManager;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_create_qr_svg() -> Result<()> {
        let svg = create_qr_svg("this is a test QR code \" < > &")?;
        assert!(svg.contains("<svg"));
        assert!(svg.contains("</svg>"));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_svg_escaping() {
        let svg = inner_generate_secure_join_qr_code(
            "descr123 \" < > &",
            "qr-code-content",
            "#000000",
            None,
            'X',
        )
        .unwrap();
        assert!(svg.contains("descr123 &quot; &lt; &gt; &amp;"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_generate_backup_qr() {
        let dir = testdir!();
        let mut tcm = TestContextManager::new();
        let ctx = tcm.alice().await;
        let provider = BackupProvider::prepare(&ctx).await.unwrap();
        let qr = provider.qr();

        println!("{}", format_backup(&qr).unwrap());
        let rendered = generate_backup_qr(&ctx, &qr).await.unwrap();
        tokio::fs::write(dir.join("qr.svg"), &rendered)
            .await
            .unwrap();
        assert_eq!(rendered.get(..4), Some("<svg"));
    }
}
