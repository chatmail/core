//! Color generation.
//!
//! This is similar to Consistent Color Generation defined in XEP-0392,
//! but uses OKLCh colorspace instead of HSLuv
//! to ensure that colors have the same lightness.
use colorutils_rs::{Oklch, Rgb, TransferFunction};
use sha1::{Digest, Sha1};

/// Converts an identifier to Hue angle.
#[expect(clippy::arithmetic_side_effects)]
fn str_to_angle(s: &str) -> f32 {
    let bytes = s.as_bytes();
    let result = Sha1::digest(bytes);
    let checksum: u16 = result.first().map_or(0, |&x| u16::from(x))
        + 256 * result.get(1).map_or(0, |&x| u16::from(x));
    f32::from(checksum) / 65536.0 * 360.0
}

/// Converts RGB tuple to a 24-bit number.
///
/// Returns a 24-bit number with 8 least significant bits corresponding to the blue color and 8
/// most significant bits corresponding to the red color.
#[expect(clippy::arithmetic_side_effects)]
fn rgb_to_u32(rgb: Rgb<u8>) -> u32 {
    65536 * u32::from(rgb.r) + 256 * u32::from(rgb.g) + u32::from(rgb.b)
}

/// Converts an identifier to RGB color.
///
/// Lightness is set to half (0.5) to make colors suitable both for light and dark theme.
pub fn str_to_color(s: &str) -> u32 {
    let lightness = 0.5;
    let chroma = 0.23;
    let angle = str_to_angle(s);
    let oklch = Oklch::new(lightness, chroma, angle);
    let rgb = oklch.to_rgb(TransferFunction::Srgb);

    rgb_to_u32(rgb)
}

/// Returns color as a "#RRGGBB" `String` where R, G, B are hex digits.
pub fn color_int_to_hex_string(color: u32) -> String {
    format!("{color:#08x}").replace("0x", "#")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::excessive_precision)]
    fn test_str_to_angle() {
        // Test against test vectors from
        // <https://xmpp.org/extensions/xep-0392.html#testvectors-fullrange-no-cvd>
        assert!((str_to_angle("Romeo") - 327.255249).abs() < 1e-6);
        assert!((str_to_angle("juliet@capulet.lit") - 209.410400).abs() < 1e-6);
        assert!((str_to_angle("😺") - 331.199341).abs() < 1e-6);
        assert!((str_to_angle("council") - 359.994507).abs() < 1e-6);
        assert!((str_to_angle("Board") - 171.430664).abs() < 1e-6);
    }

    #[test]
    fn test_rgb_to_u32() {
        assert_eq!(rgb_to_u32(Rgb::new(0, 0, 0)), 0);
        assert_eq!(rgb_to_u32(Rgb::new(0xff, 0xff, 0xff)), 0xffffff);
        assert_eq!(rgb_to_u32(Rgb::new(0, 0, 0xff)), 0x0000ff);
        assert_eq!(rgb_to_u32(Rgb::new(0, 0xff, 0)), 0x00ff00);
        assert_eq!(rgb_to_u32(Rgb::new(0xff, 0, 0)), 0xff0000);
        assert_eq!(rgb_to_u32(Rgb::new(0xff, 0x80, 0)), 0xff8000);
    }
}
