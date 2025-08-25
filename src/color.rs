//! Implementation of Consistent Color Generation.
//!
//! Consistent Color Generation is defined in XEP-0392.
//!
//! Color Vision Deficiency correction is not implemented as Delta Chat does not offer
//! corresponding settings.
use colorutils_rs::{Oklch, Rgb, Hsl, TransferFunction};
use sha1::{Digest, Sha1};

/// Converts an identifier to Hue angle.
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
fn rgb_to_u32(rgb: Rgb<u8>) -> u32 {
    65536 * (rgb.r as u32) + 256 * (rgb.g as u32) + (rgb.b as u32)
}

/// Converts an identifier to RGB color.
///
/// Saturation is set to maximum (100.0) to make colors distinguishable, and lightness is set to
/// half (50.0) to make colors suitable both for light and dark theme.
pub fn str_to_color(s: &str) -> u32 {
    let lightness = 0.5;
    let chroma = 0.2;

    let angle = str_to_angle(s);
    let hsl = Hsl::from_components(angle, 0.5, 0.5);
    let rgb = hsl.to_rgb();
    let mut oklch = Oklch::from_rgb(rgb, TransferFunction::Srgb);
    oklch.l = lightness;
    oklch.c = chroma;
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
        /*
        assert_eq!(rgb_to_u32((0.0, 0.0, 1.0)), 0x0000ff);
        assert_eq!(rgb_to_u32((0.0, 1.0, 0.0)), 0x00ff00);
        assert_eq!(rgb_to_u32((1.0, 0.0, 0.0)), 0xff0000);
        assert_eq!(rgb_to_u32((1.0, 0.5, 0.0)), 0xff8000);
        */
    }
}
