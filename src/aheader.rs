//! # Autocrypt header module.
//!
//! Parse and create [Autocrypt-headers](https://autocrypt.org/en/latest/level1.html#the-autocrypt-header).

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use anyhow::{Context as _, Error, Result, bail};

use crate::key::{DcKey, SignedPublicKey};

/// Possible values for encryption preference
#[derive(PartialEq, Eq, Debug, Default, Clone, Copy, FromPrimitive, ToPrimitive)]
#[repr(u8)]
pub enum EncryptPreference {
    #[default]
    NoPreference = 0,
    Mutual = 1,
}

impl fmt::Display for EncryptPreference {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncryptPreference::Mutual => write!(fmt, "mutual"),
            EncryptPreference::NoPreference => write!(fmt, "nopreference"),
        }
    }
}

impl FromStr for EncryptPreference {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "mutual" => Ok(EncryptPreference::Mutual),
            "nopreference" => Ok(EncryptPreference::NoPreference),
            _ => bail!("Cannot parse encryption preference {s}"),
        }
    }
}

/// Autocrypt header
#[derive(Debug)]
pub struct Aheader {
    pub addr: String,
    pub public_key: SignedPublicKey,
    pub prefer_encrypt: EncryptPreference,

    // Whether `_verified` attribute is present.
    //
    // `_verified` attribute is an extension to `Autocrypt-Gossip`
    // header that is used to tell that the sender
    // marked this key as verified.
    pub verified: bool,
}

impl fmt::Display for Aheader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "addr={};", self.addr.to_lowercase())?;
        if self.prefer_encrypt == EncryptPreference::Mutual {
            write!(fmt, " prefer-encrypt=mutual;")?;
        }
        // TODO After we reset all existing verifications,
        // we want to start sending the _verified attribute
        // if self.verified {
        //     write!(fmt, " _verified=1;")?;
        // }

        // adds a whitespace every 78 characters, this allows
        // email crate to wrap the lines according to RFC 5322
        // (which may insert a linebreak before every whitespace)
        let keydata = self.public_key.to_base64().chars().enumerate().fold(
            String::new(),
            |mut res, (i, c)| {
                #[expect(clippy::arithmetic_side_effects)]
                if i % 78 == 78 - "keydata=".len() {
                    res.push(' ')
                }
                res.push(c);
                res
            },
        );
        write!(fmt, " keydata={keydata}")
    }
}

impl FromStr for Aheader {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut attributes: BTreeMap<String, String> = s
            .split(';')
            .filter_map(|a| {
                let attribute: Vec<&str> = a.trim().splitn(2, '=').collect();
                match &attribute[..] {
                    [key, value] => Some((key.trim().to_string(), value.trim().to_string())),
                    _ => None,
                }
            })
            .collect();

        let addr = match attributes.remove("addr") {
            Some(addr) => addr,
            None => bail!("Autocrypt header has no addr"),
        };
        let public_key: SignedPublicKey = attributes
            .remove("keydata")
            .context("keydata attribute is not found")
            .and_then(|raw| {
                SignedPublicKey::from_base64(&raw).context("autocrypt key cannot be decoded")
            })
            .and_then(|key| {
                key.verify_bindings()
                    .and(Ok(key))
                    .context("Autocrypt key cannot be verified")
            })?;

        let prefer_encrypt = attributes
            .remove("prefer-encrypt")
            .and_then(|raw| raw.parse().ok())
            .unwrap_or_default();

        let verified = attributes.remove("_verified").is_some();

        // Autocrypt-Level0: unknown attributes starting with an underscore can be safely ignored
        // Autocrypt-Level0: unknown attribute, treat the header as invalid
        if attributes.keys().any(|k| !k.starts_with('_')) {
            bail!("Unknown Autocrypt attribute found");
        }

        Ok(Aheader {
            addr,
            public_key,
            prefer_encrypt,
            verified,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAWKEY: &str = "xsBNBFzG3j0BCAC6iNhT8zydvCXi8LI/gFnkadMbfmSE/rTJskRRra/utGbLyDta/yTrJgWL7O3y/g4HdDW/dN2z26Y6W13IMzx9gLInn1KQZChtqWAcr/ReUucXcymwcfg1mdkBGk3TSLeLihN6CJx8Wsv8ig+kgAzte4f5rqEEAJVQ9WZHuti7UiYs6oRzqTo06CRe9owVXxzdMf0VDQtf7ZFm9dpzKKbhH7Lu8880iiotQ9/yRCkDGp9fNThsrLdZiK6OIAcIBAqi2rI89aS1dAmnRbktQieCx5izzyYkR1KvVL3gTTllHOzfKVEC2asmtWu2e4se/+O4WMIS1eGrn7GeWVb0Vwc5ABEBAAHNETxhQEBiLmV4YW1wbGUuZGU+wsCJBBABCAAzAhkBBQJcxt5FAhsDBAsJCAcGFQgJCgsCAxYCARYhBI4xxYKBgH3ANh5cufaKrc9mtiMLAAoJEPaKrc9mtiML938H/18F+3Wf9/JaAy/8hCO1v4S2PVBhxaKCokaNFtkfaMRne2l087LscCFPiFNyb4mv6Z3YeK8Xpxlp2sI0ecvdiqLUOGfnxS6tQrj+83EjtIrZ/hXOk1h121QFWH9Zg2VNHtODXjAgdLDC0NWUrclR0ZOqEDQHeo0ibTILdokVfXFN25wakPmGaYJP2y729cb1ve7RzvIvwn+Dddfxo3ao72rBfLi7l4NQ4S0KsY4cw+/6l5bRCKYCP77wZtvCwUvfVVosLdT43agtSiBI49+ayqvZ8OCvSJa61i+v81brTiEy9GBod4eAp45Ibsuemkw+gon4ZOvUXHTjwFB+h63MrozOwE0EXMbePQEIAL/vauf1zK8JgCu3V+G+SOX0iWw5xUlCPX+ERpBbWfwu3uAqn4wYXD3JDE/fVAF668xiV4eTPtlSUd5h0mn+G7uXMMOtkb+20SoEt50f8zw8TrL9t+ZsV11GKZWJpCar5AhXWsn6EEi8I2hLL5vn55ZZmHuGgN4jjmkRl3ToKCLhaXwTBjCJem7N5EH7F75wErEITa55v4Lb4Nfca7vnvtYrI1OA446xa8gHra0SINelTD09/JM/Fw4sWVPBaRZmJK/Tnu79N23No9XBUubmFPv1pNexZsQclicnTpt/BEWhiun7d6lfGB63K1aoHRTR1pcrWvBuALuuz0gqar2zlI0AEQEAAcLAdgQYAQgAIAUCXMbeRQIbDBYhBI4xxYKBgH3ANh5cufaKrc9mtiMLAAoJEPaKrc9mtiMLKSEIAIyLCRO2OyZ0IYRvRPpMn4p7E+7Pfcz/0mSkOy+1hshgJnqivXurm8zwGrwdMqeV4eslKR9H1RUdWGUQJNbtwmmjrt5DHpIhYHl5t3FpCBaGbV20Omo00Q38lBl9MtrmZkZw+ktEk6X+0xCKssMF+2MADkSOIufbR5HrDVB89VZOHCO9DeXvCUUAw2hyJiL/LHmLzJ40zYoTmb+F//f0k0j+tRdbkefyRoCmwG7YGiT+2hnCdgcezswnzah5J3ZKlrg7jOGo1LxtbvNUzxNBbC6S/aNgwm6qxo7xegRhmEl5uZ16zwyj4qz+xkjGy25Of5mWfUDoNw7OT7sjUbHOOMc=";

    #[test]
    fn test_from_str() -> Result<()> {
        let h: Aheader =
            format!("addr=me@mail.com; prefer-encrypt=mutual; keydata={RAWKEY}").parse()?;

        assert_eq!(h.addr, "me@mail.com");
        assert_eq!(h.prefer_encrypt, EncryptPreference::Mutual);
        assert_eq!(h.verified, false);
        Ok(())
    }

    // Non-standard values of prefer-encrypt such as `reset` are treated as no preference.
    #[test]
    fn test_from_str_reset() -> Result<()> {
        let raw = format!("addr=reset@example.com; prefer-encrypt=reset; keydata={RAWKEY}");
        let h: Aheader = raw.parse()?;

        assert_eq!(h.addr, "reset@example.com");
        assert_eq!(h.prefer_encrypt, EncryptPreference::NoPreference);
        Ok(())
    }

    #[test]
    fn test_from_str_non_critical() -> Result<()> {
        let raw = format!("addr=me@mail.com; _foo=one; _bar=two; keydata={RAWKEY}");
        let h: Aheader = raw.parse()?;

        assert_eq!(h.addr, "me@mail.com");
        assert_eq!(h.prefer_encrypt, EncryptPreference::NoPreference);
        Ok(())
    }

    #[test]
    fn test_from_str_superflous_critical() {
        let raw = format!("addr=me@mail.com; _foo=one; _bar=two; other=me; keydata={RAWKEY}");
        assert!(raw.parse::<Aheader>().is_err());
    }

    #[test]
    fn test_good_headers() -> Result<()> {
        let fixed_header = concat!(
            "addr=a@b.example.org; prefer-encrypt=mutual; ",
            "keydata=xsBNBFzG3j0BCAC6iNhT8zydvCXi8LI/gFnkadMbfmSE/rTJskRRra/utGbLyDta/yTrJg",
            " WL7O3y/g4HdDW/dN2z26Y6W13IMzx9gLInn1KQZChtqWAcr/ReUucXcymwcfg1mdkBGk3TSLeLihN6",
            " CJx8Wsv8ig+kgAzte4f5rqEEAJVQ9WZHuti7UiYs6oRzqTo06CRe9owVXxzdMf0VDQtf7ZFm9dpzKK",
            " bhH7Lu8880iiotQ9/yRCkDGp9fNThsrLdZiK6OIAcIBAqi2rI89aS1dAmnRbktQieCx5izzyYkR1Kv",
            " VL3gTTllHOzfKVEC2asmtWu2e4se/+O4WMIS1eGrn7GeWVb0Vwc5ABEBAAHNETxhQEBiLmV4YW1wbG",
            " UuZGU+wsCJBBABCAAzAhkBBQJcxt5FAhsDBAsJCAcGFQgJCgsCAxYCARYhBI4xxYKBgH3ANh5cufaK",
            " rc9mtiMLAAoJEPaKrc9mtiML938H/18F+3Wf9/JaAy/8hCO1v4S2PVBhxaKCokaNFtkfaMRne2l087",
            " LscCFPiFNyb4mv6Z3YeK8Xpxlp2sI0ecvdiqLUOGfnxS6tQrj+83EjtIrZ/hXOk1h121QFWH9Zg2VN",
            " HtODXjAgdLDC0NWUrclR0ZOqEDQHeo0ibTILdokVfXFN25wakPmGaYJP2y729cb1ve7RzvIvwn+Ddd",
            " fxo3ao72rBfLi7l4NQ4S0KsY4cw+/6l5bRCKYCP77wZtvCwUvfVVosLdT43agtSiBI49+ayqvZ8OCv",
            " SJa61i+v81brTiEy9GBod4eAp45Ibsuemkw+gon4ZOvUXHTjwFB+h63MrozOwE0EXMbePQEIAL/vau",
            " f1zK8JgCu3V+G+SOX0iWw5xUlCPX+ERpBbWfwu3uAqn4wYXD3JDE/fVAF668xiV4eTPtlSUd5h0mn+",
            " G7uXMMOtkb+20SoEt50f8zw8TrL9t+ZsV11GKZWJpCar5AhXWsn6EEi8I2hLL5vn55ZZmHuGgN4jjm",
            " kRl3ToKCLhaXwTBjCJem7N5EH7F75wErEITa55v4Lb4Nfca7vnvtYrI1OA446xa8gHra0SINelTD09",
            " /JM/Fw4sWVPBaRZmJK/Tnu79N23No9XBUubmFPv1pNexZsQclicnTpt/BEWhiun7d6lfGB63K1aoHR",
            " TR1pcrWvBuALuuz0gqar2zlI0AEQEAAcLAdgQYAQgAIAUCXMbeRQIbDBYhBI4xxYKBgH3ANh5cufaK",
            " rc9mtiMLAAoJEPaKrc9mtiMLKSEIAIyLCRO2OyZ0IYRvRPpMn4p7E+7Pfcz/0mSkOy+1hshgJnqivX",
            " urm8zwGrwdMqeV4eslKR9H1RUdWGUQJNbtwmmjrt5DHpIhYHl5t3FpCBaGbV20Omo00Q38lBl9Mtrm",
            " ZkZw+ktEk6X+0xCKssMF+2MADkSOIufbR5HrDVB89VZOHCO9DeXvCUUAw2hyJiL/LHmLzJ40zYoTmb",
            " +F//f0k0j+tRdbkefyRoCmwG7YGiT+2hnCdgcezswnzah5J3ZKlrg7jOGo1LxtbvNUzxNBbC6S/aNg",
            " wm6qxo7xegRhmEl5uZ16zwyj4qz+xkjGy25Of5mWfUDoNw7OT7sjUbHOOMc="
        );

        let ah = Aheader::from_str(fixed_header)?;
        assert_eq!(ah.addr, "a@b.example.org");
        assert_eq!(ah.prefer_encrypt, EncryptPreference::Mutual);
        assert_eq!(format!("{ah}"), fixed_header);

        let rendered = ah.to_string();
        assert_eq!(rendered, fixed_header);

        let ah = Aheader::from_str(&format!(
            " _foo; __FOO=BAR ;;; addr = a@b.example.org ;\r\n   prefer-encrypt = mutual ; keydata = {RAWKEY}"
        ))?;
        assert_eq!(ah.addr, "a@b.example.org");
        assert_eq!(ah.prefer_encrypt, EncryptPreference::Mutual);

        Aheader::from_str(&format!(
            "addr=a@b.example.org; prefer-encrypt=ignoreUnknownValues; keydata={RAWKEY}"
        ))?;

        Aheader::from_str(&format!("addr=a@b.example.org; keydata={RAWKEY}"))?;
        Ok(())
    }

    #[test]
    fn test_bad_headers() {
        assert!(Aheader::from_str("").is_err());
        assert!(Aheader::from_str("foo").is_err());
        assert!(Aheader::from_str("\n\n\n").is_err());
        assert!(Aheader::from_str(" ;;").is_err());
        assert!(Aheader::from_str("addr=a@t.de; unknown=1; keydata=jau").is_err());
    }

    #[test]
    fn test_display_aheader() {
        assert!(
            format!(
                "{}",
                Aheader {
                    addr: "test@example.com".to_string(),
                    public_key: SignedPublicKey::from_base64(RAWKEY).unwrap(),
                    prefer_encrypt: EncryptPreference::Mutual,
                    verified: false
                }
            )
            .contains("prefer-encrypt=mutual;")
        );

        // According to Autocrypt Level 1 specification,
        // only "prefer-encrypt=mutual;" can be used.
        // If the setting is nopreference, the whole attribute is omitted.
        assert!(
            !format!(
                "{}",
                Aheader {
                    addr: "test@example.com".to_string(),
                    public_key: SignedPublicKey::from_base64(RAWKEY).unwrap(),
                    prefer_encrypt: EncryptPreference::NoPreference,
                    verified: false
                }
            )
            .contains("prefer-encrypt")
        );

        // Always lowercase the address in the header.
        assert!(
            format!(
                "{}",
                Aheader {
                    addr: "TeSt@eXaMpLe.cOm".to_string(),
                    public_key: SignedPublicKey::from_base64(RAWKEY).unwrap(),
                    prefer_encrypt: EncryptPreference::Mutual,
                    verified: false
                }
            )
            .contains("test@example.com")
        );

        // We don't send the _verified header yet:
        assert!(
            !format!(
                "{}",
                Aheader {
                    addr: "test@example.com".to_string(),
                    public_key: SignedPublicKey::from_base64(RAWKEY).unwrap(),
                    prefer_encrypt: EncryptPreference::NoPreference,
                    verified: true
                }
            )
            .contains("_verified")
        );
    }
}
