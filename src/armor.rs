use errors::*;
use regex::{Regex,Captures};
use serialize::base64::FromBase64;

lazy_static! {
    static ref ARMOR_HEADER_REGEX: Regex = Regex::new(r"^-----BEGIN PGP ([A-Z ]+)(?: (\d+)(?:/(\d+))?)?-----$").unwrap();
    static ref ARMOR_FOOTER_REGEX: Regex = Regex::new(r"^-----END PGP ([A-Z ]+)(?: (\d+)(?:/(\d+))?)?-----$").unwrap();
}

#[derive(PartialEq)]
enum ArmorType {
    Message(Option<usize>, Option<usize>),
    PublicKey,
    PrivateKey,
    Signature
}

impl ArmorType {
    fn from_captures(capt: Captures) -> Result<ArmorType> {
        let armor_str = try!(capt.at(1)
                             .ok_or(ErrorKind::Armor));
        match armor_str {
            "PUBLIC KEY BLOCK" => Ok(ArmorType::PublicKey),
            "PRIVATE KEY BLOCK" => Ok(ArmorType::PrivateKey),
            "SIGNATURE" => Ok(ArmorType::Signature),
            "MESSAGE" => {
                Ok(ArmorType::Message(
                    capt.at(2).map(|i| i.parse::<usize>().unwrap() ),
                    capt.at(3).map(|i| i.parse::<usize>().unwrap() )
                ))
            }
            _ => Err(ErrorKind::Armor.into())
        }
    }
    pub fn from_header(line: &str) -> Result<ArmorType> {
        let capt = try!(ARMOR_HEADER_REGEX.captures(line)
                        .ok_or(ErrorKind::Armor));
        ArmorType::from_captures(capt)
    }

    pub fn from_footer(line: &str) -> Result<ArmorType> {
        let capt = try!(ARMOR_FOOTER_REGEX.captures(line)
                        .ok_or(ErrorKind::Armor));
        ArmorType::from_captures(capt)
    }
}

#[test]
fn parsing_header_lines() {
    assert!(ArmorType::from_header("-----BEGIN PGP PUBLIC KEY BLOCK-----").is_ok());
    assert!(ArmorType::from_header("-----BEGIN PGP PRIVATE KEY BLOCK-----").is_ok());
    assert!(ArmorType::from_header("-----BEGIN PGP SIGNATURE-----").is_ok());
    assert!(ArmorType::from_header("-----BEGIN PGP MESSAGE-----").is_ok());
    assert!(ArmorType::from_header("-----BEGIN PGP MESSAGE 42-----").is_ok());
    assert!(ArmorType::from_header("-----BEGIN PGP MESSAGE 42-----").unwrap()
            == ArmorType::Message(Some(42), None));
    assert!(ArmorType::from_header("-----BEGIN PGP MESSAGE 7/9-----").is_ok());
    assert!(ArmorType::from_header("-----BEGIN PGP MESSAGE 7/9-----").unwrap()
            == ArmorType::Message(Some(7), Some(9)));
}

#[test]
fn parsing_footer_lines() {
    assert!(ArmorType::from_footer("-----END PGP PUBLIC KEY BLOCK-----").is_ok());
    assert!(ArmorType::from_footer("-----END PGP PRIVATE KEY BLOCK-----").is_ok());
    assert!(ArmorType::from_footer("-----END PGP SIGNATURE-----").is_ok());
    assert!(ArmorType::from_footer("-----END PGP MESSAGE-----").is_ok());
    assert!(ArmorType::from_footer("-----END PGP MESSAGE 42-----").is_ok());
    assert!(ArmorType::from_footer("-----END PGP MESSAGE 42-----").unwrap()
            == ArmorType::Message(Some(42), None));
    assert!(ArmorType::from_footer("-----END PGP MESSAGE 7/9-----").is_ok());
    assert!(ArmorType::from_footer("-----END PGP MESSAGE 7/9-----").unwrap()
            == ArmorType::Message(Some(7), Some(9)));
}

fn armor_crc(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B704CE; // from the spec
    for b in data {
        let byte : u32 = (*b) as u32;
        crc ^= byte << 16;
        for _ in 0..8 {
            crc <<= 1;
            if (crc & 0x01000000) == 0x01000000 {
                crc ^= 0x01864CFB;
            }
        }
    }
    crc & 0x00ffffff
}

pub fn unarmor(armored: &str) -> Result<Vec<u8>> {
    let mut lines = armored.lines();

    let begin_line = try!(lines.next().ok_or(ErrorKind::Armor));
    let armor_type = try!(ArmorType::from_header(begin_line));

    // Skip any header values - we don't care about them.
    while try!(lines.next().ok_or(ErrorKind::Armor)) != "" {}

    // Parse the body
    let mut data_bytes : Vec<u8> = Vec::new();
    let mut body_read = false;

    while !body_read {
        let line = try!(lines.next().ok_or(ErrorKind::Armor));
        if line.is_empty() {
            return Err(ErrorKind::Armor.into());
        }

        if line.as_bytes()[0] == b'=' {
            body_read = true;
            let crc_bytes = try!(line[1..].from_base64().chain_err(|| "This doesn't look like base64 data"));
            if crc_bytes.len() != 3 {
                return Err(ErrorKind::Armor.into());
            }
            let crc = ((crc_bytes[0] as u32) << 16) | ((crc_bytes[1] as u32) << 8) | (crc_bytes[2] as u32);
            if crc != armor_crc(&data_bytes) {
                return Err(ErrorKind::Armor.into());
            }
        } else {
            data_bytes.extend(try!(line.from_base64().chain_err(|| "This doesn't look like base64 data")));
        }
    }
    let footer = try!(lines.next().ok_or(ErrorKind::Armor));
    if try!(ArmorType::from_footer(footer)) != armor_type {
        return Err(ErrorKind::Armor.into());
    }
    Ok(data_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::tests::fixtures::*;

    #[test]
    fn unarmor_simple_gpg_keys() {
        assert!(unarmor(PUBKEY).is_ok());
        assert!(unarmor(PRIVKEY).is_ok());
    }
}
