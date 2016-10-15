use errors::*;
use util::*;

use std::io;
use byteorder::{BigEndian,ReadBytesExt};

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Eq)]
pub struct RsaPublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub timestamp: u32
}

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Eq)]
pub struct DsaPublicKey {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
    y: Vec<u8>
}

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Eq)]
pub struct ElgamalPublicKey {
    p: Vec<u8>,
    g: Vec<u8>,
    y: Vec<u8>
}

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Eq)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    Dsa(DsaPublicKey),
    Elgamal(ElgamalPublicKey)
}

impl PublicKey {
    fn read_rsa<T: io::Read>(data: &mut T, timestamp: u32) -> Result<PublicKey> {
        let n = try!(read_bignum(data));
        let e = try!(read_bignum(data));
        Ok(PublicKey::Rsa(RsaPublicKey {
            n: n,
            e: e,
            timestamp: timestamp
        }))
    }
    
    pub fn read<T: io::Read>(data: &mut T) -> Result<PublicKey> {
        if try!(data.read_u8().chain_err(|| "Could not read PublicKey version")) != 4 {
            return Err(ErrorKind::Unsupported("PublicKey packet is not v4").into());
        }

        let timestamp = try!(data.read_u32::<BigEndian>().chain_err(|| "Could not read PublicKey timestamp"));

        match try!(data.read_u8().chain_err(|| "Could not read PublicKey key type")) {
            1 => PublicKey::read_rsa(data, timestamp),
            _ => Err(ErrorKind::Unsupported("Key format").into())
        }
    }
}
