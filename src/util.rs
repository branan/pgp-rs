use errors::*;
use std::io;
use byteorder::{BigEndian,ReadBytesExt};

fn read_bytes<T: io::Read>(data: &mut T, len: usize) -> Result<Vec<u8>> {
    let mut result: Vec<u8> = vec![0; len];
    try!(data.read_exact(&mut result).chain_err(|| "Could not read packet bytes"));
    Ok(result)
}

pub fn read_bignum<T: io::Read>(data: &mut T) -> Result<Vec<u8>> {
    let bit_len = try!(data.read_u16::<BigEndian>().chain_err(|| "Could not read size for bignum")) as usize;
    let len = (bit_len + 7) / 8;
    read_bytes(data, len)
}
