#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;

extern crate regex;
extern crate rustc_serialize as serialize;
extern crate byteorder;

use std::io;

mod errors;
use errors::*;
mod util;

pub mod armor;
pub mod publickey;

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(Eq)]
pub enum Packet {
    PublicKey(publickey::PublicKey),
}

struct PacketIterator<'a> {
    data: &'a[u8],
    cursor: usize,

    // This means that we errored on a packet /header/ and have
    // de-synched from the bytesream. If any individual packet can't
    // be read, it will end up as a simple Result in the stream.
    errored: bool,
}

impl<'a> PacketIterator<'a> {
    pub fn new(data: &'a[u8]) -> PacketIterator<'a> {
        PacketIterator {
            data: data,
            cursor: 0,
            errored: false
        }
    }
}

impl<'a> std::iter::Iterator for PacketIterator<'a> {
    type Item = Result<Packet>;

    fn next(&mut self) -> Option<Result<Packet>> {
        // We need at least one tag byte to start with. Ideally this
        // is our "done" case - we've read all the data and can return
        // None now.
        if self.cursor >= self.data.len() || self.errored {
            return None;
        }

        let tag_byte = self.data[self.cursor];
        let tag = (tag_byte >> 2) & 0x0f;
        let len_type = tag_byte & 0x03;
        let style = (tag_byte >> 6) & 0x01;
        let check = (tag_byte >> 7) & 0x01;

        if check == 0 {
            self.errored = true;
            return Some(Err(ErrorKind::Packet.into()));
        }

        if style != 0 {
            self.errored = true;
            return Some(Err(ErrorKind::Unsupported("new-style packet length").into()));
        }

        if len_type == 3 {
            self.errored = true;
            return Some(Err(ErrorKind::Unsupported("indeterminate-length packets").into()));
        }

        // Increment the cursor for that tag byte we just read
        self.cursor += 1;

        // Read the right number of length bytes, incrementing the
        // cursor as we go
        let len_bytes = 1 << len_type;
        let mut len: usize = 0;
        for _ in 0..len_bytes {
            len = len << 8;
            len |= self.data[self.cursor] as usize;
            self.cursor += 1;
        }

        if self.cursor+len >= self.data.len() {
            self.errored = true;
            return Some(Err(ErrorKind::Packet.into()));
        }

        let mut stream = io::Cursor::new(&self.data[self.cursor..self.cursor+len]);
        self.cursor += len;

        match tag {
            6 => match publickey::PublicKey::read(&mut stream) {
                Ok(val) => Some(Ok(Packet::PublicKey(val))),
                Err(err) => Some(Err(err))
            },
            _ => Some(Err(ErrorKind::UnknownPacket(tag).into()))
        }
    }
}

pub fn read_stream(data: &[u8]) -> Vec<Result<Packet>> {
    PacketIterator::new(data).collect()
}

#[cfg(test)]
mod tests {
    pub mod fixtures {
        pub const PUBKEY: &'static str ="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mI0EVabG/AEEAKa4oAH9xQdSo9SAFmETpDpxsyvTTnwmqxhYDxllpqY1ZcEIiGB1
URtCfvy1TFozi0rJHi/QPO2wdR+xvrpIi1d+9mJQKD2VhSrp18oio3/xqxoKf7Qc
vzHGF46eCrMDn3LAXwCaQOJRY9lk4bUKjs5aHz6KAtC7XS9EddX5/5S/ABEBAAG0
IEhlZHdpZyBUZXN0IDxoZWR3aWdAZXhhbXBsZS5jb20+iLcEEwEIACEFAlWmxvwC
GwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQgOC+ukVe0tNu/QP/UOS+Ybx7
ED61M9Aa4jSCkrPayEgStqk+ZPct6M0J3QiyVAnoXrDn8jPzroV0zb6zr06XGqYC
tf6qQmTcAO4dJSfT5BQ8dRUDWG8zM0qOU2ey1r6K3/SGGmZXozSA/b6OAJijfW48
+rVctsNvDvhl/52x1XItrIxnTtw2YvRe20u4jQRVpsb8AQQAqa+HkYNTcpaLeahh
klg47XfExIWbYq2K/bmhMHLQFJ5v+5ySAFXdfMTTXDm9ghfvgmpALBa/5tj3P5Oe
eHqnIglGzlw2E/GjGs/w826Q3Co5GmhJK+8ckKuFlboRa4zckdEQELfNe8L95OyG
nv90JPRzKjtMttgDc7OxNxeheN0AEQEAAYifBBgBCAAJBQJVpsb8AhsMAAoJEIDg
vrpFXtLTyl8D/j7dR4xtQz68wvrhl6yxdVnEtIcL7pAwl4fwUWBszBnIQU+sIOxL
DuS2x8fODgRlJAxPGtGEEGLJ517lbS+oxqhTX4Z8qJXmPruXeUevUltlmJZ5Vi8F
nSCSFbU63GPL7fOIuFFug7O9rcQen+aaDNZyd5SznwxVUStGEBDEockp
=s6n/
-----END PGP PUBLIC KEY BLOCK-----";

        pub const PRIVKEY: &'static str = "-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

lgAAAgYEVabG/AEEAKa4oAH9xQdSo9SAFmETpDpxsyvTTnwmqxhYDxllpqY1ZcEI
iGB1URtCfvy1TFozi0rJHi/QPO2wdR+xvrpIi1d+9mJQKD2VhSrp18oio3/xqxoK
f7QcvzHGF46eCrMDn3LAXwCaQOJRY9lk4bUKjs5aHz6KAtC7XS9EddX5/5S/ABEB
AAH+BwMC6yKaPW6t1KDr4DT7PhWI2Zgq7mL3Z7j6l/1mDHSrKrfMXHgcQmMWooD0
jig5v69jkhfsxr/UFG83zlH76Gs1P8G9lN8MJHY5fpJV46PERXwodRnIgCKvq6DH
vcSqzb+rYPbl5oSqDssaqOMroaFk7DOPyVF2rHF/2GP8zY1bWdQvligc+ZaqJQnW
jRtN2JZj5ZEbCVxXzFyDTn83393Uzy13dH+cJrgp3re2IRqRXvYSAHhxG2m6hBNE
c/GwRe1ZEffZwazCdfYjiShKFMtqWuA+8L/0AvoNdSEXUWsGAX941Rb+IwmK+/8O
tlHI6PW28tfuRUPunkTVHo28Ltfcb5MVtu6NURyl6SKI0bqB05XG9EvFi2sVHbs1
1+MVWI6gog69Ju5CcRCKPxyEqICBMYVW79ec2GeURjNBiFFiN0uXLqDG3PCMEk/V
YiM55r6voRRc80S4mXvo8phkmSosfcgWZhJnAD8zgjxeyF8V567/ExBF0bQgSGVk
d2lnIFRlc3QgPGhlZHdpZ0BleGFtcGxlLmNvbT6ItwQTAQgAIQUCVabG/AIbAwUL
CQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRCA4L66RV7S0279A/9Q5L5hvHsQPrUz
0BriNIKSs9rISBK2qT5k9y3ozQndCLJUCehesOfyM/OuhXTNvrOvTpcapgK1/qpC
ZNwA7h0lJ9PkFDx1FQNYbzMzSo5TZ7LWvorf9IYaZlejNID9vo4AmKN9bjz6tVy2
w28O+GX/nbHVci2sjGdO3DZi9F7bS54AAAIGBFWmxvwBBACpr4eRg1Nylot5qGGS
WDjtd8TEhZtirYr9uaEwctAUnm/7nJIAVd18xNNcOb2CF++CakAsFr/m2Pc/k554
eqciCUbOXDYT8aMaz/DzbpDcKjkaaEkr7xyQq4WVuhFrjNyR0RAQt817wv3k7Iae
/3Qk9HMqO0y22ANzs7E3F6F43QARAQAB/gcDAjZ0faZ+S1VA66PeQCcCV1JfXo1X
zW+/h2quL8NnzyBfX+5vsiUhW5udvgKiNiHDvuG/8nnyxYjLCfndsiPnUNdhoB7S
ZBYhQwqSFujWm2rvLwbyyu0fxYhtcqVXhnJA7hjx6heQplbB5n3h2UkXHah41MKf
+1JGhOIPFMtLg9TadmrJcxApeBm86pzhFd5wCbCSM0DM3GIUyXNR5cq4Wq/E14Lp
OlQae7vMdmOBSI4kTPgqOUVGZSKpDxLnemYpeCgvwiDfSH4fmIeL6aIXSGgK1UN7
M0nzq+LpKrJq1k7LuDjWWwKGOKyrXBMzXDtgi5I2FLp0YUXTxQIT3Iii33yYce3m
X0uPEiPzzJ0zljT/mgzZ/I7t6yox1nWguH+WsRmt2w83KNg/UsjEQG63RfshCQb+
4Yfv7MT6loDw77aESVrg1KYZBEEEbEbZAUAQpBHyPkdnruYlhPuWcqS0TWcC3dkj
1NhNRIQAjbr3TkBQ5xxRzz+InwQYAQgACQUCVabG/AIbDAAKCRCA4L66RV7S08pf
A/4+3UeMbUM+vML64ZessXVZxLSHC+6QMJeH8FFgbMwZyEFPrCDsSw7ktsfHzg4E
ZSQMTxrRhBBiyede5W0vqMaoU1+GfKiV5j67l3lHr1JbZZiWeVYvBZ0gkhW1Otxj
y+3ziLhRboOzva3EHp/mmgzWcneUs58MVVErRhAQxKHJKQ==
=tKsK
-----END PGP PRIVATE KEY BLOCK-----";

        pub const EXPECTED_N: [u8; 128] = [166, 184, 160, 1, 253, 197, 7, 82, 163, 212, 128, 22, 97, 19, 164, 58, 113, 179, 43, 211, 78, 124, 38, 171, 24, 88, 15, 25, 101, 166, 166, 53, 101, 193, 8, 136, 96, 117, 81, 27, 66, 126, 252, 181, 76, 90, 51, 139, 74, 201, 30, 47, 208, 60, 237, 176, 117, 31, 177, 190, 186, 72, 139, 87, 126, 246, 98, 80, 40, 61, 149, 133, 42, 233, 215, 202, 34, 163, 127, 241, 171, 26, 10, 127, 180, 28, 191, 49, 198, 23, 142, 158, 10, 179, 3, 159, 114, 192, 95, 0, 154, 64, 226, 81, 99, 217, 100, 225, 181, 10, 142, 206, 90, 31, 62, 138, 2, 208, 187, 93, 47, 68, 117, 213, 249, 255, 148, 191];
        pub const EXPECTED_E: [u8; 3] = [1, 0, 1];
    }

    #[test]
    pub fn can_read_pubkey() {
        use super::*;
        use tests::fixtures::*;
        use publickey::*;
        let mut packets = read_stream(armor::unarmor(PUBKEY).unwrap().as_ref());
        assert!(packets.len() >= 1);
        assert!(packets[0].is_ok());

        let comparison_packet = Packet::PublicKey( PublicKey::Rsa( RsaPublicKey {
            n: EXPECTED_N.to_owned(),
            e: (&EXPECTED_E[..]).to_owned(),
            timestamp: 1436993276
        }));
        assert_eq!(packets.remove(0).unwrap(), comparison_packet)
    }
}
