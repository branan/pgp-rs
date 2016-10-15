#![allow(redundant_closure)]
error_chain! {
    errors {
        Unsupported(t: &'static str) {
            description("Unsupported PGP element")
            display("unsupported PGP element: '{}'", t)
        }
        Armor {
            description("Error parsing PGP armor")
            display("error parsing PGP armor")
        }
        Packet {
            description("Error parsing PGP packet")
            display("error parsing PGP packet")
        }
        UnknownPacket(t: u8) {
            description("Unknown packet type")
            display("unknown packet type: {}", t)
        }
    }
}
