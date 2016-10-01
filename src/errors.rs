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
    }
}
