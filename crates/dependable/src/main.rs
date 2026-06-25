//! `dependable` CLI entry point.
//!
//! Scaffold only — argument parsing and orchestration land with the MVP.

fn greeting() -> &'static str {
    "dependable: dependency version + vulnerability checker"
}

fn main() {
    println!("{}", greeting());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_mentions_dependable() {
        assert!(greeting().contains("dependable"));
    }
}
