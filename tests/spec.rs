//! Keeps `SPEC.md` and the tests in step: every requirement identifier in its
//! tables must name a test or proof, and every test or proof named after an
//! identifier must refer to one that exists.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// `R-4.2.1-order` → `r_4_2_1_order`.
fn snake(identifier: &str) -> String {
    identifier.to_ascii_lowercase().replace(['-', '.'], "_")
}

fn identifiers() -> BTreeSet<String> {
    let spec = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("SPEC.md")).unwrap();
    spec.lines()
        .filter_map(|line| line.strip_prefix("| "))
        .filter_map(|row| row.split(" |").next())
        .filter(|cell| {
            let mut chars = cell.chars();
            matches!(chars.next(), Some('R' | 'F' | 'D')) && chars.next() == Some('-')
        })
        .map(str::to_owned)
        .collect()
}

/// Names of functions marked as tests or proofs in `files`.
fn verifications() -> Vec<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = ["tests/requirements.rs", "tests/wpt.rs", "src/proofs.rs"];
    let mut names = Vec::new();
    for file in files {
        let source = fs::read_to_string(root.join(file)).unwrap();
        let mut marked = false;
        for line in source.lines() {
            let line = line.trim();
            if line == "#[test]" || line == "#[kani::proof]" {
                marked = true;
            } else if let Some(rest) = line.strip_prefix("fn ").filter(|_| marked) {
                names.push(rest.split('(').next().unwrap().to_owned());
                marked = false;
            }
        }
    }
    names
}

/// Whether `name` verifies `identifier`: it is the identifier in snake case,
/// followed by the end or by `_` and a word, not by a further section number.
fn verifies(name: &str, identifier: &str) -> bool {
    let prefix = snake(identifier);
    match name.strip_prefix(&prefix) {
        Some("") => true,
        Some(rest) => rest
            .strip_prefix('_')
            .and_then(|rest| rest.chars().next())
            .is_some_and(|next| !next.is_ascii_digit()),
        None => false,
    }
}

#[test]
fn every_requirement_is_verified() {
    let names = verifications();
    let unverified: Vec<_> = identifiers()
        .into_iter()
        .filter(|identifier| !names.iter().any(|name| verifies(name, identifier)))
        .collect();
    assert!(
        unverified.is_empty(),
        "requirements without a test or proof: {unverified:?}"
    );
}

#[test]
fn every_named_verification_refers_to_a_requirement() {
    let identifiers = identifiers();
    let orphans: Vec<_> = verifications()
        .into_iter()
        .filter(|name| name.starts_with("r_") || name.starts_with("f_") || name.starts_with("d_"))
        .filter(|name| {
            !identifiers
                .iter()
                .any(|identifier| verifies(name, identifier))
        })
        .collect();
    assert!(
        orphans.is_empty(),
        "tests named after no requirement: {orphans:?}"
    );
}

#[test]
fn the_table_is_not_empty() {
    assert!(identifiers().len() > 60);
}
