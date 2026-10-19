//! Entity tags (RFC 9110 §8.8.3) and the choice of the stored response a 304
//! updates (RFC 9111 §4.3.4).

/// A parsed entity tag: `entity-tag = [ weak ] opaque-tag`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityTag<'a> {
    /// Whether the tag carries the `W/` weakness indicator.
    pub weak: bool,
    /// The opaque tag without its quotes.
    pub opaque: &'a [u8],
}

impl<'a> EntityTag<'a> {
    /// Parses a single entity tag. The weakness indicator is case-sensitive
    /// (`%s"W/"`), and `etagc` excludes `"`, controls and space.
    pub fn parse(value: &'a [u8]) -> Option<Self> {
        let value = value.trim_ascii();
        let (weak, rest) = match value.strip_prefix(b"W/") {
            Some(rest) => (true, rest),
            None => (false, value),
        };
        let opaque = rest.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
        if !opaque.iter().all(|&byte| is_etagc(byte)) {
            return None;
        }
        Some(Self { weak, opaque })
    }

    /// Strong comparison (§8.8.3.2): both strong, same opaque tag.
    pub fn strong_eq(&self, other: &EntityTag<'_>) -> bool {
        !self.weak && !other.weak && self.opaque == other.opaque
    }

    /// Weak comparison (§8.8.3.2): same opaque tag, weakness ignored.
    pub fn weak_eq(&self, other: &EntityTag<'_>) -> bool {
        self.opaque == other.opaque
    }
}

/// `etagc = %x21 / %x23-7E / obs-text`
fn is_etagc(byte: u8) -> bool {
    byte == 0x21 || (0x23..=0x7e).contains(&byte) || byte >= 0x80
}

/// Whether a 304 carrying `new` may update the stored response carrying
/// `stored`, the one response this cache validated.
///
/// RFC 9111 §4.3.4 filters the stored responses by the first match of:
/// 1. strong validators in the 304 select the stored responses with the same
///    strong validator, and none may be updated if none has it;
/// 2. otherwise weak validators select the stored response they correspond to;
/// 3. otherwise a 304 without validators selects the only stored response if it
///    also lacks a validator.
///
/// Rule 1 is applied as written: a 304 whose `ETag` is a strong entity tag
/// updates the stored response only if that has the same strong tag.
///
/// Rules 2 and 3 choose among several stored responses. This cache validates
/// exactly one, and a 304 whose validators are weak or absent is taken to refer
/// to it, which is what Fetch ("HTTP-network-or-cache fetch", step 11.4) and
/// browsers do. This deviates from the letter of rules 2 and 3 in two cases, both
/// common in practice: servers regenerate `Last-Modified` for each response, so
/// the 304's can differ from the stored one (the web-platform-tests in
/// `fetch/http-cache/304-update.any.js` do this), and many servers send 304s
/// without validators. An `ETag` that does not parse as an entity tag (servers
/// send unquoted ones) is not a strong validator, so it does not prevent the
/// update either.
///
/// `stored_etag` and `new_etag` are the `ETag` field values of the stored
/// response and of the 304, valid or not.
pub fn selects_for_update(stored_etag: Option<&[u8]>, new_etag: Option<&[u8]>) -> bool {
    let Some(new_tag) = new_etag.and_then(EntityTag::parse).filter(|tag| !tag.weak) else {
        return true;
    };
    stored_etag
        .and_then(EntityTag::parse)
        .is_some_and(|stored_tag| new_tag.strong_eq(&stored_tag))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tag(value: &str) -> EntityTag<'_> {
        EntityTag::parse(value.as_bytes()).unwrap()
    }

    #[test]
    fn parsing() {
        assert_eq!(
            tag(r#""xyzzy""#),
            EntityTag {
                weak: false,
                opaque: b"xyzzy"
            }
        );
        assert_eq!(
            tag(r#"W/"xyzzy""#),
            EntityTag {
                weak: true,
                opaque: b"xyzzy"
            }
        );
        assert_eq!(
            tag(r#""""#),
            EntityTag {
                weak: false,
                opaque: b""
            }
        );
        for invalid in [
            r#"xyzzy"#,
            r#""xyz"#,
            r#"w/"xyzzy""#,
            r#""a b""#,
            r#""a"b""#,
            "",
        ] {
            assert_eq!(EntityTag::parse(invalid.as_bytes()), None, "{invalid}");
        }
    }

    /// RFC 9110 §8.8.3.2, Table 3.
    #[test]
    fn comparison_table() {
        let cases = [
            (r#"W/"1""#, r#"W/"1""#, false, true),
            (r#"W/"1""#, r#"W/"2""#, false, false),
            (r#"W/"1""#, r#""1""#, false, true),
            (r#""1""#, r#""1""#, true, true),
        ];
        for (a, b, strong, weak) in cases {
            assert_eq!(tag(a).strong_eq(&tag(b)), strong, "{a} {b}");
            assert_eq!(tag(a).weak_eq(&tag(b)), weak, "{a} {b}");
            assert_eq!(tag(b).strong_eq(&tag(a)), strong, "{b} {a}");
            assert_eq!(tag(b).weak_eq(&tag(a)), weak, "{b} {a}");
        }
    }

    fn validators(etag: Option<&str>, _last_modified: Option<u64>) -> Option<&[u8]> {
        etag.map(str::as_bytes)
    }

    #[test]
    fn strong_validator_in_304_needs_a_strong_match() {
        let stored = validators(Some(r#""a""#), None);
        assert!(selects_for_update(stored, validators(Some(r#""a""#), None)));
        assert!(!selects_for_update(
            stored,
            validators(Some(r#""b""#), None)
        ));
        let stored_weak = validators(Some(r#"W/"a""#), None);
        assert!(!selects_for_update(
            stored_weak,
            validators(Some(r#""a""#), None)
        ));
    }

    #[test]
    fn strong_validator_in_304_against_a_missing_stored_tag() {
        assert!(!selects_for_update(
            validators(None, Some(5)),
            validators(Some(r#""a""#), None)
        ));
        assert!(!selects_for_update(
            validators(Some("ABC"), None),
            validators(Some(r#""ABC""#), None)
        ));
    }

    #[test]
    fn weak_validators_in_304_update_the_validated_response() {
        let stored = validators(Some(r#""a""#), Some(5));
        assert!(selects_for_update(
            stored,
            validators(Some(r#"W/"a""#), None)
        ));
        assert!(selects_for_update(
            stored,
            validators(Some(r#"W/"b""#), None)
        ));
        assert!(selects_for_update(stored, validators(None, Some(5))));
        assert!(selects_for_update(stored, validators(None, Some(6))));
    }

    #[test]
    fn a_304_without_validators_updates_the_validated_response() {
        assert!(selects_for_update(
            validators(Some(r#""a""#), Some(5)),
            validators(None, None)
        ));
        assert!(selects_for_update(
            validators(None, None),
            validators(None, None)
        ));
    }

    #[test]
    fn an_unquoted_etag_in_the_304_does_not_prevent_the_update() {
        assert!(selects_for_update(
            validators(Some("ABC"), None),
            validators(Some("ABC"), None)
        ));
        assert!(selects_for_update(
            validators(Some(r#""a""#), None),
            validators(Some("a"), None)
        ));
    }
}
