//! Secondary cache keys from `Vary` (RFC 9111 §4.1).

use http::HeaderMap;
use http::header::VARY;
use sha2::{Digest, Sha256};

use crate::directives::is_tchar;

/// What a stored response's `Vary` requires of a later request.
///
/// Only a digest of each nominated request field is kept, never its value. A
/// response may vary on `Cookie` or `Authorization`, and a cache entry must not
/// carry credentials to disk (Chromium's `HttpVaryData` keeps only a digest for
/// the same reason). Matching compares digests, which is exact up to SHA-256
/// collisions.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum VaryKey {
    /// `Vary` contains `*`, or is not a valid list of field names: no request
    /// matches (§4.1: "A stored response with a Vary header field value
    /// containing a member "*" always fails to match").
    Never,
    /// The nominated fields, lowercased and without duplicates, each with the
    /// digest of its value in the original request, or `None` if it was absent.
    /// Empty when the response has no `Vary`.
    Fields(Vec<VaryField>),
}

/// One request field nominated by `Vary`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VaryField {
    /// The field name, lowercased.
    pub name: String,
    /// SHA-256 of the field's [normalized value](normalized_value), or `None`
    /// when the request did not have the field.
    pub digest: Option<[u8; 32]>,
}

impl VaryKey {
    /// The key for a response with `response_headers`, received for a request
    /// with `request_headers`.
    pub fn capture(response_headers: &HeaderMap, request_headers: &HeaderMap) -> Self {
        let Some(names) = nominated_fields(response_headers) else {
            return Self::Never;
        };
        Self::Fields(
            names
                .into_iter()
                .map(|name| {
                    let digest = field_digest(request_headers, &name);
                    VaryField { name, digest }
                })
                .collect(),
        )
    }

    /// Whether `request_headers` match the nominated fields of the original
    /// request (§4.1). A field absent from one request only matches if it is
    /// absent from the other.
    pub fn matches(&self, request_headers: &HeaderMap) -> bool {
        match self {
            Self::Never => false,
            Self::Fields(fields) => fields
                .iter()
                .all(|field| field_digest(request_headers, &field.name) == field.digest),
        }
    }

    /// The heap memory the key owns, in bytes.
    pub fn heap_size(&self) -> usize {
        match self {
            Self::Never => 0,
            Self::Fields(fields) => {
                fields.capacity() * size_of::<VaryField>()
                    + fields
                        .iter()
                        .map(|field| field.name.capacity())
                        .sum::<usize>()
            },
        }
    }
}

/// The lowercased, de-duplicated field names `Vary` lists across all its field
/// lines, or `None` if any member is `*` or not a field name.
fn nominated_fields(response_headers: &HeaderMap) -> Option<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for line in response_headers.get_all(VARY) {
        for member in line.as_bytes().split(|&byte| byte == b',') {
            let member = member.trim_ascii();
            if member.is_empty() {
                continue;
            }
            if member == b"*" || !member.iter().all(|&byte| is_tchar(byte)) {
                return None;
            }
            let name = String::from_utf8_lossy(member).to_ascii_lowercase();
            if !names.contains(&name) {
                names.push(name);
            }
        }
    }
    Some(names)
}

/// A request field's value in the normal form used for matching: its field
/// lines with surrounding whitespace removed, combined in order with `", "`.
///
/// §4.1 lets two requests match if one transforms into the other by removing
/// whitespace where the field's syntax allows it and by "combining multiple
/// header field lines with the same field name (see Section 5.2 of [HTTP])",
/// which joins them with a comma. Leading and trailing whitespace is never part
/// of a field value (RFC 9110 §5.5). Field-specific normalizations (reordering,
/// case) are not applied; skipping one can only cause a cache miss, never a
/// wrong match.
pub fn normalized_value(request_headers: &HeaderMap, name: &str) -> Option<Vec<u8>> {
    let mut lines = request_headers.get_all(name).iter().peekable();
    lines.peek()?;
    let mut value = Vec::new();
    for (index, line) in lines.enumerate() {
        if index > 0 {
            value.extend_from_slice(b", ");
        }
        value.extend_from_slice(line.as_bytes().trim_ascii());
    }
    Some(value)
}

fn field_digest(request_headers: &HeaderMap, name: &str) -> Option<[u8; 32]> {
    normalized_value(request_headers, name).map(|value| Sha256::digest(&value).into())
}

#[cfg(test)]
mod tests {
    use http::{HeaderName, HeaderValue};

    use super::*;

    fn headers(fields: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in fields {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    #[test]
    fn no_vary_matches_everything() {
        let key = VaryKey::capture(&headers(&[]), &headers(&[("accept", "a")]));
        assert_eq!(key, VaryKey::Fields(vec![]));
        assert!(key.matches(&headers(&[("accept", "b")])));
    }

    #[test]
    fn star_never_matches() {
        for vary in ["*", "accept, *", "Accept,*"] {
            let key = VaryKey::capture(&headers(&[("vary", vary)]), &headers(&[]));
            assert_eq!(key, VaryKey::Never);
            assert!(!key.matches(&headers(&[])));
        }
    }

    #[test]
    fn invalid_vary_never_matches() {
        let key = VaryKey::capture(&headers(&[("vary", "accept language")]), &headers(&[]));
        assert_eq!(key, VaryKey::Never);
    }

    #[test]
    fn nominated_fields_must_match() {
        let key = VaryKey::capture(
            &headers(&[("vary", "Accept-Language"), ("vary", "x-a, X-A")]),
            &headers(&[("accept-language", "en"), ("x-a", "1")]),
        );
        let VaryKey::Fields(fields) = &key else {
            panic!()
        };
        assert_eq!(
            fields.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(),
            ["accept-language", "x-a"]
        );
        assert!(key.matches(&headers(&[
            ("accept-language", "en"),
            ("x-a", "1"),
            ("other", "z")
        ])));
        assert!(!key.matches(&headers(&[("accept-language", "de"), ("x-a", "1")])));
        assert!(!key.matches(&headers(&[("x-a", "1")])));
    }

    #[test]
    fn absent_only_matches_absent() {
        let key = VaryKey::capture(&headers(&[("vary", "x-a")]), &headers(&[]));
        assert!(key.matches(&headers(&[])));
        assert!(!key.matches(&headers(&[("x-a", "")])));
    }

    #[test]
    fn every_field_line_takes_part() {
        let key = VaryKey::capture(
            &headers(&[("vary", "accept-language")]),
            &headers(&[("accept-language", "en"), ("accept-language", "de")]),
        );
        assert!(key.matches(&headers(&[
            ("accept-language", "en"),
            ("accept-language", "de")
        ])));
        assert!(key.matches(&headers(&[("accept-language", "en, de")])));
        assert!(key.matches(&headers(&[
            ("accept-language", " en "),
            ("accept-language", "de ")
        ])));
        assert!(!key.matches(&headers(&[
            ("accept-language", "en"),
            ("accept-language", "fr")
        ])));
        assert!(!key.matches(&headers(&[("accept-language", "en")])));
    }

    #[test]
    fn normal_form() {
        let request = headers(&[("x", " a "), ("x", "b,c"), ("y", "")]);
        assert_eq!(normalized_value(&request, "x").unwrap(), b"a, b,c");
        assert_eq!(normalized_value(&request, "y").unwrap(), b"");
        assert_eq!(normalized_value(&request, "z"), None);
    }

    #[test]
    fn credentials_are_not_kept() {
        let key = VaryKey::capture(
            &headers(&[("vary", "cookie")]),
            &headers(&[("cookie", "session=secret")]),
        );
        assert!(!format!("{key:?}").contains("secret"));
        assert!(key.matches(&headers(&[("cookie", "session=secret")])));
        assert!(!key.matches(&headers(&[("cookie", "session=other")])));
    }
}
