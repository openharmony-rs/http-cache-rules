//! Which response header fields are stored (RFC 9111 §3.1) and how stored
//! fields are updated from a newer response (§3.2).

use http::header::{CONTENT_LENGTH, DATE, HeaderName};
use http::{HeaderMap, HeaderValue};

use crate::date::format_http_date;

/// `Connection` and the fields RFC 9110 §7.6.1 says are removed before
/// forwarding whether or not `Connection` lists them. §3.1 lets a cache drop
/// them before storage.
const HOP_BY_HOP: [&str; 6] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
];

/// Fields specific to the proxy the cache forwards through, which §3.1 says
/// "MUST NOT be stored".
const PROXY_SPECIFIC: [&str; 3] = [
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
];

/// Whether `name` is excluded from storage: a fixed hop-by-hop field or a
/// proxy-specific one.
///
/// The fields a `Connection` field lists are kept. §3.1 only lets a cache remove
/// them before storage, because an intermediary must remove them before
/// forwarding (RFC 9110 §7.6.1), and a private cache forwards nothing. Removing
/// them would let a response strip its own `Content-Security-Policy` or
/// `Cache-Control` from every copy served from the cache while the first copy
/// keeps them. Browsers keep them too.
fn excluded_from_storage(name: &HeaderName) -> bool {
    let name = name.as_str();
    HOP_BY_HOP.contains(&name) || PROXY_SPECIFIC.contains(&name)
}

/// The header fields to store for a response received at `response_time`.
///
/// §3.1: "Caches MUST include all received response header fields -- including
/// unrecognized ones -- when storing a response", except the fields
/// [`excluded_from_storage`] lists and those in `never_store`, a local policy
/// such as not keeping `Set-Cookie` in a browser's cache. Every value of a
/// repeated field is kept, in order.
///
/// RFC 9110 §6.6.1: "A recipient with a clock that receives a response message
/// without a Date header field MUST record the time it was received and append a
/// corresponding Date header field to the message's header section if it is
/// cached", so a missing `Date` is added.
pub fn stored_fields(
    headers: &HeaderMap,
    response_time: u64,
    never_store: &[HeaderName],
) -> HeaderMap {
    let mut stored = HeaderMap::with_capacity(headers.len());
    for (name, value) in headers {
        if excluded_from_storage(name) || never_store.contains(name) {
            continue;
        }
        stored.append(name.clone(), value.clone());
    }
    if !stored.contains_key(DATE) {
        if let Ok(value) = HeaderValue::from_str(&format_http_date(response_time)) {
            stored.insert(DATE, value);
        }
    }
    stored
}

/// The stored fields after an update from `newer`, such as a 304 (§3.2).
///
/// "the cache MUST add each header field in the provided response to the stored
/// response, replacing field values that are already present", except:
/// - the fields excluded from storage, as in [`stored_fields`], and those in
///   `never_store`;
/// - `Content-Length`;
/// - `not_updated`, the fields the stored response depends upon. §3.2 allows a
///   cache that stores the result of processing a response to keep these, for
///   example `Content-Encoding` when the stored body was decoded, and
///   `Content-Range`, which the HTTP implementation processes itself.
///
/// A field that `newer` carries replaces every stored value of that field with
/// every value `newer` has for it, in order. Fields that `newer` does not carry
/// keep all their stored values.
pub fn updated_fields(
    stored: &HeaderMap,
    newer: &HeaderMap,
    never_store: &[HeaderName],
    not_updated: &[HeaderName],
) -> HeaderMap {
    let mut updated = stored.clone();
    for name in newer.keys() {
        if excluded_from_storage(name)
            || never_store.contains(name)
            || *name == CONTENT_LENGTH
            || not_updated.contains(name)
        {
            continue;
        }
        updated.remove(name);
        for value in newer.get_all(name) {
            updated.append(name.clone(), value.clone());
        }
    }
    updated
}

#[cfg(test)]
mod tests {
    use http::header::{CONTENT_ENCODING, CONTENT_SECURITY_POLICY, ETAG, LINK, SET_COOKIE};

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

    fn values<'a>(map: &'a HeaderMap, name: &str) -> Vec<&'a str> {
        map.get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    #[test]
    fn storage_keeps_every_value_and_unknown_fields() {
        let stored = stored_fields(
            &headers(&[
                ("date", "Sun, 06 Nov 1994 08:49:37 GMT"),
                ("link", "<a>; rel=preload"),
                ("link", "<b>; rel=preload"),
                ("x-unknown", "1"),
            ]),
            0,
            &[],
        );
        assert_eq!(
            values(&stored, "link"),
            ["<a>; rel=preload", "<b>; rel=preload"]
        );
        assert_eq!(values(&stored, "x-unknown"), ["1"]);
    }

    #[test]
    fn storage_drops_hop_by_hop_and_proxy_fields_but_keeps_connection_options() {
        let stored = stored_fields(
            &headers(&[
                ("connection", "close, Content-Security-Policy, X-Hop"),
                ("content-security-policy", "script-src 'self'"),
                ("x-hop", "1"),
                ("keep-alive", "timeout=5"),
                ("transfer-encoding", "chunked"),
                ("proxy-authenticate", "Basic"),
                ("proxy-authentication-info", "x"),
                ("x-kept", "1"),
            ]),
            0,
            &[],
        );
        let names: Vec<_> = stored.keys().map(|name| name.as_str()).collect();
        assert_eq!(
            names,
            ["content-security-policy", "x-hop", "x-kept", "date"]
        );
    }

    #[test]
    fn storage_applies_never_store() {
        let stored = stored_fields(
            &headers(&[("set-cookie", "a=b"), ("x", "1")]),
            0,
            &[SET_COOKIE],
        );
        assert!(!stored.contains_key(SET_COOKIE));
    }

    #[test]
    fn storage_adds_a_missing_date() {
        let stored = stored_fields(&headers(&[("x", "1")]), 784_111_777, &[]);
        assert_eq!(values(&stored, "date"), ["Sun, 06 Nov 1994 08:49:37 GMT"]);
        let kept = stored_fields(
            &headers(&[("date", "Mon, 07 Nov 1994 08:49:37 GMT")]),
            784_111_777,
            &[],
        );
        assert_eq!(values(&kept, "date"), ["Mon, 07 Nov 1994 08:49:37 GMT"]);
    }

    #[test]
    fn update_keeps_repeated_fields_the_newer_response_does_not_carry() {
        let stored = headers(&[
            ("content-security-policy", "script-src 'self'"),
            ("content-security-policy", "object-src 'none'"),
            ("cache-control", "max-age=0"),
            ("etag", "\"x\""),
        ]);
        let updated = updated_fields(
            &stored,
            &headers(&[("cache-control", "max-age=60"), ("etag", "\"x\"")]),
            &[],
            &[],
        );
        assert_eq!(
            values(&updated, CONTENT_SECURITY_POLICY.as_str()),
            ["script-src 'self'", "object-src 'none'"]
        );
        assert_eq!(values(&updated, "cache-control"), ["max-age=60"]);
        assert_eq!(values(&updated, ETAG.as_str()), ["\"x\""]);
    }

    #[test]
    fn update_replaces_with_every_value_and_adds_new_fields() {
        let stored = headers(&[("link", "<a>"), ("x", "old")]);
        let updated = updated_fields(
            &stored,
            &headers(&[("link", "<b>"), ("link", "<c>"), ("y", "new")]),
            &[],
            &[],
        );
        assert_eq!(values(&updated, LINK.as_str()), ["<b>", "<c>"]);
        assert_eq!(values(&updated, "x"), ["old"]);
        assert_eq!(values(&updated, "y"), ["new"]);
    }

    #[test]
    fn update_skips_excluded_fields() {
        let stored = headers(&[("content-length", "10"), ("content-encoding", "gzip")]);
        let newer = headers(&[
            ("content-length", "0"),
            ("content-encoding", "br"),
            ("connection", "close"),
            ("transfer-encoding", "chunked"),
            ("proxy-authenticate", "Basic"),
            ("set-cookie", "a=b"),
        ]);
        let updated = updated_fields(&stored, &newer, &[SET_COOKIE], &[CONTENT_ENCODING]);
        assert_eq!(values(&updated, "content-length"), ["10"]);
        assert_eq!(values(&updated, "content-encoding"), ["gzip"]);
        let names: Vec<_> = updated.keys().map(|name| name.as_str()).collect();
        assert_eq!(names, ["content-length", "content-encoding"]);
    }
}
