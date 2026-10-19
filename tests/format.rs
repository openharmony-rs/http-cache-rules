//! Properties of `StoredPolicy` as stored data: its heap size and, with the
//! `serde` feature, its serialized form.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_cache_rules::vary::VaryField;
use http_cache_rules::{CacheConfig, Exchange, StoredPolicy};

const T0: u64 = 1_760_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

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

fn policy(request: &[(&str, &str)], response: &[(&str, &str)]) -> StoredPolicy {
    let request = headers(request);
    let response = headers(response);
    StoredPolicy::new(
        &CacheConfig::default(),
        &Exchange {
            method: &Method::GET,
            request_headers: &request,
            status: StatusCode::OK,
            response_headers: &response,
            request_time: at(T0 - 1),
            response_time: at(T0),
        },
    )
    .unwrap()
}

/// Every field of the policy away from its default.
fn every_field_set() -> StoredPolicy {
    policy(
        &[("accept-language", "de")],
        &[
            ("date", "Thu, 09 Oct 2025 08:53:15 GMT"),
            ("age", "5"),
            (
                "cache-control",
                "max-age=600, no-cache, must-revalidate, immutable, \
                 stale-while-revalidate=30, stale-if-error=60",
            ),
            ("vary", "Accept-Language, X-Absent"),
            ("etag", "\"v1\""),
            ("last-modified", "Wed, 08 Oct 2025 08:53:15 GMT"),
        ],
    )
}

#[test]
fn heap_size_is_zero_without_vary_or_validators() {
    assert_eq!(
        policy(&[], &[("cache-control", "max-age=60")]).heap_size(),
        0
    );
}

#[test]
fn heap_size_covers_vary_and_validators() {
    let policy = every_field_set();
    let owned = 2 * size_of::<VaryField>()
        + "accept-language".len()
        + "x-absent".len()
        + "\"v1\"".len()
        + "Wed, 08 Oct 2025 08:53:15 GMT".len();
    let size = policy.heap_size();
    assert!(
        (owned..=4 * owned).contains(&size),
        "{size} is not near {owned}"
    );
}

#[test]
fn heap_size_adds_the_validators() {
    let request = [("accept-language", "de")];
    let response = [("cache-control", "max-age=60"), ("vary", "Accept-Language")];
    let without = policy(&request, &response);
    let with = policy(
        &request,
        &[
            response[0],
            response[1],
            ("etag", "\"v1\""),
            ("last-modified", "Wed, 08 Oct 2025 08:53:15 GMT"),
        ],
    );
    assert_eq!(
        with.heap_size() - without.heap_size(),
        "\"v1\"".len() + "Wed, 08 Oct 2025 08:53:15 GMT".len()
    );
}

#[test]
fn heap_size_of_vary_star_is_zero() {
    let policy = policy(&[], &[("cache-control", "max-age=60"), ("vary", "*")]);
    assert_eq!(policy.vary().heap_size(), 0);
}

/// The postcard encoding of `every_field_set()`. If this test fails, the
/// serialized form changed: bump `FORMAT_VERSION` and update the bytes, so that
/// caches discard entries written by the old version instead of misreading them.
#[cfg(feature = "serde")]
const GOLDEN: &[u8] = &[
    200, 1, 255, 239, 157, 199, 6, 128, 240, 157, 199, 6, 251, 239, 157, 199, 6, 5, 216, 4, 0, 1,
    1, 1, 1, 30, 1, 60, 1, 2, 15, 97, 99, 99, 101, 112, 116, 45, 108, 97, 110, 103, 117, 97, 103,
    101, 1, 149, 154, 69, 212, 78, 111, 207, 88, 54, 30, 208, 4, 104, 21, 86, 254, 80, 18, 159, 33,
    9, 232, 23, 222, 192, 152, 192, 12, 158, 93, 37, 120, 8, 120, 45, 97, 98, 115, 101, 110, 116,
    0, 1, 4, 34, 118, 49, 34, 1, 29, 87, 101, 100, 44, 32, 48, 56, 32, 79, 99, 116, 32, 50, 48, 50,
    53, 32, 48, 56, 58, 53, 51, 58, 49, 53, 32, 71, 77, 84,
];

#[cfg(feature = "serde")]
#[test]
fn serialized_form_is_pinned_by_format_version() {
    let policy = every_field_set();
    let bytes = postcard::to_stdvec(&policy).unwrap();
    assert_eq!(http_cache_rules::FORMAT_VERSION, 1);
    assert_eq!(bytes, GOLDEN, "got {bytes:?}");
    assert_eq!(
        postcard::from_bytes::<StoredPolicy>(&bytes).unwrap(),
        policy
    );
}
