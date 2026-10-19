#![no_main]

//! A whole round through the public API with arbitrary headers and times:
//! nothing panics, and the decisions agree with the policy's own view of
//! freshness.

use std::time::{Duration, UNIX_EPOCH};

use arbitrary::Arbitrary;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_cache_rules::{CacheConfig, Exchange, Reuse, StoredPolicy};
use libfuzzer_sys::fuzz_target;

const NAMES: [&str; 12] = [
    "cache-control", "expires", "date", "age", "last-modified", "etag", "vary", "pragma",
    "connection", "content-length", "set-cookie", "x-other",
];

#[derive(Arbitrary, Debug)]
struct Field {
    name: u8,
    value: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input {
    status: u16,
    request: Vec<Field>,
    response: Vec<Field>,
    revalidation: Vec<Field>,
    request_time: u32,
    delay: u16,
    elapsed: u32,
    later_request: Vec<Field>,
}

fn headers(fields: &[Field]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for field in fields {
        let name = HeaderName::from_static(NAMES[usize::from(field.name) % NAMES.len()]);
        if let Ok(value) = HeaderValue::from_bytes(&field.value) {
            map.append(name, value);
        }
    }
    map
}

fuzz_target!(|input: Input| {
    let Ok(status) = StatusCode::from_u16(input.status) else {
        return;
    };
    let config = CacheConfig::default();
    let request = headers(&input.request);
    let response = headers(&input.response);
    let request_time = UNIX_EPOCH + Duration::from_secs(u64::from(input.request_time));
    let response_time = request_time + Duration::from_secs(u64::from(input.delay));
    let exchange = Exchange {
        method: &Method::GET,
        request_headers: &request,
        status,
        response_headers: &response,
        request_time,
        response_time,
    };
    let stored = StoredPolicy::stored_fields(&config, &exchange);
    let Ok(policy) = StoredPolicy::new(&config, &exchange) else {
        return;
    };
    let now = response_time + Duration::from_secs(u64::from(input.elapsed));
    let later_request = headers(&input.later_request);
    match policy.evaluate(&Method::GET, &later_request, now) {
        Some(Reuse::Fresh) => assert!(policy.is_fresh(now)),
        Some(Reuse::StaleAllowed | Reuse::StaleWhileRevalidate) => assert!(!policy.is_fresh(now)),
        Some(Reuse::Validate) | None => {},
    }
    let _ = policy.presented_fields(&stored, now);
    let _ = policy.validation_fields();
    let revalidation = headers(&input.revalidation);
    let not_modified = Exchange {
        status: StatusCode::NOT_MODIFIED,
        response_headers: &revalidation,
        request_time: now,
        response_time: now,
        ..exchange
    };
    if let Ok(freshened) = policy.freshen(&config, &stored, &not_modified) {
        if let Ok(renewed) = freshened.policy {
            let _ = renewed.evaluate(&Method::GET, &later_request, now);
        }
    }
});
