#![no_main]

use http::header::{CACHE_CONTROL, PRAGMA, VARY};
use http::{HeaderMap, HeaderValue};
use http_cache_rules::VaryKey;
use http_cache_rules::directives::{DELTA_SECONDS_MAX, RequestDirectives, ResponseDirectives};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|lines: Vec<&[u8]>| {
    let mut headers = HeaderMap::new();
    for (index, line) in lines.iter().enumerate() {
        let Ok(value) = HeaderValue::from_bytes(line) else {
            continue;
        };
        let name = [CACHE_CONTROL, PRAGMA, VARY][index % 3].clone();
        headers.append(name, value);
    }
    let response = ResponseDirectives::from_headers(&headers);
    let request = RequestDirectives::from_headers(&headers);
    for value in [response.max_age, response.stale_while_revalidate, request.max_age, request.min_fresh]
        .into_iter()
        .flatten()
    {
        assert!(value <= DELTA_SECONDS_MAX);
    }
    let key = VaryKey::capture(&headers, &headers);
    assert_eq!(key.matches(&headers), key != VaryKey::Never);
});
