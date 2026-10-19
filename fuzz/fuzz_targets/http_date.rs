#![no_main]

use http_cache_rules::date::{MAX_FORMATTABLE, format_http_date, parse_http_date};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (u64, &[u8])| {
    let (now, bytes) = input;
    if let Some(time) = parse_http_date(bytes, now) {
        assert!(time <= MAX_FORMATTABLE);
        assert_eq!(parse_http_date(format_http_date(time).as_bytes(), now), Some(time));
    }
});
