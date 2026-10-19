//! The web-platform-tests in `fetch/http-cache/` that exercise RFC 9111
//! decisions, replayed against this crate.
//!
//! Each case is a sequence of requests to one URL, with the response headers the
//! test server sends and the outcome the test expects, transcribed from the
//! `*.any.js` files. A small simulator plays the cache: it looks up stored
//! responses with [`StoredPolicy::evaluate`], sends [`validation_fields`] when
//! told to validate, and stores or freshens what the server returns. Like the
//! test server (`resources/http-cache.py`), the server answers with a 304 only
//! for a request the test expects to be validated, and only when its
//! `If-None-Match` or `If-Modified-Since` repeats the validator of the first
//! response byte for byte; otherwise it sends a full response.
//!
//! Cases outside this crate's scope are left out: cache modes, `only-if-cached`,
//! invalidation, partial content, partitioning and credentials, which are the
//! caller's (see `SPEC.md`).
//!
//! [`validation_fields`]: StoredPolicy::validation_fields

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_cache_rules::date::format_http_date;
use http_cache_rules::{CacheConfig, Exchange, Reuse, StoredPolicy};

const T0: u64 = 1_760_000_000;

#[derive(Clone, Copy)]
enum Value {
    Literal(&'static str),
    /// An HTTP-date `now + seconds`, computed when the response is sent.
    Now(i64),
}

use Value::{Literal, Now};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Outcome {
    /// Served from the cache; the server saw no request.
    Cached,
    /// The server sent a full response, which was used.
    Network,
    /// `If-None-Match` matched and the server sent a 304.
    EtagValidated,
    /// `If-Modified-Since` matched and the server sent a 304.
    LmValidated,
}

struct Step {
    request_headers: &'static [(&'static str, &'static str)],
    status: u16,
    response_headers: Vec<(&'static str, Value)>,
    pause: u64,
    expect: Outcome,
}

fn step(response_headers: &[(&'static str, Value)], expect: Outcome) -> Step {
    Step {
        request_headers: &[],
        status: 200,
        response_headers: response_headers.to_vec(),
        pause: 0,
        expect,
    }
}

impl Step {
    fn request(mut self, headers: &'static [(&'static str, &'static str)]) -> Self {
        self.request_headers = headers;
        self
    }

    fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    fn pause(mut self, seconds: u64) -> Self {
        self.pause = seconds;
        self
    }
}

struct Entry {
    policy: StoredPolicy,
    headers: HeaderMap,
    body: String,
}

/// What the client received for one request.
struct Received {
    outcome: Outcome,
    status: u16,
    headers: HeaderMap,
    body: String,
}

fn time(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn header_map(fields: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

fn resolve(value: Value, now: u64) -> String {
    match value {
        Literal(value) => value.to_owned(),
        Now(delta) => format_http_date(now.checked_add_signed(delta).unwrap()),
    }
}

/// The response headers the test server sends at `now`, with its implicit
/// fields.
fn server_headers(step: &Step, now: u64, not_modified: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in &step.response_headers {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(&resolve(*value, now)).unwrap(),
        );
    }
    headers.insert(
        "date",
        HeaderValue::from_str(&format_http_date(now)).unwrap(),
    );
    headers.insert("content-type", HeaderValue::from_static("text/plain"));
    headers.insert(
        "content-length",
        HeaderValue::from_static(if not_modified { "0" } else { "36" }),
    );
    headers
}

fn configured(step: &Step, name: &str, now: u64) -> Option<String> {
    step.response_headers
        .iter()
        .find(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| resolve(*value, now))
}

fn precondition_repeats(sent: &HeaderMap, name: HeaderName, validator: &Option<String>) -> bool {
    sent.get(name)
        .is_some_and(|value| validator.as_deref() == value.to_str().ok())
}

fn run(steps: &[Step]) -> Vec<Received> {
    let config = CacheConfig::default();
    let mut entries: Vec<Entry> = Vec::new();
    let mut received = Vec::new();
    let mut now = T0;
    let first_etag = configured(&steps[0], "etag", T0);
    let first_last_modified = configured(&steps[0], "last-modified", T0);
    for (index, step) in steps.iter().enumerate() {
        let client_headers = header_map(step.request_headers);
        let candidate = entries
            .iter()
            .enumerate()
            .filter_map(|(position, entry)| {
                entry
                    .policy
                    .evaluate(&Method::GET, &client_headers, time(now))
                    .map(|reuse| (position, reuse))
            })
            .max_by_key(|(position, _)| entries[*position].policy.date());

        let mut sent_headers = client_headers.clone();
        let mut validating = None;
        match candidate {
            Some((position, Reuse::Fresh | Reuse::StaleAllowed | Reuse::StaleWhileRevalidate)) => {
                let entry = &entries[position];
                received.push(Received {
                    outcome: Outcome::Cached,
                    status: entry.policy.status(),
                    headers: entry.policy.presented_fields(&entry.headers, time(now)),
                    body: entry.body.clone(),
                });
                now += step.pause;
                continue;
            },
            Some((position, Reuse::Validate)) => {
                for (name, value) in entries[position].policy.validation_fields() {
                    sent_headers.insert(name, value);
                }
                validating = Some(position);
            },
            None => {},
        }

        let validation_expected = matches!(step.expect, EtagValidated | LmValidated);
        let etag_matches =
            validation_expected && precondition_repeats(&sent_headers, IF_NONE_MATCH, &first_etag);
        let lm_matches = validation_expected
            && !etag_matches
            && precondition_repeats(&sent_headers, IF_MODIFIED_SINCE, &first_last_modified);

        if etag_matches || lm_matches {
            let position = validating.expect("only a validation request carries preconditions");
            let response_headers = server_headers(step, now, true);
            let exchange = Exchange {
                method: &Method::GET,
                request_headers: &client_headers,
                status: StatusCode::NOT_MODIFIED,
                response_headers: &response_headers,
                request_time: time(now),
                response_time: time(now),
            };
            let entry = &mut entries[position];
            let freshened = entry
                .policy
                .freshen(&config, &entry.headers, &exchange)
                .expect("the 304 refers to the stored response");
            entry.headers = freshened.headers;
            let headers = match &freshened.policy {
                Ok(policy) => policy.presented_fields(&entry.headers, time(now)),
                Err(_) => entry.headers.clone(),
            };
            received.push(Received {
                outcome: if etag_matches {
                    Outcome::EtagValidated
                } else {
                    Outcome::LmValidated
                },
                status: entry.policy.status(),
                headers,
                body: entry.body.clone(),
            });
            match freshened.policy {
                Ok(policy) => entry.policy = policy,
                Err(_) => {
                    entries.remove(position);
                },
            }
        } else {
            let response_headers = server_headers(step, now, false);
            let body = format!("body of request {}", index + 1);
            let exchange = Exchange {
                method: &Method::GET,
                request_headers: &client_headers,
                status: StatusCode::from_u16(step.status).unwrap(),
                response_headers: &response_headers,
                request_time: time(now),
                response_time: time(now),
            };
            if let Ok(policy) = StoredPolicy::new(&config, &exchange) {
                entries.retain(|entry| !entry.policy.vary().matches(&client_headers));
                entries.push(Entry {
                    policy,
                    headers: StoredPolicy::stored_fields(&config, &exchange),
                    body: body.clone(),
                });
            }
            received.push(Received {
                outcome: Outcome::Network,
                status: step.status,
                headers: response_headers,
                body,
            });
        }
        now += step.pause;
    }
    received
}

fn assert_outcomes(steps: &[Step]) -> Vec<Received> {
    let received = run(steps);
    for (index, (step, got)) in steps.iter().zip(&received).enumerate() {
        assert_eq!(got.outcome, step.expect, "request {}", index + 1);
    }
    received
}

use Outcome::{Cached, EtagValidated, LmValidated, Network};

fn two(headers: &[(&'static str, Value)], second: Outcome) {
    assert_outcomes(&[step(headers, Network), step(headers, second)]);
}

// --- freshness.any.js ------------------------------------------------------------

#[test]
fn freshness_01_future_expires() {
    two(&[("Expires", Now(2_592_000))], Cached);
}

#[test]
fn freshness_02_past_expires() {
    two(&[("Expires", Now(-2_592_000))], Network);
}

#[test]
fn freshness_03_present_expires() {
    two(&[("Expires", Now(0))], Network);
}

#[test]
fn freshness_04_invalid_expires() {
    two(&[("Expires", Literal("0"))], Network);
}

#[test]
fn freshness_05_invalid_expires_with_last_modified_now() {
    two(
        &[("Expires", Literal("0")), ("Last-Modified", Now(0))],
        Network,
    );
}

#[test]
fn freshness_06_invalid_expires_with_past_last_modified() {
    two(
        &[("Expires", Literal("0")), ("Last-Modified", Now(-100_000))],
        Network,
    );
}

#[test]
fn freshness_07_positive_max_age() {
    two(&[("Cache-Control", Literal("max-age=3600"))], Cached);
}

#[test]
fn freshness_08_max_age_zero() {
    two(&[("Cache-Control", Literal("max-age=0"))], Network);
}

#[test]
fn freshness_09_max_age_and_past_expires() {
    two(
        &[
            ("Cache-Control", Literal("max-age=3600")),
            ("Expires", Now(-10_000)),
        ],
        Cached,
    );
}

#[test]
fn freshness_10_max_age_and_invalid_expires() {
    two(
        &[
            ("Cache-Control", Literal("max-age=3600")),
            ("Expires", Literal("0")),
        ],
        Cached,
    );
}

#[test]
fn freshness_11_max_age_zero_and_future_expires() {
    two(
        &[
            ("Cache-Control", Literal("max-age=0")),
            ("Expires", Now(10_000)),
        ],
        Network,
    );
}

#[test]
fn freshness_12_s_maxage_is_ignored_by_a_private_cache() {
    let headers = [("Cache-Control", Literal("max-age=1, s-maxage=3600"))];
    assert_outcomes(&[step(&headers, Network).pause(3), step(&headers, Network)]);
}

#[test]
fn freshness_13_age_greater_than_lifetime() {
    two(
        &[
            ("Cache-Control", Literal("max-age=3600")),
            ("Age", Literal("12000")),
        ],
        Network,
    );
}

#[test]
fn freshness_14_no_store() {
    two(&[("Cache-Control", Literal("no-store"))], Network);
}

#[test]
fn freshness_15_no_store_with_max_age_and_expires() {
    two(
        &[
            ("Cache-Control", Literal("max-age=10000, no-store")),
            ("Expires", Now(10_000)),
        ],
        Network,
    );
}

#[test]
fn freshness_16_no_cache_revalidates() {
    let received = assert_outcomes(&[
        step(
            &[
                ("Cache-Control", Literal("no-cache")),
                ("ETag", Literal("abcd")),
            ],
            Network,
        ),
        step(&[], EtagValidated),
    ]);
    assert_eq!(received[1].status, 200);
    assert_eq!(received[1].body, received[0].body);
}

#[test]
fn freshness_17_no_cache_revalidates_even_with_max_age_and_expires() {
    let headers = [
        ("Cache-Control", Literal("max-age=10000, no-cache")),
        ("Expires", Now(10_000)),
        ("ETag", Literal("abcd")),
    ];
    assert_outcomes(&[step(&headers, Network), step(&headers, EtagValidated)]);
}

// --- heuristic.any.js -------------------------------------------------------------

fn heuristic(status: u16, extra: &[(&'static str, Value)], second: Outcome) {
    let mut headers = vec![("Last-Modified", Now(-300))];
    headers.extend_from_slice(extra);
    let received = assert_outcomes(&[
        step(&headers, Network).status(status),
        step(&headers, second).status(status),
    ]);
    assert_eq!(received[1].status, status);
}

#[test]
fn heuristic_01_unknown_status_with_public() {
    heuristic(299, &[("Cache-Control", Literal("public"))], Cached);
}

#[test]
fn heuristic_02_unknown_status_without_public() {
    heuristic(299, &[], Network);
}

#[test]
fn heuristic_04_to_11_heuristically_cacheable_statuses() {
    for status in [200, 203, 204, 404, 405, 410, 414, 501] {
        heuristic(status, &[], Cached);
    }
}

#[test]
fn heuristic_12_to_17_statuses_without_heuristic_freshness() {
    for status in [201, 202, 403, 502, 503, 504] {
        heuristic(status, &[], Network);
    }
}

#[test]
fn heuristic_03_no_caching_headers_are_not_reused() {
    two(&[], Network);
}

// --- status.any.js ----------------------------------------------------------------

#[test]
fn status_01_to_26() {
    let stale = [("Expires", Now(-5000)), ("Last-Modified", Now(-100_000))];
    let fresh = [("Expires", Now(100_000)), ("Last-Modified", Now(0))];
    for status in [
        200, 203, 204, 299, 400, 404, 410, 499, 500, 502, 503, 504, 599,
    ] {
        let received = assert_outcomes(&[
            step(&stale, Network).status(status),
            step(&[], Network).status(status),
        ]);
        assert_eq!(received[1].status, status);
        let received = assert_outcomes(&[
            step(&fresh, Network).status(status),
            step(&[], Cached).status(status),
        ]);
        assert_eq!(received[1].status, status, "{status}");
        assert_eq!(received[1].body, received[0].body);
    }
}

// --- cc-request.any.js ------------------------------------------------------------

fn fresh_then(request: &'static [(&'static str, &'static str)], second: Outcome, pause: u64) {
    let headers = [("Expires", Now(100_000)), ("Last-Modified", Now(0))];
    assert_outcomes(&[
        step(&headers, Network).pause(pause),
        step(&headers, second).request(request),
    ]);
}

#[test]
fn cc_request_01_max_age_zero() {
    fresh_then(&[("Cache-Control", "max-age=0")], Network, 3);
}

#[test]
fn cc_request_02_max_age_one() {
    fresh_then(&[("Cache-Control", "max-age=1")], Network, 3);
}

#[test]
fn cc_request_03_max_age_below_age() {
    let headers = [
        ("Cache-Control", Literal("max-age=3600")),
        ("Age", Literal("1800")),
    ];
    assert_outcomes(&[
        step(&headers, Network),
        step(&headers, Network).request(&[("Cache-Control", "max-age=600")]),
    ]);
}

#[test]
fn cc_request_04_max_stale_permits_stale() {
    let headers = [("Cache-Control", Literal("max-age=1"))];
    assert_outcomes(&[
        step(&headers, Network).pause(3),
        step(&headers, Cached).request(&[("Cache-Control", "max-stale=1000")]),
    ]);
}

#[test]
fn cc_request_05_max_stale_with_age() {
    let headers = [
        ("Cache-Control", Literal("max-age=1500")),
        ("Age", Literal("2000")),
    ];
    assert_outcomes(&[
        step(&headers, Network),
        step(&headers, Cached).request(&[("Cache-Control", "max-stale=1000")]),
    ]);
}

#[test]
fn cc_request_06_min_fresh() {
    let headers = [("Cache-Control", Literal("max-age=1500"))];
    assert_outcomes(&[
        step(&headers, Network),
        step(&headers, Network).request(&[("Cache-Control", "min-fresh=2000")]),
    ]);
}

#[test]
fn cc_request_07_min_fresh_with_age() {
    let headers = [
        ("Cache-Control", Literal("max-age=1500")),
        ("Age", Literal("1000")),
    ];
    assert_outcomes(&[
        step(&headers, Network),
        step(&headers, Network).request(&[("Cache-Control", "min-fresh=1000")]),
    ]);
}

#[test]
fn cc_request_08_no_cache() {
    let headers = [("Cache-Control", Literal("max-age=3600"))];
    assert_outcomes(&[
        step(&headers, Network),
        step(&headers, Network).request(&[("Cache-Control", "no-cache")]),
    ]);
}

/// cc-request #9 and #10 mean to check this but assert nothing (typo in the
/// expected type), so the intended behaviour is checked here.
#[test]
fn cc_request_09_10_no_cache_validates_with_stored_validators() {
    let lm = [
        ("Cache-Control", Literal("max-age=3600")),
        ("Last-Modified", Now(-10_000)),
    ];
    assert_outcomes(&[
        step(&lm, Network),
        step(&lm, LmValidated).request(&[("Cache-Control", "no-cache")]),
    ]);
    let etag = [
        ("Cache-Control", Literal("max-age=3600")),
        ("ETag", Literal("aGVsbG8=")),
    ];
    assert_outcomes(&[
        step(&etag, Network),
        step(&etag, EtagValidated).request(&[("Cache-Control", "no-cache")]),
    ]);
}

#[test]
fn cc_request_11_no_store() {
    let headers = [("Cache-Control", Literal("max-age=3600"))];
    assert_outcomes(&[
        step(&headers, Network),
        step(&headers, Network).request(&[("Cache-Control", "no-store")]),
    ]);
}

// --- vary.any.js ------------------------------------------------------------------

fn vary(
    first: &'static [(&'static str, &'static str)],
    vary: &'static str,
    second: &'static [(&'static str, &'static str)],
    expect: Outcome,
) {
    let headers = [
        ("Expires", Now(5000)),
        ("Last-Modified", Now(-3000)),
        ("Vary", Literal(vary)),
    ];
    assert_outcomes(&[
        step(&headers, Network).request(first),
        step(&headers, expect).request(second),
    ]);
}

#[test]
fn vary_01_match() {
    vary(&[("Foo", "1")], "Foo", &[("Foo", "1")], Cached);
}

#[test]
fn vary_02_mismatch() {
    vary(&[("Foo", "1")], "Foo", &[("Foo", "2")], Network);
}

#[test]
fn vary_03_omitted() {
    vary(&[("Foo", "1")], "Foo", &[], Network);
}

#[test]
fn vary_04_variants_coexist() {
    let headers = [
        ("Expires", Now(5000)),
        ("Last-Modified", Now(-3000)),
        ("Vary", Literal("Foo")),
    ];
    let received = assert_outcomes(&[
        step(&headers, Network).request(&[("Foo", "1")]),
        step(&headers, Network).request(&[("Foo", "2")]),
        step(&headers, Cached).request(&[("Foo", "1")]),
    ]);
    assert_eq!(received[2].body, received[0].body);
}

#[test]
fn vary_05_unlisted_headers_are_ignored() {
    vary(
        &[("Foo", "1"), ("Other", "2")],
        "Foo",
        &[("Foo", "1"), ("Other", "3")],
        Cached,
    );
}

#[test]
fn vary_06_two_way_match() {
    vary(
        &[("Foo", "1"), ("Bar", "abc")],
        "Foo, Bar",
        &[("Foo", "1"), ("Bar", "abc")],
        Cached,
    );
}

#[test]
fn vary_07_two_way_mismatch() {
    vary(
        &[("Foo", "1"), ("Bar", "abc")],
        "Foo, Bar",
        &[("Foo", "2"), ("Bar", "abc")],
        Network,
    );
}

#[test]
fn vary_08_two_way_omitted() {
    vary(&[("Foo", "1")], "Foo, Bar", &[], Network);
}

#[test]
fn vary_09_three_way_match() {
    let fields = &[("Foo", "1"), ("Bar", "abc"), ("Baz", "789")];
    vary(fields, "Foo, Bar, Baz", fields, Cached);
}

#[test]
fn vary_10_three_way_mismatch() {
    vary(
        &[("Foo", "1"), ("Bar", "abc"), ("Baz", "789")],
        "Foo, Bar, Baz",
        &[("Foo", "2"), ("Bar", "abc"), ("Baz", "789")],
        Network,
    );
}

#[test]
fn vary_11_three_way_mismatch_in_the_middle() {
    vary(
        &[("Foo", "1"), ("Bar", "abc4"), ("Baz", "789")],
        "Foo, Bar, Baz",
        &[("Foo", "1"), ("Bar", "abc"), ("Baz", "789")],
        Network,
    );
}

#[test]
fn vary_12_absent_in_both() {
    vary(
        &[("Foo", "1"), ("Baz", "789")],
        "Foo, Bar, Baz",
        &[("Foo", "1"), ("Baz", "789")],
        Cached,
    );
}

#[test]
fn vary_13_star() {
    vary(
        &[("Foo", "1"), ("Baz", "789")],
        "*",
        &[("Baz", "789")],
        Network,
    );
}

// --- 304-update.any.js ------------------------------------------------------------

fn test_header(received: &Received, name: &str) -> String {
    received.headers[name].to_str().unwrap().to_owned()
}

#[test]
fn update_304_01_returned_headers_from_last_modified_304() {
    let received = assert_outcomes(&[
        step(
            &[
                ("Expires", Now(-5000)),
                ("Last-Modified", Now(-3000)),
                ("Test-Header", Literal("A")),
            ],
            Network,
        ),
        step(
            &[
                ("Expires", Now(-3000)),
                ("Last-Modified", Now(-3000)),
                ("Test-Header", Literal("B")),
            ],
            LmValidated,
        ),
    ]);
    assert_eq!(received[1].status, 200);
    assert_eq!(received[1].body, received[0].body);
    assert_eq!(test_header(&received[1], "test-header"), "B");
}

#[test]
fn update_304_02_stored_headers_from_last_modified_304() {
    let received = assert_outcomes(&[
        step(
            &[
                ("Expires", Now(-5000)),
                ("Last-Modified", Now(-3000)),
                ("Test-Header", Literal("A")),
            ],
            Network,
        ),
        step(
            &[
                ("Expires", Now(3000)),
                ("Last-Modified", Now(-3000)),
                ("Test-Header", Literal("B")),
            ],
            LmValidated,
        )
        .pause(3),
        step(&[], Cached),
    ]);
    assert_eq!(test_header(&received[2], "test-header"), "B");
    assert_eq!(received[2].body, received[0].body);
}

#[test]
fn update_304_03_returned_headers_from_etag_304() {
    let received = assert_outcomes(&[
        step(
            &[
                ("Expires", Now(-5000)),
                ("ETag", Literal("ABC")),
                ("Test-Header", Literal("A")),
            ],
            Network,
        ),
        step(
            &[
                ("Expires", Now(-3000)),
                ("ETag", Literal("ABC")),
                ("Test-Header", Literal("B")),
            ],
            EtagValidated,
        ),
    ]);
    assert_eq!(test_header(&received[1], "test-header"), "B");
}

#[test]
fn update_304_04_stored_headers_from_etag_304() {
    let received = assert_outcomes(&[
        step(
            &[
                ("Expires", Now(-5000)),
                ("ETag", Literal("DEF")),
                ("Test-Header", Literal("A")),
            ],
            Network,
        ),
        step(
            &[
                ("Expires", Now(3000)),
                ("ETag", Literal("DEF")),
                ("Test-Header", Literal("B")),
            ],
            EtagValidated,
        )
        .pause(3),
        step(&[], Cached),
    ]);
    assert_eq!(test_header(&received[2], "test-header"), "B");
}

#[test]
fn update_304_05_content_header() {
    let received = assert_outcomes(&[
        step(
            &[
                ("Expires", Now(-5000)),
                ("ETag", Literal("GHI")),
                ("Content-Test-Header", Literal("A")),
            ],
            Network,
        ),
        step(
            &[
                ("Expires", Now(3000)),
                ("ETag", Literal("GHI")),
                ("Content-Test-Header", Literal("B")),
            ],
            EtagValidated,
        )
        .pause(3),
        step(&[], Cached),
    ]);
    assert_eq!(test_header(&received[1], "content-test-header"), "B");
    assert_eq!(test_header(&received[2], "content-test-header"), "B");
    assert_eq!(test_header(&received[2], "content-length"), "36");
}

/// The test server recomputes `Last-Modified` for each response, so a 304's can
/// lag the stored one by a second; the stored response is still the one that
/// was validated.
#[test]
fn update_304_last_modified_that_moved_by_a_second() {
    let received = assert_outcomes(&[
        step(
            &[("Expires", Now(-5000)), ("Last-Modified", Now(-3000))],
            Network,
        )
        .pause(1),
        step(
            &[("Expires", Now(3000)), ("Last-Modified", Now(-3001))],
            LmValidated,
        ),
        step(&[], Cached),
    ]);
    assert_eq!(received[2].body, received[0].body);
}

// --- pragma-no-cache-with-cache-control.html ---------------------------------------

#[test]
fn pragma_01_pragma_no_cache_beats_max_age_and_public() {
    let headers = [
        ("Cache-Control", Literal("max-age=2592000, public")),
        ("Pragma", Literal("no-cache")),
    ];
    two(&headers, Network);
}

#[test]
fn pragma_02_immutable_beats_pragma_no_cache() {
    let headers = [
        ("Cache-Control", Literal("max-age=2592000, immutable")),
        ("Pragma", Literal("no-cache")),
    ];
    two(&headers, Cached);
}
