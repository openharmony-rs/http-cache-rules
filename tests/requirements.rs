//! One or more tests per requirement in `SPEC.md`, through the public API. Each
//! test's name starts with the requirement's identifier.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_cache_rules::date::{format_http_date, parse_http_date};
use http_cache_rules::directives::{RequestDirectives, parse_delta_seconds};
use http_cache_rules::validators::EntityTag;
use http_cache_rules::{
    CacheConfig, Exchange, FreshenError, NotStorable, Reuse, StoredPolicy, VaryKey, invalidates,
    invalidation_candidates,
};

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

fn date(offset: i64) -> String {
    format_http_date(T0.checked_add_signed(offset).unwrap())
}

/// A GET at T0 answered at T0 with `status` and `response`.
struct Case {
    method: Method,
    request: HeaderMap,
    status: StatusCode,
    response: HeaderMap,
    request_time: u64,
    response_time: u64,
}

fn case(status: u16, response: &[(&str, &str)]) -> Case {
    Case {
        method: Method::GET,
        request: HeaderMap::new(),
        status: StatusCode::from_u16(status).unwrap(),
        response: headers(response),
        request_time: T0,
        response_time: T0,
    }
}

impl Case {
    fn request(mut self, fields: &[(&str, &str)]) -> Self {
        self.request = headers(fields);
        self
    }

    fn exchange(&self) -> Exchange<'_> {
        Exchange {
            method: &self.method,
            request_headers: &self.request,
            status: self.status,
            response_headers: &self.response,
            request_time: at(self.request_time),
            response_time: at(self.response_time),
        }
    }

    fn policy(&self) -> Result<StoredPolicy, NotStorable> {
        StoredPolicy::new(&CacheConfig::default(), &self.exchange())
    }

    fn stored(&self) -> StoredPolicy {
        self.policy().expect("storable")
    }

    fn stored_fields(&self) -> HeaderMap {
        StoredPolicy::stored_fields(&CacheConfig::default(), &self.exchange())
    }
}

fn evaluate(policy: &StoredPolicy, request: &[(&str, &str)], now: u64) -> Option<Reuse> {
    policy.evaluate(&Method::GET, &headers(request), at(now))
}

fn not_modified(response: &[(&str, &str)], now: u64) -> Case {
    let mut case = case(304, response);
    case.request_time = now;
    case.response_time = now;
    case
}

// --- RFC 9111 §1.2.2 -----------------------------------------------------------------

#[test]
fn r_1_2_2_large_delta_seconds_saturate() {
    assert_eq!(
        parse_delta_seconds(b"99999999999999999999"),
        Some(2_147_483_648)
    );
    let policy = case(200, &[("cache-control", "max-age=99999999999999999999")]).stored();
    assert_eq!(policy.freshness_lifetime(), 2_147_483_648);
    let aged = case(
        200,
        &[
            ("cache-control", "max-age=60"),
            ("age", "99999999999999999999"),
        ],
    )
    .stored();
    assert_eq!(aged.current_age(at(T0)), 2_147_483_648);
    assert_eq!(evaluate(&aged, &[], T0), Some(Reuse::Validate));
}

// --- §3 ---------------------------------------------------------------------------

#[test]
fn r_3_storable_responses() {
    assert!(case(200, &[]).policy().is_ok());
    assert!(case(404, &[]).policy().is_ok());
    assert!(
        case(302, &[("cache-control", "max-age=60")])
            .policy()
            .is_ok()
    );
    assert!(case(299, &[("expires", &date(60))]).policy().is_ok());
}

#[test]
fn r_3_unstorable_responses() {
    let mut post = case(200, &[("cache-control", "max-age=60")]);
    post.method = Method::POST;
    assert_eq!(post.policy(), Err(NotStorable::Method));
    assert_eq!(case(103, &[]).policy(), Err(NotStorable::NotFinal));
    assert_eq!(case(304, &[]).policy(), Err(NotStorable::NotModified));
    assert_eq!(case(206, &[]).policy(), Err(NotStorable::PartialContent));
    assert_eq!(case(302, &[]).policy(), Err(NotStorable::NoPermission));
    assert_eq!(case(500, &[]).policy(), Err(NotStorable::NoPermission));
}

#[test]
fn r_3_partial_content_when_supported() {
    let config = CacheConfig {
        partial_content: true,
        ..CacheConfig::default()
    };
    let partial = case(206, &[("content-range", "bytes 0-4/10")]);
    assert!(StoredPolicy::new(&config, &partial.exchange()).is_ok());
}

#[test]
fn r_3_1_all_fields_are_stored() {
    let stored = case(
        200,
        &[("x-new-field", "1"), ("link", "<a>"), ("link", "<b>")],
    )
    .stored_fields();
    assert_eq!(stored["x-new-field"], "1");
    assert_eq!(stored.get_all("link").iter().count(), 2);
}

#[test]
fn r_3_1_connection_and_hop_by_hop_fields_are_not_stored() {
    let stored = case(
        200,
        &[
            ("connection", "x-hop"),
            ("x-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("upgrade", "h2c"),
        ],
    )
    .stored_fields();
    for name in ["connection", "keep-alive", "upgrade"] {
        assert!(!stored.contains_key(name), "{name}");
    }
    assert_eq!(stored["x-hop"], "1");
}

/// A response cannot hide its own fields from cached copies by naming them in
/// `Connection`, and the policy after a 304 sees the same `no-cache` as the
/// policy before it.
#[test]
fn r_3_1_connection_cannot_strip_security_or_cache_fields() {
    let original = case(
        200,
        &[
            ("connection", "cache-control, content-security-policy"),
            ("cache-control", "no-cache"),
            ("content-security-policy", "script-src 'self'"),
            ("expires", &date(3600)),
            ("etag", "\"e\""),
        ],
    );
    let stored = original.stored_fields();
    assert_eq!(stored["content-security-policy"], "script-src 'self'");
    let policy = original.stored();
    assert_eq!(evaluate(&policy, &[], T0 + 10), Some(Reuse::Validate));
    let answer = not_modified(&[("etag", "\"e\""), ("date", &date(10))], T0 + 10);
    let renewed = policy
        .freshen(&CacheConfig::default(), &stored, &answer.exchange())
        .unwrap()
        .policy
        .unwrap();
    assert_eq!(evaluate(&renewed, &[], T0 + 11), Some(Reuse::Validate));
}

#[test]
fn r_3_1_proxy_fields_are_never_stored() {
    let stored = case(
        200,
        &[
            ("proxy-authenticate", "Basic"),
            ("proxy-authentication-info", "x"),
            ("proxy-authorization", "y"),
        ],
    )
    .stored_fields();
    assert_eq!(
        stored.keys().map(|name| name.as_str()).collect::<Vec<_>>(),
        ["date"]
    );
}

#[test]
fn r_3_2_update_replaces_present_fields_and_adds_new_ones() {
    let original = case(
        200,
        &[
            ("etag", "\"a\""),
            ("x-a", "old"),
            ("x-b", "kept"),
            ("content-length", "10"),
        ],
    );
    let policy = original.stored();
    let stored = original.stored_fields();
    let answer = not_modified(
        &[
            ("etag", "\"a\""),
            ("x-a", "new"),
            ("x-c", "added"),
            ("content-length", "0"),
        ],
        T0 + 10,
    );
    let freshened = policy
        .freshen(&CacheConfig::default(), &stored, &answer.exchange())
        .unwrap();
    assert_eq!(freshened.headers["x-a"], "new");
    assert_eq!(freshened.headers["x-b"], "kept");
    assert_eq!(freshened.headers["x-c"], "added");
    assert_eq!(freshened.headers["content-length"], "10");
}

// --- §4 ---------------------------------------------------------------------------

#[test]
fn r_4_method_only_get_and_head_are_answered() {
    let policy = case(200, &[("cache-control", "max-age=60")]).stored();
    assert_eq!(
        policy.evaluate(&Method::GET, &HeaderMap::new(), at(T0)),
        Some(Reuse::Fresh)
    );
    assert_eq!(
        policy.evaluate(&Method::HEAD, &HeaderMap::new(), at(T0)),
        Some(Reuse::Fresh)
    );
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS] {
        assert_eq!(
            policy.evaluate(&method, &HeaderMap::new(), at(T0)),
            None,
            "{method}"
        );
    }
}

#[test]
fn r_4_no_cache_response_needs_validation_even_when_fresh() {
    let policy = case(200, &[("cache-control", "max-age=3600, no-cache")]).stored();
    assert_eq!(evaluate(&policy, &[], T0 + 1), Some(Reuse::Validate));
}

#[test]
fn r_4_age_restarts_after_validation() {
    let original = case(
        200,
        &[
            ("cache-control", "max-age=60"),
            ("age", "100"),
            ("etag", "\"e\""),
        ],
    );
    let answer = not_modified(&[("etag", "\"e\""), ("date", &date(500))], T0 + 500);
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    assert!(!freshened.headers.contains_key("age"));
    let renewed = freshened.policy.unwrap();
    assert_eq!(
        renewed.presented_fields(&freshened.headers, at(T0 + 500))["age"],
        "0"
    );
    let with_age = not_modified(
        &[("etag", "\"e\""), ("date", &date(500)), ("age", "7")],
        T0 + 500,
    );
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &with_age.exchange(),
        )
        .unwrap();
    assert_eq!(freshened.headers["age"], "7");
    assert_eq!(freshened.policy.unwrap().current_age(at(T0 + 500)), 7);
}

#[test]
fn r_4_age_is_generated_and_replaces_the_received_one() {
    let original = case(200, &[("cache-control", "max-age=3600"), ("age", "100")]);
    let policy = original.stored();
    let presented = policy.presented_fields(&original.stored_fields(), at(T0 + 50));
    assert_eq!(presented.get_all("age").iter().collect::<Vec<_>>(), ["150"]);
}

#[test]
fn r_4_most_recent_is_by_date() {
    let older = case(
        200,
        &[("cache-control", "max-age=60"), ("date", &date(-10))],
    )
    .stored();
    let newer = case(200, &[("cache-control", "max-age=60"), ("date", &date(0))]).stored();
    assert!(newer.date() > older.date());
}

#[test]
fn r_4_1_match_compares_nominated_fields() {
    let policy = case(
        200,
        &[("cache-control", "max-age=60"), ("vary", "Accept-Language")],
    )
    .request(&[("accept-language", "en"), ("user-agent", "a")])
    .stored();
    assert!(
        evaluate(
            &policy,
            &[("accept-language", "en"), ("user-agent", "b")],
            T0
        )
        .is_some()
    );
    assert!(evaluate(&policy, &[("accept-language", " en ")], T0).is_some());
    assert_eq!(evaluate(&policy, &[("accept-language", "de")], T0), None);
}

#[test]
fn r_4_1_match_combines_field_lines() {
    let policy = case(200, &[("cache-control", "max-age=60"), ("vary", "x-list")])
        .request(&[("x-list", "a"), ("x-list", "b")])
        .stored();
    assert!(evaluate(&policy, &[("x-list", "a, b")], T0).is_some());
    assert_eq!(
        evaluate(&policy, &[("x-list", "a"), ("x-list", "c")], T0),
        None
    );
}

#[test]
fn r_4_1_absent_only_matches_absent() {
    let policy = case(200, &[("cache-control", "max-age=60"), ("vary", "x-a")]).stored();
    assert!(evaluate(&policy, &[], T0).is_some());
    assert_eq!(evaluate(&policy, &[("x-a", "1")], T0), None);
}

#[test]
fn r_4_1_star_never_matches() {
    let policy = case(200, &[("cache-control", "max-age=60"), ("vary", "x-a, *")]).stored();
    assert_eq!(policy.vary(), &VaryKey::Never);
    assert_eq!(evaluate(&policy, &[], T0), None);
}

#[test]
fn r_4_2_fresh_while_lifetime_exceeds_age() {
    let policy = case(200, &[("cache-control", "max-age=60")]).stored();
    assert!(policy.is_fresh(at(T0 + 59)));
    assert!(!policy.is_fresh(at(T0 + 60)));
    assert_eq!(evaluate(&policy, &[], T0 + 59), Some(Reuse::Fresh));
    assert_eq!(evaluate(&policy, &[], T0 + 60), Some(Reuse::Validate));
}

#[test]
fn r_4_2_case_insensitive_dates() {
    let upper = date(60).to_uppercase();
    let policy = case(200, &[("expires", &upper), ("date", &date(0))]).stored();
    assert_eq!(policy.freshness_lifetime(), 60);
}

#[test]
fn r_4_2_gmt_only() {
    let other_zone = date(60).replace("GMT", "UTC");
    let policy = case(200, &[("expires", &other_zone)]).stored();
    assert_eq!(policy.freshness_lifetime(), 0);
}

#[test]
fn r_4_2_earlier_leap_second() {
    assert_eq!(
        parse_http_date(b"Sat, 31 Dec 2016 23:59:60 GMT", T0),
        parse_http_date(b"Sat, 31 Dec 2016 23:59:59 GMT", T0)
    );
}

#[test]
fn r_4_2_1_order_max_age_then_expires_then_heuristic() {
    let both = case(
        200,
        &[
            ("cache-control", "max-age=10"),
            ("expires", &date(100)),
            ("date", &date(0)),
        ],
    );
    assert_eq!(both.stored().freshness_lifetime(), 10);
    let expires = case(
        200,
        &[
            ("expires", &date(100)),
            ("date", &date(0)),
            ("last-modified", &date(-100_000)),
        ],
    );
    assert_eq!(expires.stored().freshness_lifetime(), 100);
    assert!(!expires.stored().is_heuristic());
    let heuristic = case(
        200,
        &[("date", &date(0)), ("last-modified", &date(-100_000))],
    )
    .stored();
    assert_eq!(heuristic.freshness_lifetime(), 10_000);
    assert!(heuristic.is_heuristic());
}

#[test]
fn r_4_2_1_order_expires_without_date_uses_receive_time() {
    let mut late = case(200, &[("expires", &date(100))]);
    late.response_time = T0 + 40;
    assert_eq!(late.stored().freshness_lifetime(), 60);
}

#[test]
fn r_4_2_1_duplicates_first_occurrence_wins() {
    let max_age = case(
        200,
        &[
            ("cache-control", "max-age=10"),
            ("cache-control", "max-age=1000"),
        ],
    );
    assert_eq!(max_age.stored().freshness_lifetime(), 10);
    let expires = case(
        200,
        &[
            ("expires", &date(10)),
            ("expires", &date(1000)),
            ("date", &date(0)),
        ],
    );
    assert_eq!(expires.stored().freshness_lifetime(), 10);
}

#[test]
fn r_4_2_1_invalid_max_age_is_stale() {
    for value in ["max-age=abc", "max-age=-5", "max-age", "max-age=1.5"] {
        let policy = case(200, &[("cache-control", value), ("expires", &date(1000))]).stored();
        assert_eq!(policy.freshness_lifetime(), 0, "{value}");
    }
}

#[test]
fn r_4_2_2_explicit_expiration_blocks_heuristics() {
    let past = case(
        200,
        &[("expires", &date(-10)), ("last-modified", &date(-100_000))],
    )
    .stored();
    assert_eq!(past.freshness_lifetime(), 0);
    assert!(!past.is_heuristic());
    let zero = case(
        200,
        &[
            ("cache-control", "max-age=0"),
            ("last-modified", &date(-100_000)),
        ],
    )
    .stored();
    assert_eq!(zero.freshness_lifetime(), 0);
}

#[test]
fn r_4_2_2_status_heuristic_only_for_cacheable_statuses_or_public() {
    let lm = date(-100_000);
    assert_eq!(
        case(299, &[("last-modified", &lm), ("cache-control", "public")])
            .stored()
            .freshness_lifetime(),
        10_000
    );
    assert_eq!(
        case(299, &[("last-modified", &lm)]).policy(),
        Err(NotStorable::NoPermission)
    );
    let private_unknown =
        case(299, &[("last-modified", &lm), ("cache-control", "private")]).stored();
    assert_eq!(private_unknown.freshness_lifetime(), 0);
    for status in [302, 303, 307] {
        let policy = case(
            status,
            &[("last-modified", &lm), ("cache-control", "private")],
        )
        .stored();
        assert_eq!(policy.freshness_lifetime(), 0, "{status}");
    }
}

#[test]
fn r_4_2_2_fraction_of_interval() {
    let policy = case(200, &[("date", &date(0)), ("last-modified", &date(-1000))]).stored();
    assert_eq!(policy.freshness_lifetime(), 100);
    let config = CacheConfig {
        heuristic: http_cache_rules::Heuristic {
            percent: 10,
            max: Some(50),
        },
        ..CacheConfig::default()
    };
    let capped = case(200, &[("date", &date(0)), ("last-modified", &date(-1000))]);
    assert_eq!(
        StoredPolicy::new(&config, &capped.exchange())
            .unwrap()
            .freshness_lifetime(),
        50
    );
    let no_last_modified = case(200, &[]).stored();
    assert_eq!(no_last_modified.freshness_lifetime(), 0);
}

#[test]
fn r_4_2_3_age_uses_date_age_and_transit_time() {
    let mut transit = case(
        200,
        &[
            ("cache-control", "max-age=3600"),
            ("date", &date(-30)),
            ("age", "5"),
        ],
    );
    transit.request_time = T0 - 10;
    let policy = transit.stored();
    // apparent_age 30, corrected_age_value 5 + 10; resident 100.
    assert_eq!(policy.current_age(at(T0 + 100)), 130);
}

#[test]
fn r_4_2_3_old_date_without_age_makes_the_response_stale() {
    let policy = case(
        200,
        &[("cache-control", "max-age=1800"), ("date", &date(-3600))],
    )
    .stored();
    assert_eq!(policy.current_age(at(T0)), 3600);
    assert_eq!(evaluate(&policy, &[], T0), Some(Reuse::Validate));
}

#[test]
fn r_4_2_4_no_stale_reuse_with_no_cache_or_must_revalidate() {
    for directives in ["max-age=1, must-revalidate", "max-age=1, no-cache"] {
        let policy = case(200, &[("cache-control", directives)]).stored();
        assert_eq!(
            evaluate(&policy, &[("cache-control", "max-stale")], T0 + 10),
            Some(Reuse::Validate)
        );
    }
    let policy = case(
        200,
        &[(
            "cache-control",
            "max-age=1, stale-while-revalidate=60, must-revalidate",
        )],
    )
    .stored();
    assert_eq!(evaluate(&policy, &[], T0 + 10), Some(Reuse::Validate));
}

#[test]
fn r_4_2_4_no_stale_reuse_without_permission() {
    let policy = case(200, &[("cache-control", "max-age=1")]).stored();
    assert_eq!(evaluate(&policy, &[], T0 + 10), Some(Reuse::Validate));
}

#[test]
fn r_4_3_1_etag_is_sent_verbatim() {
    let policy = case(
        200,
        &[("cache-control", "max-age=0"), ("etag", "W/\"x y\"")],
    )
    .stored();
    let fields = policy.validation_fields();
    assert_eq!(
        fields,
        [(
            http::header::IF_NONE_MATCH,
            HeaderValue::from_static("W/\"x y\"")
        )]
    );
}

#[test]
fn r_4_3_1_lm_is_sent_in_if_modified_since() {
    let lm = date(-100);
    let policy = case(
        200,
        &[
            ("cache-control", "max-age=0"),
            ("etag", "\"e\""),
            ("last-modified", &lm),
        ],
    )
    .stored();
    let fields = policy.validation_fields();
    assert_eq!(fields.len(), 2);
    assert_eq!(
        fields[1],
        (
            http::header::IF_MODIFIED_SINCE,
            HeaderValue::from_str(&lm).unwrap()
        )
    );
}

#[test]
fn r_4_3_3_not_modified_makes_the_stored_response_reusable() {
    let original = case(200, &[("cache-control", "max-age=10"), ("etag", "\"e\"")]);
    let policy = original.stored();
    assert_eq!(evaluate(&policy, &[], T0 + 20), Some(Reuse::Validate));
    let answer = not_modified(&[("etag", "\"e\""), ("date", &date(20))], T0 + 20);
    let freshened = policy
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    let renewed = freshened.policy.unwrap();
    assert_eq!(renewed.current_age(at(T0 + 20)), 0);
    assert_eq!(evaluate(&renewed, &[], T0 + 25), Some(Reuse::Fresh));
    assert_eq!(evaluate(&renewed, &[], T0 + 30), Some(Reuse::Validate));
}

#[test]
fn r_4_3_3_only_a_304_freshens() {
    let original = case(200, &[("cache-control", "max-age=10"), ("etag", "\"e\"")]);
    let answer = case(200, &[("etag", "\"e\"")]);
    assert_eq!(
        original
            .stored()
            .freshen(
                &CacheConfig::default(),
                &original.stored_fields(),
                &answer.exchange()
            )
            .unwrap_err(),
        FreshenError::NotNotModified
    );
}

#[test]
fn r_4_3_4_strong_validator_mismatch_does_not_update() {
    let original = case(200, &[("cache-control", "max-age=0"), ("etag", "\"a\"")]);
    let answer = not_modified(&[("etag", "\"b\"")], T0 + 1);
    let result = original.stored().freshen(
        &CacheConfig::default(),
        &original.stored_fields(),
        &answer.exchange(),
    );
    assert_eq!(result.unwrap_err(), FreshenError::ValidatorMismatch);
    let weak_stored = case(200, &[("cache-control", "max-age=0"), ("etag", "W/\"a\"")]);
    let strong_answer = not_modified(&[("etag", "\"a\"")], T0 + 1);
    let result = weak_stored.stored().freshen(
        &CacheConfig::default(),
        &weak_stored.stored_fields(),
        &strong_answer.exchange(),
    );
    assert_eq!(result.unwrap_err(), FreshenError::ValidatorMismatch);
}

#[test]
fn r_4_3_4_strong_validator_match_updates() {
    let original = case(200, &[("cache-control", "max-age=0"), ("etag", "\"a\"")]);
    let answer = not_modified(
        &[("etag", "\"a\""), ("cache-control", "max-age=60")],
        T0 + 1,
    );
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    assert_eq!(freshened.policy.unwrap().freshness_lifetime(), 60);
}

#[test]
fn r_4_3_4_update_keeps_every_value_of_fields_the_304_omits() {
    let original = case(
        200,
        &[
            ("cache-control", "max-age=0"),
            ("etag", "\"x\""),
            ("content-security-policy", "script-src 'self'"),
            ("content-security-policy", "object-src 'none'"),
        ],
    );
    let answer = not_modified(
        &[("etag", "\"x\""), ("cache-control", "max-age=60")],
        T0 + 1,
    );
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    let csp: Vec<_> = freshened
        .headers
        .get_all("content-security-policy")
        .iter()
        .collect();
    assert_eq!(csp, ["script-src 'self'", "object-src 'none'"]);
    assert_eq!(
        freshened
            .headers
            .get_all("cache-control")
            .iter()
            .collect::<Vec<_>>(),
        ["max-age=60"]
    );
}

#[test]
fn r_4_3_4_update_no_store_in_304_ends_storage() {
    let original = case(200, &[("cache-control", "max-age=0"), ("etag", "\"x\"")]);
    let answer = not_modified(&[("etag", "\"x\""), ("cache-control", "no-store")], T0 + 1);
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    assert_eq!(freshened.policy.unwrap_err(), NotStorable::ResponseNoStore);
}

#[test]
fn r_4_4_unsafe_methods_invalidate_on_success() {
    for method in [
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::from_bytes(b"FOO").unwrap(),
    ] {
        assert!(invalidates(&method, 200), "{method}");
        assert!(invalidates(&method, 302), "{method}");
        assert!(!invalidates(&method, 404), "{method}");
        assert!(!invalidates(&method, 500), "{method}");
    }
    for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
        assert!(!invalidates(&method, 200), "{method}");
    }
    let response = headers(&[("location", "/a"), ("content-location", "/b"), ("x", "c")]);
    assert_eq!(invalidation_candidates(&response), [&b"/a"[..], b"/b"]);
}

#[test]
fn r_5_1_age_first_member_and_invalid_ignored() {
    let list = case(200, &[("cache-control", "max-age=3600"), ("age", "100, 5")]).stored();
    assert_eq!(list.current_age(at(T0)), 100);
    let invalid = case(200, &[("cache-control", "max-age=3600"), ("age", "-1")]).stored();
    assert_eq!(invalid.current_age(at(T0)), 0);
}

#[test]
fn r_5_2_case_insensitive_directives() {
    let policy = case(200, &[("cache-control", "Max-Age=60, NO-CACHE")]).stored();
    assert_eq!(policy.freshness_lifetime(), 60);
    assert_eq!(evaluate(&policy, &[], T0), Some(Reuse::Validate));
    assert_eq!(
        case(200, &[("cache-control", "No-Store")]).policy(),
        Err(NotStorable::ResponseNoStore)
    );
}

#[test]
fn r_5_2_forms_token_and_quoted_string() {
    assert_eq!(
        case(200, &[("cache-control", "max-age=\"60\"")])
            .stored()
            .freshness_lifetime(),
        60
    );
    let quoted_comma = case(
        200,
        &[("cache-control", "no-cache=\"set-cookie, x\", max-age=60")],
    )
    .stored();
    assert_eq!(quoted_comma.freshness_lifetime(), 60);
    assert_eq!(evaluate(&quoted_comma, &[], T0), Some(Reuse::Validate));
}

#[test]
fn r_5_2_2_5_no_store_in_a_malformed_element_still_prevents_storage() {
    for value in [
        "no-cache no-store",
        "no-store; max-age=0",
        "max-age=0 no-store",
        "private, no-store=",
    ] {
        let response = case(
            200,
            &[("cache-control", value), ("last-modified", &date(-100_000))],
        );
        assert_eq!(
            response.policy(),
            Err(NotStorable::ResponseNoStore),
            "{value}"
        );
    }
}

#[test]
fn r_5_2_3_unknown_directives_are_ignored() {
    let policy = case(
        200,
        &[("cache-control", "community=\"UCI\", max-age=60, x-y")],
    )
    .stored();
    assert_eq!(evaluate(&policy, &[], T0), Some(Reuse::Fresh));
}

#[test]
fn r_5_2_1_1_request_max_age() {
    let policy = case(200, &[("cache-control", "max-age=3600")]).stored();
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-age=100")], T0 + 100),
        Some(Reuse::Fresh)
    );
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-age=100")], T0 + 101),
        Some(Reuse::Validate)
    );
}

#[test]
fn r_5_2_1_2_request_max_stale() {
    let policy = case(200, &[("cache-control", "max-age=10")]).stored();
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-stale=5")], T0 + 15),
        Some(Reuse::StaleAllowed)
    );
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-stale=5")], T0 + 16),
        Some(Reuse::Validate)
    );
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-stale")], T0 + 100_000),
        Some(Reuse::StaleAllowed)
    );
}

#[test]
fn r_5_2_1_3_request_min_fresh() {
    let policy = case(200, &[("cache-control", "max-age=100")]).stored();
    assert_eq!(
        evaluate(&policy, &[("cache-control", "min-fresh=50")], T0 + 50),
        Some(Reuse::Fresh)
    );
    assert_eq!(
        evaluate(&policy, &[("cache-control", "min-fresh=50")], T0 + 51),
        Some(Reuse::Validate)
    );
}

#[test]
fn r_5_2_1_4_request_no_cache() {
    let policy = case(200, &[("cache-control", "max-age=3600")]).stored();
    assert_eq!(
        evaluate(&policy, &[("cache-control", "no-cache")], T0),
        Some(Reuse::Validate)
    );
}

#[test]
fn r_5_2_1_5_request_no_store_is_not_stored() {
    let policy = case(200, &[("cache-control", "max-age=3600")])
        .request(&[("cache-control", "no-store")])
        .policy();
    assert_eq!(policy, Err(NotStorable::RequestNoStore));
}

#[test]
fn r_5_2_1_7_only_if_cached_is_recognized() {
    assert!(
        RequestDirectives::from_headers(&headers(&[("cache-control", "only-if-cached")]))
            .only_if_cached
    );
}

#[test]
fn r_5_2_2_1_response_max_age() {
    let policy = case(200, &[("cache-control", "max-age=5")]).stored();
    assert_eq!(evaluate(&policy, &[], T0 + 4), Some(Reuse::Fresh));
    assert_eq!(evaluate(&policy, &[], T0 + 5), Some(Reuse::Validate));
}

#[test]
fn r_5_2_2_2_must_revalidate() {
    let policy = case(200, &[("cache-control", "max-age=5, must-revalidate")]).stored();
    assert_eq!(evaluate(&policy, &[], T0 + 4), Some(Reuse::Fresh));
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-stale=1000")], T0 + 6),
        Some(Reuse::Validate)
    );
}

#[test]
fn r_5_2_2_3_must_understand_overrides_no_store_for_understood_statuses() {
    let understood = case(
        200,
        &[("cache-control", "max-age=60, must-understand, no-store")],
    );
    assert!(understood.policy().is_ok());
    let unknown = case(
        299,
        &[("cache-control", "max-age=60, must-understand, no-store")],
    );
    assert_eq!(unknown.policy(), Err(NotStorable::MustUnderstand));
    let unknown_without_no_store = case(299, &[("cache-control", "max-age=60, must-understand")]);
    assert_eq!(
        unknown_without_no_store.policy(),
        Err(NotStorable::MustUnderstand)
    );
}

#[test]
fn r_5_2_2_3_must_understand_with_partial_content() {
    let config = CacheConfig {
        partial_content: true,
        ..CacheConfig::default()
    };
    let partial = case(
        206,
        &[
            ("cache-control", "max-age=60, must-understand, no-store"),
            ("content-range", "bytes 0-4/10"),
        ],
    );
    assert!(StoredPolicy::new(&config, &partial.exchange()).is_ok());
    assert_eq!(partial.policy(), Err(NotStorable::PartialContent));
}

#[test]
fn r_5_2_2_4_no_cache_is_stored_but_validated() {
    let policy = case(200, &[("cache-control", "no-cache"), ("etag", "\"e\"")]).stored();
    assert_eq!(evaluate(&policy, &[], T0), Some(Reuse::Validate));
    assert!(!policy.validation_fields().is_empty());
}

#[test]
fn r_5_2_2_5_no_store_is_not_stored() {
    assert_eq!(
        case(
            200,
            &[
                ("cache-control", "max-age=10000, no-store"),
                ("expires", &date(10_000))
            ]
        )
        .policy(),
        Err(NotStorable::ResponseNoStore)
    );
}

#[test]
fn r_5_2_2_7_private_responses_are_stored_by_a_private_cache() {
    assert!(case(302, &[("cache-control", "private")]).policy().is_ok());
    assert!(
        case(200, &[("cache-control", "private, max-age=60")])
            .request(&[("authorization", "x")])
            .policy()
            .is_ok()
    );
}

#[test]
fn r_5_2_2_9_public_makes_unknown_statuses_heuristically_cacheable() {
    let policy = case(
        299,
        &[("cache-control", "public"), ("last-modified", &date(-1000))],
    )
    .stored();
    assert_eq!(policy.freshness_lifetime(), 100);
}

#[test]
fn r_5_2_2_10_s_maxage_is_ignored() {
    let policy = case(200, &[("cache-control", "max-age=1, s-maxage=3600")]).stored();
    assert_eq!(policy.freshness_lifetime(), 1);
}

#[test]
fn r_5_3_invalid_expires_is_in_the_past() {
    for value in ["0", "-1", "tomorrow", "Sun, 06 Nov 1994 08:49:37"] {
        let policy = case(
            200,
            &[("expires", value), ("last-modified", &date(-100_000))],
        )
        .stored();
        assert_eq!(policy.freshness_lifetime(), 0, "{value}");
        assert!(!policy.is_heuristic());
    }
}

#[test]
fn r_5_3_max_age_ignores_expires() {
    let policy = case(200, &[("cache-control", "max-age=3600"), ("expires", "0")]).stored();
    assert_eq!(policy.freshness_lifetime(), 3600);
}

// --- RFC 9110 ----------------------------------------------------------------------

#[test]
fn r_9110_5_6_7_formats_all_three_are_accepted() {
    let expected = Some(784_111_777);
    assert_eq!(
        parse_http_date(b"Sun, 06 Nov 1994 08:49:37 GMT", T0),
        expected
    );
    assert_eq!(
        parse_http_date(b"Sunday, 06-Nov-94 08:49:37 GMT", T0),
        expected
    );
    assert_eq!(parse_http_date(b"Sun Nov  6 08:49:37 1994", T0), expected);
    let rfc850 = case(200, &[("expires", "Thursday, 01-Jan-37 00:00:00 GMT")]).stored();
    assert!(rfc850.freshness_lifetime() > 0);
}

/// Spellings outside the three formats are invalid, which every caller treats
/// conservatively: `Expires` as already expired (§5.3), `Date` as absent, and
/// `Last-Modified` as absent (no heuristic).
#[test]
fn r_9110_5_6_7_formats_other_spellings_are_invalid() {
    for value in [
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Sun, 06-Nov-1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 08:49:37 UTC",
        "Sun, 06 Nov 1994 08:49:37 +0000",
        "06 Nov 1994 08:49:37 GMT",
    ] {
        assert_eq!(parse_http_date(value.as_bytes(), T0), None, "{value}");
        let policy = case(200, &[("expires", value), ("last-modified", value)]).stored();
        assert_eq!(policy.freshness_lifetime(), 0, "{value}");
    }
}

#[test]
fn r_9110_5_6_7_year_never_more_than_50_years_ahead() {
    // T0 is in 2025: "75" is 2075, "76" is 1976.
    assert_eq!(
        parse_http_date(b"Thursday, 01-Jan-75 00:00:00 GMT", T0),
        Some(3_313_526_400)
    );
    assert_eq!(
        parse_http_date(b"Thursday, 01-Jan-76 00:00:00 GMT", T0),
        Some(189_302_400)
    );
}

#[test]
fn r_9110_5_6_7_generate_imf_fixdate() {
    assert_eq!(
        format_http_date(784_111_777),
        "Sun, 06 Nov 1994 08:49:37 GMT"
    );
}

#[test]
fn r_9110_6_6_1_date_is_added_when_missing() {
    let mut original = case(200, &[("cache-control", "max-age=60")]);
    original.response_time = 784_111_777;
    assert_eq!(
        original.stored_fields()["date"],
        "Sun, 06 Nov 1994 08:49:37 GMT"
    );
}

#[test]
fn r_9110_6_6_1_date_is_added_to_a_304_without_one() {
    let original = case(
        200,
        &[
            ("cache-control", "max-age=60"),
            ("etag", "\"e\""),
            ("date", &date(0)),
        ],
    );
    let answer = not_modified(&[("etag", "\"e\"")], 784_111_777);
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    assert_eq!(freshened.headers["date"], "Sun, 06 Nov 1994 08:49:37 GMT");
    assert_eq!(freshened.policy.unwrap().date(), 784_111_777);
}

#[test]
fn r_9110_8_8_3_2_comparison_table() {
    let tag = |value: &'static str| EntityTag::parse(value.as_bytes()).unwrap();
    assert!(!tag("W/\"1\"").strong_eq(&tag("W/\"1\"")));
    assert!(tag("W/\"1\"").weak_eq(&tag("W/\"1\"")));
    assert!(!tag("W/\"1\"").weak_eq(&tag("W/\"2\"")));
    assert!(!tag("W/\"1\"").strong_eq(&tag("\"1\"")));
    assert!(tag("W/\"1\"").weak_eq(&tag("\"1\"")));
    assert!(tag("\"1\"").strong_eq(&tag("\"1\"")));
}

#[test]
fn r_9110_15_1_heuristically_cacheable_statuses() {
    let lm = date(-1000);
    for status in [200, 203, 204, 300, 301, 308, 404, 405, 410, 414, 501] {
        assert_eq!(
            case(status, &[("last-modified", &lm)])
                .stored()
                .freshness_lifetime(),
            100,
            "{status}"
        );
    }
    for status in [201, 202, 302, 303, 307, 403, 500, 502, 503, 504] {
        assert_eq!(
            case(status, &[("last-modified", &lm)]).policy(),
            Err(NotStorable::NoPermission),
            "{status}"
        );
    }
}

// --- RFC 5861 ----------------------------------------------------------------------

#[test]
fn r_5861_3_stale_while_revalidate_window() {
    let policy = case(
        200,
        &[("cache-control", "max-age=600, stale-while-revalidate=30")],
    )
    .stored();
    assert_eq!(evaluate(&policy, &[], T0 + 599), Some(Reuse::Fresh));
    assert_eq!(
        evaluate(&policy, &[], T0 + 600),
        Some(Reuse::StaleWhileRevalidate)
    );
    assert_eq!(
        evaluate(&policy, &[], T0 + 629),
        Some(Reuse::StaleWhileRevalidate)
    );
    assert_eq!(evaluate(&policy, &[], T0 + 630), Some(Reuse::Validate));
    assert_eq!(
        evaluate(&policy, &[("cache-control", "no-cache")], T0 + 610),
        Some(Reuse::Validate)
    );
}

#[test]
fn r_5861_4_stale_if_error_is_exposed() {
    let policy = case(
        200,
        &[("cache-control", "max-age=600, stale-if-error=1200")],
    )
    .stored();
    assert_eq!(policy.stale_if_error(), Some(1200));
}

// --- Fetch -------------------------------------------------------------------------

#[test]
fn f_definitions_fresh_stale_while_revalidate_and_stale() {
    let policy = case(
        200,
        &[("cache-control", "max-age=10, stale-while-revalidate=10")],
    )
    .stored();
    assert_eq!(evaluate(&policy, &[], T0 + 9), Some(Reuse::Fresh));
    assert_eq!(
        evaluate(&policy, &[], T0 + 19),
        Some(Reuse::StaleWhileRevalidate)
    );
    assert_eq!(evaluate(&policy, &[], T0 + 20), Some(Reuse::Validate));
}

#[test]
fn f_8_26_validators_are_sent_as_stored() {
    let policy = case(
        200,
        &[
            ("cache-control", "max-age=0"),
            ("etag", "abc"),
            ("last-modified", "garbage"),
        ],
    )
    .stored();
    let fields = policy.validation_fields();
    assert_eq!(fields[0].1, "abc");
    assert_eq!(fields[1].1, "garbage");
}

#[test]
fn f_11_4_not_modified_updates_the_stored_response() {
    let original = case(
        200,
        &[
            ("expires", &date(-5000)),
            ("etag", "abc"),
            ("test-header", "A"),
        ],
    );
    let answer = not_modified(
        &[
            ("etag", "abc"),
            ("test-header", "B"),
            ("expires", &date(3000)),
        ],
        T0 + 1,
    );
    let freshened = original
        .stored()
        .freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        )
        .unwrap();
    assert_eq!(freshened.headers["test-header"], "B");
    assert!(freshened.policy.unwrap().is_fresh(at(T0 + 4)));
}

// --- Deviations --------------------------------------------------------------------

#[test]
fn d_1_request_no_store_bypasses_stored_responses() {
    let policy = case(200, &[("cache-control", "max-age=3600")]).stored();
    assert_eq!(
        evaluate(&policy, &[("cache-control", "no-store")], T0),
        None
    );
}

#[test]
fn d_2_response_pragma_no_cache_unless_immutable() {
    let pragma = case(
        200,
        &[
            ("cache-control", "max-age=2592000, public"),
            ("pragma", "no-cache"),
        ],
    )
    .stored();
    assert_eq!(evaluate(&pragma, &[], T0), Some(Reuse::Validate));
    assert!(!pragma.is_immutable());
    let immutable = case(
        200,
        &[
            ("cache-control", "max-age=2592000, immutable"),
            ("pragma", "no-cache"),
        ],
    )
    .stored();
    assert_eq!(evaluate(&immutable, &[], T0), Some(Reuse::Fresh));
    assert!(immutable.is_immutable());
}

#[test]
fn d_3_weak_or_absent_validators_in_a_304_freshen() {
    let lm = date(-3000);
    let original = case(
        200,
        &[
            ("expires", &date(-5000)),
            ("last-modified", &lm),
            ("etag", "W/\"a\""),
        ],
    );
    for answer in [
        not_modified(&[("last-modified", &date(-2999))], T0 + 1),
        not_modified(&[("etag", "W/\"b\"")], T0 + 1),
        not_modified(&[], T0 + 1),
    ] {
        let result = original.stored().freshen(
            &CacheConfig::default(),
            &original.stored_fields(),
            &answer.exchange(),
        );
        assert!(result.is_ok());
    }
}

#[test]
fn d_4_request_max_age_zero_always_validates() {
    let policy = case(200, &[("cache-control", "max-age=3600")]).stored();
    assert_eq!(
        evaluate(&policy, &[("cache-control", "max-age=0")], T0),
        Some(Reuse::Validate)
    );
}

#[test]
fn d_5_request_pragma_no_cache_without_cache_control() {
    let policy = case(200, &[("cache-control", "max-age=3600")]).stored();
    assert_eq!(
        evaluate(&policy, &[("pragma", "no-cache")], T0),
        Some(Reuse::Validate)
    );
    assert_eq!(
        evaluate(
            &policy,
            &[("pragma", "no-cache"), ("cache-control", "max-stale")],
            T0
        ),
        Some(Reuse::Fresh)
    );
}

#[test]
fn d_6_unquoted_etags_round_trip_and_freshen() {
    let original = case(200, &[("expires", &date(-5000)), ("etag", "ABC")]);
    let policy = original.stored();
    assert_eq!(policy.validation_fields()[0].1, "ABC");
    let answer = not_modified(&[("etag", "ABC")], T0 + 1);
    assert!(
        policy
            .freshen(
                &CacheConfig::default(),
                &original.stored_fields(),
                &answer.exchange()
            )
            .is_ok()
    );
}

#[test]
fn d_7_set_cookie_is_not_stored_by_default() {
    let original = case(
        200,
        &[
            ("cache-control", "max-age=60"),
            ("set-cookie", "a=b"),
            ("set-cookie2", "c=d"),
        ],
    );
    let stored = original.stored_fields();
    assert!(!stored.contains_key("set-cookie"));
    assert!(!stored.contains_key("set-cookie2"));
    let keep = CacheConfig {
        never_store: vec![],
        ..CacheConfig::default()
    };
    assert!(StoredPolicy::stored_fields(&keep, &original.exchange()).contains_key("set-cookie"));
}
