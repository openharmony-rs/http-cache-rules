//! Property tests: the parsers against an independent implementation or a
//! reference model, and invariants of the public API over generated inputs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use http::header::{CONTENT_ENCODING, SET_COOKIE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_cache_rules::date::{MAX_FORMATTABLE, format_http_date, parse_http_date};
use http_cache_rules::directives::{DELTA_SECONDS_MAX, ResponseDirectives};
use http_cache_rules::fields::updated_fields;
use http_cache_rules::{CacheConfig, Exchange, Reuse, StoredPolicy, VaryKey};
use proptest::prelude::*;

const T0: u64 = 1_760_000_000;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn header_map(fields: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in fields {
        map.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    map
}

/// An IMF-fixdate rewritten in the RFC 850 format.
fn to_rfc850(imf: &str) -> String {
    let long_day = match &imf[0..3] {
        "Mon" => "Monday",
        "Tue" => "Tuesday",
        "Wed" => "Wednesday",
        "Thu" => "Thursday",
        "Fri" => "Friday",
        "Sat" => "Saturday",
        _ => "Sunday",
    };
    format!(
        "{long_day}, {}-{}-{} {} GMT",
        &imf[5..7],
        &imf[8..11],
        &imf[14..16],
        &imf[17..25]
    )
}

/// An IMF-fixdate rewritten in the asctime format.
fn to_asctime(imf: &str) -> String {
    let day = imf[5..7].trim_start_matches('0');
    format!(
        "{} {} {day:>2} {} {}",
        &imf[0..3],
        &imf[8..11],
        &imf[17..25],
        &imf[12..16]
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn imf_fixdate_round_trips_and_agrees_with_httpdate(time in 0..=MAX_FORMATTABLE) {
        let formatted = format_http_date(time);
        prop_assert_eq!(parse_http_date(formatted.as_bytes(), T0), Some(time));
        let oracle = httpdate::parse_http_date(&formatted).unwrap();
        prop_assert_eq!(oracle, UNIX_EPOCH + Duration::from_secs(time));
    }

    /// Two-digit years are only unambiguous where this crate's 50-year window
    /// (around T0, in 2025) and httpdate's fixed 1970..2069 window agree.
    #[test]
    fn obsolete_formats_agree_with_httpdate(time in 189_302_400u64..3_155_760_000) {
        let imf = format_http_date(time);
        for value in [to_rfc850(&imf), to_asctime(&imf)] {
            let ours = parse_http_date(value.as_bytes(), T0).map(|seconds| UNIX_EPOCH + Duration::from_secs(seconds));
            prop_assert_eq!(ours, httpdate::parse_http_date(&value).ok(), "{}", value);
        }
    }

    #[test]
    fn date_names_are_case_insensitive(time in 0..=MAX_FORMATTABLE, flips in prop::collection::vec(any::<bool>(), 29)) {
        let formatted = format_http_date(time);
        let flipped: String = formatted
            .chars()
            .zip(flips)
            .map(|(c, flip)| if flip { c.to_ascii_lowercase() } else { c.to_ascii_uppercase() })
            .collect();
        prop_assert_eq!(parse_http_date(flipped.as_bytes(), T0), Some(time));
    }

    #[test]
    fn date_parser_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..40), now in any::<u64>()) {
        if let Some(time) = parse_http_date(&bytes, now) {
            prop_assert!(time <= MAX_FORMATTABLE);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn heuristic_is_the_exact_fraction(date_value in any::<u64>(), last_modified in any::<u64>(), percent in 0u8..=100) {
        use http_cache_rules::rules::{Expires, Heuristic, LifetimeInput, freshness_lifetime};
        let input = LifetimeInput {
            max_age: None,
            expires: Expires::Absent,
            date_value,
            last_modified: Some(last_modified),
            heuristic_allowed: true,
        };
        let interval = date_value.saturating_sub(last_modified);
        let exact = (u128::from(interval) * u128::from(percent) / 100) as u64;
        prop_assert_eq!(freshness_lifetime(input, Heuristic { percent, max: None }).seconds, exact);
    }
}

// --- Cache-Control against a model ---------------------------------------------------

#[derive(Clone, Debug)]
enum Argument {
    None,
    Token(String),
    Quoted(String),
}

#[derive(Clone, Debug)]
struct ModelDirective {
    name: &'static str,
    upper: bool,
    argument: Argument,
}

const NAMES: [&str; 12] = [
    "max-age",
    "no-cache",
    "no-store",
    "must-revalidate",
    "must-understand",
    "public",
    "private",
    "immutable",
    "stale-while-revalidate",
    "stale-if-error",
    "x-ext",
    "s-maxage",
];

fn directive() -> impl Strategy<Value = ModelDirective> {
    let argument = prop_oneof![
        Just(Argument::None),
        "[0-9]{1,12}".prop_map(Argument::Token),
        "[a-z0-9!#$%&'*+.^_`|~-]{1,6}".prop_map(Argument::Token),
        "[ a-z0-9,=;\"\\\\]{0,8}".prop_map(Argument::Quoted),
    ];
    (prop::sample::select(&NAMES[..]), any::<bool>(), argument).prop_map(
        |(name, upper, argument)| ModelDirective {
            name,
            upper,
            argument,
        },
    )
}

fn render(directive: &ModelDirective) -> String {
    let name = if directive.upper {
        directive.name.to_ascii_uppercase()
    } else {
        directive.name.to_owned()
    };
    match &directive.argument {
        Argument::None => name,
        Argument::Token(token) => format!("{name}={token}"),
        Argument::Quoted(text) => {
            let escaped: String = text
                .chars()
                .flat_map(|c| {
                    if c == '"' || c == '\\' {
                        vec!['\\', c]
                    } else {
                        vec![c]
                    }
                })
                .collect();
            format!("{name}=\"{escaped}\"")
        },
    }
}

fn argument_text(argument: &Argument) -> Option<&str> {
    match argument {
        Argument::None => None,
        Argument::Token(text) | Argument::Quoted(text) => Some(text),
    }
}

fn delta(text: Option<&str>) -> Option<u64> {
    let text = text?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: u128 = 0;
    for b in text.bytes() {
        value = (value * 10 + u128::from(b - b'0')).min(u128::from(DELTA_SECONDS_MAX));
    }
    Some(value as u64)
}

/// The directives the model expects: flags by presence, numeric directives
/// from their first occurrence.
fn model(directives: &[ModelDirective], pragma_no_cache: bool) -> ResponseDirectives {
    let mut expected = ResponseDirectives::default();
    let first = |name: &str| {
        directives
            .iter()
            .find(|d| d.name == name)
            .map(|d| argument_text(&d.argument))
    };
    let has = |name: &str| directives.iter().any(|d| d.name == name);
    expected.max_age = first("max-age").map(|argument| delta(argument).unwrap_or(0));
    expected.stale_while_revalidate = first("stale-while-revalidate").and_then(delta);
    expected.stale_if_error = first("stale-if-error").and_then(delta);
    expected.no_cache = has("no-cache");
    expected.no_store = has("no-store");
    expected.must_revalidate = has("must-revalidate");
    expected.must_understand = has("must-understand");
    expected.public = has("public");
    expected.private = has("private");
    expected.immutable = has("immutable");
    if pragma_no_cache && !expected.immutable {
        expected.no_cache = true;
    }
    expected
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn cache_control_parses_like_the_model(
        directives in prop::collection::vec(directive(), 0..6),
        separators in prop::collection::vec(prop::sample::select(&[",", ", ", " ,", " , ", ",,", ",\t"][..]), 6),
        split in 0usize..7,
        pragma_no_cache in any::<bool>(),
    ) {
        let rendered: Vec<String> = directives.iter().map(render).collect();
        let split = split.min(rendered.len());
        let mut lines = Vec::new();
        for part in [&rendered[..split], &rendered[split..]] {
            if part.is_empty() {
                continue;
            }
            let mut line = String::new();
            for (index, directive) in part.iter().enumerate() {
                if index > 0 {
                    line.push_str(separators[index]);
                }
                line.push_str(directive);
            }
            lines.push(("cache-control".to_owned(), line));
        }
        if pragma_no_cache {
            lines.push(("pragma".to_owned(), "no-cache".to_owned()));
        }
        let parsed = ResponseDirectives::from_headers(&header_map(&lines));
        prop_assert_eq!(parsed, model(&directives, pragma_no_cache), "{:?}", lines);
    }
}

// --- §3.2 update against a model -----------------------------------------------------

const FIELDS: [&str; 6] = [
    "x-a",
    "x-b",
    "x-c",
    "content-length",
    "content-encoding",
    "set-cookie",
];

fn fields() -> impl Strategy<Value = Vec<(String, String)>> {
    prop::collection::vec(
        (
            prop::sample::select(&FIELDS[..]).prop_map(str::to_owned),
            "[a-z0-9]{1,3}",
        ),
        0..8,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn update_matches_the_model(stored in fields(), newer in fields()) {
        let updated = updated_fields(&header_map(&stored), &header_map(&newer), &[SET_COOKIE], &[CONTENT_ENCODING]);
        for name in FIELDS {
            let values = |list: &[(String, String)]| -> Vec<String> {
                list.iter().filter(|(n, _)| n == name).map(|(_, v)| v.clone()).collect()
            };
            let excluded = matches!(name, "content-length" | "content-encoding" | "set-cookie");
            let expected = if !excluded && !values(&newer).is_empty() { values(&newer) } else { values(&stored) };
            let got: Vec<String> = updated.get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect();
            prop_assert_eq!(got, expected, "{}", name);
        }
    }
}

// --- Vary --------------------------------------------------------------------------

const REQUEST_FIELDS: [&str; 4] = ["x-a", "x-b", "x-c", "x-d"];

fn request_fields() -> impl Strategy<Value = Vec<(String, String)>> {
    prop::collection::vec(
        (
            prop::sample::select(&REQUEST_FIELDS[..]).prop_map(str::to_owned),
            "[a-z]{0,2}",
        ),
        0..6,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn vary_matches_the_original_request(request in request_fields(), nominated in prop::sample::subsequence(&REQUEST_FIELDS[..], 0..4)) {
        let response = header_map(&[("vary".to_owned(), nominated.join(", "))]);
        let request = header_map(&request);
        prop_assert!(VaryKey::capture(&response, &request).matches(&request));
    }

    #[test]
    fn vary_ignores_unnominated_fields_and_sees_nominated_ones(
        request in request_fields(),
        nominated in prop::sample::subsequence(&REQUEST_FIELDS[..], 1..4),
        changed in prop::sample::select(&REQUEST_FIELDS[..]),
        value in "[A-Z]{1,2}",
    ) {
        let response = header_map(&[("vary".to_owned(), nominated.join(", "))]);
        let key = VaryKey::capture(&response, &header_map(&request));
        let mut other: Vec<(String, String)> = request.iter().filter(|(name, _)| name != changed).cloned().collect();
        other.push((changed.to_owned(), value));
        prop_assert_eq!(key.matches(&header_map(&other)), !nominated.contains(&changed));
    }
}

// --- Public API invariants -----------------------------------------------------------

fn response_fields() -> impl Strategy<Value = Vec<(String, String)>> {
    let cache_control = prop::collection::vec(
        prop::sample::select(
            &[
                "max-age=0",
                "max-age=60",
                "max-age=3600",
                "no-cache",
                "no-store",
                "must-revalidate",
                "public",
                "private",
                "immutable",
                "stale-while-revalidate=30",
                "max-age=abc",
            ][..],
        ),
        0..4,
    )
    .prop_map(|parts| parts.join(", "));
    let offset = -100_000i64..100_000;
    (
        prop::option::of(cache_control),
        prop::option::of(offset.clone()),
        prop::option::of(offset.clone()),
        prop::option::of(offset),
        prop::option::of(0u64..5000),
        prop::option::of(prop::sample::select(&["\"e\"", "W/\"e\"", "e"][..])),
        any::<bool>(),
    )
        .prop_map(
            |(cache_control, expires, date, last_modified, age, etag, pragma)| {
                let mut fields = Vec::new();
                let date_of =
                    |offset: i64| format_http_date(T0.checked_add_signed(offset).unwrap());
                if let Some(value) = cache_control.filter(|value| !value.is_empty()) {
                    fields.push(("cache-control".to_owned(), value));
                }
                if let Some(offset) = expires {
                    fields.push(("expires".to_owned(), date_of(offset)));
                }
                if let Some(offset) = date {
                    fields.push(("date".to_owned(), date_of(offset)));
                }
                if let Some(offset) = last_modified {
                    fields.push(("last-modified".to_owned(), date_of(offset)));
                }
                if let Some(age) = age {
                    fields.push(("age".to_owned(), age.to_string()));
                }
                if let Some(etag) = etag {
                    fields.push(("etag".to_owned(), etag.to_owned()));
                }
                if pragma {
                    fields.push(("pragma".to_owned(), "no-cache".to_owned()));
                }
                fields
            },
        )
}

fn request_directive_fields() -> impl Strategy<Value = Vec<(String, String)>> {
    prop::option::of(prop::sample::select(
        &[
            "max-age=0",
            "max-age=100",
            "max-stale",
            "max-stale=50",
            "min-fresh=30",
            "no-cache",
        ][..],
    ))
    .prop_map(|value| {
        value
            .into_iter()
            .map(|v| ("cache-control".to_owned(), v.to_owned()))
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn api_invariants(
        status in prop::sample::select(&[200u16, 203, 204, 299, 301, 302, 404, 500, 599][..]),
        response in response_fields(),
        request in request_directive_fields(),
        elapsed in 0u64..200_000,
    ) {
        let config = CacheConfig::default();
        let response = header_map(&response);
        let no_request_headers = HeaderMap::new();
        let exchange = Exchange {
            method: &Method::GET,
            request_headers: &no_request_headers,
            status: StatusCode::from_u16(status).unwrap(),
            response_headers: &response,
            request_time: at(T0),
            response_time: at(T0),
        };
        let Ok(policy) = StoredPolicy::new(&config, &exchange) else {
            let directives = ResponseDirectives::from_headers(&response);
            prop_assert!(
                directives.no_store ||
                    !(directives.public || directives.private || directives.max_age.is_some() ||
                        response.contains_key("expires") || [200, 203, 204, 301, 404].contains(&status))
            );
            return Ok(());
        };
        let now = at(T0 + elapsed);
        let stored = StoredPolicy::stored_fields(&config, &exchange);
        let request = header_map(&request);
        let decision = policy.evaluate(&Method::GET, &request, now).expect("no Vary, safe method");
        if decision == Reuse::Fresh {
            prop_assert!(policy.is_fresh(now));
        }
        if matches!(decision, Reuse::StaleAllowed | Reuse::StaleWhileRevalidate) {
            prop_assert!(!policy.is_fresh(now));
        }

        let presented = policy.presented_fields(&stored, now);
        prop_assert_eq!(presented["age"].to_str().unwrap().parse::<u64>().unwrap(), policy.current_age(now).min(DELTA_SECONDS_MAX));
        for (name, value) in stored.iter().filter(|(name, _)| name.as_str() != "age") {
            prop_assert!(presented.get_all(name).iter().any(|v| v == value));
        }

        let empty = HeaderMap::new();
        let not_modified = Exchange {
            status: StatusCode::NOT_MODIFIED,
            response_headers: &empty,
            request_time: now,
            response_time: now,
            ..exchange
        };
        let freshened = policy.freshen(&config, &stored, &not_modified).expect("a 304 without validators selects");
        let mut expected = stored.clone();
        expected.remove("age");
        expected.insert("date", HeaderValue::from_str(&format_http_date(T0 + elapsed)).unwrap());
        prop_assert_eq!(&freshened.headers, &expected);
        let renewed = freshened.policy.expect("still storable");
        prop_assert_eq!(renewed.current_age(now), 0);
        if ResponseDirectives::from_headers(&response).max_age.is_some() {
            prop_assert_eq!(renewed.freshness_lifetime(), policy.freshness_lifetime());
        }
    }
}
