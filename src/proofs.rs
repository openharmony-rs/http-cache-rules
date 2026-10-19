//! Model-checking harnesses, run with `cargo kani`.
//!
//! Each harness states a requirement of RFC 9111 (or RFC 9110, RFC 5861) as a
//! predicate written from the specification text, independently of the code
//! under test, and asks Kani to prove that the implementation satisfies it for
//! every possible input. Inputs are full-width integers and arbitrary flags
//! unless a harness says otherwise; byte-string inputs are bounded in length.
//! The requirement identifiers in the harness names are the ones in `SPEC.md`.

use crate::date::{MAX_FORMATTABLE, parse_http_date};
use crate::directives::{
    DELTA_SECONDS_MAX, MaxStale, RequestDirectives, ResponseDirectives, for_each_directive,
    parse_delta_seconds,
};
use crate::rules::{
    AgeInput, Expires, Heuristic, LifetimeInput, NotStorable, Reuse, ReuseInput, StorabilityInput,
    current_age, freshness_lifetime, is_heuristically_cacheable, reuse, storability,
    understands_status,
};
use crate::validators::{EntityTag, selects_for_update};

fn any_option_u64() -> Option<u64> {
    if kani::any() { Some(kani::any()) } else { None }
}

fn any_response_directives() -> ResponseDirectives {
    ResponseDirectives {
        max_age: any_option_u64(),
        no_cache: kani::any(),
        no_store: kani::any(),
        must_revalidate: kani::any(),
        must_understand: kani::any(),
        public: kani::any(),
        private: kani::any(),
        immutable: kani::any(),
        stale_while_revalidate: any_option_u64(),
        stale_if_error: any_option_u64(),
    }
}

fn any_request_directives() -> RequestDirectives {
    let max_stale = match kani::any::<u8>() % 3 {
        0 => None,
        1 => Some(MaxStale::Any),
        _ => Some(MaxStale::Seconds(kani::any())),
    };
    RequestDirectives {
        max_age: any_option_u64(),
        max_stale,
        min_fresh: any_option_u64(),
        no_cache: kani::any(),
        no_store: kani::any(),
        only_if_cached: kani::any(),
    }
}

fn any_expires() -> Expires {
    match kani::any::<u8>() % 3 {
        0 => Expires::Absent,
        1 => Expires::At(kani::any()),
        _ => Expires::Invalid,
    }
}

fn any_age_input() -> AgeInput {
    AgeInput {
        age_value: kani::any(),
        date_value: kani::any(),
        request_time: kani::any(),
        response_time: kani::any(),
    }
}

// --- §3 Storing Responses in Caches -------------------------------------------

/// R-3: the conditions of §3 under which a private cache may store a response,
/// transcribed bullet by bullet. A private cache ignores the two shared-cache
/// bullets, and this cache understands only GET.
fn rfc_9111_section_3_permits(input: &StorabilityInput) -> bool {
    let status = input.status;
    let understood = understands_status(status, input.partial_content);
    // "the request method is understood by the cache"
    input.method_understood
        // "the response status code is final"
        && (200..=599).contains(&status)
        // "if the response status code is 206 or 304, or the must-understand cache
        // directive is present: the cache understands the response status code"
        && (!(status == 206 || status == 304 || input.response.must_understand) || understood)
        // "the no-store cache directive is not present in the response", which
        // §5.2.2.3 lets must-understand override for an understood status
        && (!input.response.no_store || (input.response.must_understand && understood))
        // §5.2.1.5: "MUST NOT store any part of either this request or any response to it"
        && !input.request_no_store
        // "the response contains at least one of the following"
        && (input.response.public
            || input.response.private
            || input.has_expires
            || input.response.max_age.is_some()
            || is_heuristically_cacheable(status))
}

#[kani::proof]
fn r_3_storability_is_exactly_section_3() {
    let input = StorabilityInput {
        method_understood: kani::any(),
        status: kani::any(),
        partial_content: kani::any(),
        request_no_store: kani::any(),
        response: any_response_directives(),
        has_expires: kani::any(),
    };
    assert_eq!(
        storability(input).is_ok(),
        rfc_9111_section_3_permits(&input)
    );
}

#[kani::proof]
fn r_5_2_2_5_no_store_is_never_stored_unless_must_understand() {
    let input = StorabilityInput {
        method_understood: kani::any(),
        status: kani::any(),
        partial_content: kani::any(),
        request_no_store: kani::any(),
        response: any_response_directives(),
        has_expires: kani::any(),
    };
    if input.response.no_store && !input.response.must_understand {
        assert!(storability(input).is_err());
    }
    if input.request_no_store {
        assert!(storability(input).is_err());
    }
}

#[kani::proof]
fn r_3_final_statuses_only_and_never_not_modified() {
    let input = StorabilityInput {
        method_understood: kani::any(),
        status: kani::any(),
        partial_content: kani::any(),
        request_no_store: kani::any(),
        response: any_response_directives(),
        has_expires: kani::any(),
    };
    if input.status == 304 {
        assert!(storability(input).is_err());
    }
    if input.status < 200 {
        assert!(storability(input).is_err());
        if input.method_understood {
            assert_eq!(storability(input), Err(NotStorable::NotFinal));
        }
    }
}

// --- §4.2.1, §4.2.2 Freshness lifetime -----------------------------------------

#[kani::proof]
fn r_4_2_1_order_first_match() {
    let input = LifetimeInput {
        max_age: any_option_u64(),
        expires: any_expires(),
        date_value: kani::any(),
        last_modified: any_option_u64(),
        heuristic_allowed: kani::any(),
    };
    let heuristic = Heuristic {
        percent: kani::any(),
        max: any_option_u64(),
    };
    let lifetime = freshness_lifetime(input, heuristic);
    match (input.max_age, input.expires) {
        // "If the max-age response directive is present, use its value"; §5.3:
        // "If a response includes a Cache-Control header field with the max-age
        // directive, a recipient MUST ignore the Expires header field."
        (Some(max_age), _) => {
            assert_eq!(lifetime.seconds, max_age);
            assert!(!lifetime.heuristic);
        },
        // "If the Expires response header field is present, use its value minus
        // the value of the Date response header field"
        (None, Expires::At(expires)) => {
            assert_eq!(lifetime.seconds, expires.saturating_sub(input.date_value));
            assert!(!lifetime.heuristic);
        },
        // §5.3: invalid dates mean "already expired"
        (None, Expires::Invalid) => {
            assert_eq!(lifetime.seconds, 0);
            assert!(!lifetime.heuristic);
        },
        (None, Expires::Absent) => {},
    }
}

#[kani::proof]
fn r_4_2_2_explicit_and_status_gate_the_heuristic() {
    let input = LifetimeInput {
        max_age: any_option_u64(),
        expires: any_expires(),
        date_value: kani::any(),
        last_modified: any_option_u64(),
        heuristic_allowed: kani::any(),
    };
    let heuristic = Heuristic {
        percent: kani::any(),
        max: any_option_u64(),
    };
    let lifetime = freshness_lifetime(input, heuristic);
    if lifetime.heuristic {
        // "A cache MUST NOT use heuristics to determine freshness when an
        // explicit expiration time is present in the stored response."
        assert!(input.max_age.is_none());
        assert_eq!(input.expires, Expires::Absent);
        // "heuristics can only be used on responses ... whose status codes are
        // defined as heuristically cacheable ... and on responses ... marked as
        // explicitly cacheable"
        assert!(input.heuristic_allowed);
    }
    if !lifetime.heuristic && input.max_age.is_none() && input.expires == Expires::Absent {
        assert_eq!(lifetime.seconds, 0);
    }
}

fn heuristic_lifetime(date_value: u64, last_modified: u64, percent: u8, max: Option<u64>) -> u64 {
    let input = LifetimeInput {
        max_age: None,
        expires: Expires::Absent,
        date_value,
        last_modified: Some(last_modified),
        heuristic_allowed: true,
    };
    let lifetime = freshness_lifetime(input, Heuristic { percent, max });
    assert!(lifetime.heuristic);
    lifetime.seconds
}

/// "no more than some fraction of the interval since that time", for every
/// input: the heuristic lifetime never exceeds the interval or the cap.
#[kani::proof]
fn r_4_2_2_fraction_never_exceeds_the_interval() {
    let (date_value, last_modified): (u64, u64) = (kani::any(), kani::any());
    let percent: u8 = kani::any();
    let max = any_option_u64();
    let seconds = heuristic_lifetime(date_value, last_modified, percent, max);
    assert!(seconds <= date_value.saturating_sub(last_modified));
    if let Some(max) = max {
        assert!(seconds <= max);
    }
}

// --- §4.2.3 Age ----------------------------------------------------------------

/// The formula of §4.2.3, with negative intermediate values clamped to 0 and
/// overflow saturating (§1.2.2), computed in 128-bit arithmetic.
fn rfc_9111_current_age(input: AgeInput, now: u64) -> u64 {
    let apparent_age = (i128::from(input.response_time) - i128::from(input.date_value)).max(0);
    let response_delay = (i128::from(input.response_time) - i128::from(input.request_time)).max(0);
    let corrected_age_value = i128::from(input.age_value) + response_delay;
    let corrected_initial_age = apparent_age.max(corrected_age_value);
    let resident_time = (i128::from(now) - i128::from(input.response_time)).max(0);
    let current_age = corrected_initial_age + resident_time;
    current_age.min(i128::from(u64::MAX)) as u64
}

#[kani::proof]
fn r_4_2_3_current_age_matches_the_formula() {
    let input = any_age_input();
    let now: u64 = kani::any();
    assert_eq!(current_age(input, now), rfc_9111_current_age(input, now));
}

#[kani::proof]
fn r_4_2_3_age_never_decreases_as_time_passes() {
    let input = any_age_input();
    let earlier: u64 = kani::any();
    let later: u64 = kani::any();
    kani::assume(earlier <= later);
    assert!(current_age(input, earlier) <= current_age(input, later));
}

// --- §4, §4.2.4, §5.2 Reuse ------------------------------------------------------

fn any_reuse_input() -> ReuseInput {
    ReuseInput {
        lifetime: kani::any(),
        current_age: kani::any(),
        no_cache: kani::any(),
        must_revalidate: kani::any(),
        stale_while_revalidate: any_option_u64(),
        request: any_request_directives(),
    }
}

/// R-4-no-cache, R-5.2.1.4: a response with `no-cache`, or a request with
/// `no-cache`, is never used without validation.
#[kani::proof]
fn r_4_no_cache_is_never_reused_without_validation() {
    let input = any_reuse_input();
    if input.no_cache || input.request.no_cache {
        assert_eq!(reuse(input), Reuse::Validate);
    }
}

/// R-4.2: "response_is_fresh = (freshness_lifetime > current_age)", and only a
/// fresh response is used as fresh.
#[kani::proof]
fn r_4_2_fresh_means_lifetime_exceeds_age() {
    let input = any_reuse_input();
    if reuse(input) == Reuse::Fresh {
        assert!(input.lifetime > input.current_age);
    }
}

/// R-4.2.4: "A cache MUST NOT generate a stale response if it is prohibited by
/// an explicit in-protocol directive (e.g., by a no-cache response directive, a
/// must-revalidate response directive ...)" and "MUST NOT generate a stale
/// response unless ... doing so is explicitly permitted by the client or origin
/// server (e.g., by the max-stale request directive ..., extension directives
/// such as those defined in [RFC5861] ...)".
#[kani::proof]
fn r_4_2_4_stale_only_when_permitted() {
    let input = any_reuse_input();
    let decision = reuse(input);
    let stale = input.lifetime <= input.current_age;
    let used_without_validation = decision != Reuse::Validate;
    if stale && used_without_validation {
        assert!(!input.no_cache && !input.must_revalidate);
        let staleness = input.current_age - input.lifetime;
        let client_permits = match input.request.max_stale {
            Some(MaxStale::Any) => true,
            Some(MaxStale::Seconds(seconds)) => staleness <= seconds,
            None => false,
        };
        let origin_permits = match input.stale_while_revalidate {
            Some(window) => staleness < window,
            None => false,
        };
        assert!(client_permits || origin_permits);
        assert_eq!(
            decision,
            if client_permits {
                Reuse::StaleAllowed
            } else {
                Reuse::StaleWhileRevalidate
            }
        );
    }
    if !stale {
        assert!(decision == Reuse::Fresh || decision == Reuse::Validate);
    }
}

/// R-5.2.2.2: "once the response has become stale, a cache MUST NOT reuse that
/// response to satisfy another request until it has been successfully
/// validated by the origin".
#[kani::proof]
fn r_5_2_2_2_must_revalidate_when_stale() {
    let input = any_reuse_input();
    if input.must_revalidate && input.lifetime <= input.current_age {
        assert_eq!(reuse(input), Reuse::Validate);
    }
}

/// R-5.2.1.1, R-5.2.1.3: the request's `max-age` and `min-fresh` bound the age
/// and the remaining freshness of whatever is used without validation.
#[kani::proof]
fn r_5_2_1_1_and_5_2_1_3_request_limits_are_respected() {
    let input = any_reuse_input();
    if reuse(input) != Reuse::Validate {
        if let Some(max_age) = input.request.max_age {
            assert!(input.current_age <= max_age);
            assert!(max_age > 0);
        }
        if let Some(min_fresh) = input.request.min_fresh {
            assert!(
                u128::from(input.lifetime) >= u128::from(input.current_age) + u128::from(min_fresh)
            );
        }
    }
}

/// Completeness: a fresh response without any directive that restricts reuse is
/// used, so the cache actually caches.
#[kani::proof]
fn r_4_2_fresh_unrestricted_response_is_used() {
    let input = any_reuse_input();
    let unrestricted = !input.no_cache
        && !input.request.no_cache
        && input.request.max_age.is_none()
        && input.request.min_fresh.is_none();
    if unrestricted && input.lifetime > input.current_age {
        assert_eq!(reuse(input), Reuse::Fresh);
    }
}

// --- §1.2.2 delta-seconds --------------------------------------------------------

#[kani::proof]
#[kani::unwind(13)]
fn r_1_2_2_delta_seconds_saturate() {
    let bytes: [u8; 12] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 12);
    let value = &bytes[..len];
    let parsed = parse_delta_seconds(value);
    let all_digits = len > 0 && value.iter().all(u8::is_ascii_digit);
    assert_eq!(parsed.is_some(), all_digits);
    if let Some(parsed) = parsed {
        let mut exact: u128 = 0;
        for &byte in value {
            exact = exact * 10 + u128::from(byte - b'0');
        }
        assert_eq!(u128::from(parsed), exact.min(u128::from(DELTA_SECONDS_MAX)));
    }
}

// --- RFC 9110 §5.6.7 HTTP-date -----------------------------------------------------

/// The parser never panics on any input of up to 34 bytes, which covers every
/// length a valid date has (the longest, an RFC 850 date on a Wednesday, is 33)
/// and every length the dispatch distinguishes, and what it accepts is a time
/// the formatter can represent. Longer inputs take the RFC 850 path, whose
/// length check rejects them before indexing.
#[kani::proof]
#[kani::unwind(36)]
fn r_9110_5_6_7_formats_parser_is_total() {
    let bytes: [u8; 34] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 34);
    if let Some(time) = parse_http_date(&bytes[..len], kani::any()) {
        assert!(time <= MAX_FORMATTABLE);
    }
}

// --- RFC 9111 §5.2 Cache-Control syntax ------------------------------------------

/// The list parser never panics and only reports names made of token
/// characters, for every input of up to 4 bytes. Longer inputs are covered step
/// by step by the next proof, since the list parser only calls the element
/// parser at positions inside the line and moves to the position it returns.
#[kani::proof]
#[kani::unwind(6)]
fn r_5_2_forms_parser_is_total() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 4);
    for_each_directive(core::iter::once(&bytes[..len]), |name, _| {
        assert!(!name.is_empty());
        assert!(name.iter().all(|&byte| crate::directives::is_tchar(byte)));
    });
}

/// Parsing one element from any position of any line of up to 8 bytes never
/// panics, reports only token names, and always moves forward, so the list
/// parser terminates on every input.
#[kani::proof]
#[kani::unwind(10)]
fn r_5_2_forms_each_element_makes_progress() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let position: usize = kani::any();
    kani::assume(position < len);
    let (element, next) = crate::directives::parse_element(&bytes[..len], position);
    assert!(next > position);
    if let Some((name, _)) = element {
        assert!(!name.is_empty());
        assert!(name.iter().all(|&byte| crate::directives::is_tchar(byte)));
    }
}

// --- RFC 9110 §8.8.3.2, RFC 9111 §4.3.4 Validators -----------------------------------

fn any_tag<'a>(storage: &'a [u8; 3]) -> EntityTag<'a> {
    let len: usize = kani::any();
    kani::assume(len <= 3);
    EntityTag {
        weak: kani::any(),
        opaque: &storage[..len],
    }
}

#[kani::proof]
#[kani::unwind(5)]
fn r_9110_8_8_3_2_comparison_functions() {
    let (a_bytes, b_bytes): ([u8; 3], [u8; 3]) = (kani::any(), kani::any());
    let (a, b) = (any_tag(&a_bytes), any_tag(&b_bytes));
    // "two entity tags are equivalent if both are not weak and their opaque-tags
    // match character-by-character"
    assert_eq!(a.strong_eq(&b), !a.weak && !b.weak && a.opaque == b.opaque);
    // "two entity tags are equivalent if their opaque-tags match
    // character-by-character, regardless of either or both being tagged as weak"
    assert_eq!(a.weak_eq(&b), a.opaque == b.opaque);
    assert_eq!(a.strong_eq(&b), b.strong_eq(&a));
    assert!(!a.strong_eq(&b) || a.weak_eq(&b));
}

/// R-4.3.4: "If the new response contains one or more strong validators ...
/// If none of the initial set contains at least one of the same strong
/// validators, then the cache MUST NOT use the new response to update any
/// stored responses."
#[kani::proof]
#[kani::unwind(8)]
fn r_4_3_4_strong_validator_must_match_to_update() {
    let stored_bytes: [u8; 5] = kani::any();
    let new_bytes: [u8; 5] = kani::any();
    let (stored_len, new_len): (usize, usize) = (kani::any(), kani::any());
    kani::assume(stored_len <= 5 && new_len <= 5);
    let stored_etag = if kani::any() {
        Some(&stored_bytes[..stored_len])
    } else {
        None
    };
    if let Some(new_tag) = EntityTag::parse(&new_bytes[..new_len]) {
        if !new_tag.weak && selects_for_update(stored_etag, Some(&new_bytes[..new_len])) {
            let stored_tag = stored_etag.and_then(EntityTag::parse);
            assert!(stored_tag.is_some_and(|stored_tag| new_tag.strong_eq(&stored_tag)));
        }
    }
}
