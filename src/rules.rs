//! The decisions of RFC 9111 as pure functions over integers and flags.
//!
//! Everything here works on whole seconds since the Unix epoch and uses
//! saturating arithmetic, so no input can overflow (§1.2.2 requires an
//! overflowing calculation to saturate rather than wrap). The parsing layers
//! reduce headers to these inputs; keeping the decisions free of strings and
//! maps lets the model checker cover every input (see `proofs.rs`).

use crate::directives::{MaxStale, RequestDirectives, ResponseDirectives};

/// The status codes RFC 9110 §15.1 defines as heuristically cacheable.
pub const HEURISTICALLY_CACHEABLE: [u16; 12] =
    [200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501];

/// Whether `status` is heuristically cacheable (RFC 9110 §15.1).
pub fn is_heuristically_cacheable(status: u16) -> bool {
    HEURISTICALLY_CACHEABLE.contains(&status)
}

/// Whether this cache "understands" `status` (§3): it is a final status that
/// RFC 9110 §15 defines and whose caching requirements this crate implements.
/// 304 is never stored, only used to freshen (§4.3.4), and 206 only when the
/// caller stores partial content (§3.3).
pub fn understands_status(status: u16, partial_content: bool) -> bool {
    match status {
        206 => partial_content,
        200..=205 | 300..=303 | 305 | 307 | 308 | 400..=417 | 421 | 422 | 426 | 500..=505 => true,
        _ => false,
    }
}

/// Why a response may not be stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NotStorable {
    /// The request method is not one the cache stores responses for.
    Method,
    /// The status is not final (1xx), or not a valid status code.
    NotFinal,
    /// A 304, which only freshens a stored response.
    NotModified,
    /// A 206, and the cache does not store partial content (§3.3).
    PartialContent,
    /// `must-understand` with a status the cache does not understand (§5.2.2.3).
    MustUnderstand,
    /// `no-store` in the response (§5.2.2.5).
    ResponseNoStore,
    /// `no-store` in the request (§5.2.1.5).
    RequestNoStore,
    /// Nothing in the response permits storing it (§3, last bullet).
    NoPermission,
}

/// The facts §3 decides storability on.
#[derive(Clone, Copy, Debug)]
pub struct StorabilityInput {
    /// Whether the request method is one this cache stores responses for (GET).
    pub method_understood: bool,
    /// The response status code.
    pub status: u16,
    /// Whether the cache stores partial content.
    pub partial_content: bool,
    /// Whether the request carried `Cache-Control: no-store`.
    pub request_no_store: bool,
    /// The response's directives.
    pub response: ResponseDirectives,
    /// Whether the response has an `Expires` field, valid or not.
    pub has_expires: bool,
}

/// Whether a private cache may store a response (§3).
///
/// The shared-cache conditions (`private`, `Authorization`) do not apply. A
/// response with `must-understand` and a status the cache understands is stored
/// despite `no-store`, as §5.2.2.3 says a cache implementing the directive
/// should.
pub fn storability(input: StorabilityInput) -> Result<(), NotStorable> {
    let StorabilityInput {
        method_understood,
        status,
        partial_content,
        request_no_store,
        response,
        has_expires,
    } = input;
    if !method_understood {
        return Err(NotStorable::Method);
    }
    if !(200..=599).contains(&status) {
        return Err(NotStorable::NotFinal);
    }
    if status == 304 {
        return Err(NotStorable::NotModified);
    }
    if status == 206 && !partial_content {
        return Err(NotStorable::PartialContent);
    }
    let understood = understands_status(status, partial_content);
    if response.must_understand && !understood {
        return Err(NotStorable::MustUnderstand);
    }
    if response.no_store && !(response.must_understand && understood) {
        return Err(NotStorable::ResponseNoStore);
    }
    if request_no_store {
        return Err(NotStorable::RequestNoStore);
    }
    if response.public
        || response.private
        || has_expires
        || response.max_age.is_some()
        || is_heuristically_cacheable(status)
    {
        return Ok(());
    }
    Err(NotStorable::NoPermission)
}

/// The `Expires` field of a response, as far as freshness is concerned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Expires {
    /// No `Expires` field.
    Absent,
    /// A valid `Expires` time.
    At(u64),
    /// An `Expires` field that is not a valid HTTP-date; §5.3: "A cache
    /// recipient MUST interpret invalid date formats, especially the value "0",
    /// as representing a time in the past".
    Invalid,
}

/// Tuning of the heuristic freshness lifetime (§4.2.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Heuristic {
    /// The fraction of the time since `Last-Modified` used as the lifetime, in
    /// percent. §4.2.2: "A typical setting of this fraction might be 10%".
    pub percent: u8,
    /// An upper bound on the heuristic lifetime, if any.
    pub max: Option<u64>,
}

/// The facts §4.2.1 and §4.2.2 compute a freshness lifetime from.
#[derive(Clone, Copy, Debug)]
pub struct LifetimeInput {
    /// The response's `max-age` directive.
    pub max_age: Option<u64>,
    /// The response's `Expires` field.
    pub expires: Expires,
    /// The `date_value` of §4.2.3: the `Date` field, or the time the response
    /// was received when there is no valid one (RFC 9110 §6.6.1).
    pub date_value: u64,
    /// The `Last-Modified` time, if valid.
    pub last_modified: Option<u64>,
    /// Whether a heuristic lifetime may be used at all (§4.2.2): the status is
    /// heuristically cacheable or the response has `public`.
    pub heuristic_allowed: bool,
}

/// A freshness lifetime and whether it was computed heuristically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lifetime {
    /// The lifetime in seconds.
    pub seconds: u64,
    /// Whether it is a heuristic lifetime (§4.2.2).
    pub heuristic: bool,
}

/// The freshness lifetime of a response (§4.2.1), first match of: `max-age`,
/// then `Expires` minus `date_value`, then a heuristic. `s-maxage` only applies
/// to shared caches.
///
/// The heuristic (§4.2.2) is used only without an explicit expiration time, and
/// only when allowed: `heuristic.percent` of the time between `Last-Modified` and
/// `date_value`, capped by `heuristic.max`. Without `Last-Modified` it is 0.
/// (Chromium also treats permanent redirects without caching headers as fresh
/// indefinitely; this crate does not.)
pub fn freshness_lifetime(input: LifetimeInput, heuristic: Heuristic) -> Lifetime {
    let explicit = |seconds| Lifetime {
        seconds,
        heuristic: false,
    };
    if let Some(max_age) = input.max_age {
        return explicit(max_age);
    }
    match input.expires {
        Expires::At(expires) => return explicit(expires.saturating_sub(input.date_value)),
        Expires::Invalid => return explicit(0),
        Expires::Absent => {},
    }
    if !input.heuristic_allowed {
        return explicit(0);
    }
    let Some(last_modified) = input.last_modified else {
        return explicit(0);
    };
    let since_modified = input.date_value.saturating_sub(last_modified);
    let percent = u64::from(heuristic.percent.min(100));
    let mut seconds = since_modified / 100 * percent + since_modified % 100 * percent / 100;
    if let Some(max) = heuristic.max {
        seconds = seconds.min(max);
    }
    Lifetime {
        seconds,
        heuristic: true,
    }
}

/// The inputs of the age calculation of §4.2.3, in seconds since the epoch.
#[derive(Clone, Copy, Debug)]
pub struct AgeInput {
    /// The `Age` field value, or 0.
    pub age_value: u64,
    /// The `Date` field value, or the response time.
    pub date_value: u64,
    /// When the request that resulted in the stored response was sent.
    pub request_time: u64,
    /// When the response was received.
    pub response_time: u64,
}

/// `current_age` per §4.2.3, using the conservative
/// `corrected_initial_age = max(apparent_age, corrected_age_value)`.
///
/// A clock that moved backwards makes the affected terms 0 rather than negative.
pub fn current_age(input: AgeInput, now: u64) -> u64 {
    let apparent_age = input.response_time.saturating_sub(input.date_value);
    let response_delay = input.response_time.saturating_sub(input.request_time);
    let corrected_age_value = input.age_value.saturating_add(response_delay);
    let corrected_initial_age = apparent_age.max(corrected_age_value);
    let resident_time = now.saturating_sub(input.response_time);
    corrected_initial_age.saturating_add(resident_time)
}

/// What a cache may do with a stored response for a request it matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum Reuse {
    /// Fresh: use it without contacting the server.
    Fresh,
    /// Stale, but the request's `max-stale` accepts it: use it as it is.
    StaleAllowed,
    /// Stale within its `stale-while-revalidate` window (RFC 5861 §3): use it,
    /// and revalidate in the background. Fetch's "stale-while-revalidate
    /// response".
    StaleWhileRevalidate,
    /// It may only be used after successful validation (§4.3).
    Validate,
}

/// The facts the reuse decision depends on, besides the request matching.
#[derive(Clone, Copy, Debug)]
pub struct ReuseInput {
    /// The stored response's freshness lifetime.
    pub lifetime: u64,
    /// The stored response's `current_age`.
    pub current_age: u64,
    /// `no-cache` in the stored response.
    pub no_cache: bool,
    /// `must-revalidate` in the stored response.
    pub must_revalidate: bool,
    /// `stale-while-revalidate` in the stored response.
    pub stale_while_revalidate: Option<u64>,
    /// The presented request's directives.
    pub request: RequestDirectives,
}

/// Whether a stored response that matches the request may be used, and how
/// (§4, §4.2.4, §5.2, RFC 5861).
///
/// - `no-cache` in the response (§5.2.2.4) or the request (§5.2.1.4) requires
///   validation. So does a request `max-age=0`, which browsers send to force
///   revalidation and Fetch adds for the "no-cache" cache mode.
/// - A request `max-age` the current age exceeds (§5.2.1.1), or a `min-fresh`
///   the remaining freshness does not cover (§5.2.1.3), requires validation.
///   `min-fresh` asks for a fresh response, so with it a stale one is never
///   used, even if `max-stale` would accept it: "If directives conflict ..., the
///   most restrictive directive should be honored" (§4.2.1).
/// - A fresh response is used (§4.2: `freshness_lifetime > current_age`).
/// - A stale response is never used without validation when it has
///   `must-revalidate` (§5.2.2.2) or `no-cache` (§4.2.4). Otherwise the request's
///   `max-stale` (§5.2.1.2) may accept it, or the response's
///   `stale-while-revalidate` window may cover it, unless the request set
///   `max-age` or `min-fresh`, which say it does not want a stale response.
pub fn reuse(input: ReuseInput) -> Reuse {
    let ReuseInput {
        lifetime,
        current_age,
        no_cache,
        must_revalidate,
        stale_while_revalidate,
        request,
    } = input;
    if no_cache || request.no_cache || request.max_age == Some(0) {
        return Reuse::Validate;
    }
    if let Some(max_age) = request.max_age {
        if current_age > max_age {
            return Reuse::Validate;
        }
    }
    if let Some(min_fresh) = request.min_fresh {
        if lifetime <= current_age || lifetime - current_age < min_fresh {
            return Reuse::Validate;
        }
    }
    if lifetime > current_age {
        return Reuse::Fresh;
    }
    if must_revalidate {
        return Reuse::Validate;
    }
    let staleness = current_age - lifetime;
    match request.max_stale {
        Some(MaxStale::Any) => return Reuse::StaleAllowed,
        Some(MaxStale::Seconds(max_stale)) if staleness <= max_stale => return Reuse::StaleAllowed,
        _ => {},
    }
    if let Some(window) = stale_while_revalidate {
        if staleness < window && request.max_age.is_none() && request.min_fresh.is_none() {
            return Reuse::StaleWhileRevalidate;
        }
    }
    Reuse::Validate
}

/// Whether a response to `method` invalidates stored responses (§4.4): "A cache
/// MUST invalidate the target URI ... when it receives a non-error status code
/// in response to an unsafe request method (including methods whose safety is
/// unknown)". Safe methods are those of RFC 9110 §9.2.1; non-error means 2xx or
/// 3xx.
pub fn invalidates(method: &http::Method, status: u16) -> bool {
    let safe = matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS" | "TRACE");
    !safe && (200..=399).contains(&status)
}

/// The other URI references such a response invalidates (§4.4): its `Location`
/// and `Content-Location` field values, unresolved. The caller resolves them
/// against the target URI and must skip any whose origin differs from the
/// target URI's: "a cache MUST NOT trigger an invalidation under these
/// conditions if the origin ... of the URI to be invalidated differs from that
/// of the target URI".
pub fn invalidation_candidates(response_headers: &http::HeaderMap) -> Vec<&[u8]> {
    [http::header::LOCATION, http::header::CONTENT_LOCATION]
        .iter()
        .filter_map(|name| response_headers.get(name))
        .map(http::HeaderValue::as_bytes)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEN_PERCENT: Heuristic = Heuristic {
        percent: 10,
        max: None,
    };

    fn lifetime(input: LifetimeInput) -> Lifetime {
        freshness_lifetime(input, TEN_PERCENT)
    }

    fn lifetime_input() -> LifetimeInput {
        LifetimeInput {
            max_age: None,
            expires: Expires::Absent,
            date_value: 1_000_000,
            last_modified: None,
            heuristic_allowed: true,
        }
    }

    #[test]
    fn max_age_wins_over_expires() {
        let input = LifetimeInput {
            max_age: Some(60),
            expires: Expires::At(1_003_600),
            ..lifetime_input()
        };
        assert_eq!(
            lifetime(input),
            Lifetime {
                seconds: 60,
                heuristic: false
            }
        );
    }

    #[test]
    fn expires_is_relative_to_date() {
        let input = LifetimeInput {
            expires: Expires::At(1_003_600),
            ..lifetime_input()
        };
        assert_eq!(lifetime(input).seconds, 3600);
        let past = LifetimeInput {
            expires: Expires::At(999_000),
            ..lifetime_input()
        };
        assert_eq!(lifetime(past).seconds, 0);
    }

    #[test]
    fn invalid_expires_is_already_expired_and_blocks_the_heuristic() {
        let input = LifetimeInput {
            expires: Expires::Invalid,
            last_modified: Some(0),
            ..lifetime_input()
        };
        assert_eq!(
            lifetime(input),
            Lifetime {
                seconds: 0,
                heuristic: false
            }
        );
    }

    #[test]
    fn heuristic_is_ten_percent_of_time_since_last_modified() {
        let input = LifetimeInput {
            last_modified: Some(1_000_000 - 100_000),
            ..lifetime_input()
        };
        assert_eq!(
            lifetime(input),
            Lifetime {
                seconds: 10_000,
                heuristic: true
            }
        );
        let capped = freshness_lifetime(
            input,
            Heuristic {
                percent: 10,
                max: Some(3600),
            },
        );
        assert_eq!(capped.seconds, 3600);
        let not_allowed = LifetimeInput {
            heuristic_allowed: false,
            ..input
        };
        assert_eq!(lifetime(not_allowed).seconds, 0);
        let future_last_modified = LifetimeInput {
            last_modified: Some(2_000_000),
            ..input
        };
        assert_eq!(lifetime(future_last_modified).seconds, 0);
        assert_eq!(lifetime(lifetime_input()).seconds, 0);
    }

    /// Every percentage against every interval up to 20 000 s, and against
    /// intervals around every power of two: the heuristic is exactly the floor
    /// of the fraction.
    #[test]
    fn heuristic_is_exact_by_enumeration() {
        let check = |interval: u64, percent: u8| {
            let input = LifetimeInput {
                date_value: interval,
                last_modified: Some(0),
                ..lifetime_input()
            };
            let exact = (u128::from(interval) * u128::from(percent) / 100) as u64;
            let seconds = freshness_lifetime(input, Heuristic { percent, max: None }).seconds;
            assert_eq!(seconds, exact, "{interval} {percent}");
        };
        for percent in 0..=100 {
            for interval in 0..20_000 {
                check(interval, percent);
            }
            for shift in 0..64 {
                let power = 1u64 << shift;
                for interval in [
                    power - 1,
                    power,
                    power.saturating_add(1),
                    u64::MAX - power + 1,
                ] {
                    check(interval, percent);
                }
            }
        }
    }

    #[test]
    fn heuristic_does_not_overflow() {
        let input = LifetimeInput {
            date_value: u64::MAX,
            last_modified: Some(0),
            ..lifetime_input()
        };
        let result = freshness_lifetime(
            input,
            Heuristic {
                percent: 100,
                max: None,
            },
        );
        assert_eq!(result.seconds, u64::MAX);
    }

    #[test]
    fn age_follows_section_4_2_3() {
        // Received at 1000 for a request sent at 990, Date 970, Age 5.
        let input = AgeInput {
            age_value: 5,
            date_value: 970,
            request_time: 990,
            response_time: 1000,
        };
        // apparent_age 30, corrected_age_value 5 + 10 = 15, initial 30, resident 100.
        assert_eq!(current_age(input, 1100), 130);
        let with_large_age = AgeInput {
            age_value: 50,
            ..input
        };
        assert_eq!(current_age(with_large_age, 1100), 160);
    }

    #[test]
    fn age_tolerates_clocks_going_backwards() {
        let input = AgeInput {
            age_value: 0,
            date_value: 2000,
            request_time: 1100,
            response_time: 1000,
        };
        assert_eq!(current_age(input, 900), 0);
    }

    fn reuse_input() -> ReuseInput {
        ReuseInput {
            lifetime: 100,
            current_age: 10,
            no_cache: false,
            must_revalidate: false,
            stale_while_revalidate: None,
            request: RequestDirectives::default(),
        }
    }

    #[test]
    fn fresh_until_age_reaches_lifetime() {
        assert_eq!(reuse(reuse_input()), Reuse::Fresh);
        assert_eq!(
            reuse(ReuseInput {
                current_age: 99,
                ..reuse_input()
            }),
            Reuse::Fresh
        );
        assert_eq!(
            reuse(ReuseInput {
                current_age: 100,
                ..reuse_input()
            }),
            Reuse::Validate
        );
    }

    #[test]
    fn no_cache_always_validates() {
        assert_eq!(
            reuse(ReuseInput {
                no_cache: true,
                ..reuse_input()
            }),
            Reuse::Validate
        );
        let request = RequestDirectives {
            no_cache: true,
            ..Default::default()
        };
        assert_eq!(
            reuse(ReuseInput {
                request,
                ..reuse_input()
            }),
            Reuse::Validate
        );
    }

    #[test]
    fn request_max_age() {
        let request = |max_age| RequestDirectives {
            max_age: Some(max_age),
            ..Default::default()
        };
        assert_eq!(
            reuse(ReuseInput {
                request: request(10),
                ..reuse_input()
            }),
            Reuse::Fresh
        );
        assert_eq!(
            reuse(ReuseInput {
                request: request(9),
                ..reuse_input()
            }),
            Reuse::Validate
        );
        assert_eq!(
            reuse(ReuseInput {
                request: request(0),
                current_age: 0,
                ..reuse_input()
            }),
            Reuse::Validate
        );
    }

    #[test]
    fn request_min_fresh() {
        let request = |min_fresh| RequestDirectives {
            min_fresh: Some(min_fresh),
            ..Default::default()
        };
        assert_eq!(
            reuse(ReuseInput {
                request: request(90),
                ..reuse_input()
            }),
            Reuse::Fresh
        );
        assert_eq!(
            reuse(ReuseInput {
                request: request(91),
                ..reuse_input()
            }),
            Reuse::Validate
        );
    }

    #[test]
    fn min_fresh_beats_max_stale() {
        let request = RequestDirectives {
            min_fresh: Some(0),
            max_stale: Some(MaxStale::Any),
            ..Default::default()
        };
        assert_eq!(
            reuse(ReuseInput {
                current_age: 150,
                request,
                ..reuse_input()
            }),
            Reuse::Validate
        );
        assert_eq!(
            reuse(ReuseInput {
                current_age: 99,
                request,
                ..reuse_input()
            }),
            Reuse::Fresh
        );
    }

    #[test]
    fn max_stale() {
        let stale = ReuseInput {
            current_age: 150,
            ..reuse_input()
        };
        let request = |max_stale| RequestDirectives {
            max_stale: Some(max_stale),
            ..Default::default()
        };
        assert_eq!(
            reuse(ReuseInput {
                request: request(MaxStale::Any),
                ..stale
            }),
            Reuse::StaleAllowed
        );
        assert_eq!(
            reuse(ReuseInput {
                request: request(MaxStale::Seconds(50)),
                ..stale
            }),
            Reuse::StaleAllowed
        );
        assert_eq!(
            reuse(ReuseInput {
                request: request(MaxStale::Seconds(49)),
                ..stale
            }),
            Reuse::Validate
        );
        assert_eq!(
            reuse(ReuseInput {
                request: request(MaxStale::Any),
                must_revalidate: true,
                ..stale
            }),
            Reuse::Validate
        );
    }

    #[test]
    fn stale_while_revalidate_window() {
        let stale = ReuseInput {
            stale_while_revalidate: Some(30),
            ..reuse_input()
        };
        assert_eq!(
            reuse(ReuseInput {
                current_age: 129,
                ..stale
            }),
            Reuse::StaleWhileRevalidate
        );
        assert_eq!(
            reuse(ReuseInput {
                current_age: 130,
                ..stale
            }),
            Reuse::Validate
        );
        assert_eq!(
            reuse(ReuseInput {
                current_age: 110,
                must_revalidate: true,
                ..stale
            }),
            Reuse::Validate
        );
        let request = RequestDirectives {
            max_age: Some(1000),
            ..Default::default()
        };
        assert_eq!(
            reuse(ReuseInput {
                current_age: 110,
                request,
                ..stale
            }),
            Reuse::Validate
        );
    }

    fn storability_input() -> StorabilityInput {
        StorabilityInput {
            method_understood: true,
            status: 200,
            partial_content: false,
            request_no_store: false,
            response: ResponseDirectives::default(),
            has_expires: false,
        }
    }

    #[test]
    fn storability_rules() {
        assert_eq!(storability(storability_input()), Ok(()));
        assert_eq!(
            storability(StorabilityInput {
                method_understood: false,
                ..storability_input()
            }),
            Err(NotStorable::Method)
        );
        assert_eq!(
            storability(StorabilityInput {
                status: 103,
                ..storability_input()
            }),
            Err(NotStorable::NotFinal)
        );
        assert_eq!(
            storability(StorabilityInput {
                status: 304,
                ..storability_input()
            }),
            Err(NotStorable::NotModified)
        );
        assert_eq!(
            storability(StorabilityInput {
                status: 206,
                ..storability_input()
            }),
            Err(NotStorable::PartialContent)
        );
        assert_eq!(
            storability(StorabilityInput {
                status: 206,
                partial_content: true,
                ..storability_input()
            }),
            Ok(())
        );
        assert_eq!(
            storability(StorabilityInput {
                request_no_store: true,
                ..storability_input()
            }),
            Err(NotStorable::RequestNoStore)
        );
    }

    #[test]
    fn statuses_that_are_not_heuristically_cacheable_need_explicit_permission() {
        for status in [302, 303, 307, 500, 299, 599] {
            assert_eq!(
                storability(StorabilityInput {
                    status,
                    ..storability_input()
                }),
                Err(NotStorable::NoPermission),
                "{status}"
            );
            let response = ResponseDirectives {
                max_age: Some(60),
                ..Default::default()
            };
            assert_eq!(
                storability(StorabilityInput {
                    status,
                    response,
                    ..storability_input()
                }),
                Ok(())
            );
            assert_eq!(
                storability(StorabilityInput {
                    status,
                    has_expires: true,
                    ..storability_input()
                }),
                Ok(())
            );
            for response in [
                ResponseDirectives {
                    public: true,
                    ..Default::default()
                },
                ResponseDirectives {
                    private: true,
                    ..Default::default()
                },
            ] {
                assert_eq!(
                    storability(StorabilityInput {
                        status,
                        response,
                        ..storability_input()
                    }),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn no_store_and_must_understand() {
        let no_store = ResponseDirectives {
            no_store: true,
            max_age: Some(60),
            ..Default::default()
        };
        assert_eq!(
            storability(StorabilityInput {
                response: no_store,
                ..storability_input()
            }),
            Err(NotStorable::ResponseNoStore)
        );
        let must_understand = ResponseDirectives {
            must_understand: true,
            ..no_store
        };
        assert_eq!(
            storability(StorabilityInput {
                response: must_understand,
                ..storability_input()
            }),
            Ok(())
        );
        assert_eq!(
            storability(StorabilityInput {
                response: must_understand,
                status: 299,
                ..storability_input()
            }),
            Err(NotStorable::MustUnderstand)
        );
    }

    #[test]
    fn invalidation() {
        use http::Method;
        assert!(invalidates(&Method::POST, 200));
        assert!(invalidates(&Method::DELETE, 303));
        assert!(invalidates(&Method::from_bytes(b"FROB").unwrap(), 204));
        assert!(!invalidates(&Method::POST, 404));
        assert!(!invalidates(&Method::POST, 500));
        assert!(!invalidates(&Method::GET, 200));
        assert!(!invalidates(&Method::OPTIONS, 200));
    }
}
