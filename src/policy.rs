//! The state a cache keeps per stored response, and the operations on it.

use std::time::{SystemTime, UNIX_EPOCH};

use http::header::{AGE, DATE, ETAG, EXPIRES, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};

use crate::CacheConfig;
use crate::date::{format_http_date, parse_http_date};
use crate::directives::{
    DELTA_SECONDS_MAX, RequestDirectives, ResponseDirectives, parse_delta_seconds,
};
use crate::fields::{stored_fields, updated_fields};
use crate::rules::{
    AgeInput, Expires, LifetimeInput, NotStorable, Reuse, ReuseInput, StorabilityInput,
    current_age, freshness_lifetime, is_heuristically_cacheable, reuse, storability,
};
use crate::validators::selects_for_update;
use crate::vary::VaryKey;

/// The version of [`StoredPolicy`]'s serialized form. It changes whenever a
/// field is added, removed or reinterpreted, so a cache that persists policies
/// can include it in its own format version and discard entries written by
/// another version instead of misreading them.
pub const FORMAT_VERSION: u32 = 1;

/// Converts a time to whole seconds since the Unix epoch, rounding down, with
/// times before the epoch as 0.
pub fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// A request and the response it received, as a cache sees them.
#[derive(Clone, Copy, Debug)]
pub struct Exchange<'a> {
    /// The request method.
    pub method: &'a Method,
    /// The request header fields as the client presented them, before the
    /// cache added any precondition.
    pub request_headers: &'a HeaderMap,
    /// The response status.
    pub status: StatusCode,
    /// The response header fields as received.
    pub response_headers: &'a HeaderMap,
    /// When the request was sent (`request_time` of RFC 9111 §4.2.3).
    pub request_time: SystemTime,
    /// When the response was received (`response_time` of §4.2.3).
    pub response_time: SystemTime,
}

/// Why a stored response cannot be freshened by a response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FreshenError {
    /// The response is not a 304.
    NotNotModified,
    /// The 304 carries validators that do not identify the stored response
    /// (§4.3.4). It must not update it; the cache should fetch the resource
    /// again without preconditions.
    ValidatorMismatch,
}

/// The result of freshening a stored response with a 304 (RFC 9111 §4.3.4).
#[derive(Clone, Debug)]
pub struct Freshened {
    /// The stored header fields updated from the 304 (§3.2), to store. The
    /// stored `Age` is dropped, since it described the response before it was
    /// validated; an `Age` the 304 carries takes its place. To answer the
    /// request, send the stored body with the renewed policy's
    /// [`StoredPolicy::presented_fields`] of these fields.
    pub headers: HeaderMap,
    /// The policy of the updated response, or why it may no longer be stored,
    /// for example because the 304 carried `no-store`. In that case the cache
    /// serves the response this once and removes the entry.
    pub policy: Result<StoredPolicy, NotStorable>,
}

/// What a cache keeps about a stored response to decide when it may be reused.
///
/// It is computed from the request and response when the response is stored,
/// and replaced when a 304 freshens the response. It holds no header values
/// except validators: [`VaryKey`] keeps only digests of the request fields
/// `Vary` names.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StoredPolicy {
    status: u16,
    request_time: u64,
    response_time: u64,
    date_value: u64,
    age_value: u64,
    lifetime: u64,
    heuristic: bool,
    no_cache: bool,
    must_revalidate: bool,
    immutable: bool,
    stale_while_revalidate: Option<u64>,
    stale_if_error: Option<u64>,
    vary: VaryKey,
    etag: Option<Vec<u8>>,
    last_modified: Option<Vec<u8>>,
}

/// The first value of a field, for fields defined as a single value.
fn first<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a [u8]> {
    headers.get(name).map(HeaderValue::as_bytes)
}

/// `age_value` of §4.2.3 from the `Age` field. §5.1: a list-based value uses
/// its first member, and an invalid value is ignored.
fn age_value(headers: &HeaderMap) -> u64 {
    first(headers, &AGE)
        .and_then(|value| value.split(|&byte| byte == b',').next())
        .and_then(|member| parse_delta_seconds(member.trim_ascii()))
        .unwrap_or(0)
}

/// `date_value` of §4.2.3: the `Date` field, or the time the response was
/// received if it has none or an invalid one (RFC 9110 §6.6.1).
fn date_value(headers: &HeaderMap, response_time: u64) -> u64 {
    first(headers, &DATE)
        .and_then(|value| parse_http_date(value, response_time))
        .unwrap_or(response_time)
}

/// The `Expires` field: the first one counts when there are several (§4.2.1).
// TODO: Chromium, Firefox and Safari accept many invalid dates here (`UTC` for `GMT`,
// a missing comma, dashes, a one-digit hour) and reuse the response, where §5.3 makes
// it stale. Investigate parsing them as leniently, so that such sites are cached.
fn expires(headers: &HeaderMap, now: u64) -> Expires {
    match first(headers, &EXPIRES) {
        None => Expires::Absent,
        Some(value) => parse_http_date(value, now).map_or(Expires::Invalid, Expires::At),
    }
}

impl StoredPolicy {
    /// The policy for storing `exchange`, or why it may not be stored (§3).
    ///
    /// Only responses to GET are stored. A stored GET response also answers
    /// HEAD requests.
    pub fn new(config: &CacheConfig, exchange: &Exchange<'_>) -> Result<Self, NotStorable> {
        let response = ResponseDirectives::from_headers(exchange.response_headers);
        let request = RequestDirectives::from_headers(exchange.request_headers);
        let status = exchange.status.as_u16();
        storability(StorabilityInput {
            method_understood: *exchange.method == Method::GET,
            status,
            partial_content: config.partial_content,
            request_no_store: request.no_store,
            response,
            has_expires: exchange.response_headers.contains_key(EXPIRES),
        })?;
        Ok(Self::from_parts(
            config,
            status,
            exchange.request_headers,
            exchange.response_headers,
            unix_seconds(exchange.request_time),
            unix_seconds(exchange.response_time),
            age_value(exchange.response_headers),
            date_value(
                exchange.response_headers,
                unix_seconds(exchange.response_time),
            ),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        config: &CacheConfig,
        status: u16,
        request_headers: &HeaderMap,
        response_headers: &HeaderMap,
        request_time: u64,
        response_time: u64,
        age_value: u64,
        date_value: u64,
    ) -> Self {
        let response = ResponseDirectives::from_headers(response_headers);
        let lifetime = freshness_lifetime(
            LifetimeInput {
                max_age: response.max_age,
                expires: expires(response_headers, response_time),
                date_value,
                last_modified: first(response_headers, &LAST_MODIFIED)
                    .and_then(|value| parse_http_date(value, response_time)),
                heuristic_allowed: is_heuristically_cacheable(status) || response.public,
            },
            config.heuristic,
        );
        Self {
            status,
            request_time,
            response_time,
            date_value,
            age_value,
            lifetime: lifetime.seconds,
            heuristic: lifetime.heuristic,
            no_cache: response.no_cache,
            must_revalidate: response.must_revalidate,
            immutable: response.immutable,
            stale_while_revalidate: response.stale_while_revalidate,
            stale_if_error: response.stale_if_error,
            vary: VaryKey::capture(response_headers, request_headers),
            etag: first(response_headers, &ETAG).map(<[u8]>::to_vec),
            last_modified: first(response_headers, &LAST_MODIFIED).map(<[u8]>::to_vec),
        }
    }

    /// The header fields to store with the response of `exchange` (§3.1): all of
    /// them except `Connection`, the fields it lists, hop-by-hop and
    /// proxy-specific fields and `config.never_store`, with a `Date` added if
    /// the response had none.
    pub fn stored_fields(config: &CacheConfig, exchange: &Exchange<'_>) -> HeaderMap {
        stored_fields(
            exchange.response_headers,
            unix_seconds(exchange.response_time),
            &config.never_store,
        )
    }

    /// The status the response was stored with.
    pub fn status(&self) -> u16 {
        self.status
    }

    /// `current_age` of the stored response at `now` (§4.2.3).
    pub fn current_age(&self, now: SystemTime) -> u64 {
        current_age(
            AgeInput {
                age_value: self.age_value,
                date_value: self.date_value,
                request_time: self.request_time,
                response_time: self.response_time,
            },
            unix_seconds(now),
        )
    }

    /// The freshness lifetime (§4.2.1).
    pub fn freshness_lifetime(&self) -> u64 {
        self.lifetime
    }

    /// Whether the freshness lifetime is heuristic (§4.2.2).
    pub fn is_heuristic(&self) -> bool {
        self.heuristic
    }

    /// Whether the response is fresh at `now` (§4.2).
    pub fn is_fresh(&self, now: SystemTime) -> bool {
        self.lifetime > self.current_age(now)
    }

    /// The `date_value` of the response. §4 requires a cache with more than one
    /// suitable stored response to use the most recent one by this value.
    pub fn date(&self) -> u64 {
        self.date_value
    }

    /// The `stale-if-error` window of the response, if any (RFC 5861 §4).
    pub fn stale_if_error(&self) -> Option<u64> {
        self.stale_if_error
    }

    /// Whether the response has `immutable` (RFC 8246).
    pub fn is_immutable(&self) -> bool {
        self.immutable
    }

    /// The secondary key from the response's `Vary`.
    pub fn vary(&self) -> &VaryKey {
        &self.vary
    }

    /// The heap memory the policy owns, in bytes, for memory reporting.
    pub fn heap_size(&self) -> usize {
        self.vary.heap_size()
            + self.etag.as_ref().map_or(0, Vec::capacity)
            + self.last_modified.as_ref().map_or(0, Vec::capacity)
    }

    /// Whether the stored response may be used for a request with `method` and
    /// `request_headers` at `now`, and how (§4).
    ///
    /// Returns `None` when it cannot be used for this request at all, and the
    /// request goes to the origin without preconditions:
    /// - the method is neither GET nor HEAD (a cache writes unsafe methods
    ///   through to the origin, §4);
    /// - the request fields `Vary` nominates do not match (§4.1);
    /// - the request has `Cache-Control: no-store`. §5.2.1.5 only forbids storing
    ///   in that case, but browsers also bypass stored responses, and the
    ///   web-platform-tests (`fetch/http-cache/cc-request.any.js`) require it.
    ///
    /// The target URI is the caller's primary key and not checked here.
    pub fn evaluate(
        &self,
        method: &Method,
        request_headers: &HeaderMap,
        now: SystemTime,
    ) -> Option<Reuse> {
        if *method != Method::GET && *method != Method::HEAD {
            return None;
        }
        if !self.vary.matches(request_headers) {
            return None;
        }
        let request = RequestDirectives::from_headers(request_headers);
        if request.no_store {
            return None;
        }
        Some(reuse(ReuseInput {
            lifetime: self.lifetime,
            current_age: self.current_age(now),
            no_cache: self.no_cache,
            must_revalidate: self.must_revalidate,
            stale_while_revalidate: self.stale_while_revalidate,
            request,
        }))
    }

    /// The precondition fields to add to a request that validates the stored
    /// response (RFC 9111 §4.3.1, Fetch "HTTP-network-or-cache fetch" step
    /// 8.26.2.2.2): `If-None-Match` with the stored `ETag` and
    /// `If-Modified-Since` with the stored `Last-Modified`, each when present.
    pub fn validation_fields(&self) -> Vec<(HeaderName, HeaderValue)> {
        let mut fields = Vec::with_capacity(2);
        let mut add = |name: HeaderName, value: &Option<Vec<u8>>| {
            if let Some(value) = value
                .as_deref()
                .and_then(|value| HeaderValue::from_bytes(value).ok())
            {
                fields.push((name, value));
            }
        };
        add(IF_NONE_MATCH, &self.etag);
        add(IF_MODIFIED_SINCE, &self.last_modified);
        fields
    }

    /// Freshens the stored response with the 304 that `exchange` received in
    /// answer to a validation request (§4.3.3, §4.3.4).
    ///
    /// `stored_headers` are the stored response's fields. The 304 updates them
    /// as §3.2 describes, and the new policy is computed from the updated fields
    /// with the 304's `Date`, `Age` and timing: the response has just been
    /// validated, so its age starts again from the 304 (an `Age` the 304 does
    /// not carry is 0, and the stored one no longer applies).
    ///
    /// `exchange.request_headers` are the fields of the request the client
    /// presented, which `Vary` is evaluated against again, since a 304 can change
    /// `Vary`.
    pub fn freshen(
        &self,
        config: &CacheConfig,
        stored_headers: &HeaderMap,
        exchange: &Exchange<'_>,
    ) -> Result<Freshened, FreshenError> {
        if exchange.status != StatusCode::NOT_MODIFIED {
            return Err(FreshenError::NotNotModified);
        }
        let response_time = unix_seconds(exchange.response_time);
        if !selects_for_update(
            self.etag.as_deref(),
            first(exchange.response_headers, &ETAG),
        ) {
            return Err(FreshenError::ValidatorMismatch);
        }
        // RFC 9110 §6.6.1: a recipient that caches a message without `Date`
        // appends one with the time it was received, which then updates the
        // stored `Date` like any other field of the 304.
        let mut newer = exchange.response_headers.clone();
        if !newer.contains_key(DATE) {
            if let Ok(value) = HeaderValue::from_str(&format_http_date(response_time)) {
                newer.insert(DATE, value);
            }
        }
        // The stored `Age` described the response when it was first received.
        // It has just been validated, so only an `Age` the 304 carries applies.
        let mut stored_headers = stored_headers.clone();
        stored_headers.remove(AGE);
        let headers = updated_fields(
            &stored_headers,
            &newer,
            &config.never_store,
            &config.not_updated,
        );
        let response = ResponseDirectives::from_headers(&headers);
        let request = RequestDirectives::from_headers(exchange.request_headers);
        let policy = storability(StorabilityInput {
            method_understood: true,
            status: self.status,
            partial_content: config.partial_content,
            request_no_store: request.no_store,
            response,
            has_expires: headers.contains_key(EXPIRES),
        })
        .map(|()| {
            Self::from_parts(
                config,
                self.status,
                exchange.request_headers,
                &headers,
                unix_seconds(exchange.request_time),
                response_time,
                age_value(exchange.response_headers),
                date_value(exchange.response_headers, response_time),
            )
        });
        Ok(Freshened { headers, policy })
    }

    /// The header fields to send with the stored response when it is used at
    /// `now`: the stored fields with `Age` replaced by the current age (§4: "When
    /// a stored response is used to satisfy a request without validation, a
    /// cache MUST generate an Age header field ... replacing any present in the
    /// response with a value equal to the stored response's current_age").
    pub fn presented_fields(&self, stored_headers: &HeaderMap, now: SystemTime) -> HeaderMap {
        let mut headers = stored_headers.clone();
        let age = self.current_age(now).min(DELTA_SECONDS_MAX);
        headers.insert(AGE, HeaderValue::from(age));
        headers
    }
}
