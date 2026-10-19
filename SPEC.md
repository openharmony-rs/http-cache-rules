# Requirements traceability

This crate implements the rules of [RFC 9111] (HTTP Caching) that apply to a
**private** cache, plus the parts of [RFC 9110] (HTTP Semantics), [RFC 5861]
(`stale-while-revalidate`) and the [Fetch] standard that those rules depend on.

Each requirement has an identifier. `tests/spec.rs` checks that every identifier
in the tables below names at least one test or proof: a function whose name
starts with the identifier in snake case (`R-4.2.3` → `r_4_2_3…`), in
`tests/requirements.rs` (tests through the public API), `src/proofs.rs` (Kani
proofs over all inputs, run with `cargo kani`), or `tests/wpt.rs` (replays of
the web-platform-tests). Unit tests next to the code and the property tests in
`tests/properties.rs` add coverage, but are not what this table points at.

Quotes are abridged; the section numbers point at the full text.

## RFC 9111

| ID | Requirement | Where |
|---|---|---|
| R-1.2.2 | delta-seconds: "If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2^31) or the greatest positive integer it can conveniently represent." | `directives::parse_delta_seconds`; saturating arithmetic in `rules` |
| R-3 | "A cache MUST NOT store a response to a request unless" the method is understood, the status is final, 206/304/must-understand need an understood status, no `no-store`, and the response has `public`, `private` (private cache), `Expires`, `max-age`, or a heuristically cacheable status. | `rules::storability` |
| R-3.1-all | "Caches MUST include all received response header fields -- including unrecognized ones -- when storing a response" | `fields::stored_fields` |
| R-3.1-connection | `Connection` and the fields it lists are removed before forwarding; "This MAY be implemented by doing so before storage." `Connection` and RFC 9110 §7.6.1's fixed hop-by-hop fields are not stored; the fields `Connection` lists are (see Choices). | `fields::stored_fields` |
| R-3.1-proxy | "Header fields that are specific to the proxy ... MUST NOT be stored": `Proxy-Authenticate`, `Proxy-Authentication-Info`, `Proxy-Authorization`. | `fields::stored_fields` |
| R-3.2 | "the cache MUST add each header field in the provided response to the stored response, replacing field values that are already present", except fields excepted from storage, fields the stored response depends on, automatically processed fields, and `Content-Length`. | `fields::updated_fields` |
| R-4-method | Reuse requires that "the request method associated with the stored response allows it to be used for the presented request"; "A cache MUST write through requests with methods that are unsafe". | `StoredPolicy::evaluate` |
| R-4-no-cache | Reuse requires that "the stored response does not contain the no-cache directive ..., unless it is successfully validated". | `rules::reuse` |
| R-4-age | "When a stored response is used to satisfy a request without validation, a cache MUST generate an Age header field ..., replacing any present in the response with a value equal to the stored response's current_age". | `StoredPolicy::presented_fields` |
| R-4-most-recent | "When more than one suitable response is stored, a cache MUST use the most recent one (as determined by the Date header field)." The caller chooses; the crate exposes the value. | `StoredPolicy::date` |
| R-4.1-match | A stored response with `Vary` is not used "unless all the presented request header fields nominated by that Vary field value match"; fields match after removing whitespace and "combining multiple header field lines". | `vary::VaryKey` |
| R-4.1-absent | "If ... a header field is absent from a request, it can only match another request if it is also absent there." | `vary::VaryKey::matches` |
| R-4.1-star | "A stored response with a Vary header field value containing a member "*" always fails to match." | `vary::VaryKey::capture` |
| R-4.2-fresh | "response_is_fresh = (freshness_lifetime > current_age)" | `rules::reuse` |
| R-4.2-case | "a cache recipient SHOULD match the field value [of dates] case-insensitively." | `date::parse_http_date` |
| R-4.2-gmt | "A cache recipient SHOULD consider a date with a zone abbreviation other than "GMT" to be invalid for calculating expiration." | `date::parse_http_date` |
| R-4.2-earlier | "the recipient MUST internally represent a parsed Expires date as the nearest time equal to or earlier than the received value." | `date::parse_http_date` (whole seconds; a leap second reads as :59) |
| R-4.2.1-order | Freshness lifetime is the first match of `s-maxage` (shared only), `max-age`, `Expires` minus `Date` (or the receive time), else heuristic. | `rules::freshness_lifetime` |
| R-4.2.1-duplicates | "When there is more than one value present for a given directive ..., either the first occurrence should be used or the response should be considered stale." The first occurrence is used. | `directives`, `policy::expires` |
| R-4.2.1-invalid | "Caches are encouraged to consider responses that have invalid freshness information (e.g., a max-age directive with non-integer content) to be stale." | `directives::ResponseDirectives` |
| R-4.2.2-explicit | "A cache MUST NOT use heuristics to determine freshness when an explicit expiration time is present in the stored response." | `rules::freshness_lifetime` |
| R-4.2.2-status | Heuristics only for heuristically cacheable statuses and responses marked `public`. | `rules::freshness_lifetime`, `StoredPolicy::new` |
| R-4.2.2-fraction | "a heuristic expiration value that is no more than some fraction of the interval since that time. A typical setting of this fraction might be 10%." | `rules::freshness_lifetime` |
| R-4.2.3 | `apparent_age`, `corrected_age_value` (relative to the request time), `corrected_initial_age = max(...)`, `resident_time`, `current_age`. | `rules::current_age` |
| R-4.2.4 | "A cache MUST NOT generate a stale response if it is prohibited by an explicit in-protocol directive (e.g., by a no-cache ..., a must-revalidate ...)" and "MUST NOT generate a stale response unless ... explicitly permitted by the client or origin server". | `rules::reuse` |
| R-4.3.1-etag | When validating, a cache "MUST send the relevant entity tags ... if the entity tags were provided in the stored response(s) being validated." | `StoredPolicy::validation_fields` |
| R-4.3.1-lm | It "SHOULD send the Last-Modified value (using If-Modified-Since) if the request is not for a subrange, a single stored response is being validated, and that response contains a Last-Modified value." | `StoredPolicy::validation_fields` |
| R-4.3.3 | "A 304 (Not Modified) response status code indicates that the stored response can be updated and reused". | `StoredPolicy::freshen` |
| R-4.3.4-strong | "If none of the initial set contains at least one of the same strong validators, then the cache MUST NOT use the new response to update any stored responses." | `validators::selects_for_update` |
| R-4.3.4-update | "For each stored response identified, the cache MUST update its header fields with the header fields provided in the 304 (Not Modified) response, as per Section 3.2." | `StoredPolicy::freshen` |
| R-4.4 | "A cache MUST invalidate the target URI ... when it receives a non-error status code in response to an unsafe request method (including methods whose safety is unknown)"; Location and Content-Location are candidates, never cross-origin. | `rules::invalidates`, `rules::invalidation_candidates` (the caller resolves and checks origins) |
| R-5.1 | Age: "a cache encountering a message with a list-based Age field value SHOULD use the first member", and an invalid value "SHOULD [be] ignore[d]". | `policy::age_value` |
| R-5.2-case | "Cache directives are identified by a token, to be compared case-insensitively". | `directives` |
| R-5.2-forms | Arguments "can use both token and quoted-string syntax. ... recipients ought to accept both forms". | `directives::for_each_directive` |
| R-5.2.3 | "A cache MUST ignore unrecognized cache directives." | `directives` |
| R-5.2.1.1 | Request `max-age`: "the client prefers a response whose age is less than or equal to the specified number of seconds". | `rules::reuse` |
| R-5.2.1.2 | Request `max-stale`: accepts a stale response, stale by no more than the value, or of any age without a value. | `rules::reuse` |
| R-5.2.1.3 | Request `min-fresh`: "a response that will still be fresh for at least the specified number of seconds". | `rules::reuse` |
| R-5.2.1.4 | Request `no-cache`: "a stored response not be used to satisfy the request without successful validation". | `rules::reuse` |
| R-5.2.1.5 | Request `no-store`: "a cache MUST NOT store any part of either this request or any response to it." | `rules::storability` |
| R-5.2.1.7 | Request `only-if-cached` is recognized; answering 504 is the caller's. | `directives::RequestDirectives` |
| R-5.2.2.1 | Response `max-age`: "considered stale after its age is greater than the specified number of seconds". | `rules::freshness_lifetime` |
| R-5.2.2.2 | `must-revalidate`: "once the response has become stale, a cache MUST NOT reuse that response ... until it has been successfully validated". | `rules::reuse` |
| R-5.2.2.3 | `must-understand`: "the cache SHOULD ignore the no-store directive if it understands and implements the status code's caching requirements." | `rules::storability` |
| R-5.2.2.4 | `no-cache`: "the response MUST NOT be used to satisfy any other request without forwarding it for validation". | `rules::reuse` |
| R-5.2.2.5 | `no-store`: "a cache MUST NOT store any part of either the immediate request or the response". | `rules::storability` |
| R-5.2.2.7 | `private`: "a private cache MAY store the response ..., even if the response would not otherwise be heuristically cacheable". | `rules::storability` |
| R-5.2.2.9 | `public`: marks the response cacheable; without explicit freshness "it is heuristically cacheable". | `rules::storability`, `StoredPolicy::new` |
| R-5.2.2.10 | `s-maxage` applies to shared caches only. | `rules::freshness_lifetime` |
| R-5.3-invalid | "A cache recipient MUST interpret invalid date formats, especially the value "0", as representing a time in the past". | `rules::freshness_lifetime` |
| R-5.3-max-age | "If a response includes a Cache-Control header field with the max-age directive ..., a recipient MUST ignore the Expires header field." | `rules::freshness_lifetime` |

## RFC 9110

| ID | Requirement | Where |
|---|---|---|
| R-9110-5.6.7-formats | "A recipient that parses a timestamp value in an HTTP field MUST accept all three HTTP-date formats." | `date::parse_http_date` |
| R-9110-5.6.7-year | "Recipients of a timestamp value in rfc850-date format ... MUST interpret a timestamp that appears to be more than 50 years in the future as representing the most recent year in the past that had the same last two digits." | `date::parse_http_date` |
| R-9110-5.6.7-generate | "When a sender generates a field that contains one or more timestamps defined as HTTP-date, the sender MUST generate those timestamps in the IMF-fixdate format." | `date::format_http_date` |
| R-9110-6.6.1 | "A recipient with a clock that receives a response message without a Date header field MUST record the time it was received and append a corresponding Date header field ... if it is cached". | `fields::stored_fields`, `policy::date_value` |
| R-9110-8.8.3.2 | Strong and weak entity tag comparison (Table 3). | `validators::EntityTag` |
| R-9110-15.1 | Heuristically cacheable: "200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501". | `rules::HEURISTICALLY_CACHEABLE` |

## RFC 5861

| ID | Requirement | Where |
|---|---|---|
| R-5861-3 | `stale-while-revalidate`: "caches MAY serve the response ... after it becomes stale, up to the indicated number of seconds" while revalidating. | `rules::reuse` (`Reuse::StaleWhileRevalidate`) |
| R-5861-4 | `stale-if-error` is recognized and exposed; serving on error is the caller's. | `StoredPolicy::stale_if_error` |

## Fetch

| ID | Requirement | Where |
|---|---|---|
| F-definitions | "A fresh response is a response whose current age is within its freshness lifetime. A stale-while-revalidate response is a response that is not a fresh response and whose current age is within the stale-while-revalidate lifetime. A stale response is a response that is not a fresh response or a stale-while-revalidate response." | `Reuse` |
| F-8.26 | HTTP-network-or-cache fetch 8.26.2.2.2: "If storedResponse's header list contains `ETag`, then append (`If-None-Match`, `ETag`'s value)"; likewise `Last-Modified` → `If-Modified-Since`. Values are sent verbatim. | `StoredPolicy::validation_fields` |
| F-11.4 | 11.4: on a 304 to a revalidation, "Update storedResponse's header list using forwardResponse's header list, as per the "Freshening Stored Responses upon Validation" chapter". | `StoredPolicy::freshen` |

## Deviations

Each deviation is what browsers do and, where noted, what the web-platform-tests
require. Each one is tested under its identifier.

| ID | Deviation | Why |
|---|---|---|
| D-1 | A request with `Cache-Control: no-store` does not use a stored response (`evaluate` returns `None`). §5.2.1.5 only forbids storing. | Browsers bypass the cache; `fetch/http-cache/cc-request.any.js` ("doesn't reuse fresh response when request contains Cache-Control: no-store"). |
| D-2 | A response `Pragma: no-cache` counts as `no-cache` unless `Cache-Control` has `immutable`. §5.4 gives response `Pragma` no meaning. | `fetch/http-cache/pragma-no-cache-with-cache-control.html` requires both halves (Mozilla bug 1937766). |
| D-3 | A 304 whose validators are weak or absent freshens the stored response it validated, whether or not they correspond (§4.3.4 rules 2 and 3 would not select it). A strong `ETag` must still match (R-4.3.4-strong). | Fetch 11.4 updates the revalidated response; browsers do the same; servers regenerate `Last-Modified` and omit validators (`fetch/http-cache/304-update.any.js` sees `Last-Modified` move by a second). |
| D-4 | A request `max-age=0` always requires validation, even when the stored response's age is 0. §5.2.1.1 would accept age 0. | Browsers send it to force validation, and Fetch adds it for the "no-cache" cache mode, which must always validate. Ages are whole seconds, so age 0 is common right after storing. |
| D-5 | A request `Pragma: no-cache` without `Cache-Control` counts as `no-cache`. RFC 9111 deprecates `Pragma` and dropped this rule of RFC 7234 §5.4. | Browsers still honour it; Fetch sends it for the "no-store" and "reload" modes. |
| D-6 | An `ETag` that is not a valid entity tag (unquoted) is still sent back verbatim in `If-None-Match`, and does not prevent freshening. | `fetch/http-cache/304-update.any.js` and `freshness.any.js` use unquoted ETags. |
| D-7 | By default `Set-Cookie` and `Set-Cookie2` are not stored (`CacheConfig::never_store`), against §3.1 "MUST include all received response header fields". | A browser applies cookies when the response arrives, and a cached copy would keep them on disk past their expiry. Chromium does not persist them either. Configurable. |

## Choices the RFC leaves open

- Fields that `Connection` lists are stored. §3.1 lets a cache drop them because an intermediary must remove them before forwarding; a private cache forwards nothing, browsers keep them, and dropping them would let a response hide its own `Content-Security-Policy` or `Cache-Control` from the copies served from the cache.
- A malformed `Cache-Control` element (`no-cache no-store`, `no-store; max-age=0`) is skipped, but the restrictive directives it names as bare tokens are honoured: `no-store`, `no-cache` and `must-revalidate` in responses, `no-store` and `no-cache` in requests. Dropping them would fail unsafely, and §4.2.1 says "the most restrictive directive should be honored". Firefox reads such fields the same way; Chromium ignores them.
- A request with `min-fresh` never gets a stale response, even with `max-stale`, for the same reason.
- `private` makes a response storable but does not, unlike `public`, allow a heuristic freshness lifetime for a status that is not heuristically cacheable. §4.2.2 names `public` as its example; the web-platform-tests only cover `public`.
- Dates in spellings other than the three of RFC 9110 §5.6.7 (`Sun, 6 Nov 1994 …`, `… UTC`, `… +0000`) are invalid. Every use of a date is conservative when it is invalid: `Expires` means already expired (§5.3), `Date` falls back to the receive time, and `Last-Modified` yields no heuristic. Chromium and Firefox accept some of these spellings.
- Qualified `no-cache="…"` and `private="…"` are handled as unqualified, as the notes in §5.2.2.4 and §5.2.2.7 say most caches do.
- Heuristic: 10% of `Date − Last-Modified`, no cap (configurable), and 0 without `Last-Modified`. Chromium also treats permanent redirects without caching headers as fresh indefinitely; this crate does not.
- `corrected_initial_age` uses the conservative `max(apparent_age, corrected_age_value)`.
- The `stale-while-revalidate` window ends when `staleness` reaches the value (`staleness < window`), matching freshness ending when the age reaches the lifetime.
- `Vary` matching only applies the normalizations that are always valid (trimming, combining field lines). Field-specific normalizations are skipped, which can only cause a miss, never a wrong match.
- A `Vary` that is not a valid list of field names never matches.
- 304s never update `Content-Encoding` or `Content-Range` by default (§3.2 allows a cache to keep fields its stored response depends on).
- Only GET responses are stored; a stored GET response also answers HEAD.
- `must-understand` is implemented; the understood statuses are the final ones RFC 9110 defines, 206 only with partial-content support, and never 304.

## Left to the caller

- The cache key (target URI, method, partitioning, credentials mode) and choosing between several stored responses (R-4-most-recent gives the value to choose by).
- Fetch cache modes, including `only-if-cached` answering 504, and the request headers Fetch adds for them.
- Storing, combining and serving partial content (§3.3, §3.4) and evaluating received preconditions (§4.3.2).
- Resolving and origin-checking the invalidation candidates (§4.4).
- Serving stale on error (`stale-if-error`) and revalidating in the background for `Reuse::StaleWhileRevalidate`.
- Removing a stored response when `freshen` reports it is no longer storable or mismatched.
- Trailer fields (§3.1).
- `immutable` (RFC 8246): it does not change freshness here, and is exposed by `StoredPolicy::is_immutable` for callers that skip revalidation of fresh immutable responses on reload, as Firefox and Safari do.

## Known limitations

- `Vary` keys are unsalted SHA-256 digests. A nominated field with little entropy, such as `Authorization` with Basic credentials, can be recovered from a stored key by guessing. Chromium stores the same kind of digest. A caller that cannot accept this should not store responses whose `Vary` names credentials.

[RFC 9111]: https://www.rfc-editor.org/rfc/rfc9111
[RFC 9110]: https://www.rfc-editor.org/rfc/rfc9110
[RFC 5861]: https://www.rfc-editor.org/rfc/rfc5861
[Fetch]: https://fetch.spec.whatwg.org/
