//! The caching rules of [RFC 9111] for a private HTTP cache, such as a web
//! browser's, with the `stale-while-revalidate` extension of [RFC 5861].
//!
//! This crate decides; it does not store. Given a request and the response it
//! received, it says whether the response may be stored and which of its fields
//! to keep. Given a stored response and a new request, it says whether the
//! stored response may be used as it is, used while it is revalidated, or only
//! used after validation, and which precondition fields to send. Given a 304,
//! it updates the stored fields and computes the new freshness. Bodies, keys,
//! eviction and I/O are the caller's.
//!
//! ```
//! use std::time::{Duration, SystemTime};
//! use http::{HeaderMap, HeaderValue, Method, StatusCode};
//! use http_cache_rules::{CacheConfig, Exchange, Reuse, StoredPolicy};
//!
//! let config = CacheConfig::default();
//! let request_headers = HeaderMap::new();
//! let mut response_headers = HeaderMap::new();
//! response_headers.insert("cache-control", HeaderValue::from_static("max-age=60"));
//! let sent = SystemTime::now();
//! let exchange = Exchange {
//!     method: &Method::GET,
//!     request_headers: &request_headers,
//!     status: StatusCode::OK,
//!     response_headers: &response_headers,
//!     request_time: sent,
//!     response_time: sent,
//! };
//!
//! let policy = StoredPolicy::new(&config, &exchange).expect("storable");
//! let stored_fields = StoredPolicy::stored_fields(&config, &exchange);
//!
//! let later = sent + Duration::from_secs(30);
//! assert_eq!(policy.evaluate(&Method::GET, &HeaderMap::new(), later), Some(Reuse::Fresh));
//! let presented = policy.presented_fields(&stored_fields, later);
//! assert_eq!(presented["age"], "30");
//!
//! let much_later = sent + Duration::from_secs(90);
//! assert_eq!(policy.evaluate(&Method::GET, &HeaderMap::new(), much_later), Some(Reuse::Validate));
//! ```
//!
//! Requirements are traced to their tests and proofs in `SPEC.md`.
//!
//! [RFC 9111]: https://www.rfc-editor.org/rfc/rfc9111
//! [RFC 5861]: https://www.rfc-editor.org/rfc/rfc5861

pub mod date;
pub mod directives;
pub mod fields;
mod policy;
pub mod rules;
pub mod validators;
pub mod vary;

#[cfg(kani)]
mod proofs;

use http::HeaderName;
use http::header::{CONTENT_ENCODING, CONTENT_RANGE, SET_COOKIE};

pub use crate::policy::{
    Exchange, FORMAT_VERSION, FreshenError, Freshened, StoredPolicy, unix_seconds,
};
pub use crate::rules::{Heuristic, NotStorable, Reuse, invalidates, invalidation_candidates};
pub use crate::vary::VaryKey;

/// The choices RFC 9111 leaves to the cache.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// How a heuristic freshness lifetime is computed (§4.2.2).
    pub heuristic: Heuristic,
    /// Whether the caller stores 206 responses and combines partial content
    /// (§3.3, §3.4). If not, 206 responses are not storable.
    pub partial_content: bool,
    /// Response fields never stored, beyond those §3.1 excludes. A browser keeps
    /// cookies out of its HTTP cache, since they are applied when the response
    /// arrives and must not outlive their own expiry on disk.
    pub never_store: Vec<HeaderName>,
    /// Stored fields a 304 does not update because the stored response depends
    /// on them (§3.2): `Content-Encoding` when bodies are stored decoded,
    /// `Content-Range` because the HTTP layer processes it.
    pub not_updated: Vec<HeaderName>,
}

impl Default for CacheConfig {
    /// 10% heuristic without a cap (as Chromium), no partial content, no
    /// `Set-Cookie`/`Set-Cookie2` in the cache, and `Content-Encoding` and
    /// `Content-Range` not updated by a 304.
    fn default() -> Self {
        Self {
            heuristic: Heuristic {
                percent: 10,
                max: None,
            },
            partial_content: false,
            never_store: vec![SET_COOKIE, HeaderName::from_static("set-cookie2")],
            not_updated: vec![CONTENT_ENCODING, CONTENT_RANGE],
        }
    }
}
