//! `Cache-Control` (RFC 9111 §5.2), `Pragma` (§5.4) and delta-seconds (§1.2.2).

use std::borrow::Cow;

use http::HeaderMap;
use http::header::{CACHE_CONTROL, PRAGMA};

/// The value delta-seconds saturate at (RFC 9111 §1.2.2): "If a cache receives
/// a delta-seconds value greater than the greatest integer it can represent, or
/// if any of its subsequent calculations overflows, the cache MUST consider the
/// value to be 2147483648 (2^31)".
pub const DELTA_SECONDS_MAX: u64 = 2_147_483_648;

/// Parses `delta-seconds = 1*DIGIT`, saturating at [`DELTA_SECONDS_MAX`].
pub fn parse_delta_seconds(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut result = 0u64;
    for &byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        result = (result * 10 + u64::from(byte - b'0')).min(DELTA_SECONDS_MAX);
    }
    Some(result)
}

/// The directives of a response's `Cache-Control` that a private cache acts on.
///
/// Directive names are compared case-insensitively and arguments may use the
/// token or the quoted-string form (§5.2). When a directive appears more than
/// once, its first occurrence counts (§4.2.1). Unrecognized directives are
/// ignored (§5.2.3). The restrictive directives `no-store`, `no-cache` and
/// `must-revalidate` are honoured even inside a malformed element.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResponseDirectives {
    /// `max-age` (§5.2.2.1). An invalid argument reads as 0, so that invalid
    /// freshness information makes the response stale, as §4.2.1 encourages.
    pub max_age: Option<u64>,
    /// `no-cache` (§5.2.2.4), qualified or not. The qualified form is handled as
    /// the unqualified one, as the note in §5.2.2.4 says most caches do.
    pub no_cache: bool,
    /// `no-store` (§5.2.2.5).
    pub no_store: bool,
    /// `must-revalidate` (§5.2.2.2).
    pub must_revalidate: bool,
    /// `must-understand` (§5.2.2.3).
    pub must_understand: bool,
    /// `public` (§5.2.2.9).
    pub public: bool,
    /// `private` (§5.2.2.7), qualified or not.
    pub private: bool,
    /// `immutable` (RFC 8246). It does not change freshness, but it exempts the
    /// response from `Pragma: no-cache`, see [`ResponseDirectives::from_headers`].
    pub immutable: bool,
    /// `stale-while-revalidate` (RFC 5861 §3). Ignored when its argument is invalid.
    pub stale_while_revalidate: Option<u64>,
    /// `stale-if-error` (RFC 5861 §4). Ignored when its argument is invalid.
    pub stale_if_error: Option<u64>,
}

/// How much staleness a request accepts through `max-stale` (§5.2.1.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaxStale {
    /// `max-stale` without an argument: a stale response of any age.
    Any,
    /// `max-stale=N`: stale by no more than N seconds.
    Seconds(u64),
}

/// The directives of a request's `Cache-Control` (§5.2.1), and `Pragma`.
/// `no-store` and `no-cache` are honoured even inside a malformed element.
///
/// When the request has no `Cache-Control` field, `Pragma: no-cache` counts as
/// `no-cache`, as RFC 7234 §5.4 required and browsers still do; RFC 9111
/// deprecates `Pragma` without replacing that rule.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestDirectives {
    /// `max-age` (§5.2.1.1). An invalid argument reads as 0.
    pub max_age: Option<u64>,
    /// `max-stale` (§5.2.1.2). Ignored when its argument is invalid.
    pub max_stale: Option<MaxStale>,
    /// `min-fresh` (§5.2.1.3). An invalid argument is ignored.
    pub min_fresh: Option<u64>,
    /// `no-cache` (§5.2.1.4), or `Pragma: no-cache` without `Cache-Control`.
    pub no_cache: bool,
    /// `no-store` (§5.2.1.5).
    pub no_store: bool,
    /// `only-if-cached` (§5.2.1.7).
    pub only_if_cached: bool,
}

impl ResponseDirectives {
    /// Reads the directives from every `Cache-Control` field line of `headers`.
    ///
    /// A response `Pragma: no-cache` counts as `no-cache` unless `Cache-Control`
    /// has `immutable`. RFC 9111 §5.4 leaves `Pragma` in responses without a
    /// meaning; browsers treat it as `no-cache`, and the web-platform-tests in
    /// `fetch/http-cache/pragma-no-cache-with-cache-control.html` require both
    /// halves of this rule (Mozilla bug 1937766).
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut directives = Self::default();
        let mut seen_max_age = false;
        let mut seen_swr = false;
        let mut seen_sie = false;
        let lines = headers
            .get_all(CACHE_CONTROL)
            .iter()
            .map(|value| value.as_bytes());
        for_each_directive(lines, |name, argument| {
            if name.eq_ignore_ascii_case(b"max-age") {
                if !seen_max_age {
                    seen_max_age = true;
                    directives.max_age = Some(
                        argument
                            .as_deref()
                            .and_then(parse_delta_seconds)
                            .unwrap_or(0),
                    );
                }
            } else if name.eq_ignore_ascii_case(b"no-cache") {
                directives.no_cache = true;
            } else if name.eq_ignore_ascii_case(b"no-store") {
                directives.no_store = true;
            } else if name.eq_ignore_ascii_case(b"must-revalidate") {
                directives.must_revalidate = true;
            } else if name.eq_ignore_ascii_case(b"must-understand") {
                directives.must_understand = true;
            } else if name.eq_ignore_ascii_case(b"public") {
                directives.public = true;
            } else if name.eq_ignore_ascii_case(b"private") {
                directives.private = true;
            } else if name.eq_ignore_ascii_case(b"immutable") {
                directives.immutable = true;
            } else if name.eq_ignore_ascii_case(b"stale-while-revalidate") {
                if !seen_swr {
                    seen_swr = true;
                    directives.stale_while_revalidate =
                        argument.as_deref().and_then(parse_delta_seconds);
                }
            } else if name.eq_ignore_ascii_case(b"stale-if-error") && !seen_sie {
                seen_sie = true;
                directives.stale_if_error = argument.as_deref().and_then(parse_delta_seconds);
            }
        });
        directives.no_store |= named_in_malformed_element(headers, b"no-store");
        directives.no_cache |= named_in_malformed_element(headers, b"no-cache");
        directives.must_revalidate |= named_in_malformed_element(headers, b"must-revalidate");
        if !directives.immutable && has_pragma_no_cache(headers) {
            directives.no_cache = true;
        }
        directives
    }
}

fn has_pragma_no_cache(headers: &HeaderMap) -> bool {
    let mut no_cache = false;
    let lines = headers.get_all(PRAGMA).iter().map(|value| value.as_bytes());
    for_each_directive(lines, |name, _| {
        no_cache |= name.eq_ignore_ascii_case(b"no-cache")
    });
    no_cache
}

impl RequestDirectives {
    /// Reads the directives from every `Cache-Control` field line of `headers`,
    /// falling back to `Pragma: no-cache` when there is none.
    pub fn from_headers(headers: &HeaderMap) -> Self {
        let mut directives = Self::default();
        let mut seen_max_age = false;
        let mut seen_max_stale = false;
        let mut seen_min_fresh = false;
        let lines = headers
            .get_all(CACHE_CONTROL)
            .iter()
            .map(|value| value.as_bytes());
        for_each_directive(lines, |name, argument| {
            if name.eq_ignore_ascii_case(b"max-age") {
                if !seen_max_age {
                    seen_max_age = true;
                    directives.max_age = Some(
                        argument
                            .as_deref()
                            .and_then(parse_delta_seconds)
                            .unwrap_or(0),
                    );
                }
            } else if name.eq_ignore_ascii_case(b"max-stale") {
                if !seen_max_stale {
                    seen_max_stale = true;
                    directives.max_stale = match argument.as_deref() {
                        None => Some(MaxStale::Any),
                        Some(argument) => parse_delta_seconds(argument).map(MaxStale::Seconds),
                    };
                }
            } else if name.eq_ignore_ascii_case(b"min-fresh") {
                if !seen_min_fresh {
                    seen_min_fresh = true;
                    directives.min_fresh = argument.as_deref().and_then(parse_delta_seconds);
                }
            } else if name.eq_ignore_ascii_case(b"no-cache") {
                directives.no_cache = true;
            } else if name.eq_ignore_ascii_case(b"no-store") {
                directives.no_store = true;
            } else if name.eq_ignore_ascii_case(b"only-if-cached") {
                directives.only_if_cached = true;
            }
        });
        directives.no_store |= named_in_malformed_element(headers, b"no-store");
        directives.no_cache |= named_in_malformed_element(headers, b"no-cache");
        if !headers.contains_key(CACHE_CONTROL) && has_pragma_no_cache(headers) {
            directives.no_cache = true;
        }
        directives
    }
}

/// Calls `f` with the name and argument of each well-formed element of a
/// comma-separated list of `token [ "=" ( token / quoted-string ) ]` elements
/// (RFC 9111 §5.2, RFC 9110 §5.6.1), across all field `lines`.
///
/// Empty elements are skipped, as RFC 9110 §5.6.1 requires. A malformed element
/// is skipped up to the next comma that is not inside a quoted string, so it
/// cannot swallow the elements after it. Optional whitespace around `=` is
/// tolerated. A quoted-string argument is returned unquoted, with its
/// quoted-pairs resolved.
pub fn for_each_directive<'a>(
    lines: impl Iterator<Item = &'a [u8]>,
    f: impl FnMut(&[u8], Option<Cow<'a, [u8]>>),
) {
    for_each_element(lines, f, |_| {});
}

/// Like [`for_each_directive`], and calls `malformed` with the bytes of each
/// element that is skipped because it is malformed.
fn for_each_element<'a>(
    lines: impl Iterator<Item = &'a [u8]>,
    mut f: impl FnMut(&[u8], Option<Cow<'a, [u8]>>),
    mut malformed: impl FnMut(&'a [u8]),
) {
    for line in lines {
        let mut position = 0;
        while position < line.len() {
            let (element, next) = parse_element(line, position);
            match element {
                Some((name, argument)) => f(name, argument),
                None => malformed(&line[position..next.min(line.len())]),
            }
            position = next;
        }
    }
}

/// Whether a malformed element of the `Cache-Control` field lines of `headers`
/// names the directive `name` as a bare token.
///
/// A malformed element such as `no-cache no-store` or `no-store; max-age=0`
/// still names directives, and dropping a restrictive one is the unsafe way to
/// fail: §5.2.2.5 is a MUST NOT store, and §4.2.1 says "If directives conflict
/// ..., the most restrictive directive should be honored". So the restrictive
/// directives a malformed element names, and only those, are honoured, the way
/// Firefox reads such fields; a wrong guess can only cost a cache hit.
fn named_in_malformed_element(headers: &HeaderMap, name: &[u8]) -> bool {
    let lines = headers
        .get_all(CACHE_CONTROL)
        .iter()
        .map(|value| value.as_bytes());
    let mut found = false;
    for_each_element(
        lines,
        |_, _| {},
        |span| {
            found |= span
                .split(|&byte| !is_tchar(byte))
                .any(|token| token.eq_ignore_ascii_case(name));
        },
    );
    found
}

pub(crate) type Element<'a> = (&'a [u8], Option<Cow<'a, [u8]>>);

/// Parses the element starting at `position` and returns it, if well-formed,
/// with the position just after the comma that ends it.
pub(crate) fn parse_element(line: &[u8], mut position: usize) -> (Option<Element<'_>>, usize) {
    position = skip_whitespace(line, position);
    let name_start = position;
    while position < line.len() && is_tchar(line[position]) {
        position += 1;
    }
    let name = &line[name_start..position];
    if name.is_empty() {
        return (None, skip_to_next_element(line, position));
    }
    position = skip_whitespace(line, position);
    let mut argument = None;
    if position < line.len() && line[position] == b'=' {
        position = skip_whitespace(line, position + 1);
        if position < line.len() && line[position] == b'"' {
            match parse_quoted_string(line, position) {
                Some((value, end)) => {
                    argument = Some(value);
                    position = end;
                },
                None => return (None, line.len()),
            }
        } else {
            let start = position;
            while position < line.len() && is_tchar(line[position]) {
                position += 1;
            }
            if position == start {
                return (None, skip_to_next_element(line, position));
            }
            argument = Some(Cow::Borrowed(&line[start..position]));
        }
        position = skip_whitespace(line, position);
    }
    if position < line.len() && line[position] != b',' {
        return (None, skip_to_next_element(line, position));
    }
    (Some((name, argument)), position + 1)
}

/// Parses the quoted-string starting with the `"` at `position`. Returns its
/// unescaped content and the position after the closing quote, or `None` when
/// the string is not terminated.
fn parse_quoted_string(line: &[u8], position: usize) -> Option<(Cow<'_, [u8]>, usize)> {
    let start = position + 1;
    let mut index = start;
    let mut escaped: Option<Vec<u8>> = None;
    while index < line.len() {
        match line[index] {
            b'"' => {
                let value = match escaped {
                    Some(bytes) => Cow::Owned(bytes),
                    None => Cow::Borrowed(&line[start..index]),
                };
                return Some((value, index + 1));
            },
            b'\\' if index + 1 < line.len() => {
                let bytes = escaped.get_or_insert_with(|| line[start..index].to_vec());
                bytes.push(line[index + 1]);
                index += 2;
            },
            byte => {
                if let Some(bytes) = escaped.as_mut() {
                    bytes.push(byte);
                }
                index += 1;
            },
        }
    }
    None
}

/// The position after the next comma that is not inside a quoted string.
fn skip_to_next_element(line: &[u8], mut position: usize) -> usize {
    let mut in_quotes = false;
    while position < line.len() {
        match line[position] {
            b'\\' if in_quotes => position += 1,
            b'"' => in_quotes = !in_quotes,
            b',' if !in_quotes => return position + 1,
            _ => {},
        }
        position += 1;
    }
    line.len()
}

fn skip_whitespace(line: &[u8], mut position: usize) -> usize {
    while position < line.len() && matches!(line[position], b' ' | b'\t') {
        position += 1;
    }
    position
}

/// `tchar` of RFC 9110 §5.6.2.
pub(crate) fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn response(lines: &[&str]) -> ResponseDirectives {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(CACHE_CONTROL, HeaderValue::from_str(line).unwrap());
        }
        ResponseDirectives::from_headers(&headers)
    }

    fn request(cache_control: &[&str], pragma: &[&str]) -> RequestDirectives {
        let mut headers = HeaderMap::new();
        for line in cache_control {
            headers.append(CACHE_CONTROL, HeaderValue::from_str(line).unwrap());
        }
        for line in pragma {
            headers.append(PRAGMA, HeaderValue::from_str(line).unwrap());
        }
        RequestDirectives::from_headers(&headers)
    }

    fn elements(line: &str) -> Vec<(String, Option<String>)> {
        let mut out = Vec::new();
        for_each_directive(std::iter::once(line.as_bytes()), |name, argument| {
            out.push((
                String::from_utf8_lossy(name).into_owned(),
                argument.map(|a| String::from_utf8_lossy(&a).into_owned()),
            ))
        });
        out
    }

    #[test]
    fn restrictive_directives_survive_malformed_elements() {
        for value in [
            "no-cache no-store",
            "no-store; max-age=0",
            "max-age=0 no-store",
            "private, no-store=",
        ] {
            assert!(response(&[value]).no_store, "{value}");
        }
        assert!(response(&["max-age=60 no-cache"]).no_cache);
        assert!(response(&["max-age=60 must-revalidate;"]).must_revalidate);
        let permissive = response(&["max-age=60, public junk, immutable;x"]);
        assert!(!permissive.public && !permissive.immutable);
        assert_eq!(permissive.max_age, Some(60));
        let request = request(&["max-age=10 no-cache", "x no-store"], &[]);
        assert!(request.no_cache && request.no_store);
        assert_eq!(request.max_age, None);
    }

    #[test]
    fn delta_seconds() {
        assert_eq!(parse_delta_seconds(b"0"), Some(0));
        assert_eq!(parse_delta_seconds(b"0060"), Some(60));
        assert_eq!(parse_delta_seconds(b"2147483647"), Some(2_147_483_647));
        assert_eq!(parse_delta_seconds(b"2147483649"), Some(DELTA_SECONDS_MAX));
        assert_eq!(
            parse_delta_seconds(b"99999999999999999999999999999999"),
            Some(DELTA_SECONDS_MAX)
        );
        for invalid in [
            &b""[..],
            b"-1",
            b"+1",
            b"1.5",
            b" 1",
            b"1 ",
            b"0x10",
            b"abc",
        ] {
            assert_eq!(parse_delta_seconds(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn list_syntax() {
        assert_eq!(
            elements(r#"max-age=60, no-cache="Set-Cookie, X-Foo", private"#),
            vec![
                ("max-age".into(), Some("60".into())),
                ("no-cache".into(), Some("Set-Cookie, X-Foo".into())),
                ("private".into(), None),
            ]
        );
        assert_eq!(
            elements(" ,, public ,\tmax-age = 5 ,"),
            vec![
                ("public".into(), None),
                ("max-age".into(), Some("5".into()))
            ]
        );
        assert_eq!(
            elements(r#"a="x\"y", b"#),
            vec![("a".into(), Some(r#"x"y"#.into())), ("b".into(), None)]
        );
    }

    #[test]
    fn line_ends_are_handled_everywhere() {
        assert_eq!(elements("public, "), vec![("public".into(), None)]);
        assert_eq!(elements("public,\t"), vec![("public".into(), None)]);
        assert_eq!(elements("public, max-age="), vec![("public".into(), None)]);
        assert_eq!(elements("public, max-age= "), vec![("public".into(), None)]);
        assert_eq!(
            elements("public, max-age=5 junk"),
            vec![("public".into(), None)]
        );
        assert_eq!(
            elements(r#"public, foo="ab\"#),
            vec![("public".into(), None)]
        );
        assert_eq!(
            elements("public, max-age =5 "),
            vec![
                ("public".into(), None),
                ("max-age".into(), Some("5".into()))
            ]
        );
    }

    #[test]
    fn quotes_and_escapes_inside_malformed_elements() {
        assert_eq!(
            elements(r#"junk "a, no-store, b", ok"#),
            vec![("ok".into(), None)]
        );
        assert_eq!(
            elements(r#"junk "a\", no-store", ok"#),
            vec![("ok".into(), None)]
        );
        assert_eq!(elements(r#"a\, ok"#), vec![("ok".into(), None)]);
    }

    #[test]
    fn malformed_elements_do_not_swallow_their_neighbours() {
        assert_eq!(
            elements(r#"max-age=60 junk, no-store"#),
            vec![("no-store".into(), None)]
        );
        assert_eq!(elements(r#"=5, no-store"#), vec![("no-store".into(), None)]);
        assert_eq!(
            elements(r#"max-age=, no-store"#),
            vec![("no-store".into(), None)]
        );
        assert_eq!(
            elements(r#"foo="a, b" junk, no-store"#),
            vec![("no-store".into(), None)]
        );
        assert_eq!(elements(r#"foo="unterminated, no-store"#), vec![]);
    }

    #[test]
    fn names_are_case_insensitive() {
        let directives = response(&["Max-Age=60, NO-STORE, Must-Revalidate"]);
        assert_eq!(directives.max_age, Some(60));
        assert!(directives.no_store);
        assert!(directives.must_revalidate);
    }

    #[test]
    fn quoted_arguments_are_accepted() {
        assert_eq!(response(&[r#"max-age="60""#]).max_age, Some(60));
    }

    #[test]
    fn first_max_age_wins_across_lines() {
        assert_eq!(response(&["max-age=60", "max-age=3600"]).max_age, Some(60));
        assert_eq!(response(&["max-age=60, max-age=3600"]).max_age, Some(60));
    }

    #[test]
    fn invalid_max_age_reads_as_zero() {
        assert_eq!(response(&["max-age=abc"]).max_age, Some(0));
        assert_eq!(response(&["max-age"]).max_age, Some(0));
        assert_eq!(response(&["max-age=-1"]).max_age, Some(0));
    }

    #[test]
    fn qualified_no_cache_and_private_count_as_unqualified() {
        let directives = response(&[r#"no-cache="set-cookie", private="x""#]);
        assert!(directives.no_cache);
        assert!(directives.private);
    }

    #[test]
    fn response_extensions() {
        let directives =
            response(&["max-age=1, stale-while-revalidate=30, stale-if-error=60, immutable"]);
        assert_eq!(directives.stale_while_revalidate, Some(30));
        assert_eq!(directives.stale_if_error, Some(60));
        assert!(directives.immutable);
        assert_eq!(
            response(&["stale-while-revalidate"]).stale_while_revalidate,
            None
        );
    }

    #[test]
    fn response_pragma_no_cache_unless_immutable() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("max-age=2592000, public"),
        );
        headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
        assert!(ResponseDirectives::from_headers(&headers).no_cache);
        headers.insert(
            CACHE_CONTROL,
            HeaderValue::from_static("max-age=2592000, immutable"),
        );
        assert!(!ResponseDirectives::from_headers(&headers).no_cache);
    }

    #[test]
    fn request_directives() {
        let directives = request(
            &["max-age=10, max-stale, min-fresh=5, no-store, only-if-cached"],
            &[],
        );
        assert_eq!(directives.max_age, Some(10));
        assert_eq!(directives.max_stale, Some(MaxStale::Any));
        assert_eq!(directives.min_fresh, Some(5));
        assert!(directives.no_store);
        assert!(directives.only_if_cached);
        assert!(!directives.no_cache);
        assert_eq!(
            request(&["max-stale=7"], &[]).max_stale,
            Some(MaxStale::Seconds(7))
        );
        assert_eq!(request(&["max-stale=x"], &[]).max_stale, None);
    }

    #[test]
    fn pragma_no_cache_only_without_cache_control() {
        assert!(request(&[], &["no-cache"]).no_cache);
        assert!(request(&[], &["foo, No-Cache"]).no_cache);
        assert!(!request(&["max-age=10"], &["no-cache"]).no_cache);
    }
}
