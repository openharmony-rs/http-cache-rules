//! A minimal private HTTP cache in front of the cache-tests origin server, making
//! every RFC 9111 decision through http-cache-rules; `run.mjs` runs the suite
//! through it. Everything the crate leaves to its caller is done here in the
//! simplest way: the key is the request target, variants are kept in a list, the
//! most recent usable one (by `Date`) is used, client preconditions are passed
//! through, and Range requests bypass the cache.
//!
//! Usage: `cache-tests-proxy <listen address> <origin address>`

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Method, StatusCode};
use http_cache_rules::directives::RequestDirectives;
use http_cache_rules::{
    CacheConfig, Exchange, FreshenError, Reuse, StoredPolicy, invalidates, invalidation_candidates,
};

#[derive(Clone)]
struct Entry {
    policy: StoredPolicy,
    headers: HeaderMap,
    status: u16,
    body: Vec<u8>,
}

type Cache = Arc<Mutex<HashMap<String, Vec<Entry>>>>;

struct Request {
    method: Method,
    target: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    reason: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

/// What a request needs besides itself: the cache, its configuration, the origin
/// address, and the URL prefixes under which the origin's resources are known.
#[derive(Clone)]
struct Context {
    cache: Cache,
    config: CacheConfig,
    origin: String,
    prefixes: Vec<String>,
}

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "transfer-encoding",
    "upgrade",
    "trailer",
    "content-length",
];

fn read_head(reader: &mut BufReader<TcpStream>) -> std::io::Result<Option<(String, HeaderMap)>> {
    let mut first = String::new();
    if reader.read_line(&mut first)? == 0 {
        return Ok(None);
    }
    let mut headers = HeaderMap::new();
    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        let line = line.strip_suffix(b"\n").unwrap_or(&line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(&line[..colon]),
            HeaderValue::from_bytes(line[colon + 1..].trim_ascii()),
        ) else {
            continue;
        };
        headers.append(name, value);
    }
    Ok(Some((first.trim_end().to_owned(), headers)))
}

fn read_body(
    reader: &mut BufReader<TcpStream>,
    headers: &HeaderMap,
    until_eof: bool,
) -> std::io::Result<Vec<u8>> {
    let chunked = headers
        .get_all(header::TRANSFER_ENCODING)
        .iter()
        .any(|value| {
            value
                .to_str()
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("chunked")
        });
    let content_length = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok()?.trim().parse::<usize>().ok());
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            reader.read_line(&mut size)?;
            let size = size.trim().split(';').next().unwrap_or("0");
            let size = usize::from_str_radix(size, 16).unwrap_or(0);
            if size == 0 {
                loop {
                    let mut trailer = String::new();
                    if reader.read_line(&mut trailer)? == 0 || trailer.trim().is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0; size];
            reader.read_exact(&mut chunk)?;
            body.extend_from_slice(&chunk);
            let mut crlf = String::new();
            reader.read_line(&mut crlf)?;
        }
    } else if let Some(length) = content_length {
        body = vec![0; length];
        reader.read_exact(&mut body)?;
    } else if until_eof {
        reader.read_to_end(&mut body)?;
    }
    Ok(body)
}

fn push_field(out: &mut Vec<u8>, name: &HeaderName, value: &HeaderValue) {
    out.extend_from_slice(name.as_str().as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

/// Send `request` to the origin, with `extra` replacing the request's own fields
/// of the same names.
fn forward(
    origin: &str,
    request: &Request,
    extra: &[(HeaderName, HeaderValue)],
) -> std::io::Result<Response> {
    let mut stream = TcpStream::connect(origin)?;
    let mut out = format!(
        "{} {} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n",
        request.method, request.target
    )
    .into_bytes();
    for (name, value) in &request.headers {
        let replaced = extra.iter().any(|(extra_name, _)| extra_name == name);
        if !HOP_BY_HOP.contains(&name.as_str()) && name != header::HOST && !replaced {
            push_field(&mut out, name, value);
        }
    }
    for (name, value) in extra {
        push_field(&mut out, name, value);
    }
    if !request.body.is_empty() || matches!(request.method.as_str(), "POST" | "PUT" | "PATCH") {
        out.extend_from_slice(format!("Content-Length: {}\r\n", request.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&request.body);
    stream.write_all(&out)?;
    let mut reader = BufReader::new(stream);
    loop {
        let Some((status_line, headers)) = read_head(&mut reader)? else {
            return Err(std::io::Error::other("origin closed the connection"));
        };
        let mut parts = status_line.splitn(3, ' ');
        let _version = parts.next();
        let status: u16 = parts
            .next()
            .and_then(|status| status.parse().ok())
            .ok_or_else(|| std::io::Error::other("bad status"))?;
        let reason = parts.next().unwrap_or("").to_owned();
        if (100..200).contains(&status) {
            continue;
        }
        let no_body = request.method == Method::HEAD || status == 204 || status == 304;
        let body = if no_body {
            Vec::new()
        } else {
            read_body(&mut reader, &headers, true)?
        };
        return Ok(Response {
            status,
            reason,
            headers,
            body,
        });
    }
}

fn reason(status: u16) -> String {
    StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown")
        .to_owned()
}

fn write_response(
    stream: &mut TcpStream,
    method: &Method,
    response: &Response,
) -> std::io::Result<()> {
    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, response.reason).into_bytes();
    for (name, value) in &response.headers {
        if !HOP_BY_HOP.contains(&name.as_str()) {
            push_field(&mut out, name, value);
        }
    }
    if response.status != 304 && response.status != 204 {
        out.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    if *method != Method::HEAD {
        out.extend_from_slice(&response.body);
    }
    stream.write_all(&out)
}

fn exchange<'a>(
    request: &'a Request,
    response: &'a Response,
    sent: SystemTime,
    received: SystemTime,
) -> Exchange<'a> {
    Exchange {
        method: &request.method,
        request_headers: &request.headers,
        status: StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY),
        response_headers: &response.headers,
        request_time: sent,
        response_time: received,
    }
}

fn serve_stored(entry: &Entry, now: SystemTime) -> Response {
    Response {
        status: entry.status,
        reason: reason(entry.status),
        headers: entry.policy.presented_fields(&entry.headers, now),
        body: entry.body.clone(),
    }
}

fn store(
    context: &Context,
    key: &str,
    request: &Request,
    response: &Response,
    sent: SystemTime,
    received: SystemTime,
) {
    if request.method != Method::GET || request.headers.contains_key(header::RANGE) {
        return;
    }
    let exchange = exchange(request, response, sent, received);
    let Ok(policy) = StoredPolicy::new(&context.config, &exchange) else {
        return;
    };
    let headers = StoredPolicy::stored_fields(&context.config, &exchange);
    let mut cache = context.cache.lock().unwrap();
    let list = cache.entry(key.to_owned()).or_default();
    list.retain(|entry| !entry.policy.vary().matches(&request.headers));
    list.push(Entry {
        policy,
        headers,
        status: response.status,
        body: response.body.clone(),
    });
}

fn invalidate(context: &Context, key: &str, response: &Response) {
    let mut cache = context.cache.lock().unwrap();
    cache.remove(key);
    for candidate in invalidation_candidates(&response.headers) {
        let Ok(candidate) = std::str::from_utf8(candidate) else {
            continue;
        };
        let path = if candidate.starts_with('/') {
            Some(candidate)
        } else {
            context
                .prefixes
                .iter()
                .find_map(|prefix| candidate.strip_prefix(prefix.as_str()))
        };
        if let Some(path) = path {
            cache.remove(path);
        }
    }
}

/// Whether `stale-if-error` lets `entry` answer when the origin failed. The
/// crate does not expose `must-revalidate` or `no-cache` yet, so neither
/// restricts this here.
fn stale_if_error_allows(entry: &Entry, now: SystemTime) -> bool {
    let Some(window) = entry.policy.stale_if_error() else {
        return false;
    };
    let staleness = entry
        .policy
        .current_age(now)
        .saturating_sub(entry.policy.freshness_lifetime());
    staleness <= window
}

/// Validate `entry`, stored for `key` at `position`, with the origin, update the
/// cache, and return what the client gets.
fn validate(
    context: &Context,
    key: &str,
    request: &Request,
    position: usize,
    entry: &Entry,
) -> std::io::Result<Response> {
    let client_conditional = [header::IF_NONE_MATCH, header::IF_MODIFIED_SINCE]
        .iter()
        .any(|name| request.headers.contains_key(name));
    let extra = if client_conditional {
        Vec::new()
    } else {
        entry.policy.validation_fields()
    };
    let sent = SystemTime::now();
    let response = forward(&context.origin, request, &extra);
    let received = SystemTime::now();
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            if stale_if_error_allows(entry, received) {
                return Ok(serve_stored(entry, received));
            }
            return Err(error);
        },
    };
    if matches!(response.status, 500 | 502 | 503 | 504) && stale_if_error_allows(entry, received) {
        return Ok(serve_stored(entry, received));
    }
    if response.status != 304 {
        store(context, key, request, &response, sent, received);
        return Ok(response);
    }
    let exchange = exchange(request, &response, sent, received);
    match entry
        .policy
        .freshen(&context.config, &entry.headers, &exchange)
    {
        Ok(freshened) => {
            let mut cache = context.cache.lock().unwrap();
            let list = cache.entry(key.to_owned()).or_default();
            let index = list
                .iter()
                .position(|stored| stored.policy == entry.policy && stored.body == entry.body)
                .unwrap_or(position);
            let served = match freshened.policy {
                Ok(policy) => {
                    let updated = Entry {
                        policy,
                        headers: freshened.headers,
                        status: entry.status,
                        body: entry.body.clone(),
                    };
                    let served = serve_stored(&updated, received);
                    if index < list.len() {
                        list[index] = updated;
                    }
                    served
                },
                Err(_) => {
                    if index < list.len() {
                        list.remove(index);
                    }
                    Response {
                        status: entry.status,
                        reason: reason(entry.status),
                        headers: freshened.headers,
                        body: entry.body.clone(),
                    }
                },
            };
            Ok(if client_conditional { response } else { served })
        },
        Err(FreshenError::ValidatorMismatch) => {
            if let Some(list) = context.cache.lock().unwrap().get_mut(key) {
                list.retain(|stored| stored.policy != entry.policy);
            }
            if client_conditional {
                return Ok(response);
            }
            let sent = SystemTime::now();
            let response = forward(&context.origin, request, &[])?;
            let received = SystemTime::now();
            store(context, key, request, &response, sent, received);
            Ok(response)
        },
        Err(FreshenError::NotNotModified) => unreachable!("the response is a 304"),
    }
}

fn handle(context: &Context, request: Request) -> Response {
    let key = request.target.clone();
    let now = SystemTime::now();
    if !matches!(request.method.as_str(), "GET" | "HEAD") {
        return match forward(&context.origin, &request, &[]) {
            Ok(response) => {
                if invalidates(&request.method, response.status) {
                    invalidate(context, &key, &response);
                }
                response
            },
            Err(_) => gateway_error(502),
        };
    }
    let only_if_cached = RequestDirectives::from_headers(&request.headers).only_if_cached;
    if request.headers.contains_key(header::RANGE) {
        if only_if_cached {
            return gateway_error(504);
        }
        return forward(&context.origin, &request, &[]).unwrap_or_else(|_| gateway_error(502));
    }
    let candidate = context.cache.lock().unwrap().get(&key).and_then(|list| {
        list.iter()
            .enumerate()
            .filter_map(|(position, entry)| {
                let reuse = entry
                    .policy
                    .evaluate(&request.method, &request.headers, now)?;
                Some((position, reuse, entry.clone()))
            })
            .max_by_key(|(_, _, entry)| entry.policy.date())
    });
    match candidate {
        Some((_, Reuse::Fresh | Reuse::StaleAllowed, entry)) => serve_stored(&entry, now),
        Some((position, Reuse::StaleWhileRevalidate, entry)) => {
            let served = serve_stored(&entry, now);
            let context = context.clone();
            let background = Request {
                method: Method::GET,
                target: request.target,
                headers: request.headers,
                body: Vec::new(),
            };
            std::thread::spawn(move || {
                let _ = validate(&context, &key, &background, position, &entry);
            });
            served
        },
        Some((position, Reuse::Validate, entry)) => {
            if only_if_cached {
                return gateway_error(504);
            }
            validate(context, &key, &request, position, &entry)
                .unwrap_or_else(|_| gateway_error(502))
        },
        None => {
            if only_if_cached {
                return gateway_error(504);
            }
            let sent = SystemTime::now();
            match forward(&context.origin, &request, &[]) {
                Ok(response) => {
                    store(context, &key, &request, &response, sent, SystemTime::now());
                    response
                },
                Err(_) => gateway_error(502),
            }
        },
    }
}

fn gateway_error(status: u16) -> Response {
    Response {
        status,
        reason: reason(status),
        headers: HeaderMap::new(),
        body: Vec::new(),
    }
}

fn connection(context: Context, mut stream: TcpStream) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some((line, headers)) = read_head(&mut reader)? else {
        return Ok(());
    };
    let mut parts = line.split(' ');
    let method =
        Method::from_bytes(parts.next().unwrap_or("GET").as_bytes()).unwrap_or(Method::GET);
    let target = parts.next().unwrap_or("/").to_owned();
    let body = read_body(&mut reader, &headers, false)?;
    let request = Request {
        method: method.clone(),
        target,
        headers,
        body,
    };
    let response = handle(&context, request);
    write_response(&mut stream, &method, &response)?;
    stream.flush()
}

/// The URL prefixes of `address` (`host:port`), with `localhost` and `127.0.0.1`
/// as the host.
fn prefixes(address: &str) -> Vec<String> {
    let port = address.rsplit(':').next().unwrap_or("");
    vec![
        format!("http://{address}"),
        format!("http://localhost:{port}"),
        format!("http://127.0.0.1:{port}"),
    ]
}

fn main() {
    let mut args = std::env::args().skip(1);
    let listen = args.next().unwrap_or_else(|| "127.0.0.1:18001".into());
    let origin = args.next().unwrap_or_else(|| "127.0.0.1:18000".into());
    let context = Context {
        cache: Arc::default(),
        config: CacheConfig::default(),
        prefixes: [prefixes(&listen), prefixes(&origin)].concat(),
        origin,
    };
    let listener = TcpListener::bind(&listen).expect("bind");
    eprintln!("caching proxy on {listen} -> {}", context.origin);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let context = context.clone();
        std::thread::spawn(move || {
            let _ = connection(context, stream);
        });
    }
}
