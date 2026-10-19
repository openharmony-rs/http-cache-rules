# http-cache-rules

This is an experimental crate, written largely by an AI-agent. 

The caching rules of [RFC 9111] for a private HTTP cache, such as a web
browser's, with [RFC 5861] `stale-while-revalidate` and the cache-related steps
of the [Fetch] standard.

The crate does not implement a cache itself. Given a request and its response, it returns
whether the response may be stored and which header fields to keep. Given a
stored response and a new request, it says whether the stored response may be
used as it is, used while it is revalidated in the background, or only used
after validation, and which precondition fields to send. Given a 304, it updates
the stored fields and computes the new freshness. Bodies, keys, eviction and I/O
stay with the caller.

```rust
let policy = StoredPolicy::new(&config, &exchange)?;          // §3, or why not
let fields = StoredPolicy::stored_fields(&config, &exchange); // §3.1
match policy.evaluate(&method, &request_headers, now) {       // §4
    Some(Reuse::Fresh | Reuse::StaleAllowed) => serve(policy.presented_fields(&fields, now)),
    Some(Reuse::StaleWhileRevalidate) => { /* serve, revalidate in the background */ }
    Some(Reuse::Validate) => send_with(policy.validation_fields()), // §4.3.1
    None => send_unconditionally(),
}
// On a 304:
let freshened = policy.freshen(&config, &fields, &not_modified_exchange)?; // §4.3.4
```

## How it is verified

- **Traceability.** [`SPEC.md`](SPEC.md) lists each requirement of RFC 9111,
  RFC 9110, RFC 5861 and Fetch that the crate implements, quoting the text,
  plus every deliberate deviation and choice with its justification.
  `tests/spec.rs` fails if a requirement has no test or proof named after it, or
  if a test names a requirement that does not exist.
- **Model checking.** `src/proofs.rs` states requirements as predicates written
  from the specification text and proves with [Kani] that the implementation
  satisfies them for every input:
  - storability is exactly §3;
  - the freshness lifetime follows §4.2.1, and the heuristic of §4.2.2 is only
    used when allowed and never exceeds its interval or cap;
  - age is the §4.2.3 formula with saturation, and never decreases;
  - a stale response is only used when §4.2.4 permits it, and `no-cache`,
    `must-revalidate`, `max-age` and `min-fresh` are honoured;
  - a strong `ETag` in a 304 must match before it updates anything;
  - the date parser never panics and only returns representable times (inputs
    of up to 34 bytes, which covers every valid length);
  - each step of the `Cache-Control` parser makes progress, so the parser
    terminates.
- **Exhaustive tests** where model checking is too slow: every instant from
  1970 to 9999 round-trips through the date formatter and parser, and the
  heuristic is the exact fraction for every percentage and every interval up to
  20 000 s and around every power of two (property tests sample the rest).
- **Web-platform-tests.** `tests/wpt.rs` replays the cases of
  `fetch/http-cache/` that concern these rules against a simulated cache and
  test server.
- **HTTP caching tests.** `just cache-tests` runs the suite of
  [cache-tests.fyi] in browser-cache mode through a minimal private cache built
  on the crate (`tests/cache-tests/proxy.rs`), and fails if any result differs
  from `tests/cache-tests/expected.json`. Its expectations were written by
  another author than the crate's.
- **Property tests and fuzzing.** `tests/properties.rs` checks the date parser
  against the `httpdate` crate, the `Cache-Control` parser and the 304 header
  update against reference models, and API invariants over generated inputs.
  `fuzz/` has libFuzzer targets for the parsers and a whole round through the
  API.
- **Mutation testing** with `cargo mutants`: every viable mutant is caught,
  except one equivalent mutant listed with its reason in
  `.cargo/mutants.toml`.

```sh
cargo test
cargo kani                       # https://model-checking.github.io/kani/
cargo +nightly fuzz run exchange # also: http_date, directives
cargo mutants
just cache-tests                 # needs Node.js and network access
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.

[RFC 9111]: https://www.rfc-editor.org/rfc/rfc9111
[RFC 5861]: https://www.rfc-editor.org/rfc/rfc5861
[Fetch]: https://fetch.spec.whatwg.org/
[Kani]: https://model-checking.github.io/kani/
[cache-tests.fyi]: https://cache-tests.fyi/
