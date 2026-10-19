# The commit of https://github.com/http-tests/cache-tests that `cache-tests` runs.
cache_tests_rev := "d644cf4bf487763646aac19d2c8b846daa0f604d"
target_dir := env("CARGO_TARGET_DIR", justfile_directory() / "target")

# Run the HTTP caching tests of cache-tests.fyi through a cache built on this crate, and compare
# the results with tests/cache-tests/expected.json (`just cache-tests --update` rewrites it).
cache-tests *args:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release --example cache-tests-proxy
    suite="{{ target_dir }}/cache-tests"
    if [ "$(git -C "$suite" rev-parse -q --verify HEAD 2>/dev/null)" != "{{ cache_tests_rev }}" ]; then
        git init -q "$suite"
        git -C "$suite" fetch -q --depth 1 https://github.com/http-tests/cache-tests "{{ cache_tests_rev }}"
        git -C "$suite" checkout -q --force FETCH_HEAD
    fi
    node tests/cache-tests/run.mjs "$suite" "{{ target_dir }}/release/examples/cache-tests-proxy" {{ args }}
