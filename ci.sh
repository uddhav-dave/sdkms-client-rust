#!/bin/bash

set -exo pipefail

echo
echo -- TESTING ASYNC API ---
echo
cargo test --features async --test async_calls --example 'async_*'

echo
echo -- TESTING SYNC API ---
echo
cargo test --examples