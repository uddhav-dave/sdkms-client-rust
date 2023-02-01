#!/bin/bash -ex

set -exo pipefail

# Testing Async Interface with integration tests and an example
cargo test --features async --tests --lib --example 'async_*'

# Testing blocking interface
cargo test --tests --lib

# compile check all examples
cargo test --examples
