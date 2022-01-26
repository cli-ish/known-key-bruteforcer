#!/bin/bash
echo "Build release..."
cargo build --release
# shellcheck disable=SC2012
echo "Current size: $(ls -all -h ./target/release/known-key-bruteforcer | awk '{print $5}')"
echo "Strip binary..."
strip ./target/release/known-key-bruteforcer
echo "Final size: $(ls -all -h ./target/release/known-key-bruteforcer | awk '{print $5}')"
echo "Done..."
./target/release/known-key-bruteforcer -h