#!/usr/bin/env bash

set -u

time nix flake check -j2 -v -L >flake-check.stdout 2>flake-check.stderr
code=$?
printf 'exit_code=%s\n' "$code" >flake-check.exit_code
printf '=== STDOUT ===\n'
cat flake-check.stdout
printf '=== STDERR ===\n'
cat flake-check.stderr
printf '=== EXIT_CODE ===\n'
cat flake-check.exit_code

exit "$code"
