#!/bin/sh
set -eu

mkdir -p coverage
profile="coverage/coverage.out"
go test ./... -coverprofile="$profile"
total="$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')"
awk -v total="$total" 'BEGIN { if (total + 0 < 80) { printf "coverage %.1f%% is below 80%%\n", total; exit 1 } }'
go tool cover -html="$profile" -o coverage/index.html
printf 'coverage %.1f%% (minimum 80%%)\n' "$total"
