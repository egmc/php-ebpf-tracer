#!/bin/sh
# Hammers the demo app so the tracer has something to sample.
set -eu

TARGET="${TARGET:-http://php:8080}"
INTERVAL="${INTERVAL:-1}"

echo "load generator -> $TARGET"

# Wait for the app to come up.
until curl -fsS -o /dev/null "$TARGET/" 2>/dev/null; do
	sleep 1
done

while true; do
	for path in /fast /slow /random /fast /error; do
		curl -fsS -o /dev/null "$TARGET$path" 2>/dev/null || true
	done
	sleep "$INTERVAL"
done
