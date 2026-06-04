# Unit tests for unified_trace utility functions.
#
# These tests don't link against libbpf — they cover pure-C helpers
# (event sorting, JSON escaping) by including the relevant source
# directly. This keeps the unit tier fast and dependency-free.

CC      ?= gcc
CFLAGS  ?= -O0 -g -Wall -I../../include -I../../src/symbolize

TESTS := test_event_sort test_chrome_json

.PHONY: all test clean

all: $(TESTS)

test: all
	@echo "=== unit tests ==="
	@for t in $(TESTS); do \
		echo "--- $$t"; \
		./$$t || exit 1; \
	done
	@echo "=== unit tests OK ==="

test_event_sort: test_event_sort.c
	$(CC) $(CFLAGS) $< -o $@

test_chrome_json: test_chrome_json.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TESTS)
