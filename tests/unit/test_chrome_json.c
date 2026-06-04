/* SPDX-License-Identifier: MIT */
/*
 * Unit test for the JSON-escape helper used by unified_trace's stack
 * emitter. Symbol names are attacker-controlled in principle (they
 * come from /proc/<pid>/maps + DWARF in the traced process) so any
 * unescaped quote or control byte would break the trace JSON.
 *
 * Like test_event_sort.c, we re-declare the function rather than
 * include unified_trace.c. The body must stay in sync.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static void json_escape(char *dst, size_t dst_len, const char *src)
{
    size_t di = 0;
    if (dst_len == 0) return;
    for (size_t si = 0; src[si] && di + 2 < dst_len; si++) {
        unsigned char c = (unsigned char)src[si];
        if (c == '"' || c == '\\') {
            if (di + 3 >= dst_len) break;
            dst[di++] = '\\';
            dst[di++] = c;
        } else if (c < 0x20) {
            if (di + 7 >= dst_len) break;
            di += snprintf(dst + di, dst_len - di, "\\u%04x", c);
        } else {
            dst[di++] = c;
        }
    }
    dst[di] = '\0';
}

static void expect_equal(const char *got, const char *want, const char *label)
{
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "FAIL %s: got %s want %s\n", label, got, want);
        exit(1);
    }
}

int main(void)
{
    char buf[256];

    /* Ordinary symbol — unchanged. */
    json_escape(buf, sizeof(buf), "ggml_cuda_op_mul_mat");
    expect_equal(buf, "ggml_cuda_op_mul_mat", "plain");

    /* Embedded double-quote — must be escaped. */
    json_escape(buf, sizeof(buf), "frame\"with\"quotes");
    expect_equal(buf, "frame\\\"with\\\"quotes", "quotes");

    /* Backslash. */
    json_escape(buf, sizeof(buf), "C:\\path\\to\\file");
    expect_equal(buf, "C:\\\\path\\\\to\\\\file", "backslash");

    /* C++ template name with angle brackets — no escaping needed. */
    json_escape(buf, sizeof(buf), "std::vector<int>::push_back");
    expect_equal(buf, "std::vector<int>::push_back", "template");

    /* Newline (control char) — should become
. */
    char in[] = "line1\nline2";
    json_escape(buf, sizeof(buf), in);
    expect_equal(buf, "line1\\u000aline2", "newline");

    /* Truncation: dst too small — must NUL-terminate, not overflow. */
    char small[8];
    json_escape(small, sizeof(small), "abcdefghijklmnop");
    assert(strlen(small) < sizeof(small));
    assert(small[sizeof(small) - 1] == '\0');

    /* Zero-length destination — must not write. */
    char zero[1] = { 0x7F };
    json_escape(zero, 0, "anything");
    assert(zero[0] == 0x7F);

    /* Empty input — produces empty output. */
    json_escape(buf, sizeof(buf), "");
    expect_equal(buf, "", "empty");

    printf("OK test_chrome_json: 8 cases passed\n");
    return 0;
}
