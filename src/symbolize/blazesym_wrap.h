/* SPDX-License-Identifier: GPL-2.0 */
/*
 * C ABI to the blazesym_wrap Rust static library.
 *
 * Build pipeline:
 *   cargo build --release --manifest-path src/symbolize/Cargo.toml
 *   gcc unified_trace.c -L src/symbolize/target/release -lblazesym_wrap \
 *       -lpthread -ldl -o bin/unified_trace
 *
 * Lifecycle:
 *   void *sym = bsw_new();
 *   ...for each batch of addresses captured from BPF:
 *     struct bsw_frame frames[MAX];
 *     size_t n = bsw_resolve(sym, pid, addrs, naddrs, frames, MAX);
 *     for (size_t i = 0; i < n; i++)
 *         printf("%s @ %s:%u\n", frames[i].sym, frames[i].file, frames[i].line);
 *   bsw_free(sym);
 */

#ifndef BLAZESYM_WRAP_H
#define BLAZESYM_WRAP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Keep this aligned with BswFrame in blazesym_wrap.rs.
 * Any change here MUST be mirrored in the Rust struct or you'll get
 * silent memory corruption when the ABI drifts.
 */
#define BSW_STR_MAX 512

struct bsw_frame {
    uint64_t addr;
    uint32_t line;
    uint8_t  inlined;
    /* 3 bytes of padding implied; struct alignment kept simple. */
    char     sym[BSW_STR_MAX];
    char     file[BSW_STR_MAX];
    char     lib[BSW_STR_MAX];
};

/* Opaque handle. Internally a *Symbolizer on the Rust side. */
typedef struct bsw_symbolizer bsw_symbolizer_t;

bsw_symbolizer_t *bsw_new(void);
void bsw_free(bsw_symbolizer_t *sym);

/* Resolve up to `out_cap` frames from `n` raw user-space addresses.
 * Returns the number of frames actually written (may exceed `n` due
 * to inlined-frame expansion). Returns 0 on any error.
 */
size_t bsw_resolve(bsw_symbolizer_t *sym,
                   uint32_t pid,
                   const uint64_t *addrs,
                   size_t n,
                   struct bsw_frame *out,
                   size_t out_cap);

/* Writes the wrapper's CARGO_PKG_VERSION into `buf`. Returns 0 on success. */
int bsw_version(char *buf, size_t buf_cap);

#ifdef __cplusplus
}
#endif

#endif /* BLAZESYM_WRAP_H */
