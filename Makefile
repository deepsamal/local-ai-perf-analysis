# Makefile for eBPF AI-agent perf analyzer.
#
# Layered targets:
#   make / make all        — build BPF objects + user binaries + blazesym
#   make mock              — build mock libcudart for tests (no GPU needed)
#   make test              — run mock + unit tests; no GPU required
#   make test-gpu          — run real-CUDA e2e (auto-skips if no nvidia-smi)
#   make test-python       — run Python agent e2e (auto-skips if no torch)
#   make bench             — measure tracer overhead against mock workload
#   make clean             — wipe build artifacts (keeps Cargo cache)
#   make distclean         — clean + wipe Cargo target dir
#
# Build dependencies:
#   * clang, llvm        — compile BPF .c → .bpf.o
#   * libbpf, libelf, zlib — link user-space loaders
#   * cargo / rustc      — build blazesym wrapper (optional; falls back
#                           to lib+offset resolution if absent)

CLANG   ?= clang
LLC     ?= llc
CC      ?= gcc
CARGO   ?= cargo

# Directories
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
USER_DIR := $(SRC_DIR)/user
SYM_DIR := $(SRC_DIR)/symbolize
INC_DIR := include
BIN_DIR := bin
OBJ_DIR := obj
TEST_DIR := tests

# Flags
CLANG_FLAGS := -O2 -target bpf -D__TARGET_ARCH_x86 -D__BPF_TRACING__ \
               -I$(INC_DIR) \
               -I/usr/include/$(shell uname -m)-linux-gnu \
               -g -Wall
CFLAGS  := -O2 -Wall -I$(INC_DIR) -I$(SYM_DIR)
LDFLAGS := -lbpf -lelf -lz

# blazesym static archive (built by `cargo build --release`).
# A static archive lets us avoid an LD_LIBRARY_PATH dance at runtime.
BLAZESYM_LIB := $(SYM_DIR)/target/release/libblazesym_wrap.a
BLAZESYM_LDFLAGS := -lpthread -ldl -lm

# Detect cargo at config time; if absent we still build everything else
# and unified_trace falls back to the raw-address resolver.
HAVE_CARGO := $(shell command -v $(CARGO) 2>/dev/null)

# Find all BPF and user programs
BPF_SRC := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJ := $(patsubst $(BPF_DIR)/%.bpf.c,$(OBJ_DIR)/%.bpf.o,$(BPF_SRC))

USER_SRC := $(wildcard $(USER_DIR)/*.c)
USER_BIN := $(patsubst $(USER_DIR)/%.c,$(BIN_DIR)/%,$(USER_SRC))

.PHONY: all clean distclean dirs symbolize mock test test-gpu test-python bench help

all: dirs $(BPF_OBJ) $(USER_BIN)

dirs:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)

# ---------- BPF programs ----------

$(OBJ_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(INC_DIR)/common.h $(INC_DIR)/maps.h
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# ---------- blazesym wrapper (Rust) ----------

ifdef HAVE_CARGO
symbolize: $(BLAZESYM_LIB)

$(BLAZESYM_LIB): $(SYM_DIR)/blazesym_wrap.rs $(SYM_DIR)/Cargo.toml
	$(CARGO) build --release --manifest-path $(SYM_DIR)/Cargo.toml
else
symbolize:
	@echo "WARNING: cargo not found; unified_trace will fall back to raw-address stacks"
$(BLAZESYM_LIB):
	@:
endif

# ---------- user-space binaries ----------

# Default rule for simple loaders (trace_exec, trace_cuda, count_packets).
$(BIN_DIR)/%: $(USER_DIR)/%.c $(INC_DIR)/common.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# unified_trace links the blazesym archive when available. Falling
# back to a stub keeps the build succeeding in environments without
# Rust; the C side has runtime null-checks for symbolizer == NULL.
ifdef HAVE_CARGO
$(BIN_DIR)/unified_trace: $(USER_DIR)/unified_trace.c \
                          $(OBJ_DIR)/trace_cpu_sched.bpf.o \
                          $(OBJ_DIR)/trace_cuda.bpf.o \
                          $(BLAZESYM_LIB) \
                          $(SYM_DIR)/blazesym_wrap.h \
                          $(INC_DIR)/common.h
	$(CC) $(CFLAGS) $< $(BLAZESYM_LIB) -o $@ $(LDFLAGS) $(BLAZESYM_LDFLAGS)
else
# Stub: a tiny .c that satisfies bsw_* symbols by returning NULL/0.
$(OBJ_DIR)/blazesym_stub.o: $(SYM_DIR)/blazesym_wrap.h
	@mkdir -p $(OBJ_DIR)
	@printf '%s\n' \
	  '#include "blazesym_wrap.h"' \
	  '#include <string.h>' \
	  'bsw_symbolizer_t *bsw_new(void){ return NULL; }' \
	  'void bsw_free(bsw_symbolizer_t *s){ (void)s; }' \
	  'size_t bsw_resolve(bsw_symbolizer_t *s, uint32_t p, const uint64_t *a, size_t n, struct bsw_frame *o, size_t c){ (void)s;(void)p;(void)a;(void)n;(void)o;(void)c; return 0; }' \
	  'int bsw_version(char *b, size_t c){ if(c){strncpy(b,"stub",c);b[c-1]=0;} return 0; }' \
	  > $(OBJ_DIR)/blazesym_stub.c
	$(CC) $(CFLAGS) -c $(OBJ_DIR)/blazesym_stub.c -o $@

$(BIN_DIR)/unified_trace: $(USER_DIR)/unified_trace.c \
                          $(OBJ_DIR)/trace_cpu_sched.bpf.o \
                          $(OBJ_DIR)/trace_cuda.bpf.o \
                          $(OBJ_DIR)/blazesym_stub.o \
                          $(SYM_DIR)/blazesym_wrap.h \
                          $(INC_DIR)/common.h
	$(CC) $(CFLAGS) $< $(OBJ_DIR)/blazesym_stub.o -o $@ $(LDFLAGS)
endif

# ---------- mock CUDA / test workload ----------

mock:
	$(MAKE) -C $(TEST_DIR)/mock

# ---------- tests ----------

test: all mock
	@echo "=== running mock+unit tests (no GPU required) ==="
	@$(MAKE) -C $(TEST_DIR)/unit test
	@bash $(TEST_DIR)/e2e/run_mock.sh

test-gpu: all
	@if ! command -v nvidia-smi >/dev/null 2>&1; then \
		echo "SKIP: nvidia-smi not found; no GPU available"; exit 0; \
	fi
	@bash $(TEST_DIR)/e2e/run_gpu.sh

test-python: all
	@if ! python3 -c "import torch" 2>/dev/null; then \
		echo "SKIP: python3 + torch not available"; exit 0; \
	fi
	@bash $(TEST_DIR)/e2e/run_python_agent.sh

bench: all mock
	@bash $(TEST_DIR)/e2e/run_mock.sh --bench

# ---------- maintenance ----------

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)
	$(MAKE) -C $(TEST_DIR)/mock clean 2>/dev/null || true
	$(MAKE) -C $(TEST_DIR)/unit clean 2>/dev/null || true

distclean: clean
	rm -rf $(SYM_DIR)/target

help:
	@echo "eBPF AI-agent perf analyzer"
	@echo "  make             - build BPF objects, user binaries, symbolizer"
	@echo "  make mock        - build mock libcudart for tests (no GPU)"
	@echo "  make test        - mock + unit tests"
	@echo "  make test-gpu    - real-CUDA e2e (auto-skips w/o GPU)"
	@echo "  make test-python - Python agent e2e (auto-skips w/o torch)"
	@echo "  make bench       - measure tracer overhead on mock workload"
	@echo "  make clean       - remove build artifacts"
	@echo "  make distclean   - clean + remove Cargo target"
