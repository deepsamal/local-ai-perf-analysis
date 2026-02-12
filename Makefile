# Makefile for eBPF project

CLANG ?= clang
LLC ?= llc
CC ?= gcc

# Directories
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
USER_DIR := $(SRC_DIR)/user
INC_DIR := include
BIN_DIR := bin
OBJ_DIR := obj

# Flags
CLANG_FLAGS := -O2 -target bpf -D__TARGET_ARCH_x86 -D__BPF_TRACING__ \
               -I$(INC_DIR) \
               -I/usr/include/$(shell uname -m)-linux-gnu \
               -g -Wall
CFLAGS := -O2 -Wall -I$(INC_DIR)
LDFLAGS := -lbpf -lelf -lz

# Find all BPF and user programs
BPF_SRC := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJ := $(patsubst $(BPF_DIR)/%.bpf.c,$(OBJ_DIR)/%.bpf.o,$(BPF_SRC))

USER_SRC := $(wildcard $(USER_DIR)/*.c)
USER_BIN := $(patsubst $(USER_DIR)/%.c,$(BIN_DIR)/%,$(USER_SRC))

.PHONY: all clean dirs

all: dirs $(BPF_OBJ) $(USER_BIN)

dirs:
	@mkdir -p $(BIN_DIR) $(OBJ_DIR)

# Compile BPF programs
$(OBJ_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

# Compile user-space programs (general rule)
$(BIN_DIR)/%: $(USER_DIR)/%.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Special rule for unified_trace (needs multiple BPF objects)
$(BIN_DIR)/unified_trace: $(USER_DIR)/unified_trace.c $(OBJ_DIR)/trace_cpu_sched.bpf.o $(OBJ_DIR)/trace_cuda.bpf.o
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -rf $(BIN_DIR) $(OBJ_DIR)

help:
	@echo "eBPF Tool Makefile"
	@echo "  make          - Build all programs"
	@echo "  make clean    - Remove build artifacts"
	@echo "  make help     - Show this help"
