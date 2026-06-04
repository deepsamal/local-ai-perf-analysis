# Mock libcudart + workload driver.
#
# These are built without any project deps so they work even on a
# minimal CI runner.

CC      ?= gcc
CFLAGS  ?= -O2 -Wall

LIB := libfake_cudart.so
BIN := workload

.PHONY: all clean

all: $(LIB) $(BIN)

# -fPIC + -shared for the mock library; no symbol export list because
# the tracer attaches by name and we want everything visible.
$(LIB): fake_cudart.c
	$(CC) $(CFLAGS) -fPIC -shared $< -o $@

# Workload links nothing CUDA-related; it dlopens the mock at runtime.
$(BIN): workload.c
	$(CC) $(CFLAGS) $< -o $@ -ldl

clean:
	rm -f $(LIB) $(BIN)
