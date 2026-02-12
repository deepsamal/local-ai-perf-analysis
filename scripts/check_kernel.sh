#!/bin/bash
# Check if kernel supports eBPF features

echo "Checking kernel eBPF support..."
echo

# Check kernel version
KERNEL_VERSION=$(uname -r)
echo "Kernel version: $KERNEL_VERSION"

# Check for BPF filesystem
if mount | grep -q bpffs; then
    echo "✓ BPF filesystem mounted"
else
    echo "✗ BPF filesystem not mounted"
    echo "  Run: sudo mount -t bpf bpf /sys/fs/bpf/"
fi

# Check for required kernel configs
CONFIGS=(
    "CONFIG_BPF=y"
    "CONFIG_BPF_SYSCALL=y"
    "CONFIG_BPF_JIT=y"
    "CONFIG_HAVE_EBPF_JIT=y"
)

if [ -f /proc/config.gz ]; then
    CONFIG_FILE=/proc/config.gz
    CAT_CMD="zcat"
elif [ -f /boot/config-$(uname -r) ]; then
    CONFIG_FILE=/boot/config-$(uname -r)
    CAT_CMD="cat"
else
    echo "⚠ Cannot find kernel config file"
    exit 0
fi

echo
echo "Kernel configuration:"
for config in "${CONFIGS[@]}"; do
    if $CAT_CMD $CONFIG_FILE 2>/dev/null | grep -q "^$config"; then
        echo "✓ $config"
    else
        echo "✗ $config"
    fi
done

echo
echo "Check complete!"
