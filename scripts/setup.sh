#!/bin/bash
# Setup script for eBPF development environment

set -e

echo "Installing eBPF development dependencies..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

case "$OS" in
    ubuntu|debian)
        sudo apt-get update
        sudo apt-get install -y \
            clang llvm \
            libbpf-dev \
            linux-headers-$(uname -r) \
            build-essential \
            libelf-dev \
            zlib1g-dev
        ;;
    fedora|rhel|centos)
        sudo dnf install -y \
            clang llvm \
            libbpf-devel \
            kernel-devel \
            elfutils-libelf-devel \
            zlib-devel
        ;;
    arch)
        sudo pacman -S --needed \
            clang llvm \
            libbpf \
            linux-headers \
            base-devel \
            elfutils
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "Dependencies installed successfully!"
echo "Run 'make' to build the project."
