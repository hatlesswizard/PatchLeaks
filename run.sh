#!/bin/bash

# PatchLeaks Go - Quick Start Script

set -e

echo "═══════════════════════════════════════════════════════════════"
echo "  PatchLeaks - Go Implementation"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go 1.21 or higher."
    echo "   Visit: https://go.dev/dl/"
    exit 1
fi

echo "✅ Go version: $(go version)"
echo ""

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.21"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "❌ Go version $GO_VERSION is too old. Please upgrade to Go 1.21 or higher."
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
go mod download
if [ $? -ne 0 ]; then
    echo "❌ Failed to download dependencies"
    exit 1
fi
echo "✅ Dependencies installed"
echo ""

# Build the application
echo "🔨 Building application..."
go build -o patchleaks
if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi
echo "✅ Build successful"
echo ""

# Check if templates need conversion
if grep -q "{% for" templates/*.html 2>/dev/null; then
    echo "⚠️  WARNING: Templates still use Jinja2 syntax"
    echo "   Please convert templates to Go syntax before running"
    echo "   See TEMPLATE_EXAMPLES.md for conversion guide"
    echo ""
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Run the application
echo "🚀 Starting PatchLeaks..."
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""

./patchleaks "$@"

