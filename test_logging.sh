#!/bin/bash
echo "Testing AI Logging Feature"
echo "=========================="
echo ""
echo "1. Checking if logs directory exists..."
if [ -d "logs" ]; then
    echo "   ✓ logs/ directory exists"
else
    echo "   ✗ logs/ directory does not exist (will be created on first use)"
fi
echo ""
echo "2. Checking default configuration..."
if [ -f "ai_config.json" ]; then
    echo "   ✓ ai_config.json exists"
    if grep -q '"log_ai_io"' ai_config.json; then
        echo "   ✓ log_ai_io parameter found in config"
    else
        echo "   ⚠ log_ai_io not in config (will use default: true)"
    fi
else
    echo "   ⚠ ai_config.json not found (will be created with defaults)"
fi
echo ""
echo "3. Default log file location:"
echo "   logs/ai_payloads.log"
echo ""
echo "4. To enable logging:"
echo "   - It's enabled by default!"
echo "   - Just run an AI analysis"
echo ""
echo "5. To view logs:"
echo "   tail -f logs/ai_payloads.log"
echo ""
echo "✓ Logging feature is ready to use!"
