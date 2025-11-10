#!/bin/bash

# Test script to verify config reload works without restart

echo "Testing Config Reload Fix"
echo "========================="
echo ""

# Check if ai_config.json exists
if [ ! -f "ai_config.json" ]; then
    echo "✓ No existing ai_config.json - will use defaults"
else
    echo "✓ Found existing ai_config.json"
    echo "  Current service: $(grep -o '"service"[[:space:]]*:[[:space:]]*"[^"]*"' ai_config.json | cut -d'"' -f4)"
fi

echo ""
echo "Instructions to test:"
echo "1. Start the application: ./patchleaks"
echo "2. Open the web interface in your browser"
echo "3. Navigate to AI Settings"
echo "4. Change AI service or any other setting"
echo "5. Save the settings"
echo "6. Check the terminal logs - you should see:"
echo "   'AI config reloaded successfully - changes are now active'"
echo "7. The new settings should be used immediately without restart"
echo ""
echo "What was fixed:"
echo "- The handler was creating a local 'config' variable that shadowed the global one"
echo "- Now it uses 'newConfig' and properly updates the global 'config' variable"
echo "- Additional parameters (like log_ai_io) are preserved during save"
echo ""
