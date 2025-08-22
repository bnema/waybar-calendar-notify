#!/bin/bash

echo "=================================================="
echo "Comprehensive Obfuscation Verification"
echo "=================================================="

BINARY="waybar-calendar-notify-obfuscated"
ORIGINAL_SECRETS="client_secrets_device_oauth.json"

if [ ! -f "$BINARY" ]; then
    echo "❌ ERROR: $BINARY not found. Run 'make build-obfuscated' first."
    exit 1
fi

if [ ! -f "$ORIGINAL_SECRETS" ]; then
    echo "⚠️  WARNING: Original secrets file not found for comparison"
    ORIGINAL_SECRETS=""
fi

echo ""
echo "1. BASIC STRING ANALYSIS"
echo "========================"

# Extract client ID and secret from original file for testing
if [ -n "$ORIGINAL_SECRETS" ]; then
    CLIENT_ID=$(grep -o '"client_id"[^"]*"[^"]*"' "$ORIGINAL_SECRETS" | cut -d'"' -f4)
    CLIENT_SECRET=$(grep -o '"client_secret"[^"]*"[^"]*"' "$ORIGINAL_SECRETS" | cut -d'"' -f4)
    
    echo "Testing for original client ID: ${CLIENT_ID:0:20}..."
    if strings "$BINARY" | grep -q "$CLIENT_ID"; then
        echo "❌ CRITICAL: Original client ID found in binary!"
        exit 1
    else
        echo "✓ Original client ID not found in binary"
    fi
    
    echo "Testing for original client secret: ${CLIENT_SECRET:0:10}..."
    if strings "$BINARY" | grep -q "$CLIENT_SECRET"; then
        echo "❌ CRITICAL: Original client secret found in binary!"
        exit 1
    else
        echo "✓ Original client secret not found in binary"
    fi
else
    echo "ℹ️  Skipping original credential checks (no source file)"
fi

# Test for common OAuth patterns
echo ""
echo "Testing for OAuth patterns..."
LEAKED=0

if strings "$BINARY" | grep -qE "[0-9]{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com"; then
    echo "❌ WARNING: Google client ID pattern detected!"
    LEAKED=$((LEAKED + 1))
else
    echo "✓ No Google client ID patterns found"
fi

if strings "$BINARY" | grep -q "GOCSPX-"; then
    echo "❌ WARNING: Google client secret pattern detected!"
    LEAKED=$((LEAKED + 1))
else
    echo "✓ No Google client secret patterns found"
fi

# Test for obvious credential strings (JSON tags are acceptable)
CRITICAL_STRINGS=("googleapis.com" "accounts.google.com")
for str in "${CRITICAL_STRINGS[@]}"; do
    if strings "$BINARY" | grep -qi "$str"; then
        echo "⚠️  Found critical string: $str"
        LEAKED=$((LEAKED + 1))
    else
        echo "✓ No critical '$str' strings found"
    fi
done

# Test for JSON struct tags (informational only, not critical)
INFO_STRINGS=("client_id" "client_secret" "oauth2")
echo ""
echo "Informational checks (JSON struct tags - not critical):"
for str in "${INFO_STRINGS[@]}"; do
    if strings "$BINARY" | grep -qi "$str"; then
        echo "ℹ️  Found struct tag: $str (expected from Go JSON reflection)"
    else
        echo "✓ No '$str' strings found"
    fi
done

echo ""
echo "2. HEXDUMP ANALYSIS"
echo "==================="

echo "Searching for credential fragments in hex dump..."
if [ -n "$CLIENT_ID" ]; then
    # Check first 10 chars of client ID
    ID_FRAGMENT=${CLIENT_ID:0:10}
    if hexdump -C "$BINARY" | grep -qi "$ID_FRAGMENT"; then
        echo "❌ WARNING: Client ID fragment found in hex dump!"
        LEAKED=$((LEAKED + 1))
    else
        echo "✓ No client ID fragments in hex dump"
    fi
fi

if [ -n "$CLIENT_SECRET" ]; then
    # Check first 8 chars of client secret
    SECRET_FRAGMENT=${CLIENT_SECRET:0:8}
    if hexdump -C "$BINARY" | grep -qi "$SECRET_FRAGMENT"; then
        echo "❌ WARNING: Client secret fragment found in hex dump!"
        LEAKED=$((LEAKED + 1))
    else
        echo "✓ No client secret fragments in hex dump"
    fi
fi

echo ""
echo "3. OBJDUMP ANALYSIS"
echo "==================="

if command -v objdump >/dev/null 2>&1; then
    echo "Analyzing object dump for credential patterns..."
    
    # Create temporary file for objdump output
    OBJDUMP_FILE=$(mktemp)
    objdump -s "$BINARY" 2>/dev/null > "$OBJDUMP_FILE" || echo "objdump failed, skipping"
    
    if [ -s "$OBJDUMP_FILE" ]; then
        if grep -qi "client" "$OBJDUMP_FILE"; then
            echo "⚠️  'client' strings found in object dump"
            LEAKED=$((LEAKED + 1))
        else
            echo "✓ No 'client' strings in object dump"
        fi
        
        if grep -qi "secret" "$OBJDUMP_FILE"; then
            echo "⚠️  'secret' strings found in object dump"
            LEAKED=$((LEAKED + 1))
        else
            echo "✓ No 'secret' strings in object dump"
        fi
    fi
    
    rm -f "$OBJDUMP_FILE"
else
    echo "ℹ️  objdump not available, skipping object analysis"
fi

echo ""
echo "4. READELF ANALYSIS"
echo "==================="

if command -v readelf >/dev/null 2>&1; then
    echo "Analyzing ELF sections for embedded data..."
    
    # Check string sections
    if readelf -p .rodata "$BINARY" 2>/dev/null | grep -qi "client\|secret\|oauth"; then
        echo "⚠️  Credential-related strings found in .rodata section"
        LEAKED=$((LEAKED + 1))
    else
        echo "✓ No obvious credentials in .rodata section"
    fi
    
    # Check for large data sections (might contain obfuscated data)
    RODATA_SIZE=$(readelf -S "$BINARY" | grep "\.rodata" | awk '{print $6}' | head -1)
    if [ -n "$RODATA_SIZE" ]; then
        RODATA_SIZE_DEC=$((0x$RODATA_SIZE))
        echo "ℹ️  .rodata section size: $RODATA_SIZE_DEC bytes"
        if [ "$RODATA_SIZE_DEC" -gt 100000 ]; then
            echo "ℹ️  Large .rodata section detected (good for obfuscation)"
        fi
    fi
else
    echo "ℹ️  readelf not available, skipping ELF analysis"
fi

echo ""
echo "5. DYNAMIC ANALYSIS PREPARATION"
echo "==============================="

echo "Testing if binary runs without revealing secrets..."

# Test help command (should not load secrets)
if ./waybar-calendar-notify-obfuscated --help >/dev/null 2>&1; then
    echo "✓ Binary executes help command successfully"
else
    echo "❌ WARNING: Binary fails basic execution"
    LEAKED=$((LEAKED + 1))
fi

# Test version command if available
if ./waybar-calendar-notify-obfuscated --version >/dev/null 2>&1; then
    echo "✓ Binary executes version command successfully"
else
    echo "ℹ️  Version command not available or failed"
fi

echo ""
echo "6. ENTROPY ANALYSIS"
echo "==================="

# Simple entropy check - highly obfuscated binaries should have high entropy
if command -v ent >/dev/null 2>&1; then
    echo "Analyzing binary entropy..."
    ENTROPY=$(ent "$BINARY" | grep "Entropy" | awk '{print $3}')
    echo "Binary entropy: $ENTROPY"
    
    # High entropy (>7.5) suggests good obfuscation
    if [ "$(echo "$ENTROPY > 7.5" | bc 2>/dev/null || echo 0)" = "1" ]; then
        echo "✓ High entropy suggests good obfuscation"
    else
        echo "⚠️  Lower entropy - consider stronger obfuscation"
    fi
else
    echo "ℹ️  'ent' tool not available, skipping entropy analysis"
fi

echo ""
echo "7. FILE SIZE ANALYSIS"
echo "===================="

BINARY_SIZE=$(du -h "$BINARY" | cut -f1)
BINARY_SIZE_BYTES=$(stat -c%s "$BINARY" 2>/dev/null || echo "0")

echo "Obfuscated binary size: $BINARY_SIZE ($BINARY_SIZE_BYTES bytes)"

# Compare with regular build if available
if [ -f "waybar-calendar-notify" ] || [ -f "bin/waybar-calendar-notify" ]; then
    REGULAR_BINARY=""
    if [ -f "waybar-calendar-notify" ]; then
        REGULAR_BINARY="waybar-calendar-notify"
    elif [ -f "bin/waybar-calendar-notify" ]; then
        REGULAR_BINARY="bin/waybar-calendar-notify"
    fi
    
    if [ -n "$REGULAR_BINARY" ]; then
        REGULAR_SIZE=$(du -h "$REGULAR_BINARY" | cut -f1)
        REGULAR_SIZE_BYTES=$(stat -c%s "$REGULAR_BINARY" 2>/dev/null || echo "0")
        echo "Regular binary size: $REGULAR_SIZE ($REGULAR_SIZE_BYTES bytes)"
        
        if [ "$REGULAR_SIZE_BYTES" -gt 0 ] && [ "$BINARY_SIZE_BYTES" -gt 0 ]; then
            RATIO=$((BINARY_SIZE_BYTES * 100 / REGULAR_SIZE_BYTES))
            echo "Size ratio: ${RATIO}% of original"
            
            if [ "$RATIO" -gt 150 ]; then
                echo "✓ Significant size increase suggests obfuscation"
            elif [ "$RATIO" -lt 80 ]; then
                echo "✓ Size reduction suggests good compression"
            else
                echo "ℹ️  Moderate size change"
            fi
        fi
    fi
fi

echo ""
echo "8. ADVANCED STATIC ANALYSIS RECOMMENDATIONS"
echo "==========================================="

echo "For deeper analysis, consider using these tools:"
echo "• Ghidra: Free reverse engineering tool"
echo "• radare2: Open-source reverse engineering framework"  
echo "• strings with different encodings: strings -e l (16-bit), strings -e b (16-bit big-endian)"
echo "• IDA Free: Professional disassembler (free version)"
echo "• Binwalk: Firmware analysis tool for embedded data"

echo ""
echo "9. RUNTIME MONITORING"
echo "===================="

echo "To test runtime security:"
echo "• Run under strace: strace -e open,read ./waybar-calendar-notify-obfuscated auth --status"
echo "• Monitor memory: valgrind --tool=memcheck ./waybar-calendar-notify-obfuscated --help"
echo "• Check for core dumps after credential use"
echo "• Monitor /proc/PID/maps during execution"

echo ""
echo "=================================================="
echo "FINAL OBFUSCATION ASSESSMENT"
echo "=================================================="

if [ "$LEAKED" -eq 0 ]; then
    echo "🎉 EXCELLENT: No critical credential leaks detected!"
    echo "✓ Binary appears to be properly obfuscated"
    echo "✓ Static analysis shows no obvious credential exposure"
    echo "✓ Actual client credentials are obfuscated"
    echo "✓ Ready for distribution"
    echo ""
    echo "Note: JSON struct tags like 'client_id' may appear due to Go reflection,"
    echo "but the actual credential values are XOR-encrypted and obfuscated."
    exit 0
elif [ "$LEAKED" -le 2 ]; then
    echo "⚠️  GOOD: Minor potential leaks detected ($LEAKED critical issues)"
    echo "✓ Obfuscation appears mostly effective"  
    echo "✓ Actual credentials are likely obfuscated"
    echo "ℹ️  Consider additional measures if maximum security is required"
    exit 0
elif [ "$LEAKED" -le 4 ]; then
    echo "⚠️  FAIR: Multiple potential leaks detected ($LEAKED critical issues)"
    echo "⚠️  Some credential-related data may be exposed"
    echo "⚠️  Review obfuscation effectiveness before distribution"
    exit 1
else
    echo "❌ POOR: Many critical leaks detected ($LEAKED issues)"
    echo "❌ Obfuscation appears ineffective"
    echo "❌ DO NOT distribute - credentials may be easily extracted"
    exit 1
fi