#!/bin/bash
# Decode tools for secrets-scanner AI Agent
# Provides convenient wrappers for common decoding operations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: decode-tools.sh <command> [args]"
    echo ""
    echo "Commands:"
    echo "  jwt <token>              Decode JWT header and payload (no verification)"
    echo "  jwt-header <token>       Decode JWT header only"
    echo "  jwt-payload <token>      Decode JWT payload only"
    echo "  b64 <string>             Base64 decode"
    echo "  b64url <string>          Base64URL decode"
    echo "  hex <string>             Hex decode to ASCII"
    echo "  url <string>             URL decode"
    echo "  entropy <string>         Calculate Shannon entropy"
    echo ""
    echo "Examples:"
    echo "  decode-tools.sh jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig"
    echo "  decode-tools.sh b64 dGVzdA=="
    echo "  decode-tools.sh entropy 'AKIAIOSFODNN7EXAMPLE'"
}

# Base64 decode (handles both standard and URL-safe)
b64_decode() {
    local input="$1"
    # Add padding if needed
    local pad=$((4 - ${#input} % 4))
    if [ "$pad" -ne 4 ]; then
        for i in $(seq 1 $pad); do
            input="${input}="
        done
    fi
    # Replace URL-safe chars
    input=$(echo "$input" | tr '_-' '/+')
    echo "$input" | base64 -d 2>/dev/null || echo "$input" | python3 -c "import sys, base64; print(base64.b64decode(sys.stdin.read()).decode('utf-8', errors='replace'))"
}

# Base64URL decode
b64url_decode() {
    local input="$1"
    # Add padding if needed
    local pad=$((4 - ${#input} % 4))
    if [ "$pad" -ne 4 ]; then
        for i in $(seq 1 $pad); do
            input="${input}="
        done
    fi
    echo "$input" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "$input" | python3 -c "import sys, base64; print(base64.urlsafe_b64decode(sys.stdin.read()).decode('utf-8', errors='replace'))"
}

# JWT decode
decode_jwt() {
    local token="$1"
    local part="${2:-all}"
    
    IFS='.' read -r header payload signature <<< "$token"
    
    if [ "$part" = "header" ] || [ "$part" = "all" ]; then
        echo "=== JWT HEADER ==="
        b64url_decode "$header" | python3 -m json.tool 2>/dev/null || b64url_decode "$header"
        echo ""
    fi
    
    if [ "$part" = "payload" ] || [ "$part" = "all" ]; then
        echo "=== JWT PAYLOAD ==="
        b64url_decode "$payload" | python3 -m json.tool 2>/dev/null || b64url_decode "$payload"
        echo ""
    fi
    
    if [ "$part" = "all" ]; then
        echo "=== JWT SIGNATURE ==="
        echo "$signature" | cut -c1-20
        echo ""
    fi
}

# Hex decode
hex_decode() {
    local input="$1"
    # Remove spaces and 0x prefix if present
    input=$(echo "$input" | sed 's/ //g' | sed 's/^0x//')
    echo "$input" | xxd -r -p 2>/dev/null || python3 -c "import sys; print(bytes.fromhex('$input').decode('utf-8', errors='replace'))"
}

# URL decode
url_decode() {
    local input="$1"
    python3 -c "import urllib.parse; print(urllib.parse.unquote('$input'))"
}

# Calculate Shannon entropy
calc_entropy() {
    local input="$1"
    python3 -c "
import math
import sys
s = '$input'
if not s:
    print('0.0')
    sys.exit(0)
entropy = 0
for x in set(s):
    p_x = float(s.count(x)) / len(s)
    if p_x > 0:
        entropy += - p_x * math.log(p_x, 2)
print(f'{entropy:.4f}')
print(f'Max possible for length {len(s)}: {math.log2(len(s)):.4f}')
print(f'Normalized: {entropy / math.log2(max(len(set(s)), 2)):.4f}')
"
}

# Main
case "${1:-}" in
    jwt)
        decode_jwt "$2"
        ;;
    jwt-header)
        decode_jwt "$2" "header"
        ;;
    jwt-payload)
        decode_jwt "$2" "payload"
        ;;
    b64)
        b64_decode "$2"
        ;;
    b64url)
        b64url_decode "$2"
        ;;
    hex)
        hex_decode "$2"
        ;;
    url)
        url_decode "$2"
        ;;
    entropy)
        calc_entropy "$2"
        ;;
    *)
        usage
        exit 1
        ;;
esac
