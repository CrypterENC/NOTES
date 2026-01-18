#!/bin/bash

# Enhanced enumeration script to find ALL existing vault item IDs in database
# Uses API endpoint with multiple user tokens

echo "Enumerating ALL vault item IDs using API endpoint..."
echo "Create multiple test accounts to get their tokens, then query each vault"
echo ""

# Array of session cookies (add more as you have sessions)
session_cookies=(
    "connect.sid=s%3AoJ5g5Gk6fvmfemhAviLKS-521lOrK8af.ln45ExmnMcmhS0AznQaRhb7lxiyxxpcQD%2B78Nsrsy%2FI"  # Your session
    # Add more session cookies here
    # "connect.sid=token2"
)

all_item_ids=()

for session_cookie in "${session_cookies[@]}"; do
    echo "Getting API token for session: ${session_cookie:0:30}..."

    # Get API token using session cookie
    token_response=$(curl -s \
        -X GET "http://10.0.0.10/api/token" \
        -H "Cookie: $session_cookie" \
        -H "Content-Type: application/json")

    echo "Token API response: $token_response"

    # Extract token from response (assuming it's {"token":"value"})
    api_token=$(echo "$token_response" | jq -r '.token' 2>/dev/null)

    if [ -z "$api_token" ] || [ "$api_token" = "null" ]; then
        echo "Failed to get API token"
        continue
    fi

    echo "Got API token: ${api_token:0:20}..."

    # Now query vault with API token
    response=$(curl -s \
        -X GET "http://10.0.0.10/api/vault/${api_token}" \
        -H "Content-Type: application/json")

    echo "Vault API response: $response"

    # Parse JSON array of vault items
    if echo "$response" | jq -e '.[]' >/dev/null 2>&1; then
        echo "Found vault items for this user:"
        echo "$response" | jq -r '.[] | "ID: \(.id) - Title: \(.title)"'

        # Extract item IDs
        item_ids=$(echo "$response" | jq -r '.[].id')
        all_item_ids+=($item_ids)
    else
        echo "No items or invalid response for this token"
    fi

    echo ""
done

echo "All unique item IDs found in database:"
printf '%s\n' "${all_item_ids[@]}" | sort -u

echo ""
echo "Total items found: $(printf '%s\n' "${all_item_ids[@]}" | sort -u | wc -l)"
