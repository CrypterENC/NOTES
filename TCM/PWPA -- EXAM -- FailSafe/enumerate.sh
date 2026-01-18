#!/bin/bash

# Enhanced enumeration script to find ALL existing vault item IDs in database
# Uses API endpoint with multiple user tokens

echo "Enumerating ALL vault item IDs using API endpoint..."
echo "Create multiple test accounts to get their tokens, then query each vault"
echo ""

# Array of user tokens (add more as you create accounts)
tokens=(
    "s%3AoJ5g5Gk6fvmfemhAviLKS-521lOrK8af.ln45ExmnMcmhS0AznQaRhb7lxiyxxpcQD%2B78Nsrsy%2FI"  # Your token
    # Add more tokens here as you create accounts
    # "token2"
    # "token3"
)

all_item_ids=()

for token in "${tokens[@]}"; do
    echo "Querying vault for token: ${token:0:20}..."

    response=$(curl -s \
        -X GET "http://10.0.0.10/api/vault/${token}" \
        -H "Content-Type: application/json")

    echo "Raw API response: $response"

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
