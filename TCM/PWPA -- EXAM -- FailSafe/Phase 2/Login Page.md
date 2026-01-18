-  Since we already made a account lets try to login.
```shell
┌──(root㉿kali)-[~/pwpa]
└─# curl -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser1","password":"Password123!"}'
{"message":"Login successful.","success":true}                                                                                                    
```