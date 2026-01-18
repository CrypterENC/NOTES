-  Since we already made a account lets try to login.
```shell
┌──(root㉿kali)-[~/pwpa]
└─# curl -X POST http://10.0.0.10/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser1","password":"Password123!"}'
{"message":"Login successful.","success":true}                                                                                          
```

###   Test Brute Force on Login page : Vulner : Broken Authentication
- Here is the request for login page
```http
POST /login HTTP/1.1
Host: 10.0.0.10
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.0.0.10/
Content-Type: application/json
Content-Length: 50
Origin: http://10.0.0.10
Connection: keep-alive
Cookie: connect.sid=s%3ASxCi3ONYEr_xpY1Ou7mZckehJm63XXjQ.Vu489IEbAHVAh1Qp8ZEfxIY32P6aPpUQaePFQFaoR4I
Priority: u=0

{"username":"testuser1","password":"test"}
```
- Wordlist used : `xato-net-10-million-passwords-100.txt` from SecLists.
#### After perform Brute-Force on Login-page  


- 