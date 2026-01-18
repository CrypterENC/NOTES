```bash
for endpoint in /api/users /api/passwords /api/admin /api/profile /api/settings /api/share /api/export /api/import /login /logout /dashboard /home; do
  echo "Testing: $endpoint"
  curl -s -I http://10.0.0.10$endpoint | head -1
done
```

-  **Using FFUF to find all the endpoints : **
```bash
ffuf -u http://10.0.0.10/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

- Output : 

```shell
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.0.10/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 7634, Words: 2593, Lines: 196, Duration: 286ms]
account                 [Status: 200, Size: 17, Words: 2, Lines: 1, Duration: 284ms]
api                     [Status: 401, Size: 48, Words: 2, Lines: 1, Duration: 292ms]
css                     [Status: 301, Size: 173, Words: 7, Lines: 11, Duration: 276ms]
images                  [Status: 301, Size: 179, Words: 7, Lines: 11, Duration: 277ms]
js                      [Status: 301, Size: 171, Words: 7, Lines: 11, Duration: 277ms]
signout                 [Status: 302, Size: 23, Words: 4, Lines: 1, Duration: 285ms]
vault                   [Status: 200, Size: 17, Words: 2, Lines: 1, Duration: 290ms]
:: Progress: [4614/4614] :: Job [1/1] :: 141 req/sec :: Duration: [0:00:34] :: Errors: 0 ::

```