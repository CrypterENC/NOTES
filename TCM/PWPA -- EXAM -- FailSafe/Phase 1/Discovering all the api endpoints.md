```bash
for endpoint in /api/users /api/passwords /api/admin /api/profile /api/settings /api/share /api/export /api/import /login /logout /dashboard /home; do
  echo "Testing: $endpoint"
  curl -s -I http://10.0.0.10$endpoint | head -1
done
```

-  