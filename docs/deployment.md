# Development deployment

Start the local relay and PostgreSQL:

```powershell
cd D:\crypto_pigeon
docker compose up --build -d
```

For local development only, set `RELAY_URL=http://127.0.0.1:8443` and `ALLOW_INSECURE_LOCAL_RELAY=1` before starting a client. A networked deployment must use HTTPS/WSS, a real secret manager, and a reverse proxy configured not to retain request IP logs.
