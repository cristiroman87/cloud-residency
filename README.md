# Flask Lab (redo)

This version is rewritten to be Docker-safe and cloud-ready.

## Services

- `app.py` -> browser-facing frontend on port `5000`
- `app2.py` -> container-safe observability API on port `5001`
- `app3.py` -> identity/auth API on port `5002`

## Why this version is different

The original lab tried to inspect host Linux services from inside a slim container.
That does not work well in Docker, so `app2.py` now shows container-safe metrics:

- system info
- network interfaces
- listening sockets
- processes
- logs
- internet fetch

`app3.py` still handles users, groups, permissions, and login/session concepts.

## Local development

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 app2.py
python3 app3.py
python3 app.py
```

## Docker

Build and start everything with Compose:

```bash
docker-compose up --build
```

App1 is exposed on `:5000` and App3 is exposed on `:5002` so the browser login demo can work.
