from __future__ import annotations

import json
import os
from html import escape
from string import Template

import requests
from flask import Flask, request , Response

app = Flask(__name__)

APP2_URL = os.environ.get('APP2_URL', 'http://app2:5001').rstrip('/')
APP3_URL = os.environ.get('APP3_URL', 'http://app3:5002').rstrip('/')


def safe_get_json(url: str, timeout: int = 5) -> dict:
    try:
        response = requests.get(url, timeout=timeout)
        try:
            data = response.json()
        except Exception:
            data = {'raw': response.text}
        if isinstance(data, dict):
            data.setdefault('_http_status', response.status_code)
            return data
        return {'value': data, '_http_status': response.status_code}
    except Exception as exc:
        return {'error': str(exc)}

############################################################
# Internal App3 proxy
#
# The browser should only communicate with the public App1
# endpoint through the ALB.
#
# App1 forwards authentication requests to App3 over Docker's
# internal network:
#
# Browser -> ALB -> App1 -> App3 -> RDS
#
# Cookies are forwarded in both directions so Flask sessions
# continue to work through the proxy.
############################################################

def proxy_to_app3(path: str):
    target_url = f"{APP3_URL}{path}"

    # Forward the browser's relevant request headers to App3.
    headers = {}

    if request.headers.get("Content-Type"):
        headers["Content-Type"] = request.headers["Content-Type"]

    if request.headers.get("Cookie"):
        headers["Cookie"] = request.headers["Cookie"]

    try:
        upstream = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            timeout=5,
        )

    except requests.RequestException as exc:
        return {
            "error": "app3_unavailable",
            "detail": str(exc),
        }, 502

    # Return App3's response to the browser.
    response = Response(
        upstream.content,
        status=upstream.status_code,
        content_type=upstream.headers.get(
            "Content-Type",
            "application/json",
        ),
    )

    # App3 creates the Flask session cookie during login.
    # Forward that Set-Cookie header back to the browser.
    if "Set-Cookie" in upstream.headers:
        response.headers["Set-Cookie"] = upstream.headers["Set-Cookie"]

    return response
###########################################################
# App3 authentication proxy routes
#
# These routes give the browser one public API surface.
# App3 itself remains an internal Docker service.
############################################################

@app.post("/api/signup")
def proxy_signup():
    return proxy_to_app3("/api/signup")


@app.post("/api/login")
def proxy_login():
    return proxy_to_app3("/api/login")


@app.post("/api/logout")
def proxy_logout():
    return proxy_to_app3("/api/logout")


@app.get("/api/me")
def proxy_me():
    return proxy_to_app3("/api/me")


@app.get("/api/admin")
def proxy_admin():
    return proxy_to_app3("/api/admin")


def page_shell(title: str, active: str, body: str) -> str:
    nav = {
        'dashboard': 'active' if active == 'dashboard' else '',
        'network': 'active' if active == 'network' else '',
        'services': 'active' if active == 'services' else '',
        'logs': 'active' if active == 'logs' else '',
        'identity': 'active' if active == 'identity' else '',
        'architecture': 'active' if active == 'architecture' else '',
        'health': 'active' if active == 'health' else '',
    }

    template = Template('''
    <!doctype html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>$title</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #f5f7fa; color: #111827; }
            .topbar { background: #111827; color: white; padding: 18px 28px; }
            .topbar h1 { margin: 0; font-size: 1.4rem; }
            .topbar p { margin: 6px 0 0 0; color: #cbd5e1; }
            .nav { margin-top: 14px; display: flex; gap: 12px; flex-wrap: wrap; }
            .nav a { color: white; text-decoration: none; padding: 8px 12px; border-radius: 8px; background: rgba(255,255,255,0.08); }
            .nav a.active { background: #2563eb; }
            .container { max-width: 1100px; margin: 0 auto; padding: 28px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
            .card { background: white; border-radius: 14px; padding: 18px; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }
            .label { font-size: 0.85rem; color: #6b7280; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.04em; }
            .value { font-size: 1rem; font-weight: bold; word-break: break-word; }
            pre { white-space: pre-wrap; word-wrap: break-word; background: #f3f4f6; padding: 12px; border-radius: 10px; overflow-x: auto; }
            .muted { color: #6b7280; }
            .wide { grid-column: 1 / -1; }
            .pill { display: inline-block; padding: 3px 9px; border-radius: 999px; background: #e5e7eb; font-size: 0.8rem; }
            input { padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 10px; min-width: 220px; }
            button { padding: 10px 14px; border: none; border-radius: 10px; background: #2563eb; color: white; cursor: pointer; }
            button.secondary { background: #374151; }
            .status { margin-top: 12px; padding: 12px; border-radius: 10px; background: #0f172a; color: #e2e8f0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: pre-wrap; }
            table { width: 100%; border-collapse: collapse; }
            th, td { text-align: left; border-bottom: 1px solid #e5e7eb; padding: 8px 6px; vertical-align: top; }
            th { color: #4b5563; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.03em; }
            .small { font-size: 0.9rem; color: #374151; }
        </style>
    </head>
    <body>
        <div class="topbar">
            <h1>Cloud Residency Lab</h1>
            <p>Three Flask services: frontend, container observability, and identity/auth.</p>
            <div class="nav">
                <a class="$dashboard" href="/">Dashboard</a>
                <a class="$network" href="/network">Network</a>
                <a class="$services" href="/services">Services</a>
                <a class="$logs" href="/logs">Logs</a>
                <a class="$identity" href="/identity">Identity</a>
                <a class="$architecture" href="/architecture">Architecture</a>
                <a class="$health" href="/health">Health</a>
            </div>
        </div>
        <div class="container">
            $body
        </div>
    </body>
    </html>
    ''')

    return template.substitute(
        title=escape(title),
        body=body,
        **nav,
    )


@app.get('/')
def dashboard():
    system = safe_get_json(f'{APP2_URL}/api/system')
    internet = safe_get_json(f'{APP2_URL}/api/internet')

    body = f'''
    <div class="grid">
        <div class="card"><div class="label">Hostname</div><div class="value">{escape(str(system.get('hostname', 'unknown')))}</div></div>
        <div class="card"><div class="label">IP Address</div><div class="value">{escape(str(system.get('ip_address', 'unknown')))}</div></div>
        <div class="card"><div class="label">Kernel</div><div class="value">{escape(str(system.get('kernel', 'unknown')))}</div></div>
        <div class="card"><div class="label">Platform</div><div class="value">{escape(str(system.get('platform', 'unknown')))}</div></div>
        <div class="card"><div class="label">Service Uptime</div><div class="value">{escape(str(system.get('service_uptime', 'unknown')))}</div></div>
        <div class="card"><div class="label">Last Refresh</div><div class="value">{escape(str(system.get('timestamp', 'unknown')))}</div></div>
        <div class="card wide"><div class="label">Memory</div><pre>{escape(str(system.get('memory', 'unknown')))}</pre></div>
        <div class="card wide"><div class="label">Disk</div><pre>{escape(str(system.get('disk', 'unknown')))}</pre></div>
        <div class="card wide"><div class="label">Internet Old Saying</div><div class="value">{escape(str(internet.get('github_zen', 'unknown')))}</div></div>
    </div>
    '''
    return page_shell('Dashboard', 'dashboard', body)


@app.get('/network')
def network():
    data = safe_get_json(f'{APP2_URL}/api/network')
    body = f'''
    <div class="grid">
        <div class="card wide"><div class="label">Interfaces</div><pre>{escape(json.dumps(data.get('interfaces', data.get('error', 'unknown')), indent=2, sort_keys=True))}</pre></div>
        <div class="card wide"><div class="label">Routes</div><pre>{escape(json.dumps(data.get('routes', data.get('error', 'unknown')), indent=2, sort_keys=True))}</pre></div>
        <div class="card wide"><div class="label">Listening Ports</div><pre>{escape(json.dumps(data.get('listeners', data.get('error', 'unknown')), indent=2, sort_keys=True))}</pre></div>
        <div class="card wide"><div class="label">Resolver</div><pre>{escape(str(data.get('resolver', 'unknown')))}</pre></div>
        <div class="card"><div class="label">Last Refresh</div><div class="value">{escape(str(data.get('timestamp', 'unknown')))}</div></div>
    </div>
    '''
    return page_shell('Network', 'network', body)


@app.get('/services')
def services():
    data = safe_get_json(f'{APP2_URL}/api/services')
    processes = data.get('processes', [])
    rows = []
    for proc in processes:
        rows.append(
            '<tr>'
            f"<td>{escape(str(proc.get('pid', '')))}</td>"
            f"<td>{escape(str(proc.get('name', '')))}</td>"
            f"<td>{escape(str(proc.get('username', '')))}</td>"
            f"<td>{escape(str(proc.get('status', '')))}</td>"
            f"<td>{escape(str(proc.get('rss', '')))}</td>"
            f"<td><pre>{escape(str(proc.get('cmdline', '')))}</pre></td>"
            '</tr>'
        )
    process_table = '\n'.join(rows) if rows else '<tr><td colspan="6">No processes found.</td></tr>'

    body = f'''
    <div class="grid">
        <div class="card wide">
            <div class="label">What this page shows</div>
            <div class="small">Containers do not use systemd. This page lists the processes running inside the container instead.</div>
        </div>
        <div class="card"><div class="label">Container PID</div><div class="value">{escape(str(data.get('container_pid', 'unknown')))}</div></div>
        <div class="card"><div class="label">Last Refresh</div><div class="value">{escape(str(data.get('timestamp', 'unknown')))}</div></div>
        <div class="card wide"><div class="label">Note</div><pre>{escape(str(data.get('note', '')))}</pre></div>
        <div class="card wide">
            <div class="label">Running Processes</div>
            <table>
                <thead>
                    <tr>
                        <th>PID</th><th>Name</th><th>User</th><th>Status</th><th>RSS</th><th>Command</th>
                    </tr>
                </thead>
                <tbody>{process_table}</tbody>
            </table>
        </div>
    </div>
    '''
    return page_shell('Services', 'services', body)


@app.get('/logs')
def logs():
    data = safe_get_json(f'{APP2_URL}/api/logs')
    body = f'''
    <div class="grid">
        <div class="card wide"><div class="label">Recent Logs</div><pre>{escape(str(data.get('recent_logs', 'unknown')))}</pre></div>
        <div class="card"><div class="label">Log File</div><div class="value">{escape(str(data.get('log_file', 'unknown')))}</div></div>
        <div class="card"><div class="label">Last Refresh</div><div class="value">{escape(str(data.get('timestamp', 'unknown')))}</div></div>
    </div>
    '''
    return page_shell('Logs', 'logs', body)


@app.get('/identity')
def identity():
    users = safe_get_json(f'{APP3_URL}/api/users')
    groups = safe_get_json(f'{APP3_URL}/api/groups')
    perms = safe_get_json(f'{APP3_URL}/api/permissions')
    env = safe_get_json(f'{APP3_URL}/api/env')
    me = safe_get_json(f'{APP3_URL}/api/me')

    file_rows = []
    for item in perms.get('files', []):
        if 'error' in item:
            file_rows.append(f'''
                <tr>
                    <td>{escape(str(item.get('name', '')))}</td>
                    <td colspan="3" class="small">{escape(str(item['error']))}</td>
                </tr>
            ''')
        else:
            file_rows.append(f'''
                <tr>
                    <td>{escape(str(item.get('name', '')))}</td>
                    <td>{escape(str(item.get('owner', 'unknown')))}</td>
                    <td>{escape(str(item.get('group', 'unknown')))}</td>
                    <td>{escape(str(item.get('permissions', 'unknown')))}</td>
                </tr>
            ''')
    file_rows_html = '\n'.join(file_rows)

    
    status_json = {
        'current_user': me.get('user', {}).get('username', 'not logged in') if me.get('ok') else 'not logged in',
        'me': me,
    }

    body_template = Template('''
    <div class="grid">
        <div class="card wide">
            <div class="label">Login / Signup</div>
            <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:12px;">
                <input id="username" placeholder="username">
                <input id="password" type="password" placeholder="password">
                <button onclick="signup()">Signup</button>
                <button onclick="login()">Login</button>
                <button class="secondary" onclick="logout()">Logout</button>
                <button class="secondary" onclick="refreshMe()">Who am I?</button>
                <button class="secondary" onclick="adminTest()">Admin Test</button>
            </div>
            <div id="auth_status" class="status">$status_json</div>
        </div>

        <div class="card"><div class="label">Current User</div><div class="value">$current_user</div></div>
        <div class="card"><div class="label">UID</div><div class="value">$uid</div></div>
        <div class="card"><div class="label">GID</div><div class="value">$gid</div></div>
        <div class="card"><div class="label">Primary Group</div><div class="value">$primary_group</div></div>

        <div class="card wide"><div class="label">All Groups</div><pre>$all_groups</pre></div>

        <div class="card"><div class="label">USER</div><div class="value">$env_user</div></div>
        <div class="card"><div class="label">HOME</div><div class="value">$env_home</div></div>
        <div class="card wide"><div class="label">SHELL</div><div class="value">$env_shell</div></div>
        <div class="card wide"><div class="label">PATH</div><pre>$env_path</pre></div>
        <div class="card wide"><div class="label">VIRTUAL_ENV</div><div class="value">$env_venv</div></div>

        <div class="card wide">
            <div class="label">Project Files / Permissions</div>
            <table>
                <thead>
                    <tr><th>File</th><th>Owner</th><th>Group</th><th>Permissions</th></tr>
                </thead>
                <tbody>
                    $file_rows
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // The browser now talks only to App1.
        // App1 proxies /api/* requests internally to App3.
        const APP3 = "";

        function setStatus(text) {
            document.getElementById("auth_status").textContent = text;
        }

        async function callApp3(path, options = {}) {
            try {
                const res = await fetch(APP3 + path, {
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json",
                        ...(options.headers || {})
                    },
                    ...options
                });

                const text = await res.text();
                let data;
                try {
                    data = JSON.parse(text);
                } catch {
                    data = { raw: text };
                }

                setStatus(JSON.stringify({ ok: res.ok, status: res.status, data: data }, null, 2));
            } catch (err) {
                setStatus("FETCH ERROR: " + err);
                console.error(err);
            }
        }

        async function signup() {
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            await callApp3("/api/signup", {
                method: "POST",
                body: JSON.stringify({ username, password })
            });
        }

        async function login() {
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;
            await callApp3("/api/login", {
                method: "POST",
                body: JSON.stringify({ username, password })
            });
        }

        async function logout() {
            await callApp3("/api/logout", { method: "POST" });
        }

        async function refreshMe() {
            await callApp3("/api/me", { method: "GET" });
        }

        async function adminTest() {
            await callApp3("/api/admin", { method: "GET" });
        }
    </script>
    ''')

    body = body_template.substitute(
        status_json=escape(json.dumps(status_json, indent=2, sort_keys=True)),
        current_user=escape(str(users.get('current_user', 'unknown'))),
        uid=escape(str(users.get('uid', 'unknown'))),
        gid=escape(str(users.get('gid', 'unknown'))),
        primary_group=escape(str(groups.get('primary_group', 'unknown'))),
        all_groups=escape(json.dumps(groups.get('all_groups', []), indent=2, sort_keys=True)),
        env_user=escape(str(env.get('USER', ''))),
        env_home=escape(str(env.get('HOME', ''))),
        env_shell=escape(str(env.get('SHELL', ''))),
        env_path=escape(str(env.get('PATH', ''))),
        env_venv=escape(str(env.get('VIRTUAL_ENV', ''))),
        file_rows=file_rows_html
            )

    return page_shell('Identity', 'identity', body)


@app.get('/architecture')
def architecture():
    body = '''
    <div class="grid">
        <div class="card wide">
            <div class="label">System Flow</div>
            <pre>
Browser
  |
  v
App1 (:5000)
  |
  +--> App2 (:5001) -> container metrics / network / logs / internet
  |
  +--> App3 (:5002) -> users / groups / permissions / authentication
            </pre>
        </div>
        <div class="card wide">
            <div class="label">Why this layout works</div>
            <div class="value">The browser only needs App1. App1 talks to App2 and App3 over Docker's internal network. App3 is also exposed on port 5002 so the browser-based login demo can work with CORS and cookies.</div>
        </div>
        <div class="card wide">
            <div class="label">What changed from the old lab</div>
            <div class="value">App2 no longer assumes systemd or journalctl exist inside a container. It now shows container-safe observability data instead of trying to inspect a host OS from inside Docker.</div>
        </div>
    </div>
    '''
    return page_shell('Architecture', 'architecture', body)

def check(name: str, url: str) -> dict:
    try:
        r = requests.get(url, timeout=4)

        if r.status_code == 200:
            return {
                'name': name,
                'ok': True,
                'text': 'ACTIVE (running)',
                'detail': f'HTTP {r.status_code}',
            }

        return {
            'name': name,
            'ok': False,
            'text': 'DOWN',
            'detail': f'HTTP {r.status_code}',
        }

    except Exception as exc:
        return {
            'name': name,
            'ok': False,
            'text': 'DOWN',
            'detail': str(exc),
        }


@app.get('/health')
def health():
    
    app2 = check('App 2', f'{APP2_URL}/api/health')
    app3 = check('App 3', f'{APP3_URL}/api/health')

    def light(ok: bool) -> str:
        color = '#16a34a' if ok else '#dc2626'
        return f'<span style="color:{color}; font-size:1.3rem; font-weight:bold;">●</span>'

    body = f'''
    <div class="grid">
        <div class="card"><div class="label">Main App</div><div class="value">{light(True)} ACTIVE (running)</div><div class="muted">This page loaded, so App1 is alive.</div></div>
        <div class="card"><div class="label">App 2</div><div class="value">{light(app2['ok'])} {escape(app2['text'])}</div><div class="muted">{escape(app2['detail'])}</div></div>
        <div class="card"><div class="label">App 3</div><div class="value">{light(app3['ok'])} {escape(app3['text'])}</div><div class="muted">{escape(app3['detail'])}</div></div>
        <div class="card wide"><div class="label">Meaning</div><div class="value">Green means the app responded. Red means the app is down, unreachable, or returned an error.</div></div>
    </div>
    '''
    return page_shell('Health', 'health', body)

@app.get('/ready')
def ready():

    app2 = check('App 2', f'{APP2_URL}/api/health')
    app3 = check('App 3', f'{APP3_URL}/api/ready')

    if app2['ok'] and app3['ok']:
        return {
            'ok': True,
            'app2': 'ready',
            'app3': 'ready',
        }, 200

    return {
        'ok': False,
        'app2': 'ready' if app2['ok'] else 'unavailable',
        'app3': 'ready' if app3['ok'] else 'unavailable',
    }, 503

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
