from __future__ import annotations

import logging
import os
import platform
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil
import requests
from flask import Flask, jsonify, request
from logging.handlers import RotatingFileHandler

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = Path(os.environ.get('LOG_DIR', str(BASE_DIR / 'logs')))
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / 'app2.log'

START_TIME = time.time()

logger = logging.getLogger('app2')
logger.setLevel(logging.INFO)
logger.handlers.clear()
logger.propagate = False

file_handler = RotatingFileHandler(LOG_FILE, maxBytes=512_000, backupCount=3)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(file_handler)

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
logger.addHandler(stream_handler)


@app.before_request
def log_request() -> None:
    logger.info('request %s %s from %s', request.method, request.path, request.remote_addr)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def human_bytes(value: float | int) -> str:
    value = float(value)
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f'{value:.1f} {unit}' if unit != 'B' else f'{int(value)} B'
        value /= 1024
    return f'{value:.1f} TB'


def human_duration(seconds: float) -> str:
    seconds = int(seconds)
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f'{days}d')
    if hours:
        parts.append(f'{hours}h')
    if minutes:
        parts.append(f'{minutes}m')
    parts.append(f'{seconds}s')
    return ' '.join(parts)


def tail_lines(path: Path, count: int = 40) -> str:
    if not path.exists():
        return 'No log file yet.'
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception as exc:  # pragma: no cover - safety net for runtime environments
        return f'ERROR reading log file: {exc}'
    if not lines:
        return 'Log file is empty.'
    return '\n'.join(lines[-count:])


def first_ipv4() -> str:
    try:
        hostname = socket.gethostname()
        _, _, addrs = socket.gethostbyname_ex(hostname)
        for ip in addrs:
            if not ip.startswith('127.'):
                return ip
    except Exception:
        pass

    for nic_addrs in psutil.net_if_addrs().values():
        for addr in nic_addrs:
            if getattr(addr, 'family', None) == socket.AF_INET and not addr.address.startswith('127.'):
                return addr.address
    return 'unknown'


def read_resolv_conf() -> str:
    path = Path('/etc/resolv.conf')
    try:
        return path.read_text(encoding='utf-8', errors='replace').strip()
    except Exception as exc:  # pragma: no cover
        return f'ERROR reading {path}: {exc}'


def parse_route_table() -> list[dict[str, Any]]:
    route_file = Path('/proc/net/route')
    routes: list[dict[str, Any]] = []
    if not route_file.exists():
        return routes

    def hex_ip(value: str) -> str:
        packed = struct.pack('<L', int(value, 16))
        return socket.inet_ntoa(packed)

    try:
        lines = route_file.read_text(encoding='utf-8', errors='replace').splitlines()
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 11:
                continue
            iface, destination, gateway, flags, refcnt, use, metric, mask, mtu, window, irtt = fields[:11]
            routes.append({
                'iface': iface,
                'destination': hex_ip(destination),
                'gateway': hex_ip(gateway),
                'netmask': hex_ip(mask),
                'flags': flags,
                'metric': int(metric),
            })
    except Exception as exc:  # pragma: no cover
        routes.append({'error': str(exc)})
    return routes


def list_interfaces() -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    for name, addrs in psutil.net_if_addrs().items():
        item = {'name': name, 'addresses': []}
        for addr in addrs:
            family = getattr(addr, 'family', None)
            family_name = 'unknown'
            if family == socket.AF_INET:
                family_name = 'ipv4'
            elif family == socket.AF_INET6:
                family_name = 'ipv6'
            elif hasattr(psutil, 'AF_LINK') and family == psutil.AF_LINK:
                family_name = 'link'
            item['addresses'].append({
                'family': family_name,
                'address': addr.address,
                'netmask': getattr(addr, 'netmask', None),
                'broadcast': getattr(addr, 'broadcast', None),
            })
        interfaces.append(item)
    return interfaces


def list_listeners() -> list[dict[str, Any]]:
    listeners: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status != psutil.CONN_LISTEN:
                continue
            laddr = conn.laddr if conn.laddr else None
            if not laddr:
                continue
            key = (getattr(conn, 'status', 'LISTEN'), laddr.ip, laddr.port)
            if key in seen:
                continue
            seen.add(key)
            listeners.append({
                'ip': laddr.ip,
                'port': laddr.port,
                'pid': conn.pid,
                'family': 'ipv6' if ':' in laddr.ip else 'ipv4',
            })
    except Exception as exc:  # pragma: no cover
        listeners.append({'error': str(exc)})
    return sorted(listeners, key=lambda x: (x.get('ip', ''), x.get('port', 0)))


def list_processes(limit: int = 20) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username', 'status', 'cmdline', 'memory_info']):
        try:
            info = proc.info
            mem = info.get('memory_info')
            processes.append({
                'pid': info.get('pid'),
                'name': info.get('name'),
                'username': info.get('username'),
                'status': info.get('status'),
                'rss': mem.rss if mem else 0,
                'cmdline': ' '.join(info.get('cmdline') or []),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    processes.sort(key=lambda x: x['rss'], reverse=True)
    return processes[:limit]


@app.get('/api/system')
def system():
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    boot = datetime.fromtimestamp(psutil.boot_time(), tz=timezone.utc)
    return jsonify({
        'hostname': socket.gethostname(),
        'ip_address': first_ipv4(),
        'kernel': platform.release(),
        'platform': platform.platform(),
        'python': platform.python_version(),
        'service_uptime': human_duration(time.time() - START_TIME),
        'boot_time': boot.isoformat(),
        'memory': f'{human_bytes(vm.used)} used of {human_bytes(vm.total)} ({vm.percent}%)',
        'disk': f'{human_bytes(disk.used)} used of {human_bytes(disk.total)} ({disk.percent}%)',
        'timestamp': now_iso(),
    })


@app.get('/api/network')
def network():
    return jsonify({
        'interfaces': list_interfaces(),
        'routes': parse_route_table(),
        'listeners': list_listeners(),
        'resolver': read_resolv_conf(),
        'timestamp': now_iso(),
    })


@app.get('/api/services')
def services():
    return jsonify({
        'note': 'Containers do not use systemd; this page shows container processes instead.',
        'container_pid': os.getpid(),
        'processes': list_processes(),
        'timestamp': now_iso(),
    })


@app.get('/api/logs')
def logs():
    return jsonify({
        'recent_logs': tail_lines(LOG_FILE, 50),
        'log_file': str(LOG_FILE),
        'timestamp': now_iso(),
    })


@app.get('/api/internet')
def internet():
    try:
        zen = requests.get('https://api.github.com/zen', timeout=10).text.strip()
    except Exception as exc:
        zen = f'ERROR: {exc}'
    return jsonify({
        'github_zen': zen,
        'timestamp': now_iso(),
    })


@app.get('/api/health')
def health():
    return jsonify({'ok': True, 'service': 'app2', 'timestamp': now_iso()})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)
