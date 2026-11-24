"""
SANOVA Unified Local Runner (Flask + Shared `src/` & `static/`).

Chạy ứng dụng cục bộ bằng Python/Flask thuần nhưng dùng CHUNG 100% mã nguồn
(`src/entry.py`, `src/sanova_legacy_api.py`, `src/flask_d1_shim.py`) và giao diện
(`static/`) với bản triển khai trên Cloudflare Workers.

- Sửa 1 lần trong `src/` hoặc `static/` -> cập nhật ngay cho cả Local Flask lẫn Cloudflare.
- Khi chạy cục bộ (`python run_local.py`): đọc/ghi trực tiếp các file `*.json` trong thư mục dự án.
- Khi đẩy lên Cloudflare (`git push`): tự động đọc/ghi bảng `json_store` trên Cloudflare D1.
"""

import asyncio
import json
import mimetypes
import os
import sys
import tempfile
import threading
import types
from pathlib import Path
from urllib.parse import unquote, urlparse

from flask import Flask, Response as FlaskResponse, request as flask_request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"
STATIC_DIR = BASE_DIR / "static"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Các file JSON cấu hình của Node/Wrangler (không phải dữ liệu kho)
IGNORED_JSON_FILES = {
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    "wrangler.json",
}

# Lưu phiên đăng nhập tạm ở thư mục TEMP để không tạo file rác trong git,
# đồng thời không bị mất phiên khi Flask tự reload sau khi sửa code.
SESSIONS_CACHE_FILE = Path(tempfile.gettempdir()) / "sanova_local_sessions.json"


# ==============================================================================
# 1. Shim nhẹ cho module `workers` của Cloudflare khi chạy trên CPython cục bộ
# ==============================================================================
class LocalWorkerResponse:
    def __init__(self, body="", status=200, headers=None):
        self.body = body if body is not None else ""
        self.status = int(status)
        self.headers = dict(headers or {})


class LocalWorkerEntrypoint:
    def __init__(self, env=None):
        self.env = env


if "workers" not in sys.modules:
    workers_mod = types.ModuleType("workers")
    workers_mod.Response = LocalWorkerResponse
    workers_mod.WorkerEntrypoint = LocalWorkerEntrypoint
    sys.modules["workers"] = workers_mod


class _BytesBuffer:
    def __init__(self, data: bytes):
        self._data = data

    def to_py(self):
        return self._data


class _HeadersProxy:
    def __init__(self, headers):
        self._raw = {str(k): str(v) for k, v in headers.items()}
        self._lower = {k.lower(): v for k, v in self._raw.items()}

    def get(self, key, default=None):
        return self._lower.get(str(key).lower(), default)

    def items(self):
        return self._raw.items()


class LocalWorkerRequest:
    def __init__(self, url: str, method: str, headers, body_bytes: bytes):
        self.url = url
        self.method = method
        self.headers = _HeadersProxy(headers)
        self._body = body_bytes or b""

    async def text(self):
        return self._body.decode("utf-8", errors="replace")

    async def arrayBuffer(self):
        return _BytesBuffer(self._body)


# ==============================================================================
# 2. Giả lập Cloudflare D1 (đọc/ghi trực tiếp các file `*.json` cục bộ)
# ==============================================================================
class _D1Row(dict):
    def __getattr__(self, item):
        try:
            return self[item]
        except KeyError as exc:
            raise AttributeError(item) from exc

    def to_py(self):
        return dict(self)


class _D1AllResult:
    def __init__(self, rows):
        self.results = [_D1Row(r) for r in rows]


class _LocalD1Statement:
    def __init__(self, db, sql: str):
        self._db = db
        self._sql = " ".join(sql.strip().split())
        self._params = ()

    def bind(self, *params):
        self._params = params
        return self

    async def first(self):
        sql_up = self._sql.upper()
        if "FROM JSON_STORE WHERE STORE_KEY" in sql_up and self._params:
            key = str(self._params[0])
            payload = self._db.read_payload(key)
            if payload is None:
                return None
            return _D1Row({"payload": payload})
        return None

    async def all(self):
        sql_up = self._sql.upper()
        if "FROM SQLITE_MASTER" in sql_up:
            return _D1AllResult([{"name": "json_store"}])
        if "FROM JSON_STORE" in sql_up:
            rows = []
            for key, payload in self._db.read_all_payloads().items():
                rows.append({"store_key": key, "payload": payload})
            return _D1AllResult(rows)
        return _D1AllResult([])

    async def run(self):
        sql_up = self._sql.upper()
        if sql_up.startswith("INSERT INTO JSON_STORE") and len(self._params) >= 2:
            key = str(self._params[0])
            payload = str(self._params[1])
            self._db.write_payload(key, payload)
        return {"success": True}


class LocalJsonDatabase:
    def __init__(self, root_dir: Path):
        self.root_dir = root_dir

    def _path_for_key(self, store_key: str) -> Path:
        if store_key == "sessions":
            return SESSIONS_CACHE_FILE
        safe_name = os.path.basename(str(store_key).strip())
        if not safe_name.endswith(".json"):
            safe_name += ".json"
        return self.root_dir / safe_name

    def read_payload(self, store_key: str):
        path = self._path_for_key(store_key)
        if not path.is_file():
            return None
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return None

    def read_all_payloads(self):
        result = {}
        for p in self.root_dir.glob("*.json"):
            if p.name in IGNORED_JSON_FILES:
                continue
            try:
                result[p.stem] = p.read_text(encoding="utf-8")
            except Exception:
                continue
        if SESSIONS_CACHE_FILE.is_file():
            try:
                result["sessions"] = SESSIONS_CACHE_FILE.read_text(encoding="utf-8")
            except Exception:
                pass
        return result

    def write_payload(self, store_key: str, payload: str):
        path = self._path_for_key(store_key)
        try:
            parsed = json.loads(payload)
            formatted = json.dumps(parsed, ensure_ascii=False, indent=2)
        except Exception:
            formatted = payload
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        tmp_path.write_text(formatted, encoding="utf-8")
        os.replace(tmp_path, path)

    def prepare(self, sql: str):
        return _LocalD1Statement(self, sql)


# ==============================================================================
# 3. Giả lập Cloudflare `[assets]` (phục vụ file từ `./static/`)
# ==============================================================================
class LocalAssets:
    def __init__(self, static_dir: Path):
        self.static_dir = static_dir.resolve()

    async def fetch(self, asset_url: str):
        parsed = urlparse(str(asset_url))
        rel_path = unquote(parsed.path or "").lstrip("/")
        target = (self.static_dir / rel_path).resolve()
        if not str(target).startswith(str(self.static_dir)) or not target.is_file():
            return LocalWorkerResponse("Not Found", status=404, headers={"Content-Type": "text/plain; charset=utf-8"})
        mime, _ = mimetypes.guess_type(str(target))
        content_type = mime or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
            content_type = f"{content_type}; charset=utf-8"
        return LocalWorkerResponse(target.read_bytes(), status=200, headers={"Content-Type": content_type})


class LocalEnv:
    def __init__(self):
        self.DATABASE = LocalJsonDatabase(BASE_DIR)
        self.ASSETS = LocalAssets(STATIC_DIR)


# ==============================================================================
# 4. Khởi tạo Flask app gắn trực tiếp vào `src/entry.py`
# ==============================================================================
import entry as worker_entry  # noqa: E402

_ENV = LocalEnv()
_WORKER = worker_entry.Default(_ENV)
_WORKER_LOCK = threading.Lock()

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB


def _try_serve_static_asset(req_path: str):
    """Phục vụ trực tiếp các file tĩnh (/js/*, /css/*, /images/*, ...) giống Cloudflare Assets."""
    if req_path in worker_entry.PAGE_ASSET_MAP or req_path in ("/", "/login", "/portal"):
        return None
    rel = req_path.lstrip("/")
    if not rel:
        return None
    target = (STATIC_DIR / rel).resolve()
    if str(target).startswith(str(STATIC_DIR.resolve())) and target.is_file():
        return send_from_directory(str(STATIC_DIR), rel)
    return None


@app.route("/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
@app.route("/<path:subpath>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def proxy_to_worker(subpath):
    req_path = "/" + subpath if subpath else "/"
    if flask_request.method in ("GET", "HEAD"):
        static_resp = _try_serve_static_asset(req_path)
        if static_resp is not None:
            return static_resp

    worker_req = LocalWorkerRequest(
        url=flask_request.url,
        method=flask_request.method,
        headers=flask_request.headers,
        body_bytes=flask_request.get_data(cache=False),
    )

    with _WORKER_LOCK:
        worker_resp = asyncio.run(_WORKER.fetch(worker_req))

    body = worker_resp.body
    if isinstance(body, str):
        body = body.encode("utf-8")
    elif not isinstance(body, (bytes, bytearray)):
        body = str(body).encode("utf-8")

    return FlaskResponse(
        body,
        status=worker_resp.status,
        headers=worker_resp.headers,
    )


if __name__ == "__main__":
    host = os.environ.get("SANOVA_HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", os.environ.get("SANOVA_PORT", "5000")))
    print("=" * 64)
    print(f"  SANOVA Unified Local Server (Flask -> src/ + static/)")
    print(f"  URL       : http://{host}:{port}")
    print(f"  Data      : {BASE_DIR} (*.json)")
    print(f"  Shared src: {SRC_DIR} & {STATIC_DIR}")
    print("=" * 64)
    app.run(host=host, port=port, debug=True, threaded=True)
