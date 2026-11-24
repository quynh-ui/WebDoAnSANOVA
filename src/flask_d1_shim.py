import base64
import hashlib
import hmac
import json
import os
import re
import secrets
from copy import deepcopy
from urllib.parse import parse_qs, unquote, urlparse

# ==============================================================================
# 1. VIRTUAL D1 JSON STORE (loaded per-request from Cloudflare D1 `json_store`)
# ==============================================================================
_VFS_DATA = {}
_VFS_DIRTY = set()

FILENAME_TO_KEY = {
    "users.json": "users",
    "audit_logs.json": "audit_logs",
    "roles.json": "roles",
    "role_permissions.json": "role_permissions",
    "system_settings.json": "system_settings",
    "warehouse_data.json": "warehouse_data",
    "warehouse_config.json": "warehouse_config",
    "products_catalog.json": "products_catalog",
    "approvals_data.json": "approvals_data",
    "stocktake_data.json": "stocktake_data",
    "daily_closings.json": "daily_closings",
    "reports_history.json": "reports_history",
    "inbound_receipts.json": "inbound_receipts",
    "picking_orders.json": "picking_orders",
    "return_orders.json": "return_orders",
    "prepacking_orders.json": "prepacking_orders",
    "packing_orders.json": "packing_orders",
    "scan_history.json": "scan_history",
    "staff_tasks.json": "staff_tasks",
    "notifications.json": "notifications",
    "reconciliation_records.json": "reconciliation_records",
    "dispatcher_notifications.json": "dispatcher_notifications",
    "admin_notifications.json": "admin_notifications",
}


def normalize_store_key(filename):
    base = os.path.basename(str(filename or "")).strip()
    if base in FILENAME_TO_KEY:
        return FILENAME_TO_KEY[base]
    if base.endswith(".json"):
        return base[:-5]
    return base


def vfs_begin(initial_map):
    global _VFS_DATA, _VFS_DIRTY
    _VFS_DATA = dict(initial_map or {})
    _VFS_DIRTY = set()


def vfs_load(filename, default=None):
    key = normalize_store_key(filename)
    if key in _VFS_DATA and _VFS_DATA[key] is not None:
        return deepcopy(_VFS_DATA[key])
    return deepcopy(default)


def vfs_save(filename, data):
    key = normalize_store_key(filename)
    _VFS_DATA[key] = deepcopy(data)
    _VFS_DIRTY.add(key)


def vfs_get_dirty_items():
    return {k: _VFS_DATA[k] for k in _VFS_DIRTY if k in _VFS_DATA}


# ==============================================================================
# 2. PYODIDE-SAFE PASSWORD HASHING & UTILITIES (Werkzeug compatible)
# ==============================================================================
def _pbkdf2_sha256_hex(password_str, salt_str, iterations, dklen=32):
    pwd_b = password_str.encode("utf-8")
    salt_b = salt_str.encode("utf-8")
    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha256", pwd_b, salt_b, iterations, dklen=dklen).hex()
    blocks = (dklen + 31) // 32
    out = bytearray()
    for block_index in range(1, blocks + 1):
        u = hmac.new(pwd_b, salt_b + block_index.to_bytes(4, "big"), hashlib.sha256).digest()
        res = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac.new(pwd_b, u, hashlib.sha256).digest()
            for idx in range(32):
                res[idx] ^= u[idx]
        out.extend(res)
    return bytes(out[:dklen]).hex()


def generate_password_hash(password, method="sha256i", salt_length=12):
    salt = secrets.token_hex(salt_length)
    iters = 2_000
    digest = _pbkdf2_sha256_hex(str(password), salt, iters)
    return f"sha256i${iters}${salt}${digest}"


def check_password_hash(stored_password, input_password):
    if not stored_password or not input_password:
        return False
    raw = str(stored_password)
    if raw.startswith("sha256i$"):
        parts = raw.split("$", 3)
        if len(parts) == 4:
            try:
                _, iter_str, salt, expected_hex = parts
                iters = max(1, min(100_000, int(iter_str)))
                return hmac.compare_digest(_pbkdf2_sha256_hex(input_password, salt, iters), expected_hex)
            except Exception:
                return False
        return False
    if raw.startswith("sha256$"):
        parts = raw.split("$", 2)
        if len(parts) == 3:
            _, salt, expected_hex = parts
            return hmac.compare_digest(_pbkdf2_sha256_hex(input_password, salt, 100_000), expected_hex)
        return False
    if raw.startswith("pbkdf2:sha256:"):
        parts = raw.split("$", 2)
        if len(parts) == 3:
            try:
                mp = parts[0].split(":")
                iters = int(mp[2]) if len(mp) >= 3 else 260_000
                _, salt, expected_hex = parts
                return hmac.compare_digest(_pbkdf2_sha256_hex(input_password, salt, iters), expected_hex)
            except Exception:
                return False
        return False
    if raw.startswith("scrypt:"):
        parts = raw.split("$", 2)
        if len(parts) == 3 and hasattr(hashlib, "scrypt"):
            try:
                mp = parts[0].split(":")
                n_val, r_val, p_val = int(mp[1]), int(mp[2]), int(mp[3])
                salt, expected_hex = parts[1], parts[2]
                dklen = len(bytes.fromhex(expected_hex))
                digest = hashlib.scrypt(
                    input_password.encode("utf-8"),
                    salt=salt.encode("utf-8"),
                    n=n_val,
                    r=r_val,
                    p=p_val,
                    maxmem=64 * 1024 * 1024,
                    dklen=dklen,
                ).hex()
                return hmac.compare_digest(digest, expected_hex)
            except Exception:
                return False
        return False
    return hmac.compare_digest(raw, str(input_password))


def secure_filename(filename):
    name = str(filename or "").strip().replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return name or "upload"


# ==============================================================================
# 3. MINI-FLASK SHIM (request, session, jsonify, make_response, redirect, app)
# ==============================================================================
class HTTPAbort(Exception):
    def __init__(self, code, description=""):
        super().__init__(description)
        self.code = int(code)
        self.description = str(description or "")


class MultiDict(dict):
    def __init__(self, mapping=None):
        super().__init__()
        self._lists = {}
        if isinstance(mapping, dict):
            for k, v in mapping.items():
                if isinstance(v, list):
                    self._lists[k] = list(v)
                    super().__setitem__(k, v[0] if v else "")
                else:
                    self._lists[k] = [v]
                    super().__setitem__(k, v)

    def get(self, key, default=None, type=None):
        val = super().get(key, default)
        if val is None:
            return default
        if type is not None:
            try:
                return type(val)
            except Exception:
                return default
        return val

    def getlist(self, key):
        return list(self._lists.get(key, []))

    def to_dict(self, flat=True):
        return dict(self) if flat else {k: list(v) for k, v in self._lists.items()}


class HeadersDict(dict):
    def get(self, key, default=None):
        kl = str(key).lower()
        for k, v in self.items():
            if str(k).lower() == kl:
                return v
        return default


class UserAgentObj:
    def __init__(self, ua_str=""):
        self.string = str(ua_str or "")

    def __str__(self):
        return self.string


class UploadedFile:
    def __init__(self, filename, raw_bytes, content_type="application/octet-stream"):
        self.filename = filename or ""
        self._bytes = raw_bytes if isinstance(raw_bytes, (bytes, bytearray)) else bytes(raw_bytes or b"")
        self.content_type = content_type

    def read(self):
        return bytes(self._bytes)

    def save(self, _dst):
        return None

    def to_data_uri(self):
        b64 = base64.b64encode(self._bytes).decode("ascii")
        return f"data:{self.content_type};base64,{b64}"


def parse_multipart_form_data(content_type, raw_bytes):
    form_fields = {}
    files = {}
    m = re.search(r'boundary=(?:"([^"]+)"|([^\s;]+))', content_type or "")
    if not m or not raw_bytes:
        return MultiDict(form_fields), files
    boundary = (m.group(1) or m.group(2)).encode("latin-1")
    delimiter = b"--" + boundary
    parts = raw_bytes.split(delimiter)
    for part in parts[1:]:
        if part.startswith(b"--"):
            break
        if part.startswith(b"\r\n"):
            part = part[2:]
        if part.endswith(b"\r\n"):
            part = part[:-2]
        if b"\r\n\r\n" not in part:
            continue
        raw_hdrs, body = part.split(b"\r\n\r\n", 1)
        hdr_text = raw_hdrs.decode("utf-8", errors="replace")
        disp_m = re.search(r'name="([^"]+)"', hdr_text)
        if not disp_m:
            continue
        field_name = disp_m.group(1)
        file_m = re.search(r'filename="([^"]*)"', hdr_text)
        ct_m = re.search(r"Content-Type:\s*([^\r\n]+)", hdr_text, re.I)
        ct = ct_m.group(1).strip() if ct_m else "application/octet-stream"
        if file_m is not None:
            files[field_name] = UploadedFile(file_m.group(1), body, ct)
        else:
            form_fields.setdefault(field_name, []).append(body.decode("utf-8", errors="replace"))
    return MultiDict(form_fields), files


class RequestProxy:
    def __init__(self):
        self.reset()

    def reset(self):
        self.method = "GET"
        self.path = "/"
        self.url = "http://localhost/"
        self.base_url = "http://localhost/"
        self.host_url = "http://localhost/"
        self.full_path = "/"
        self.args = MultiDict()
        self.headers = HeadersDict()
        self.cookies = {}
        self.remote_addr = "worker-edge"
        self.user_agent = UserAgentObj("Cloudflare Worker")
        self.form = MultiDict()
        self.files = {}
        self.data = b""
        self._json_loaded = False
        self._json_val = None

    def load_from_worker(self, url_str, method, headers_dict, raw_bytes):
        self.reset()
        parsed = urlparse(url_str)
        self.method = str(method or "GET").upper()
        self.url = url_str
        self.path = unquote(parsed.path or "/")
        self.host_url = f"{parsed.scheme}://{parsed.netloc}/"
        self.base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.full_path = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
        self.args = MultiDict(parse_qs(parsed.query, keep_blank_values=True))
        self.headers = HeadersDict(headers_dict or {})
        self.remote_addr = self.headers.get("CF-Connecting-IP") or self.headers.get("X-Forwarded-For") or "worker-edge"
        self.user_agent = UserAgentObj(self.headers.get("User-Agent") or "Cloudflare Worker")
        cookie_hdr = self.headers.get("Cookie") or ""
        for part in cookie_hdr.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                self.cookies[k.strip()] = v.strip()
        self.data = raw_bytes if isinstance(raw_bytes, (bytes, bytearray)) else bytes(raw_bytes or b"")
        ct = (self.headers.get("Content-Type") or "").lower()
        if "multipart/form-data" in ct:
            self.form, self.files = parse_multipart_form_data(self.headers.get("Content-Type"), self.data)
        elif "application/x-www-form-urlencoded" in ct and self.data:
            self.form = MultiDict(parse_qs(self.data.decode("utf-8", errors="replace"), keep_blank_values=True))

    def get_json(self, silent=False, force=False):
        if self._json_loaded:
            return self._json_val
        self._json_loaded = True
        try:
            if not self.data:
                self._json_val = None
            else:
                self._json_val = json.loads(self.data.decode("utf-8"))
        except Exception:
            if silent:
                self._json_val = None
            else:
                raise
        return self._json_val

    @property
    def json(self):
        return self.get_json(silent=True)

    def get_data(self, as_text=False):
        return self.data.decode("utf-8", errors="replace") if as_text else self.data


class SessionDict(dict):
    def __init__(self):
        super().__init__()
        self.permanent = True
        self.modified = False


class ResponseObj:
    def __init__(self, body="", status=200, headers=None, mimetype=None):
        self.body = body
        self.status_code = int(status)
        self.headers = HeadersDict(headers or {})
        if mimetype and not self.headers.get("Content-Type"):
            self.headers["Content-Type"] = mimetype

    def set_cookie(self, key, value="", max_age=None, path="/", httponly=True, samesite="Lax", secure=False):
        parts = [f"{key}={value}", f"Path={path}"]
        if max_age is not None:
            parts.append(f"Max-Age={int(max_age)}")
        if httponly:
            parts.append("HttpOnly")
        if samesite:
            parts.append(f"SameSite={samesite}")
        if secure:
            parts.append("Secure")
        self.headers["Set-Cookie"] = "; ".join(parts)


Response = ResponseObj
request = RequestProxy()
session = SessionDict()


def jsonify(*args, **kwargs):
    if args and kwargs:
        payload = dict(args[0])
        payload.update(kwargs)
    elif len(args) == 1:
        payload = args[0]
    elif len(args) > 1:
        payload = list(args)
    else:
        payload = kwargs
    return ResponseObj(
        json.dumps(payload, ensure_ascii=False, default=str),
        status=200,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )


def make_response(rv, status=None, headers=None):
    if isinstance(rv, ResponseObj):
        resp = rv
    elif isinstance(rv, tuple):
        body = rv[0]
        st = rv[1] if len(rv) > 1 else 200
        hdrs = rv[2] if len(rv) > 2 else None
        resp = make_response(body, status=st, headers=hdrs)
    elif isinstance(rv, (dict, list)):
        resp = jsonify(rv)
    elif isinstance(rv, (bytes, bytearray)):
        resp = ResponseObj(bytes(rv), status=200)
    else:
        resp = ResponseObj(str(rv if rv is not None else ""), status=200, headers={"Content-Type": "text/html; charset=utf-8"})
    if status is not None:
        resp.status_code = int(status)
    if isinstance(headers, dict):
        resp.headers.update(headers)
    return resp


def redirect(location, code=302):
    return ResponseObj("", status=code, headers={"Location": str(location)})


def url_for(endpoint, **values):
    if endpoint == "static":
        fname = values.get("filename", "")
        return "/" + str(fname).lstrip("/")
    return "/" + str(endpoint).lstrip("/")


def abort(code, description=""):
    raise HTTPAbort(code, description)


def flash(message, category="message"):
    return None


def render_template(template_name, **context):
    return ResponseObj(
        f"Template '{template_name}' is served via Cloudflare Assets.",
        status=200,
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )


def render_template_string(source, **context):
    return ResponseObj(str(source), status=200, headers={"Content-Type": "text/html; charset=utf-8"})


class _NullLogger:
    def info(self, *a, **kw): pass
    def warning(self, *a, **kw): pass
    def error(self, *a, **kw): pass
    def exception(self, *a, **kw): pass


def _compile_rule(rule):
    parts = []
    pos = 0
    for m in re.finditer(r"<(?:(?P<conv>[a-zA-Z_]+):)?(?P<name>[a-zA-Z_][a-zA-Z0-9_]*)>", rule):
        parts.append(re.escape(rule[pos : m.start()]))
        conv = m.group("conv") or "string"
        name = m.group("name")
        if conv == "path":
            parts.append(f"(?P<{name}>.+)")
        elif conv == "int":
            parts.append(f"(?P<{name}>\\d+)")
        else:
            parts.append(f"(?P<{name}>[^/]+)")
        pos = m.end()
    parts.append(re.escape(rule[pos:]))
    return re.compile("^" + "".join(parts) + "$")


class Flask:
    def __init__(self, import_name, static_folder="static"):
        self.import_name = import_name
        self.static_folder = static_folder
        self.secret_key = "sanova_cf_worker_secret"
        self.config = {}
        self.logger = _NullLogger()
        self._routes = []
        self._before_request_funcs = []
        self._after_request_funcs = []
        self._context_processors = []

    def route(self, rule, methods=None, **options):
        allowed = {m.upper() for m in (methods or ["GET"])}
        if "GET" in allowed:
            allowed.add("HEAD")
        regex = _compile_rule(rule)

        def decorator(fn):
            self._routes.append((rule, regex, allowed, fn))
            return fn

        return decorator

    def before_request(self, fn):
        self._before_request_funcs.append(fn)
        return fn

    def after_request(self, fn):
        self._after_request_funcs.append(fn)
        return fn

    def context_processor(self, fn):
        self._context_processors.append(fn)
        return fn

    def errorhandler(self, code_or_exc):
        def decorator(fn):
            return fn
        return decorator

    def template_filter(self, name=None):
        def decorator(fn):
            return fn
        return decorator

    def dispatch(self, path, method):
        method_up = str(method or "GET").upper()
        matched_fn = None
        matched_kwargs = {}
        path_matched_other_method = False

        for _rule, regex, allowed, fn in self._routes:
            m = regex.match(path)
            if m:
                if method_up in allowed:
                    matched_fn = fn
                    matched_kwargs = m.groupdict()
                    break
                path_matched_other_method = True

        if not matched_fn:
            if path_matched_other_method:
                return ResponseObj(
                    json.dumps({"error": "Method Not Allowed"}, ensure_ascii=False),
                    status=405,
                    headers={"Content-Type": "application/json; charset=utf-8"},
                )
            return None

        try:
            rv = matched_fn(**matched_kwargs)
            resp = make_response(rv)
        except HTTPAbort as ab:
            resp = jsonify({"success": False, "error": ab.description or f"HTTP {ab.code}"})
            resp.status_code = ab.code
        except Exception as exc:
            resp = jsonify({"success": False, "error": f"Lỗi xử lý API: {exc}"})
            resp.status_code = 500
        return resp
