import csv
import hashlib
import hmac
import io
import json
import secrets
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlparse
from workers import Response, WorkerEntrypoint

DEFAULT_SYSTEM_SETTINGS = {
    "security": {
        "session_timeout": 30,
        "session_warning_enabled": True,
        "session_warning_minutes": 5,
        "max_failed_logins": 5,
        "lockout_duration": 15,
        "log_failed_logins": True,
        "single_session_only": False,
    },
    "password": {
        "min_length": 8,
        "require_uppercase": True,
        "require_number": True,
        "require_special": False,
        "force_change_first_login": True,
        "prevent_common_passwords": True,
        "password_expiry_days": 90,
    },
    "backup": {
        "auto_backup_enabled": True,
        "backup_frequency": "daily",
        "retention_count": 7,
        "last_backup_time": "Chưa có",
        "history": [],
    },
    "notifications": {
        "alert_failed_login": True,
        "alert_account_locked": True,
        "alert_system_error": True,
        "alert_stock_discrepancy": True,
    },
    "general": {
        "system_name": "SANOVA WMS",
        "timezone": "Asia/Ho_Chi_Minh (GMT+7)",
        "date_format": "DD/MM/YYYY",
        "log_retention_days": 90,
    },
}

PERMISSION_MODULES = [
    {"id": "users", "name": "Quản lý người dùng", "icon": "👥"},
    {"id": "locations", "name": "Quản lý kho, kệ, vị trí", "icon": "🏠"},
    {"id": "products", "name": "Quản lý danh mục sản phẩm", "icon": "📦"},
    {"id": "inbound", "name": "Nhập kho", "icon": "↔️"},
    {"id": "outbound", "name": "Xuất kho / Lấy hàng", "icon": "↔️"},
    {"id": "stocktake", "name": "Kiểm kê & điều chỉnh tồn", "icon": "📋"},
    {"id": "reports", "name": "Báo cáo & thống kê", "icon": "📊"},
    {"id": "settings", "name": "Cấu hình hệ thống", "icon": "⚙️"},
]

PERMISSION_ACTIONS = [
    ("view", "Xem"),
    ("create", "Thêm"),
    ("edit", "Sửa"),
    ("delete", "Xóa"),
    ("approve", "Phê duyệt"),
]

INITIAL_ROLES = {
    "ADMIN": {
        "id": "ADMIN",
        "role_code": "ADMIN",
        "name": "Quản trị viên (Admin)",
        "role_name": "Quản trị viên (Admin)",
        "desc": "Quản trị toàn bộ hệ thống",
        "description": "Quản trị toàn bộ hệ thống",
        "icon": "👑",
        "status": "Hoạt động",
        "is_system": True,
        "permissions": {
            m["id"]: {"view": True, "create": True, "edit": True, "delete": True, "approve": True}
            for m in PERMISSION_MODULES
        },
        "detail_permissions": {},
    },
    "WAREHOUSE_MANAGER": {
        "id": "WAREHOUSE_MANAGER",
        "role_code": "WAREHOUSE_MANAGER",
        "name": "Quản lý kho (Manager)",
        "role_name": "Quản lý kho (Manager)",
        "desc": "Quản lý nghiệp vụ kho và vận hành hệ thống kho.",
        "description": "Quản lý nghiệp vụ kho và vận hành",
        "icon": "📚",
        "status": "Hoạt động",
        "is_system": True,
        "permissions": {
            "users": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "locations": {"view": True, "create": True, "edit": True, "delete": False, "approve": False},
            "products": {"view": True, "create": True, "edit": True, "delete": False, "approve": False},
            "inbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": True},
            "outbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "stocktake": {"view": True, "create": False, "edit": False, "delete": False, "approve": True},
            "reports": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "settings": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
        },
        "detail_permissions": {},
    },
    "WAREHOUSE_STAFF": {
        "id": "WAREHOUSE_STAFF",
        "role_code": "WAREHOUSE_STAFF",
        "name": "Nhân viên kho (Staff)",
        "role_name": "Nhân viên kho (Staff)",
        "desc": "Thực hiện hoạt động nhập, lấy, đóng gói",
        "description": "Thực hiện hoạt động nhập, lấy, đóng gói",
        "icon": "👤",
        "status": "Hoạt động",
        "is_system": True,
        "permissions": {
            "users": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "locations": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "products": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "inbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "outbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "stocktake": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "reports": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "settings": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
        },
        "detail_permissions": {},
    },
    "COORDINATOR": {
        "id": "COORDINATOR",
        "role_code": "COORDINATOR",
        "name": "Điều phối / Kế toán kho",
        "role_name": "Điều phối / Kế toán kho",
        "desc": "Theo dõi, đối soát và hỗ trợ nghiệp vụ kho",
        "description": "Theo dõi, đối soát và hỗ trợ nghiệp vụ kho",
        "icon": "📋",
        "status": "Hoạt động",
        "is_system": True,
        "permissions": {
            "users": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "locations": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "products": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "inbound": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "outbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "stocktake": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "reports": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "settings": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
        },
        "detail_permissions": {},
    },
}

ROLE_NAME_TO_KEY = {
    "Quản trị viên": "ADMIN",
    "Quản trị viên (Admin)": "ADMIN",
    "Quản lý kho": "WAREHOUSE_MANAGER",
    "Quản lý kho (Manager)": "WAREHOUSE_MANAGER",
    "Nhân viên kho": "WAREHOUSE_STAFF",
    "Nhân viên kho (Staff)": "WAREHOUSE_STAFF",
    "Điều phối / Kế toán kho": "COORDINATOR",
    "Điều phối / Kế toán": "COORDINATOR",
}

SEVERITY_LABELS = {
    "critical": "Khẩn cấp / Nghiêm trọng",
    "action_required": "Cần xử lý",
    "important": "Quan trọng",
    "info": "Thông tin hệ thống",
}

DEFAULT_INITIAL_USERS = {
    "admin": {
        "staff_code": "ADM001",
        "password": "Admin21102005@",
        "name": "Phạm Đức Long",
        "email": "duc.long@sanova.vn",
        "role": "Quản trị viên",
        "status": "Hoạt động",
        "last_login": "Chưa có",
        "scope": "Kho chính - SANOVA",
    }
}

_DB_BOOTSTRAPPED = False


async def ensure_db_ready(env):
    global _DB_BOOTSTRAPPED
    if _DB_BOOTSTRAPPED:
        return
    await env.DATABASE.prepare(
        "CREATE TABLE IF NOT EXISTS json_store (store_key TEXT PRIMARY KEY, payload TEXT)"
    ).run()
    existing_users = await db_get_json(env, "users", {})
    if not isinstance(existing_users, dict) or not existing_users:
        await db_set_json(env, "users", deepcopy(DEFAULT_INITIAL_USERS))
    _DB_BOOTSTRAPPED = True


async def read_json_body(request):
    try:
        raw = await request.text()
        if not raw:
            return {}
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


async def serve_asset_html(env, request, asset_path):
    parsed = urlparse(request.url)
    asset_url = f"{parsed.scheme}://{parsed.netloc}{asset_path}"
    return await env.ASSETS.fetch(asset_url)


async def db_get_json(env, store_key, default):
    row = (
        await env.DATABASE.prepare(
            "SELECT payload FROM json_store WHERE store_key = ? LIMIT 1"
        )
        .bind(store_key)
        .first()
    )
    if not row:
        return default
    payload = getattr(row, "payload", None)
    if payload is None and hasattr(row, "to_py"):
        py_row = row.to_py()
        payload = py_row.get("payload") if isinstance(py_row, dict) else None
    if not payload:
        return default
    try:
        return json.loads(payload)
    except Exception:
        return default


async def db_set_json(env, store_key, value):
    serialized = json.dumps(value, ensure_ascii=False)
    await env.DATABASE.prepare(
        """
        INSERT INTO json_store (store_key, payload)
        VALUES (?, ?)
        ON CONFLICT(store_key) DO UPDATE SET payload = excluded.payload
        """
    ).bind(store_key, serialized).run()


def json_response(data, status=200, extra_headers=None):
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if extra_headers:
        headers.update(extra_headers)
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=status,
        headers=headers,
    )


def text_response(text, status=200):
    return Response(
        text,
        status=status,
        headers={"Content-Type": "text/plain; charset=utf-8"},
    )


def verify_stored_password(stored_password, input_password):
    if not stored_password or not input_password:
        return False
    raw = str(stored_password)
    if raw.startswith("sha256$"):
        parts = raw.split("$", 2)
        if len(parts) == 3:
            _, salt, expected_hex = parts
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                input_password.encode("utf-8"),
                salt.encode("utf-8"),
                100_000,
            ).hex()
            return hmac.compare_digest(digest, expected_hex)
        return False
    if raw.startswith("pbkdf2:sha256:"):
        parts = raw.split("$", 2)
        if len(parts) == 3:
            _, salt, expected_hex = parts
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                input_password.encode("utf-8"),
                salt.encode("utf-8"),
                260_000,
            ).hex()
            return hmac.compare_digest(digest, expected_hex)
        return False
    if raw.startswith("scrypt:"):
        parts = raw.split("$", 2)
        if len(parts) == 3 and hasattr(hashlib, "scrypt"):
            try:
                method_parts = parts[0].split(":")
                n_val = int(method_parts[1])
                r_val = int(method_parts[2])
                p_val = int(method_parts[3])
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


def hash_new_password(password):
    salt = secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    ).hex()
    return f"sha256${salt}${digest}"


def _extract_bearer_token(request):
    auth = request.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    cookie_hdr = request.headers.get("Cookie") or ""
    for part in cookie_hdr.split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            if k == "sanova_session":
                return v.strip()
    return ""


async def get_authenticated_user(env, request):
    token = _extract_bearer_token(request)
    if not token:
        return None, None
    sessions = await db_get_json(env, "sessions", {})
    sess = sessions.get(token) if isinstance(sessions, dict) else None
    if not isinstance(sess, dict):
        return None, None
    username = sess.get("username")
    users = await db_get_json(env, "users", {})
    user_obj = users.get(username) if isinstance(users, dict) else None
    if not user_obj or user_obj.get("status") != "Hoạt động":
        return None, None
    return username, {**user_obj, "username": username}


async def require_admin(env, request):
    username, user = await get_authenticated_user(env, request)
    if not user:
        return None, None, json_response(
            {"success": False, "message": "Chưa đăng nhập hoặc phiên hết hạn."},
            status=401,
        )
    if "Quản trị viên" not in str(user.get("role", "")):
        return None, None, json_response(
            {"success": False, "message": "Bạn không có quyền truy cập phân hệ Quản trị."},
            status=403,
        )
    return username, user, None


async def append_audit_log(
    env, actor_name, actor_username, category, action, target,
    result="Thành công", reason="", changes=None
):
    logs = await db_get_json(env, "audit_logs", [])
    now = datetime.now(timezone.utc)
    entry = {
        "id": f"LOG-{now.strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}",
        "timestamp": now.strftime("%d/%m/%Y – %H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "actor": actor_name or "Hệ thống",
        "by": f"{actor_name or 'Hệ thống'} ({actor_username or 'system'})",
        "category": category,
        "action": action,
        "target": str(target),
        "result": result,
        "status": result,
        "ip": "worker-edge",
        "device": "Cloudflare Worker",
        "changes": changes or [],
        "reason": reason,
    }
    logs.insert(0, entry)
    await db_set_json(env, "audit_logs", logs[:1000])
    return entry


async def create_admin_noti(
    env, group, title, message, target_url="/admin", severity="info",
    recipient="ALL_ADMINS", dedup_key="", account="", reason="", impact=""
):
    notis = await db_get_json(env, "admin_notifications", [])
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    if dedup_key:
        for item in notis:
            if item.get("dedup_key") == dedup_key:
                if item.get("message") != message:
                    item["message"] = message
                    item["created_at"] = now_str
                    item["read_by"] = []
                    await db_set_json(env, "admin_notifications", notis[:200])
                return
    notis.insert(
        0,
        {
            "id": f"NOTI-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}",
            "group": group,
            "severity": severity,
            "severity_label": SEVERITY_LABELS.get(severity, "Thông tin"),
            "title": title,
            "message": message,
            "account": account,
            "reason": reason,
            "impact": impact,
            "target_url": target_url,
            "created_at": now_str,
            "recipient": recipient,
            "read_by": [],
            "dedup_key": dedup_key,
        },
    )
    await db_set_json(env, "admin_notifications", notis[:200])


def _count_role_users(users_dict, role_code, role_obj):
    r_name = role_obj.get("name") or role_obj.get("role_name", "")
    return sum(
        1
        for u in users_dict.values()
        if u.get("role_code") == role_code
        or u.get("role") == r_name
        or ROLE_NAME_TO_KEY.get(u.get("role", "")) == role_code
    )


def _validate_password_against_policy(password, pwd_cfg):
    min_len = int(pwd_cfg.get("min_length", 8))
    if len(password) < min_len:
        return False, f"Mật khẩu phải có tối thiểu {min_len} ký tự."
    if pwd_cfg.get("require_uppercase") and not any(c.isupper() for c in password):
        return False, "Mật khẩu phải chứa ít nhất 1 chữ cái in hoa."
    if pwd_cfg.get("require_number") and not any(c.isdigit() for c in password):
        return False, "Mật khẩu phải chứa ít nhất 1 chữ số."
    if pwd_cfg.get("require_special") and password.isalnum():
        return False, "Mật khẩu phải chứa ít nhất 1 ký tự đặc biệt."
    return True, ""


def _role_redirect_path(role_name):
    r = str(role_name or "")
    if "Quản trị viên" in r:
        return "/admin"
    if "Quản lý kho" in r:
        return "/warehouse/manager"
    if "Điều phối" in r or "Kế toán" in r:
        return "/dispatcher"
    return "/staff/dashboard"


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        parsed = urlparse(request.url)
        path = parsed.path
        method = str(request.method).upper()
        qs = parse_qs(parsed.query)

        # 0. Giao diện web HTML phục vụ từ Cloudflare Assets
        if method == "GET":
            if path in ("/", "/welcome"):
                return await serve_asset_html(self.env, request, "/index.html")
            if path == "/login":
                return await serve_asset_html(self.env, request, "/login.html")
            if path in (
                "/admin",
                "/admin/users",
                "/admin/roles",
                "/admin/logs",
                "/admin/settings",
                "/admin/profile",
                "/admin/notifications",
            ):
                return await serve_asset_html(self.env, request, "/admin.html")
            if path in ("/warehouse/manager", "/staff/dashboard", "/dispatcher"):
                return await serve_asset_html(self.env, request, "/portal.html")
            if path == "/logout":
                return Response(
                    "",
                    status=302,
                    headers={
                        "Location": "/login",
                        "Set-Cookie": "sanova_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
                    },
                )

        await ensure_db_ready(self.env)

        # 1. Đăng nhập, Kiểm tra phiên & Đăng xuất
        if path == "/api/auth/me" and method == "GET":
            username, user = await get_authenticated_user(self.env, request)
            if not user:
                return json_response(
                    {"success": False, "message": "Chưa đăng nhập hoặc phiên hết hạn."},
                    status=401,
                )
            return json_response(
                {
                    "success": True,
                    "redirect_to": _role_redirect_path(user.get("role")),
                    "user": {
                        "username": username,
                        "name": user.get("name", ""),
                        "email": user.get("email", ""),
                        "role": user.get("role", ""),
                        "scope": user.get("scope", "Kho chính - SANOVA"),
                    },
                }
            )

        if path == "/api/auth/login" and method == "POST":
            body = await read_json_body(request)
            login_input = str(body.get("username", "")).strip()
            password = str(body.get("password", ""))
            users = await db_get_json(self.env, "users", {})
            matched_username, matched_user = None, None
            if isinstance(users, dict):
                for uname, udata in users.items():
                    if (
                        uname.lower() == login_input.lower()
                        or str(udata.get("staff_code", "")).lower() == login_input.lower()
                    ):
                        matched_username, matched_user = uname, udata
                        break

            if not matched_user or not verify_stored_password(matched_user.get("password"), password):
                await append_audit_log(
                    self.env,
                    login_input or "Khách",
                    login_input or "guest",
                    "Bảo mật",
                    "Đăng nhập thất bại (Sai mật khẩu)",
                    login_input or "Chưa nhập",
                    result="Thất bại",
                    reason="Sai thông tin xác thực",
                )
                await create_admin_noti(
                    self.env,
                    "security",
                    "Đăng nhập thất bại",
                    f"Tài khoản '{login_input or 'Chưa nhập'}' vừa nhập sai mật khẩu.",
                    target_url="/admin/logs?category=Bảo+mật",
                    severity="important",
                )
                return json_response(
                    {"success": False, "message": "Tên đăng nhập hoặc mật khẩu không chính xác."},
                    status=401,
                )

            if matched_user.get("status") != "Hoạt động":
                return json_response(
                    {"success": False, "message": f"Tài khoản đang ở trạng thái '{matched_user.get('status')}'."},
                    status=403,
                )

            token = secrets.token_hex(24)
            sessions = await db_get_json(self.env, "sessions", {})
            sessions[token] = {
                "username": matched_username,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            await db_set_json(self.env, "sessions", sessions)

            matched_user["last_login"] = datetime.now(timezone.utc).strftime("%d/%m/%Y · %H:%M")
            users[matched_username] = matched_user
            await db_set_json(self.env, "users", users)

            await append_audit_log(
                self.env,
                matched_user.get("name", matched_username),
                matched_username,
                "Bảo mật",
                "Đăng nhập hệ thống",
                matched_username,
                result="Thành công",
            )
            return json_response(
                {
                    "success": True,
                    "token": token,
                    "redirect_to": _role_redirect_path(matched_user.get("role")),
                    "user": {
                        "username": matched_username,
                        "name": matched_user.get("name", ""),
                        "role": matched_user.get("role", ""),
                        "scope": matched_user.get("scope", "Kho chính - SANOVA"),
                    },
                },
                extra_headers={
                    "Set-Cookie": f"sanova_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"
                },
            )

        if path == "/api/auth/logout" and method == "POST":
            token = _extract_bearer_token(request)
            username, user = await get_authenticated_user(self.env, request)
            if token:
                sessions = await db_get_json(self.env, "sessions", {})
                sessions.pop(token, None)
                await db_set_json(self.env, "sessions", sessions)
            if username and user:
                await append_audit_log(
                    self.env,
                    user.get("name", username),
                    username,
                    "Bảo mật",
                    "Đăng xuất hệ thống",
                    username,
                )
            return json_response(
                {"success": True},
                extra_headers={
                    "Set-Cookie": "sanova_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
                },
            )

        # 2. Dashboard Admin
        if path == "/admin/api/dashboard" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            users = await db_get_json(self.env, "users", {})
            logs = await db_get_json(self.env, "audit_logs", [])
            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            role_counts = {
                "Quản trị viên": 0,
                "Quản lý kho": 0,
                "Nhân viên kho": 0,
                "Điều phối / Kế toán kho": 0,
            }
            for u in users.values():
                r = u.get("role", "")
                if "Quản trị viên" in r:
                    role_counts["Quản trị viên"] += 1
                elif "Quản lý kho" in r:
                    role_counts["Quản lý kho"] += 1
                elif "Nhân viên kho" in r:
                    role_counts["Nhân viên kho"] += 1
                elif "Điều phối" in r or "Kế toán" in r:
                    role_counts["Điều phối / Kế toán kho"] += 1

            today_logs = [l for l in logs if l.get("date") == today]
            return json_response(
                {
                    "success": True,
                    "total_users": len(users),
                    "active_users": sum(1 for u in users.values() if u.get("status") == "Hoạt động"),
                    "locked_count": sum(1 for u in users.values() if u.get("status") == "Tạm khóa"),
                    "pending_count": sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt"),
                    "role_counts": role_counts,
                    "today_activity": {
                        "created": sum(1 for l in today_logs if "Tạo" in l.get("action", "")),
                        "updated": sum(1 for l in today_logs if "Cập nhật" in l.get("action", "")),
                        "status": sum(1 for l in today_logs if "khóa" in l.get("action", "").lower()),
                        "settings": sum(1 for l in today_logs if "cấu hình" in l.get("action", "").lower()),
                    },
                    "recent_logs": logs[:5],
                    "system_settings": {
                        "session_timeout": sys_cfg.get("security", {}).get("session_timeout", 30),
                        "max_login_attempts": sys_cfg.get("security", {}).get("max_failed_logins", 5),
                        "minimum_password_length": sys_cfg.get("password", {}).get("min_length", 8),
                    },
                }
            )

        # 3. Quản lý người dùng
        if path == "/admin/api/users" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            users = await db_get_json(self.env, "users", {})
            q = (qs.get("q", [""])[0] or "").strip().lower()
            role_f = qs.get("role", ["ALL"])[0]
            status_f = qs.get("status", ["ALL"])[0]
            page = max(1, int(qs.get("page", ["1"])[0] or 1))
            per_page = 10

            items = []
            for uname, u in users.items():
                if q and not any(
                    q in str(u.get(k, "") if k != "username" else uname).lower()
                    for k in ("staff_code", "name", "username", "email")
                ):
                    continue
                if role_f != "ALL" and u.get("role") != role_f:
                    continue
                if status_f != "ALL" and u.get("status") != status_f:
                    continue
                items.append({**u, "username": uname})

            total_pages = max(1, (len(items) + per_page - 1) // per_page)
            page = min(page, total_pages)
            return json_response(
                {
                    "success": True,
                    "items": items[(page - 1) * per_page : page * per_page],
                    "page": page,
                    "total_pages": total_pages,
                    "total_filtered": len(items),
                    "stats": {
                        "total": len(users),
                        "active": sum(1 for u in users.values() if u.get("status") == "Hoạt động"),
                        "locked": sum(1 for u in users.values() if u.get("status") == "Tạm khóa"),
                        "pending": sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt"),
                    },
                }
            )

        if path == "/admin/api/users/export-data" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            users = await db_get_json(self.env, "users", {})
            q = (qs.get("q", [""])[0] or "").strip().lower()
            role_f = qs.get("role", ["ALL"])[0]
            status_f = qs.get("status", ["ALL"])[0]
            items = []
            for uname, u in users.items():
                if q and not any(
                    q in str(u.get(k, "") if k != "username" else uname).lower()
                    for k in ("staff_code", "name", "username", "email")
                ):
                    continue
                if role_f != "ALL" and u.get("role") != role_f:
                    continue
                if status_f != "ALL" and u.get("status") != status_f:
                    continue
                safe_u = {k: v for k, v in u.items() if k != "password"}
                safe_u["username"] = uname
                items.append(safe_u)
            return json_response(
                {
                    "success": True,
                    "exported_at": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC"),
                    "filters": {"q": q, "role": role_f, "status": status_f},
                    "stats": {
                        "total": len(users),
                        "filtered": len(items),
                        "active": sum(1 for u in users.values() if u.get("status") == "Hoạt động"),
                        "locked": sum(1 for u in users.values() if u.get("status") == "Tạm khóa"),
                        "pending": sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt"),
                    },
                    "items": items,
                }
            )

        if path == "/admin/api/users/create" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            staff_code = str(data.get("staff_code", "")).strip().upper()
            name = str(data.get("name", "")).strip()
            raw_email = str(data.get("email", "")).strip()
            email = f"{raw_email.split('@')[0].strip()}@sanova.vn" if raw_email else ""
            username = str(data.get("username", "")).strip()
            role = str(data.get("role", "")).strip()
            scope = str(data.get("scope", "")).strip() or "Kho chính - SANOVA"
            password = str(data.get("password", ""))
            confirm_password = str(data.get("confirm_password", ""))
            status = str(data.get("status", "Hoạt động")).strip()

            if not staff_code or not name or not username or not role or not password:
                return json_response({"success": False, "message": "Thiếu thông tin bắt buộc."}, 400)
            if password != confirm_password:
                return json_response({"success": False, "message": "Xác nhận mật khẩu không khớp."}, 400)

            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            ok_pwd, pwd_msg = _validate_password_against_policy(password, sys_cfg.get("password", {}))
            if not ok_pwd:
                return json_response({"success": False, "message": pwd_msg}, 400)

            users = await db_get_json(self.env, "users", {})
            if username in users:
                return json_response({"success": False, "message": f"Tên đăng nhập '{username}' đã tồn tại."}, 400)
            if any(str(u.get("staff_code", "")).upper() == staff_code for u in users.values()):
                return json_response({"success": False, "message": f"Mã nhân viên '{staff_code}' đã tồn tại."}, 400)

            now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y · %H:%M")
            users[username] = {
                "staff_code": staff_code,
                "name": name,
                "email": email,
                "role": role,
                "scope": scope,
                "password": hash_new_password(password),
                "status": status if status in ("Hoạt động", "Chờ kích hoạt") else "Hoạt động",
                "last_login": "Chưa có",
                "created_at": now_str,
                "created_by": actor_user.get("name", actor_uname),
            }
            await db_set_json(self.env, "users", users)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "TÀI KHOẢN",
                f"Tạo người dùng {name} ({staff_code})",
                username,
                changes=[
                    {"field": "Vai trò", "before": "", "after": role},
                    {"field": "Phạm vi kho", "before": "", "after": scope},
                ],
            )
            if users[username]["status"] == "Chờ kích hoạt":
                await create_admin_noti(
                    self.env,
                    "account",
                    "Tài khoản chờ kích hoạt",
                    f"Tài khoản {name} ({username}) đang chờ kích hoạt.",
                    target_url="/admin/users?status=Chờ+kích+hoạt",
                    severity="action_required",
                )
            return json_response({"success": True, "message": f"Tạo tài khoản {username} thành công."})

        if path == "/admin/api/users/update" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            username = str(data.get("username", "")).strip()
            users = await db_get_json(self.env, "users", {})
            if username not in users:
                return json_response({"success": False, "message": "Tài khoản không tồn tại."}, 404)
            u = users[username]
            new_role = str(data.get("role", u.get("role", ""))).strip()
            if username == actor_uname and "Quản trị viên" not in new_role:
                return json_response({"success": False, "message": "Không cho phép tự hạ quyền quản trị."}, 400)
            changes = []
            for field, label in (("name", "Họ tên"), ("email", "Email"), ("role", "Vai trò"), ("scope", "Phạm vi kho")):
                if field in data:
                    val = str(data.get(field) or "").strip()
                    if field == "email" and val and "@" not in val:
                        val = f"{val}@sanova.vn"
                    if u.get(field) != val:
                        changes.append({"field": label, "before": u.get(field, ""), "after": val})
                        u[field] = val
            await db_set_json(self.env, "users", users)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "TÀI KHOẢN",
                f"Cập nhật tài khoản {username}",
                username,
                changes=changes,
            )
            return json_response({"success": True, "message": "Cập nhật tài khoản thành công."})

        if path == "/admin/api/users/toggle-status" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            username = str(data.get("username", "")).strip()
            users = await db_get_json(self.env, "users", {})
            if username not in users:
                return json_response({"success": False, "message": "Tài khoản không tồn tại."}, 404)
            target = users[username]
            if username == actor_uname or "Quản trị viên" in str(target.get("role", "")) or username in ("admin", "duc.long"):
                return json_response({"success": False, "message": "Không được phép khóa tài khoản Quản trị viên."}, 403)
            old_st = target.get("status", "Hoạt động")
            new_st = "Tạm khóa" if old_st == "Hoạt động" else "Hoạt động"
            target["status"] = new_st
            await db_set_json(self.env, "users", users)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "TÀI KHOẢN",
                f"{new_st} tài khoản {target.get('name', username)}",
                username,
                changes=[{"field": "Trạng thái", "before": old_st, "after": new_st}],
            )
            return json_response({"success": True, "status": new_st, "message": f"Đã chuyển trạng thái sang '{new_st}'."})

        if path == "/admin/api/users/reset-password" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            username = str(data.get("username", "")).strip()
            new_pwd = str(data.get("new_password", ""))
            users = await db_get_json(self.env, "users", {})
            if username not in users:
                return json_response({"success": False, "message": "Tài khoản không tồn tại."}, 404)
            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            ok_pwd, pwd_msg = _validate_password_against_policy(new_pwd, sys_cfg.get("password", {}))
            if not ok_pwd:
                return json_response({"success": False, "message": pwd_msg}, 400)
            users[username]["password"] = hash_new_password(new_pwd)
            await db_set_json(self.env, "users", users)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "BẢO MẬT",
                "Đặt lại mật khẩu người dùng",
                username,
            )
            return json_response({"success": True, "message": "Đã đặt lại mật khẩu thành công."})

        # 4. Vai trò & Phân quyền
        if path == "/admin/api/roles" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            users = await db_get_json(self.env, "users", {})
            counts = {code: _count_role_users(users, code, obj) for code, obj in roles_data.items()}
            return json_response(
                {
                    "success": True,
                    "roles": roles_data,
                    "modules": PERMISSION_MODULES,
                    "actions": PERMISSION_ACTIONS,
                    "role_user_counts": counts,
                    "total_assigned_accounts": sum(counts.values()),
                }
            )

        if path == "/admin/api/roles/create" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            role_code = str(data.get("role_code", "")).strip().upper()
            role_name = str(data.get("name", "")).strip()
            desc = str(data.get("desc", "")).strip()
            matrix_perms = data.get("permissions", {})
            if not role_code or not role_name or not role_code.replace("_", "").isalnum():
                return json_response({"success": False, "message": "Mã vai trò hoặc tên vai trò không hợp lệ."}, 400)
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            if role_code in roles_data:
                return json_response({"success": False, "message": f"Mã vai trò '{role_code}' đã tồn tại."}, 400)
            clean_matrix = {}
            has_any = False
            for m in PERMISSION_MODULES:
                mid = m["id"]
                clean_matrix[mid] = {}
                raw_m = matrix_perms.get(mid, {}) if isinstance(matrix_perms, dict) else {}
                for aid, _ in PERMISSION_ACTIONS:
                    v = bool(raw_m.get(aid, False))
                    clean_matrix[mid][aid] = v
                    if v:
                        has_any = True
            if not has_any:
                return json_response({"success": False, "message": "Cần chọn ít nhất 1 quyền cho vai trò."}, 400)
            roles_data[role_code] = {
                "id": role_code,
                "role_code": role_code,
                "name": role_name,
                "role_name": role_name,
                "desc": desc or "Vai trò tùy chỉnh SANOVA",
                "description": desc or "Vai trò tùy chỉnh SANOVA",
                "icon": "🛡️",
                "status": "Hoạt động",
                "is_system": False,
                "permissions": clean_matrix,
                "detail_permissions": data.get("detail_permissions", {})
                if isinstance(data.get("detail_permissions"), dict)
                else {},
            }
            await db_set_json(self.env, "roles", roles_data)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Phân quyền",
                f"Thêm mới vai trò {role_name}",
                role_code,
            )
            return json_response({"success": True, "message": f"Đã tạo vai trò '{role_name}'."})

        if path == "/admin/api/roles/save-permissions" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            role_code = str(data.get("role_code") or data.get("role_id") or "").strip()
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            if role_code not in roles_data:
                return json_response({"success": False, "message": "Vai trò không tồn tại."}, 404)
            if role_code != "ADMIN":
                roles_data[role_code]["permissions"] = data.get("permissions", {})
                if isinstance(data.get("detail_permissions"), dict):
                    roles_data[role_code]["detail_permissions"] = data["detail_permissions"]
            await db_set_json(self.env, "roles", roles_data)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Phân quyền",
                f"Cập nhật phân quyền vai trò {role_code}",
                role_code,
            )
            return json_response({"success": True, "message": "Đã lưu phân quyền thành công."})

        if path == "/admin/api/roles/reset-default" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            role_code = str(data.get("role_code") or data.get("role_id") or "").strip()
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            if role_code not in INITIAL_ROLES:
                return json_response({"success": False, "message": "Không có cấu hình mặc định cho vai trò này."}, 400)
            roles_data[role_code]["permissions"] = deepcopy(INITIAL_ROLES[role_code]["permissions"])
            roles_data[role_code]["detail_permissions"] = {}
            await db_set_json(self.env, "roles", roles_data)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Phân quyền",
                f"Khôi phục quyền mặc định {role_code}",
                role_code,
            )
            return json_response({"success": True, "message": "Đã khôi phục quyền mặc định."})

        if path == "/admin/api/roles/toggle-status" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            role_code = str(data.get("role_code", "")).strip()
            target_status = str(data.get("target_status", "Ngừng sử dụng")).strip()
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            if role_code not in roles_data:
                return json_response({"success": False, "message": "Vai trò không tồn tại."}, 404)
            role_obj = roles_data[role_code]
            if role_obj.get("is_system") or role_code in ("ADMIN", "WAREHOUSE_MANAGER", "WAREHOUSE_STAFF", "COORDINATOR"):
                return json_response({"success": False, "message": "Không thể ngừng sử dụng vai trò hệ thống mặc định."}, 400)
            users = await db_get_json(self.env, "users", {})
            used_cnt = _count_role_users(users, role_code, role_obj)
            if target_status == "Ngừng sử dụng" and used_cnt > 0:
                return json_response({"success": False, "message": f"Đang có {used_cnt} tài khoản dùng vai trò này."}, 400)
            old_st = role_obj.get("status", "Hoạt động")
            role_obj["status"] = target_status
            await db_set_json(self.env, "roles", roles_data)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Phân quyền",
                f"{target_status} vai trò {role_code}",
                role_code,
                changes=[{"field": "Trạng thái", "before": old_st, "after": target_status}],
            )
            return json_response({"success": True, "message": f"Đã chuyển trạng thái vai trò sang {target_status}."})

        # 5. Nhật ký hệ thống (Audit Logs - chỉ đọc & xuất CSV)
        if path == "/admin/api/logs" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            all_logs = await db_get_json(self.env, "audit_logs", [])
            q = (qs.get("q", [""])[0] or "").strip().lower()
            date_from = (qs.get("from", [""])[0] or "").strip()
            date_to = (qs.get("to", [""])[0] or "").strip()
            category = qs.get("category", ["ALL"])[0]
            actor = qs.get("actor", ["ALL"])[0]
            result_f = qs.get("result", ["ALL"])[0]
            limit = max(1, min(100, int(qs.get("limit", ["10"])[0] or 10)))
            page = max(1, int(qs.get("page", ["1"])[0] or 1))

            filtered = []
            for l in all_logs:
                res_val = l.get("result") or l.get("status") or "Thành công"
                if q and not any(q in str(l.get(k, "")).lower() for k in ("actor", "by", "action", "target", "id")):
                    continue
                if category != "ALL" and l.get("category") != category:
                    continue
                if actor != "ALL" and l.get("actor") != actor:
                    continue
                if result_f != "ALL" and res_val != result_f:
                    continue
                ld = l.get("date", "")
                if date_from and ld < date_from:
                    continue
                if date_to and ld > date_to:
                    continue
                filtered.append({**l, "result": res_val})

            total_pages = max(1, (len(filtered) + limit - 1) // limit)
            page = min(page, total_pages)
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return json_response(
                {
                    "success": True,
                    "kpi": {
                        "total": len(all_logs),
                        "today": sum(1 for l in all_logs if l.get("date") == today_str),
                        "success": sum(1 for l in all_logs if (l.get("result") or l.get("status")) == "Thành công"),
                        "failed_warn": sum(
                            1 for l in all_logs if (l.get("result") or l.get("status")) in ("Thất bại", "Cảnh báo", "Bị từ chối")
                        ),
                    },
                    "items": filtered[(page - 1) * limit : page * limit],
                    "total_filtered": len(filtered),
                    "page": page,
                    "limit": limit,
                    "total_pages": total_pages,
                    "actors": sorted(list({l.get("actor") for l in all_logs if l.get("actor")})),
                }
            )

        if path == "/admin/api/logs/export-data" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            all_logs = await db_get_json(self.env, "audit_logs", [])
            q = (qs.get("q", [""])[0] or "").strip().lower()
            date_from = (qs.get("from", [""])[0] or "").strip()
            date_to = (qs.get("to", [""])[0] or "").strip()
            category = qs.get("category", ["ALL"])[0]
            actor = qs.get("actor", ["ALL"])[0]
            result_f = qs.get("result", ["ALL"])[0]
            filtered = []
            for l in all_logs:
                res_val = l.get("result") or l.get("status") or "Thành công"
                if q and not any(q in str(l.get(k, "")).lower() for k in ("actor", "by", "action", "target", "id")):
                    continue
                if category != "ALL" and l.get("category") != category:
                    continue
                if actor != "ALL" and l.get("actor") != actor:
                    continue
                if result_f != "ALL" and res_val != result_f:
                    continue
                ld = l.get("date", "")
                if date_from and ld < date_from:
                    continue
                if date_to and ld > date_to:
                    continue
                filtered.append({**l, "result": res_val})
            today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            return json_response(
                {
                    "success": True,
                    "exported_at": datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M:%S UTC"),
                    "filters": {
                        "q": q,
                        "from": date_from,
                        "to": date_to,
                        "category": category,
                        "actor": actor,
                        "result": result_f,
                    },
                    "kpi": {
                        "total": len(all_logs),
                        "filtered": len(filtered),
                        "today": sum(1 for l in all_logs if l.get("date") == today_str),
                        "success": sum(1 for l in filtered if l.get("result") == "Thành công"),
                        "failed_warn": sum(
                            1 for l in filtered if l.get("result") in ("Thất bại", "Cảnh báo", "Bị từ chối")
                        ),
                    },
                    "items": filtered,
                }
            )

        if path == "/admin/logs/export" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            all_logs = await db_get_json(self.env, "audit_logs", [])
            buf = io.StringIO()
            buf.write("\ufeff")
            writer = csv.writer(buf)
            writer.writerow(
                ["Mã sự kiện", "Thời gian", "Người thực hiện", "Nhóm hoạt động", "Hành động", "Đối tượng", "Kết quả", "Ghi chú"]
            )
            for l in all_logs:
                writer.writerow(
                    [
                        l.get("id", ""),
                        l.get("timestamp", ""),
                        l.get("by", ""),
                        l.get("category", ""),
                        l.get("action", ""),
                        l.get("target", ""),
                        l.get("result") or l.get("status", ""),
                        l.get("reason", ""),
                    ]
                )
            return Response(
                buf.getvalue().encode("utf-8"),
                status=200,
                headers={
                    "Content-Type": "text/csv; charset=utf-8",
                    "Content-Disposition": "attachment; filename=SANOVA_Audit_Logs.csv",
                },
            )

        # 6. Cấu hình hệ thống & Sao lưu snapshot vào D1
        if path == "/admin/api/settings" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            return json_response({"success": True, "settings": cfg})

        if path == "/admin/api/settings/save" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            group = data.get("group")
            new_vals = data.get("values", {})
            if group not in DEFAULT_SYSTEM_SETTINGS:
                return json_response({"success": False, "message": "Nhóm cấu hình không hợp lệ."}, 400)
            cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            old_grp = deepcopy(cfg.get(group, {}))
            changes = []
            for k, v in new_vals.items():
                if k != "history" and old_grp.get(k) != v:
                    changes.append({"field": k, "before": str(old_grp.get(k)), "after": str(v)})
                cfg[group][k] = v
            await db_set_json(self.env, "system_settings", cfg)
            if changes:
                await append_audit_log(
                    self.env,
                    actor_user.get("name", actor_uname),
                    actor_uname,
                    "Cấu hình",
                    f"Cập nhật nhóm {group}",
                    group.upper(),
                    changes=changes,
                )
            return json_response({"success": True, "message": "Đã lưu cấu hình hệ thống."})

        if path == "/admin/api/settings/backup/create" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            now = datetime.now(timezone.utc)
            snap_id = f"SNAP-{now.strftime('%Y%m%d-%H%M%S')}"
            snapshot_payload = {
                "users": await db_get_json(self.env, "users", {}),
                "roles": await db_get_json(self.env, "roles", INITIAL_ROLES),
                "audit_logs": await db_get_json(self.env, "audit_logs", []),
                "system_settings": await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS),
            }
            await db_set_json(self.env, f"backup_{snap_id}", snapshot_payload)
            cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            rec = {
                "id": snap_id,
                "filename": f"{snap_id}.json",
                "created_at": now.strftime("%d/%m/%Y – %H:%M:%S"),
                "type": "Thủ công (D1)",
                "by": actor_user.get("name", actor_uname),
            }
            cfg.setdefault("backup", {}).setdefault("history", []).insert(0, rec)
            cfg["backup"]["last_backup_time"] = rec["created_at"]
            await db_set_json(self.env, "system_settings", cfg)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Cấu hình",
                "Tạo bản sao lưu dữ liệu D1",
                snap_id,
            )
            return json_response({"success": True, "message": "Đã tạo bản sao lưu thành công.", "record": rec})

        if path == "/admin/api/settings/backup/download" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            snap_id = (qs.get("id", [""])[0] or "").strip()
            if not snap_id:
                return json_response({"success": False, "message": "Thiếu mã bản sao lưu (id)."}, 400)
            snapshot = await db_get_json(self.env, f"backup_{snap_id}", None)
            if not isinstance(snapshot, dict):
                return json_response({"success": False, "message": f"Không tìm thấy bản sao lưu '{snap_id}'."}, 404)
            raw_users = snapshot.get("users") if isinstance(snapshot.get("users"), dict) else {}
            safe_users = {
                uname: {k: v for k, v in udata.items() if k != "password"}
                for uname, udata in raw_users.items()
                if isinstance(udata, dict)
            }
            return json_response(
                {
                    "success": True,
                    "id": snap_id,
                    "snapshot": {
                        "users": safe_users,
                        "roles": snapshot.get("roles", {}),
                        "audit_logs": snapshot.get("audit_logs", []),
                        "system_settings": snapshot.get("system_settings", {}),
                    },
                }
            )

        # 7. Hồ sơ cá nhân Admin (chỉ sửa họ tên, email, đổi mật khẩu của chính mình)
        if path == "/admin/api/profile" and method == "GET":
            uname, user, err = await require_admin(self.env, request)
            if err:
                return err
            logs = await db_get_json(self.env, "audit_logs", [])
            mine = [l for l in logs if uname in str(l.get("by", "")) or l.get("target") == uname]
            safe_user = {k: v for k, v in user.items() if k != "password"}
            return json_response({"success": True, "user": safe_user, "logs": mine[:15]})

        if path == "/admin/api/profile/update" and method == "POST":
            uname, user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            name = str(data.get("name", "")).strip()
            raw_email = str(data.get("email", "")).strip()
            if not name or not raw_email:
                return json_response({"success": False, "message": "Họ tên và email không được để trống."}, 400)
            email = raw_email if "@" in raw_email else f"{raw_email}@sanova.vn"
            users = await db_get_json(self.env, "users", {})
            old_name, old_email = users[uname].get("name", ""), users[uname].get("email", "")
            users[uname]["name"] = name
            users[uname]["email"] = email
            await db_set_json(self.env, "users", users)
            await append_audit_log(
                self.env,
                name,
                uname,
                "Tài khoản",
                "Cập nhật thông tin tài khoản cá nhân",
                uname,
                changes=[
                    {"field": "Họ tên", "before": old_name, "after": name},
                    {"field": "Email", "before": old_email, "after": email},
                ],
            )
            return json_response({"success": True, "message": "Đã cập nhật hồ sơ cá nhân.", "name": name, "email": email})

        if path == "/admin/api/profile/change-password" and method == "POST":
            uname, user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            cur_pwd = str(data.get("current_password", ""))
            new_pwd = str(data.get("new_password", ""))
            cfm_pwd = str(data.get("confirm_password", ""))
            if not verify_stored_password(user.get("password"), cur_pwd):
                return json_response({"success": False, "message": "Mật khẩu hiện tại không đúng."}, 400)
            if new_pwd != cfm_pwd or cur_pwd == new_pwd:
                return json_response(
                    {"success": False, "message": "Mật khẩu mới không hợp lệ hoặc trùng mật khẩu cũ."},
                    400,
                )
            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            ok_pwd, pwd_msg = _validate_password_against_policy(new_pwd, sys_cfg.get("password", {}))
            if not ok_pwd:
                return json_response({"success": False, "message": pwd_msg}, 400)
            users = await db_get_json(self.env, "users", {})
            users[uname]["password"] = hash_new_password(new_pwd)
            await db_set_json(self.env, "users", users)
            await append_audit_log(
                self.env,
                user.get("name", uname),
                uname,
                "Bảo mật",
                "Đổi mật khẩu tài khoản cá nhân",
                uname,
            )
            return json_response({"success": True, "message": "Đổi mật khẩu thành công."})

        # 8. Thông báo chuông Admin
        if path == "/admin/api/notifications" and method == "GET":
            uname, _, err = await require_admin(self.env, request)
            if err:
                return err
            notis = await db_get_json(self.env, "admin_notifications", [])
            items = []
            unread = 0
            for n in notis:
                is_read = uname in n.get("read_by", [])
                if not is_read:
                    unread += 1
                items.append({**n, "is_read": is_read})
            return json_response({"success": True, "unread_count": unread, "notifications": items})

        if path == "/admin/api/notifications/read-all" and method == "POST":
            uname, _, err = await require_admin(self.env, request)
            if err:
                return err
            notis = await db_get_json(self.env, "admin_notifications", [])
            for n in notis:
                rb = n.setdefault("read_by", [])
                if uname not in rb:
                    rb.append(uname)
            await db_set_json(self.env, "admin_notifications", notis)
            return json_response({"success": True})

        # 9. Các route hiện có của Worker
        if path == "/api/dispatcher/notifications" and method == "GET":
            notis = await db_get_json(self.env, "dispatcher_notifications", [])
            unread = len([n for n in notis if not n.get("is_read")])
            return json_response(
                {
                    "success": True,
                    "unread_count": unread,
                    "notifications": notis,
                }
            )

        if path == "/api/health" and method == "GET":
            res = await self.env.DATABASE.prepare(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).all()
            raw_results = getattr(res, "results", None)
            if raw_results is not None and hasattr(raw_results, "to_py"):
                rows = raw_results.to_py()
            else:
                rows = list(raw_results or [])
            table_names = [
                (r.get("name") if isinstance(r, dict) else getattr(r, "name", None))
                for r in rows
            ]
            table_names = [t for t in table_names if t]
            return json_response(
                {
                    "success": True,
                    "service": "webdoansanova",
                    "d1_tables": table_names,
                }
            )

        return text_response("SANOVA Worker is running on Cloudflare D1.")