import csv
import hashlib
import hmac
import io
import json
import re
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

MODULE_SUB_PERMISSIONS = {
    "users": [
        ("view", "Xem danh sách người dùng"),
        ("create", "Thêm người dùng mới"),
        ("edit", "Chỉnh sửa thông tin & vai trò"),
        ("lock", "Khóa / Mở khóa tài khoản"),
        ("reset_pwd", "Đặt lại mật khẩu"),
    ],
    "locations": [
        ("view", "Xem sơ đồ kho, kệ, vị trí"),
        ("create", "Thêm kho, kệ, vị trí"),
        ("edit", "Chỉnh sửa thông số vị trí"),
        ("disable", "Ngừng sử dụng vị trí"),
    ],
    "products": [
        ("view", "Xem danh mục sản phẩm (SKU)"),
        ("create", "Thêm sản phẩm mới"),
        ("edit", "Chỉnh sửa thông tin sản phẩm"),
        ("disable", "Ngừng kinh doanh sản phẩm"),
    ],
    "inbound": [
        ("view", "Xem phiếu nhập kho"),
        ("receive", "Tiếp nhận hàng & ghi nhận vị trí"),
        ("approve", "Xác nhận nhập lên kệ"),
    ],
    "outbound": [
        ("view", "Xem đơn & phiếu lấy hàng (Picking)"),
        ("pick", "Thực hiện lấy hàng & đóng gói"),
        ("confirm", "Xác nhận lấy hàng & bàn giao"),
    ],
    "stocktake": [
        ("view", "Xem phiên kiểm kê"),
        ("count", "Thực hiện kiểm đếm tồn thực tế"),
        ("request_adj", "Lập yêu cầu điều chỉnh tồn"),
        ("approve", "Phê duyệt điều chỉnh tồn kho"),
    ],
    "reports": [
        ("view", "Xem báo cáo tồn kho & biến động"),
        ("export", "Xuất báo cáo Excel / CSV"),
    ],
    "settings": [
        ("view", "Xem cấu hình & nhật ký hệ thống"),
        ("edit", "Chỉnh sửa chính sách bảo mật & sao lưu"),
    ],
}

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

DEFAULT_WAREHOUSES = [
    {"warehouse_id": "KHO-01", "warehouse_name": "Kho chính (KHO-01)"},
    {"warehouse_id": "KHO-RT", "warehouse_name": "Kho trả hàng (KHO-RT)"},
]

DEFAULT_INITIAL_USERS = {
    "admin": {
        "staff_code": "ADM001",
        "password": "Admin21102005@",
        "name": "Phạm Đức Long",
        "email": "duc.long@sanova.vn",
        "phone": "0901234567",
        "role": "Quản trị viên",
        "status": "Hoạt động",
        "last_login": "Chưa có",
        "scope": "Tất cả kho",
    }
}

_DB_BOOTSTRAPPED = False


async def get_warehouse_scope_options(env):
    cfg = await db_get_json(env, "warehouse_config", None)
    warehouses = (
        cfg.get("warehouses")
        if isinstance(cfg, dict) and isinstance(cfg.get("warehouses"), list) and cfg.get("warehouses")
        else DEFAULT_WAREHOUSES
    )
    scopes = []
    for w in warehouses:
        if not isinstance(w, dict):
            continue
        wid = str(w.get("warehouse_id") or "").strip()
        wname = str(w.get("warehouse_name") or "").strip()
        if wname and wid and wid not in wname:
            label = f"{wname} ({wid})"
        else:
            label = wname or wid
        if label and label not in scopes:
            scopes.append(label)
    if not scopes:
        scopes = [w["warehouse_name"] for w in DEFAULT_WAREHOUSES]
    if "Tất cả kho" not in scopes:
        scopes.append("Tất cả kho")
    return scopes


def _generate_next_staff_code(users_dict):
    max_num = 1000
    if isinstance(users_dict, dict):
        for u in users_dict.values():
            if not isinstance(u, dict):
                continue
            code = str(u.get("staff_code") or "").strip().upper()
            m = re.match(r"^NV(\d+)$", code)
            if m:
                num = int(m.group(1))
                if num > max_num:
                    max_num = num
    return f"NV{max_num + 1:06d}"


def _validate_sanova_email(raw_email):
    email = str(raw_email or "").strip().lower()
    if not email:
        return False, "", "Email nội bộ (@sanova.vn) không được để trống."
    if not re.match(r"^[a-z0-9][a-z0-9._-]{1,63}@sanova\.vn$", email):
        return (
            False,
            "",
            "Email nội bộ phải hợp lệ và kết thúc bằng đuôi @sanova.vn (VD: e.nguyen@sanova.vn).",
        )
    return True, email, ""


def _validate_phone(raw_phone, required=False):
    cleaned = re.sub(r"[\s.\-()]+", "", str(raw_phone or "").strip())
    if not cleaned:
        if required:
            return False, "", "Số điện thoại liên hệ không được để trống."
        return True, "", ""
    if not re.match(r"^(0|\+84)[0-9]{8,10}$", cleaned):
        return (
            False,
            "",
            "Số điện thoại không hợp lệ (VD: 0912345678, gồm 9–11 chữ số).",
        )
    return True, cleaned, ""


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


def verify_stored_password(stored_password, input_password):
    if not stored_password or not input_password:
        return False
    raw = str(stored_password)
    if raw.startswith("sha256i$"):
        parts = raw.split("$", 3)
        if len(parts) == 4:
            try:
                _, iter_str, salt, expected_hex = parts
                iters = max(1, min(100_000, int(iter_str)))
                digest = _pbkdf2_sha256_hex(input_password, salt, iters)
                return hmac.compare_digest(digest, expected_hex)
            except Exception:
                return False
        return False
    if raw.startswith("sha256$"):
        parts = raw.split("$", 2)
        if len(parts) == 3:
            _, salt, expected_hex = parts
            digest = _pbkdf2_sha256_hex(input_password, salt, 100_000)
            return hmac.compare_digest(digest, expected_hex)
        return False
    if raw.startswith("pbkdf2:sha256:"):
        parts = raw.split("$", 2)
        if len(parts) == 3:
            try:
                method_parts = parts[0].split(":")
                iters = int(method_parts[2]) if len(method_parts) >= 3 else 260_000
                _, salt, expected_hex = parts
                digest = _pbkdf2_sha256_hex(input_password, salt, iters)
                return hmac.compare_digest(digest, expected_hex)
            except Exception:
                return False
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
    salt = secrets.token_hex(12)
    iters = 2_000
    digest = _pbkdf2_sha256_hex(password, salt, iters)
    return f"sha256i${iters}${salt}${digest}"


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
        return "/manager"
    if "Điều phối" in r or "Kế toán" in r:
        return "/dispatcher"
    return "/staff/dashboard"


def _format_time_ago(created_at_str):
    if not created_at_str:
        return "Vừa xong"
    try:
        dt = datetime.strptime(str(created_at_str)[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        diff = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
        if diff < 60:
            return "Vừa xong"
        if diff < 3600:
            return f"{diff // 60} phút trước"
        if diff < 86400:
            return f"{diff // 3600} giờ trước"
        return f"{diff // 86400} ngày trước"
    except Exception:
        return str(created_at_str)


def _list_role_users(users_dict, role_code, role_obj):
    r_name = role_obj.get("name") or role_obj.get("role_name", "")
    matched = []
    for uname, u in (users_dict or {}).items():
        if (
            u.get("role_code") == role_code
            or u.get("role") == r_name
            or ROLE_NAME_TO_KEY.get(u.get("role", "")) == role_code
        ):
            matched.append(
                {
                    "username": uname,
                    "staff_code": u.get("staff_code", ""),
                    "name": u.get("name", ""),
                    "status": u.get("status", "Hoạt động"),
                }
            )
    return matched


PAGE_ASSET_MAP = {
    # Admin (7 trang)
    "/admin": "/admin/admin_dashboard.html",
    "/admin/users": "/admin/admin_users.html",
    "/admin/roles": "/admin/admin_roles.html",
    "/admin/logs": "/admin/admin_logs.html",
    "/admin/settings": "/admin/admin_settings.html",
    "/admin/profile": "/admin/admin_profile.html",
    "/admin/notifications": "/admin/admin_notifications.html",
    # Manager (9 trang)
    "/manager": "/manager/manager_dashboard.html",
    "/warehouse/manager": "/manager/manager_dashboard.html",
    "/manager/products": "/manager/manager_products.html",
    "/manager/warehouse-config": "/manager/manager_warehouse_config.html",
    "/manager/inventory": "/manager/manager_inventory.html",
    "/manager/approvals": "/manager/manager_approvals.html",
    "/manager/stocktake": "/manager/manager_stocktake.html",
    "/manager/daily-closing": "/manager/manager_daily_closing.html",
    "/manager/reports": "/manager/manager_reports.html",
    "/manager/profile": "/manager/manager_profile.html",
    # Staff (9 trang)
    "/staff/dashboard": "/staff/staff_dashboard.html",
    "/staff/inbound": "/staff/staff_inbound.html",
    "/staff/scan": "/staff/staff_scan.html",
    "/staff/picking-returns": "/staff/staff_picking_returns.html",
    "/staff/prepacking": "/staff/staff_prepacking.html",
    "/staff/packing-handover": "/staff/staff_packing_handover.html",
    "/staff/stocktake": "/staff/staff_stocktake.html",
    "/staff/history": "/staff/staff_history.html",
    "/staff/profile": "/staff/staff_profile.html",
    # Dispatcher (7 trang)
    "/dispatcher": "/dispatcher/dispatcher_dashboard.html",
    "/dispatcher/picking-requests": "/dispatcher/dispatcher_picking_requests.html",
    "/dispatcher/order-tracking": "/dispatcher/dispatcher_order_tracking.html",
    "/dispatcher/reconciliation-data": "/dispatcher/dispatcher_reconciliation_data.html",
    "/dispatcher/outbound-reconciliation": "/dispatcher/dispatcher_outbound_reconciliation.html",
    "/dispatcher/reports": "/dispatcher/dispatcher_reports.html",
    "/dispatcher/profile": "/dispatcher/dispatcher_profile.html",
}

LEGACY_API_PREFIXES = (
    "/manager/api/",
    "/warehouse/api/",
    "/api/staff/",
    "/api/dispatcher/",
    "/staff/box-info/",
    "/q/",
)

_LEGACY_MODULE = None


def _get_legacy_module():
    global _LEGACY_MODULE
    if _LEGACY_MODULE is None:
        import sanova_legacy_api
        _LEGACY_MODULE = sanova_legacy_api
    return _LEGACY_MODULE


def _extract_warehouse_id(scope_str):
    m = re.search(r"\b(KHO-[A-Z0-9]+)\b", str(scope_str or "").upper())
    return m.group(1) if m else "KHO-01"


async def dispatch_legacy_api(env, request, path, method):
    import flask_d1_shim as shim

    # 1. Tải toàn bộ bảng json_store từ D1 vào VFS trong 1 truy vấn
    res = await env.DATABASE.prepare("SELECT store_key, payload FROM json_store").all()
    raw_results = getattr(res, "results", None)
    if raw_results is not None and hasattr(raw_results, "to_py"):
        rows = raw_results.to_py()
    else:
        rows = list(raw_results or [])
    vfs_map = {}
    for row in rows:
        k = row.get("store_key") if isinstance(row, dict) else getattr(row, "store_key", None)
        p = row.get("payload") if isinstance(row, dict) else getattr(row, "payload", None)
        if k and p is not None:
            try:
                vfs_map[k] = json.loads(p)
            except Exception:
                pass
    shim.vfs_begin(vfs_map)

    # 2. Đọc headers và raw body bytes (hỗ trợ cả JSON, form và upload file multipart)
    headers_dict = {}
    for hk in (
        "Content-Type",
        "Authorization",
        "Cookie",
        "User-Agent",
        "X-Forwarded-For",
        "CF-Connecting-IP",
        "X-CSRF-Token",
        "Accept",
    ):
        hv = request.headers.get(hk)
        if hv is not None:
            headers_dict[hk] = str(hv)

    raw_bytes = b""
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            buf = await request.arrayBuffer()
            if buf is not None:
                raw_bytes = bytes(buf.to_py())
        except Exception:
            try:
                txt = await request.text()
                raw_bytes = (txt or "").encode("utf-8")
            except Exception:
                raw_bytes = b""

    shim.request.load_from_worker(str(request.url), method, headers_dict, raw_bytes)

    # 3. Đồng bộ phiên đăng nhập từ D1 sang shim.session
    shim.session.clear()
    username, user = await get_authenticated_user(env, request)
    if username and user:
        safe_u = {k: v for k, v in user.items() if k != "password"}
        safe_u["username"] = username
        safe_u.setdefault("warehouse_id", _extract_warehouse_id(safe_u.get("scope")))
        shim.session["user"] = safe_u

    # 4. Thực thi route gốc trong sanova_legacy_api
    legacy = _get_legacy_module()
    resp_obj = legacy.app.dispatch(path, method)
    if resp_obj is None:
        return json_response({"success": False, "message": f"API endpoint not found: {path}"}, 404)

    # 5. Ghi các key bị thay đổi về Cloudflare D1
    dirty = shim.vfs_get_dirty_items()
    for dk, dv in dirty.items():
        await db_set_json(env, dk, dv)

    return Response(
        resp_obj.body,
        status=resp_obj.status_code,
        headers=dict(resp_obj.headers),
    )


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
            if path in PAGE_ASSET_MAP:
                return await serve_asset_html(self.env, request, PAGE_ASSET_MAP[path])
            if path == "/favicon.ico":
                return Response("", status=204)
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
                        "lockout_duration": sys_cfg.get("security", {}).get("lockout_duration", 15),
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

        if path == "/admin/api/users/meta" and method == "GET":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            users = await db_get_json(self.env, "users", {})
            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            scopes = await get_warehouse_scope_options(self.env)
            active_roles = [
                r.get("name") or r.get("role_name") or code
                for code, r in roles_data.items()
                if isinstance(r, dict) and r.get("status", "Hoạt động") == "Hoạt động"
            ]
            return json_response(
                {
                    "success": True,
                    "next_staff_code": _generate_next_staff_code(users),
                    "warehouse_scopes": scopes,
                    "password_policy": sys_cfg.get("password", DEFAULT_SYSTEM_SETTINGS["password"]),
                    "roles": active_roles,
                }
            )

        if path == "/admin/api/users/create" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            users = await db_get_json(self.env, "users", {})
            staff_code = str(data.get("staff_code", "")).strip().upper() or _generate_next_staff_code(users)
            name = str(data.get("name", "")).strip()
            raw_email = str(data.get("email", "")).strip()
            raw_phone = str(data.get("phone", "")).strip()
            username = str(data.get("username", "")).strip()
            role = str(data.get("role", "")).strip()
            valid_scopes = await get_warehouse_scope_options(self.env)
            scope = str(data.get("scope", "")).strip() or valid_scopes[0]
            password = str(data.get("password", ""))
            confirm_password = str(data.get("confirm_password", ""))
            status = str(data.get("status", "Hoạt động")).strip()

            if not staff_code or not name or not username or not role or not password:
                return json_response({"success": False, "message": "Thiếu thông tin bắt buộc."}, 400)
            ok_email, email, email_msg = _validate_sanova_email(raw_email)
            if not ok_email:
                return json_response({"success": False, "message": email_msg}, 400)
            ok_phone, phone, phone_msg = _validate_phone(raw_phone, required=True)
            if not ok_phone:
                return json_response({"success": False, "message": phone_msg}, 400)
            if scope not in valid_scopes:
                return json_response(
                    {"success": False, "message": "Phạm vi kho không hợp lệ. Vui lòng chọn từ danh sách kho hệ thống."},
                    400,
                )
            if password != confirm_password:
                return json_response({"success": False, "message": "Xác nhận mật khẩu không khớp."}, 400)

            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            ok_pwd, pwd_msg = _validate_password_against_policy(password, sys_cfg.get("password", {}))
            if not ok_pwd:
                return json_response({"success": False, "message": pwd_msg}, 400)

            if username in users:
                return json_response({"success": False, "message": f"Tên đăng nhập '{username}' đã tồn tại."}, 400)
            if any(str(u.get("staff_code", "")).upper() == staff_code for u in users.values()):
                return json_response({"success": False, "message": f"Mã nhân viên '{staff_code}' đã tồn tại."}, 400)
            if any(str(u.get("email", "")).strip().lower() == email for u in users.values()):
                return json_response({"success": False, "message": f"Email '{email}' đã được sử dụng."}, 400)

            now_str = datetime.now(timezone.utc).strftime("%d/%m/%Y · %H:%M")
            users[username] = {
                "staff_code": staff_code,
                "name": name,
                "email": email,
                "phone": phone,
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
                    {"field": "Email", "before": "", "after": email},
                    {"field": "Số điện thoại", "before": "", "after": phone},
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
            safe_new = {k: v for k, v in users[username].items() if k != "password"}
            safe_new["username"] = username
            return json_response(
                {
                    "success": True,
                    "message": f"Tạo tài khoản {username} thành công.",
                    "new_user": safe_new,
                    "stats": {
                        "total": len(users),
                        "active": sum(1 for u in users.values() if u.get("status") == "Hoạt động"),
                        "locked": sum(1 for u in users.values() if u.get("status") == "Tạm khóa"),
                        "pending": sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt"),
                    },
                }
            )

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
            if "email" in data:
                ok_email, clean_email, email_msg = _validate_sanova_email(data.get("email"))
                if not ok_email:
                    return json_response({"success": False, "message": email_msg}, 400)
                if any(
                    un != username and str(ud.get("email", "")).strip().lower() == clean_email
                    for un, ud in users.items()
                ):
                    return json_response({"success": False, "message": f"Email '{clean_email}' đã được sử dụng."}, 400)
                data["email"] = clean_email
            if "phone" in data:
                ok_phone, clean_phone, phone_msg = _validate_phone(data.get("phone"), required=False)
                if not ok_phone:
                    return json_response({"success": False, "message": phone_msg}, 400)
                data["phone"] = clean_phone
            changes = []
            for field, label in (
                ("name", "Họ tên"),
                ("email", "Email"),
                ("phone", "Số điện thoại"),
                ("role", "Vai trò"),
                ("scope", "Phạm vi kho"),
            ):
                if field in data:
                    val = str(data.get(field) or "").strip()
                    if u.get(field, "") != val:
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
            role_users = {code: _list_role_users(users, code, obj) for code, obj in roles_data.items()}
            return json_response(
                {
                    "success": True,
                    "roles": roles_data,
                    "modules": PERMISSION_MODULES,
                    "actions": PERMISSION_ACTIONS,
                    "sub_permissions": MODULE_SUB_PERMISSIONS,
                    "total_system_perms": len(PERMISSION_MODULES) * len(PERMISSION_ACTIONS),
                    "role_user_counts": counts,
                    "role_users": role_users,
                    "total_assigned_accounts": sum(counts.values()),
                }
            )

        if path == "/admin/api/roles/preview-diff" and method == "POST":
            _, _, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            role_code = str(data.get("role_code", "")).strip()
            new_perms = data.get("permissions", {})
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            if role_code not in roles_data:
                return json_response({"success": False, "message": "Vai trò không tồn tại."}, 404)
            role_obj = roles_data[role_code]
            old_perms = role_obj.get("permissions", {})
            act_map = dict(PERMISSION_ACTIONS)
            added, revoked = [], []
            for m in PERMISSION_MODULES:
                mid, mname = m["id"], m["name"]
                old_m = old_perms.get(mid, {}) if isinstance(old_perms.get(mid), dict) else {}
                new_m = new_perms.get(mid, {}) if isinstance(new_perms.get(mid), dict) else {}
                for aid, alabel in PERMISSION_ACTIONS:
                    ov = bool(old_m.get(aid, False))
                    nv = bool(new_m.get(aid, False))
                    if not ov and nv:
                        added.append(f"{mname} → {alabel}")
                    elif ov and not nv:
                        revoked.append(f"{mname} → {alabel}")
            users = await db_get_json(self.env, "users", {})
            return json_response(
                {
                    "success": True,
                    "role_name": role_obj.get("name") or role_obj.get("role_name") or role_code,
                    "added": added,
                    "revoked": revoked,
                    "affected_users": _count_role_users(users, role_code, role_obj),
                }
            )

        if path == "/admin/api/roles/update" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            role_code = str(data.get("role_code", "")).strip()
            roles_data = await db_get_json(self.env, "roles", INITIAL_ROLES)
            if role_code not in roles_data:
                return json_response({"success": False, "message": "Vai trò không tồn tại."}, 404)
            role_obj = roles_data[role_code]
            new_name = str(data.get("name", role_obj.get("name", ""))).strip()
            new_desc = str(data.get("desc", role_obj.get("desc", ""))).strip()
            new_status = str(data.get("status", role_obj.get("status", "Hoạt động"))).strip()
            if not new_name:
                return json_response({"success": False, "message": "Tên vai trò không được để trống."}, 400)
            users = await db_get_json(self.env, "users", {})
            used_cnt = _count_role_users(users, role_code, role_obj)
            if new_status == "Ngừng sử dụng" and (role_obj.get("is_system") or role_code == "ADMIN" or used_cnt > 0):
                return json_response(
                    {"success": False, "message": "Không thể ngừng sử dụng vai trò hệ thống hoặc đang có tài khoản."},
                    400,
                )
            role_obj["name"] = new_name
            role_obj["role_name"] = new_name
            role_obj["desc"] = new_desc
            role_obj["description"] = new_desc
            role_obj["status"] = new_status
            if role_code != "ADMIN" and isinstance(data.get("permissions"), dict):
                role_obj["permissions"] = data["permissions"]
            await db_set_json(self.env, "roles", roles_data)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Phân quyền",
                f"Cập nhật vai trò {new_name}",
                role_code,
            )
            return json_response({"success": True, "message": f"Đã cập nhật vai trò '{new_name}' thành công."})

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
            return json_response(
                {"success": True, "role_code": role_code, "message": f"Đã tạo vai trò '{role_name}'."}
            )

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

        if path == "/admin/api/settings/reset" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            group = data.get("group")
            if group not in DEFAULT_SYSTEM_SETTINGS:
                return json_response({"success": False, "message": "Nhóm cấu hình không hợp lệ."}, 400)
            cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            if group == "backup":
                old_hist = cfg.get("backup", {}).get("history", [])
                cfg["backup"] = deepcopy(DEFAULT_SYSTEM_SETTINGS["backup"])
                cfg["backup"]["history"] = old_hist
            else:
                cfg[group] = deepcopy(DEFAULT_SYSTEM_SETTINGS[group])
            await db_set_json(self.env, "system_settings", cfg)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Cấu hình",
                f"Khôi phục mặc định nhóm {group}",
                group.upper(),
            )
            return json_response({"success": True, "message": "Đã khôi phục nhóm cấu hình về mặc định."})

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
            raw_bytes = len(json.dumps(snapshot_payload, ensure_ascii=False).encode("utf-8"))
            size_label = f"{max(1, round(raw_bytes / 1024, 1))} KB"
            await db_set_json(self.env, f"backup_{snap_id}", snapshot_payload)
            cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            rec = {
                "id": snap_id,
                "filename": f"{snap_id}.json",
                "created_at": now.strftime("%d/%m/%Y – %H:%M:%S"),
                "size": size_label,
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

        if path == "/admin/api/settings/backup/restore" and method == "POST":
            actor_uname, actor_user, err = await require_admin(self.env, request)
            if err:
                return err
            data = await read_json_body(request)
            snap_id = str(data.get("id") or data.get("filename") or "").strip()
            if snap_id.endswith(".json"):
                snap_id = snap_id[:-5]
            if not snap_id:
                return json_response({"success": False, "message": "Thiếu mã bản sao lưu cần khôi phục."}, 400)
            snapshot = await db_get_json(self.env, f"backup_{snap_id}", None)
            if not isinstance(snapshot, dict):
                return json_response({"success": False, "message": f"Không tìm thấy bản sao lưu '{snap_id}'."}, 404)
            if isinstance(snapshot.get("users"), dict) and snapshot["users"]:
                await db_set_json(self.env, "users", snapshot["users"])
            if isinstance(snapshot.get("roles"), dict) and snapshot["roles"]:
                await db_set_json(self.env, "roles", snapshot["roles"])
            if isinstance(snapshot.get("system_settings"), dict):
                cur_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
                restored_cfg = deepcopy(snapshot["system_settings"])
                restored_cfg.setdefault("backup", {})["history"] = cur_cfg.get("backup", {}).get("history", [])
                await db_set_json(self.env, "system_settings", restored_cfg)
            await append_audit_log(
                self.env,
                actor_user.get("name", actor_uname),
                actor_uname,
                "Cấu hình",
                f"Khôi phục dữ liệu từ snapshot {snap_id}",
                snap_id,
            )
            return json_response({"success": True, "message": f"Đã khôi phục dữ liệu từ {snap_id} thành công."})

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
            sys_cfg = await db_get_json(self.env, "system_settings", DEFAULT_SYSTEM_SETTINGS)
            mine = [l for l in logs if uname in str(l.get("by", "")) or l.get("target") == uname]
            safe_user = {k: v for k, v in user.items() if k != "password"}
            return json_response(
                {
                    "success": True,
                    "user": safe_user,
                    "logs": mine[:15],
                    "security_policy": sys_cfg.get("security", DEFAULT_SYSTEM_SETTINGS["security"]),
                    "password_policy": sys_cfg.get("password", DEFAULT_SYSTEM_SETTINGS["password"]),
                }
            )

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
                items.append({**n, "is_read": is_read, "time_ago": _format_time_ago(n.get("created_at"))})
            return json_response({"success": True, "unread_count": unread, "notifications": items})

        if path.startswith("/admin/api/notifications/read/") and method == "POST":
            uname, _, err = await require_admin(self.env, request)
            if err:
                return err
            noti_id = path.rsplit("/", 1)[-1].strip()
            notis = await db_get_json(self.env, "admin_notifications", [])
            for n in notis:
                if str(n.get("id")) == noti_id:
                    rb = n.setdefault("read_by", [])
                    if uname not in rb:
                        rb.append(uname)
                    break
            await db_set_json(self.env, "admin_notifications", notis)
            return json_response({"success": True})

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

        # 9. Thông báo Điều phối & Bridge toàn bộ API Manager / Staff / Dispatcher sang D1
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

        if path == "/api/dispatcher/notifications/read" and method == "POST":
            data = await read_json_body(request)
            noti_id = data.get("id")
            notis = await db_get_json(self.env, "dispatcher_notifications", [])
            for n in notis:
                if not noti_id or str(n.get("id")) == str(noti_id):
                    n["is_read"] = True
            await db_set_json(self.env, "dispatcher_notifications", notis)
            return json_response({"success": True})

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

        if any(path.startswith(pfx) for pfx in LEGACY_API_PREFIXES):
            return await dispatch_legacy_api(self.env, request, path, method)

        return text_response("SANOVA Worker is running on Cloudflare D1.")