import os
import json
import csv
import io
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
import shutil
import tempfile
import threading

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, make_response, abort,
    jsonify, flash
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

# ==========================================================
# 1. CẤU HÌNH FLASK & ĐỒNG BỘ TIẾN TRÌNH
# ==========================================================

app = Flask(__name__)
app.secret_key = os.environ.get("SANOVA_SECRET_KEY", "sanova_enterprise_secret_key_2026")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SANOVA_HTTPS", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30)
)

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent

DATA_FILE = str(BASE_DIR / "users.json")
LOGS_FILE = str(BASE_DIR / "audit_logs.json")
WAREHOUSE_FILE = str(BASE_DIR / "warehouse_data.json")
SETTINGS_FILE = str(BASE_DIR / "system_settings.json")
ROLES_FILE = str(BASE_DIR / "role_permissions.json")
ROLES_JSON_FILE = str(BASE_DIR / "roles.json")

BACKUP_DIR = BASE_DIR / "backups"
os.makedirs(BACKUP_DIR, exist_ok=True)

_json_lock = threading.RLock()

# ==========================================================
# 2. CẤU HÌNH HỆ THỐNG & ĐỊNH NGHĨA 8 NHÓM CHỨC NĂNG SANOVA
# ==========================================================

DEFAULT_SETTINGS = {
    "session_timeout": 30,
    "max_login_attempts": 5,
    "minimum_password_length": 8
}

ROLE_PERMISSIONS = {
    "Quản trị viên": [
        "Quản lý tài khoản và phân quyền",
        "Tra cứu nhật ký quản trị hệ thống",
        "Cấu hình hệ thống",
        "Quản lý tài khoản cá nhân"
    ],
    "Quản lý kho": [
        "Xem tồn kho, lịch sử giao dịch và báo cáo",
        "Xác nhận nhập hàng lên kệ",
        "Theo dõi kiểm kê và hàng ngoài kệ/trả",
        "Phê duyệt yêu cầu điều chỉnh tồn kho",
        "Rà soát và chốt tồn kho cuối ngày",
        "Quản lý danh mục sản phẩm",
        "Quản lý kho, kệ, tầng và vị trí"
    ],
    "Nhân viên kho": [
        "Quét QR nhận diện vị trí và sản phẩm",
        "Thực hiện nhập, lấy và điều chuyển hàng",
        "Kiểm kê và lập yêu cầu điều chỉnh",
        "Quản lý hàng ngoài kệ và trả hàng",
        "Pre-packing, đóng gói và bàn giao đơn"
    ],
    "Điều phối / Kế toán kho": [
        "Nhập dữ liệu đơn hàng và POS",
        "Tra cứu đơn hàng và trạng thái xử lý",
        "Đối soát xuất hàng đa nguồn",
        "Xem và xuất báo cáo tồn kho"
    ]
}

# 8 nhóm chức năng chuẩn theo mẫu giao diện SANOVA
PERMISSION_MODULES = [
    {"id": "users", "name": "Quản lý người dùng", "icon": "👥"},
    {"id": "locations", "name": "Quản lý kho, kệ, vị trí", "icon": "🏠"},
    {"id": "products", "name": "Quản lý danh mục sản phẩm", "icon": "📦"},
    {"id": "inbound", "name": "Nhập kho", "icon": "↔️"},
    {"id": "outbound", "name": "Xuất kho / Lấy hàng", "icon": "↔️"},
    {"id": "stocktake", "name": "Kiểm kê & điều chỉnh tồn", "icon": "📋"},
    {"id": "reports", "name": "Báo cáo & thống kê", "icon": "📊"},
    {"id": "settings", "name": "Cấu hình hệ thống", "icon": "⚙️"}
]

# 5 cột hành động ngang chuẩn mẫu
PERMISSION_ACTIONS = [
    ("view", "Xem"),
    ("create", "Thêm"),
    ("edit", "Sửa"),
    ("delete", "Xóa"),
    ("approve", "Phê duyệt")
]

# 4 vai trò chuẩn SANOVA với ma trận quyền mặc định
INITIAL_ROLES = {
    "ADMIN": {
        "id": "ADMIN",
        "role_code": "ADMIN",
        "name": "Quản trị viên (Admin)",
        "role_name": "Quản trị viên (Admin)",
        "desc": "Quản trị toàn bộ hệ thống",
        "description": "Quản trị toàn bộ hệ thống",
        "icon": "👑",
        "is_system": True,
        "permissions": {m["id"]: {"view": True, "create": True, "edit": True, "delete": True, "approve": True} for m in PERMISSION_MODULES}
    },
    "WAREHOUSE_MANAGER": {
        "id": "WAREHOUSE_MANAGER",
        "role_code": "WAREHOUSE_MANAGER",
        "name": "Quản lý kho (Manager)",
        "role_name": "Quản lý kho (Manager)",
        "desc": "Quản lý nghiệp vụ kho và vận hành hệ thống kho.",
        "description": "Quản lý nghiệp vụ kho và vận hành",
        "icon": "📚",
        "is_system": True,
        "permissions": {
            "users": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "locations": {"view": True, "create": True, "edit": True, "delete": False, "approve": False},
            "products": {"view": True, "create": True, "edit": True, "delete": False, "approve": False},
            "inbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": True},
            "outbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "stocktake": {"view": True, "create": False, "edit": False, "delete": False, "approve": True},
            "reports": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "settings": {"view": False, "create": False, "edit": False, "delete": False, "approve": False}
        }
    },
    "WAREHOUSE_STAFF": {
        "id": "WAREHOUSE_STAFF",
        "role_code": "WAREHOUSE_STAFF",
        "name": "Nhân viên kho (Staff)",
        "role_name": "Nhân viên kho (Staff)",
        "desc": "Thực hiện hoạt động nhập, lấy, đóng gói",
        "description": "Thực hiện hoạt động nhập, lấy, đóng gói",
        "icon": "👤",
        "is_system": True,
        "permissions": {
            "users": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "locations": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "products": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "inbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "outbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "stocktake": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "reports": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "settings": {"view": False, "create": False, "edit": False, "delete": False, "approve": False}
        }
    },
    "COORDINATOR": {
        "id": "COORDINATOR",
        "role_code": "COORDINATOR",
        "name": "Điều phối / Kế toán kho",
        "role_name": "Điều phối / Kế toán kho",
        "desc": "Theo dõi, đối soát và hỗ trợ nghiệp vụ kho",
        "description": "Theo dõi, đối soát và hỗ trợ nghiệp vụ kho",
        "icon": "📋",
        "is_system": True,
        "permissions": {
            "users": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "locations": {"view": False, "create": False, "edit": False, "delete": False, "approve": False},
            "products": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "inbound": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "outbound": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "stocktake": {"view": True, "create": False, "edit": False, "delete": False, "approve": False},
            "reports": {"view": True, "create": True, "edit": False, "delete": False, "approve": False},
            "settings": {"view": False, "create": False, "edit": False, "delete": False, "approve": False}
        }
    }
}

# ==========================================================
# 3. LƯU TRỮ JSON VỚI LOCK ĐỒNG BỘ & BACKUP
def read_json(filename, default):
    path = Path(filename)
    if not path.is_absolute():
        path = BASE_DIR / path
        
    if not path.exists():
        return default
        
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        app.logger.exception(f"LỖI ĐỌC JSON: {path}")
        return default


def write_json(filename, data):
    path = Path(filename)
    if not path.is_absolute():
        path = BASE_DIR / path
        
    path.parent.mkdir(parents=True, exist_ok=True)

    with _json_lock:
        temp_path = None
        try:
            # Giữ nguyên phần ghi file tạm và os.replace của bạn ở dưới đây
            temp_path = path.with_suffix(".tmp")
            with temp_path.open("w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(temp_path, path)
        except Exception:
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)
            raise

def load_users():
    return read_json(DATA_FILE, {})

def save_users(users):
    write_json(DATA_FILE, users)

def load_logs():
    return read_json(LOGS_FILE, [])

def load_settings():
    settings = DEFAULT_SETTINGS.copy()
    settings.update(read_json(SETTINGS_FILE, {}))
    return settings

def save_settings(settings):
    write_json(SETTINGS_FILE, settings)

def load_role_definitions():
    data = read_json(ROLES_JSON_FILE, None)
    if not data or len(data) < 4:
        write_json(ROLES_JSON_FILE, INITIAL_ROLES)
        return INITIAL_ROLES.copy()
    if "ADMIN" in data:
        data["ADMIN"]["permissions"] = {m["id"]: {"view": True, "create": True, "edit": True, "delete": True, "approve": True} for m in PERMISSION_MODULES}
    return data

def save_role_definitions(data):
    if "ADMIN" in data:
        data["ADMIN"]["permissions"] = {m["id"]: {"view": True, "create": True, "edit": True, "delete": True, "approve": True} for m in PERMISSION_MODULES}
    write_json(ROLES_JSON_FILE, data)

def load_roles():
    roles = read_json(ROLES_FILE, None)
    return roles if roles is not None else ROLE_PERMISSIONS.copy()

def save_roles(roles):
    write_json(ROLES_FILE, roles)

def load_warehouse_data():
    return read_json(
        WAREHOUSE_FILE,
        {
            "inventory": [],
            "pending_queue": [],
            "operations_summary": {}
        }
    )

def save_warehouse_data(data):
    write_json(WAREHOUSE_FILE, data)

def sync_account_alerts_to_notifications():
    users = load_users()
    pending_users = [u for u in users.values() if u.get("status") == "Chờ kích hoạt"]
    locked_users = [u for u in users.values() if u.get("status") == "Tạm khóa"]

    if pending_users:
        create_admin_notification(
            group="account",
            severity="action_required",
            title="Tài khoản chờ kích hoạt",
            message=f"Hiện có {len(pending_users)} tài khoản đang chờ kích hoạt.",
            target_url="/admin/users?status=Chờ+kích+hoạt",
            dedup_key="sync_pending_accounts"
        )
    if locked_users:
        create_admin_notification(
            group="account",
            severity="action_required",
            title="Tài khoản đang tạm khóa",
            message=f"Hiện có {len(locked_users)} tài khoản đang ở trạng thái tạm khóa.",
            target_url="/admin/users?status=Tạm+khóa",
            dedup_key="sync_locked_accounts"
        )
# ==========================================================
# 4. BẢO MẬT MẬT KHẨU & BẢO VỆ CSRF
# ==========================================================

def validate_password(password):
    settings = load_settings()
    minimum = settings.get("minimum_password_length", 8)
    return len(password) >= minimum

def verify_password(stored_password, input_password):
    if not stored_password:
        return False
    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored_password, input_password)
        except ValueError:
            return False
    return secrets.compare_digest(stored_password, input_password)

def hash_password(password):
    return generate_password_hash(password)

@app.before_request
def protect_requests():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if (
            request.path in ("/login", "/")
            or request.path.startswith("/warehouse/api/")
            or request.path.startswith("/admin/api/settings/")
            or request.path.startswith("/admin/api/notifications")
        ):
            return

        supplied_token = (
            request.form.get("csrf_token")
            or request.headers.get("X-CSRF-Token")
        )

        if not supplied_token or not secrets.compare_digest(
            supplied_token,
            session["_csrf_token"]
        ):
            abort(400, description="CSRF token không hợp lệ")

@app.context_processor
def inject_global_vars():
    user_session = session.get("user", {})
    return {
        "csrf_token": lambda: session.get("_csrf_token", ""),
        "logged_in_user": user_session,
        "current_path": request.path
    }

# ==========================================================
# 5. XÁC THỰC, PHÂN QUYỀN TỰ ĐỘNG & AUDIT LOGS
# ==========================================================

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))

        username = session["user"].get("username")
        users = load_users()
        user = users.get(username)

        if not user or user.get("status") != "Hoạt động":
            session.clear()
            return redirect(url_for("login"))

        session["user"].update({
            "name": user.get("name", ""),
            "email": user.get("email", ""),
            "role": user.get("role", ""),
            "scope": user.get("scope", "")
        })

        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if session["user"].get("role") != "Quản trị viên":
            abort(403)
        return f(*args, **kwargs)
    return decorated

def warehouse_manager_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        role = session["user"].get("role", "")
        if not any(k in role for k in ("Quản lý kho", "Quản trị viên")):
            abort(403)
        return f(*args, **kwargs)
    return decorated

def has_permission(user_role, module_id, action_id):
    """Admin luôn tự động có toàn quyền trên toàn hệ thống mà không cần cấu hình trước"""
    if not user_role:
        return False
    if user_role == "Quản trị viên":
        return True

    roles_data = load_role_definitions()
    for r in roles_data.values():
        if r.get("role_name") == user_role or r.get("name") == user_role:
            perms = r.get("permissions", {}).get(module_id, {})
            if isinstance(perms, dict):
                return perms.get(action_id, False)
            if isinstance(perms, list):
                return action_id in perms
    return False

# ==========================================================
# 6. ROUTE WELCOME / LOGIN / LOGOUT
# ==========================================================

@app.route("/")
@app.route("/welcome")
def welcome():
    if "user" in session:
        role = session["user"].get("role")
        if role == "Quản trị viên":
            return redirect(url_for("admin_dashboard"))
        if role == "Quản lý kho":
            return redirect(url_for("warehouse_manager_dashboard"))
    return render_template("welcome.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        role = session['user'].get('role')
        if role == 'Quản trị viên':
            return redirect(url_for('admin_dashboard'))
        elif role == 'Quản lý kho':
            return redirect(url_for('warehouse_manager_dashboard'))

    error = None
    login_input = ""
    if request.method == 'POST':
        login_input = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        users = load_users()
        matched_username = None
        user_info = None

        # Tìm theo tên đăng nhập hoặc mã nhân viên (không phân biệt hoa/thường)
        for uname, udata in users.items():
            if uname.lower() == login_input.lower() or str(udata.get('staff_code', '')).lower() == login_input.lower():
                matched_username = uname
                user_info = udata
                break

        if user_info and verify_password(user_info.get('password'), password):
            if user_info.get('status') == 'Tạm khóa':
                error = "Tài khoản của bạn đang bị tạm khóa. Vui lòng liên hệ Quản trị viên để được hỗ trợ."
                add_audit_log(
                    category="Bảo mật",
                    action="Đăng nhập bị từ chối (Tài khoản tạm khóa)",
                    target=matched_username,
                    result="Cảnh báo",
                    reason="Tài khoản đang trong trạng thái tạm khóa"
                )
            elif user_info.get('status') == 'Chờ kích hoạt':
                error = "Tài khoản chưa được kích hoạt. Vui lòng liên hệ Quản trị viên."
            else:
                user_info['last_login'] = datetime.now().strftime("%d/%m/%Y · %H:%M")
                save_users(users)

                # Không bật session.permanent dài ngày để luôn yêu cầu xác thực lại khi hết phiên/đăng xuất
                session.permanent = False
                session['user'] = {
                    'username': matched_username,
                    'name': user_info.get('name'),
                    'email': user_info.get('email'),
                    'role': user_info.get('role'),
                    'scope': user_info.get('scope', 'Kho chính - SANOVA')
                }

                add_audit_log(
                    category="Bảo mật",
                    action="Đăng nhập hệ thống",
                    target=matched_username,
                    result="Thành công"
                )

                if user_info.get('role') == 'Quản trị viên':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect('/warehouse/manager')
        else:
            add_audit_log(
                category="Bảo mật",
                action="Đăng nhập thất bại (Sai mật khẩu)",
                target=login_input or "Chưa nhập",
                result="Thất bại",
                reason="Người dùng nhập sai thông tin xác thực"
            )
            error = "Mã nhân viên / Tên đăng nhập hoặc mật khẩu chưa chính xác. Vui lòng kiểm tra lại."

    return render_template('login.html', error=error, username=login_input)

@app.route('/logout')
def logout():
    username = session.get('user', {}).get('username', 'admin')
    # Ghi log đăng xuất
    add_audit_log(
        category="Bảo mật",
        action="Đăng xuất hệ thống",
        target=username,
        result="Thành công"
    )
    session.clear()
    return redirect(url_for('login'))

# ==========================================================
# 7. ROUTE TỔNG QUAN HỆ THỐNG (ADMIN DASHBOARD)
@app.route("/admin")
@admin_required
def admin_dashboard():
    users = load_users()
    logs = load_logs()
    roles = load_roles()

    today = datetime.now().strftime("%Y-%m-%d")

    total_users = len(users)
    active_users = sum(1 for u in users.values() if u.get("status") == "Hoạt động")
    locked_count = sum(1 for u in users.values() if u.get("status") == "Tạm khóa")
    pending_count = sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt")

    role_counts = {r: 0 for r in roles}
    for user in users.values():
        role = user.get("role")
        if role in role_counts:
            role_counts[role] += 1
        elif role:
            role_counts[role] = 1

    gradient_parts = []
    current_pct = 0.0
    role_colors = {
        "Quản trị viên": "#064e3b",
        "Quản lý kho": "#10b981",
        "Nhân viên kho": "#86efac",
        "Điều phối / Kế toán kho": "#cbd5e1"
    }

    if total_users > 0:
        for r_name in roles:
            count = role_counts.get(r_name, 0)
            pct = (count / total_users) * 100.0
            next_pct = current_pct + pct
            color = role_colors.get(r_name, "#94a3b8")
            gradient_parts.append(f"{color} {current_pct:.1f}% {next_pct:.1f}%")
            current_pct = next_pct
        donut_gradient = "conic-gradient(" + ", ".join(gradient_parts) + ")"
    else:
        donut_gradient = "conic-gradient(#e2e8f0 0% 100%)"

    today_logs = [log for log in logs if log.get("date") == today]
    today_created_count = sum(1 for l in today_logs if l.get("category") == "TÀI KHOẢN" and "Tạo" in l.get("action", ""))
    today_updated_count = sum(1 for l in today_logs if "Cập nhật" in l.get("action", "") or "vai trò" in l.get("action", "").lower())
    today_status_count = sum(1 for l in today_logs if "khóa" in l.get("action", "").lower() or "trạng thái" in l.get("action", "").lower())
    today_config_count = sum(1 for l in today_logs if l.get("category") == "CẤU HÌNH" or "cấu hình" in l.get("action", "").lower())

    recent_logs = []
    for l in logs[:5]:
        entry = l.copy()
        if not entry.get("target"):
            entry["target"] = entry.get("action", "").split(":")[-1].strip() if ":" in entry.get("action", "") else "Hệ thống"
        recent_logs.append(entry)
    
    sys_cfg = load_system_settings()
    dashboard_settings = {
        "session_timeout": sys_cfg.get("security", {}).get("session_timeout", 30),
        "max_login_attempts": sys_cfg.get("security", {}).get("max_failed_logins", 5),
        "minimum_password_length": sys_cfg.get("password", {}).get("min_length", 8),
        "lockout_duration": sys_cfg.get("security", {}).get("lockout_duration", 15)
    }

    return render_template(
        "ADMIN/admin_dashboard.html",
        current_user=session.get("user", {}),
        total_users=total_users,
        active_users=active_users,
        locked_count=locked_count,
        pending_count=pending_count,
        role_counts=role_counts,
        donut_gradient=donut_gradient,
        logs=recent_logs,
        today_created_count=today_created_count,
        today_updated_count=today_updated_count,
        today_status_count=today_status_count,
        today_config_count=today_config_count,
        system_settings=dashboard_settings
    )

# ==========================================================
# 8. ROUTE QUẢN LÝ NGƯỜI DÙNG (USER MANAGEMENT)
# ==========================================================

@app.route("/admin/users")
@admin_required
def admin_users():
    users = load_users()
    roles_definitions = load_role_definitions()

    total_users = len(users)
    active_users = sum(1 for u in users.values() if u.get("status") == "Hoạt động")
    locked_users = sum(1 for u in users.values() if u.get("status") == "Tạm khóa")
    pending_users = sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt")

    q = request.args.get("q", "").strip().lower()
    role_filter = request.args.get("role", "ALL")
    status_filter = request.args.get("status", "ALL")

    filtered_users = []
    for uname, udata in users.items():
        staff_code = str(udata.get("staff_code", "")).lower()
        full_name = str(udata.get("name", "")).lower()
        username_str = str(uname).lower()
        email_str = str(udata.get("email", "")).lower()

        matches_q = (
            not q
            or (q in staff_code)
            or (q in full_name)
            or (q in username_str)
            or (q in email_str)
        )
        matches_role = (role_filter == "ALL") or (udata.get("role") == role_filter)
        matches_status = (status_filter == "ALL") or (udata.get("status") == status_filter)

        if matches_q and matches_role and matches_status:
            user_entry = udata.copy()
            user_entry["username"] = uname
            filtered_users.append(user_entry)

    per_page = 10
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1

    total_filtered = len(filtered_users)
    total_pages = max(1, (total_filtered + per_page - 1) // per_page)
    page = min(page, total_pages)

    start_idx = (page - 1) * per_page
    paginated_users = filtered_users[start_idx:start_idx + per_page]

    warehouses = ["Kho chính - SANOVA", "Kho phụ - SANOVA", "Kho trung chuyển"]

    active_role_names = [
        r.get("name", r.get("role_name")) for r in roles_definitions.values() 
        if r.get("status", "Hoạt động") == "Hoạt động"
    ]

    return render_template(
        "ADMIN/admin_users.html",
        current_user=session["user"],
        users=paginated_users,
        total_users=total_users,
        active_users=active_users,
        locked_users=locked_users,
        pending_users=pending_users,
        roles=active_role_names,
        warehouses=warehouses,
        q=request.args.get("q", ""),
        role_filter=role_filter,
        status_filter=status_filter,
        page=page,
        total_pages=total_pages,
        total_filtered=total_filtered
    )

@app.route("/admin/api/users/create", methods=["POST"])
@admin_required
def api_admin_create_user():
    data = request.get_json() if request.is_json else request.form

    staff_code = data.get("staff_code", "").strip().upper()
    name = data.get("name", "").strip()
    raw_email = data.get("email", "").strip()
    
    if raw_email:
        prefix = raw_email.split("@")[0].strip()
        email = f"{prefix}@sanova.vn"
    else:
        email = ""

    username = data.get("username", "").strip()
    role = data.get("role", "").strip()
    scope = data.get("scope", "").strip() or "Kho chính - SANOVA"
    password = data.get("password", "")
    confirm_password = data.get("confirm_password", "")
    status = data.get("status", "Hoạt động").strip()

    users = load_users()

    if not staff_code or not name or not username or not role or not password or not confirm_password:
        return jsonify({"success": False, "message": "Vui lòng nhập đầy đủ các trường bắt buộc (*)."}), 400

    for u in users.values():
        if u.get("staff_code", "").upper() == staff_code:
            return jsonify({"success": False, "message": f"Mã nhân viên '{staff_code}' đã tồn tại trong hệ thống!"}), 400

    if username in users:
        return jsonify({"success": False, "message": f"Tên đăng nhập '{username}' đã được sử dụng!"}), 400

    if password != confirm_password:
        return jsonify({"success": False, "message": "Xác nhận mật khẩu không khớp!"}), 400

    if not validate_password(password):
        return jsonify({"success": False, "message": "Mật khẩu không đáp ứng độ dài tối thiểu theo chính sách hệ thống!"}), 400

    now_str = datetime.now().strftime("%d/%m/%Y · %H:%M")
    creator_name = session["user"].get("name", "Admin")

    new_user_data = {
        "staff_code": staff_code,
        "name": name,
        "email": email,
        "role": role,
        "scope": scope,
        "password": hash_password(password),
        "status": status,
        "last_login": "Chưa có",
        "created_at": now_str,
        "created_by": creator_name
    }

    users[username] = new_user_data
    save_users(users)

    add_audit_log(
        category="TÀI KHOẢN",
        action=f"Tạo người dùng {name} ({staff_code})",
        target=username,
        changes=[
            {"field": "Mã NV", "before": "", "after": staff_code},
            {"field": "Email", "before": "", "after": email},
            {"field": "Vai trò", "before": "", "after": role},
            {"field": "Phạm vi kho", "before": "", "after": scope}
        ]
    )
    if status == "Chờ kích hoạt":
        create_admin_notification(
            group="account",
            severity="action_required",
            title="Tài khoản chờ kích hoạt",
            message=f"Tài khoản {name} ({username}) vừa được tạo và đang chờ kích hoạt.",
            target_url="/admin/users?status=Chờ+kích+hoạt"
        )
    stats = {
        "total": len(users),
        "active": sum(1 for u in users.values() if u.get("status") == "Hoạt động"),
        "locked": sum(1 for u in users.values() if u.get("status") == "Tạm khóa"),
        "pending": sum(1 for u in users.values() if u.get("status") == "Chờ kích hoạt")
    }

    return jsonify({
        "success": True,
        "message": f"Tạo tài khoản {username} thành công!",
        "stats": stats,
        "new_user": {
            "staff_code": staff_code,
            "name": name,
            "username": username,
            "email": email,
            "role": role,
            "scope": scope,
            "status": status,
            "created_at": now_str,
            "created_by": creator_name,
            "last_login": "Chưa có"
        }
    })

@app.route("/admin/users/update", methods=["POST"])
@admin_required
def admin_update_user():
    username = request.form.get("username", "").strip()
    name = request.form.get("name", "").strip()
    raw_email = request.form.get("email", "").strip()
    email = f"{raw_email.split('@')[0].strip()}@sanova.vn" if raw_email else ""
    role = request.form.get("role", "").strip()
    scope = request.form.get("scope", "").strip()

    users = load_users()
    if username not in users:
        abort(404, description="Tài khoản không tồn tại")

    user = users[username]
    if username == session["user"]["username"] and role != "Quản trị viên":
        flash("Không cho phép Admin tự hạ quyền quản trị của chính mình!", "danger")
        return redirect(url_for("admin_users"))

    changes = []
    for field, new_val in [("name", name), ("email", email), ("role", role), ("scope", scope)]:
        old_val = user.get(field)
        if old_val != new_val:
            changes.append({"field": field, "before": old_val, "after": new_val})
            user[field] = new_val

    save_users(users)
    add_audit_log("TÀI KHOẢN", f"Cập nhật thông tin tài khoản {name}", username, changes=changes)
    flash("Cập nhật thông tin tài khoản thành công!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/toggle-status/<username>", methods=["POST"])
@admin_required
def toggle_status(username):
    users = load_users()
    if username not in users:
        abort(404)

    target_user = users[username]
    if target_user.get("role") == "Quản trị viên" or username in ("admin", "duc.long"):
        flash("Không được phép khóa tài khoản Quản trị viên!", "danger")
        return redirect(url_for("admin_users"))

    old_status = target_user.get("status", "Hoạt động")
    new_status = "Tạm khóa" if old_status == "Hoạt động" else "Hoạt động"
    target_user["status"] = new_status
    save_users(users)

    add_audit_log(
        "TÀI KHOẢN",
        f"{new_status} tài khoản {target_user.get('name')}",
        username,
        changes=[{"field": "Trạng thái", "before": old_status, "after": new_status}]
    )
    if new_status == "Tạm khóa":
            create_admin_notification(
                group="account",
                severity="action_required",
                title="Tài khoản bị tạm khóa",
                message=f"Tài khoản {users[username].get('name')} ({username}) đã chuyển sang trạng thái Tạm khóa.",
                target_url="/admin/users?status=Tạm+khóa"
            )
    flash(f"Đã chuyển trạng thái tài khoản {username} sang '{new_status}'!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/reset-password", methods=["POST"])
@admin_required
def reset_password():
    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "")

    users = load_users()
    if username not in users:
        abort(404)

    if not validate_password(new_password):
        flash("Mật khẩu không đáp ứng độ dài tối thiểu!", "danger")
        return redirect(url_for("admin_users"))

    users[username]["password"] = hash_password(new_password)
    save_users(users)

    is_self = (username == session["user"]["username"])
    action_text = "Đổi mật khẩu cá nhân" if is_self else f"Admin đặt lại mật khẩu cho {users[username].get('name')}"
    add_audit_log("BẢO MẬT", action_text, username)
    flash(f"Đã đặt lại mật khẩu cho tài khoản {username} thành công!", "success")
    return redirect(url_for("admin_users"))

# ==========================================================
# 9. ROUTE VAI TRÒ & PHÂN QUYỀN (HOÀN THIỆN 3 CHỨC NĂNG)
# ==========================================================

ROLE_NAME_TO_KEY = {
    "Quản trị viên": "ADMIN",
    "Quản trị viên (Admin)": "ADMIN",
    "Quản lý kho": "WAREHOUSE_MANAGER",
    "Quản lý kho (Manager)": "WAREHOUSE_MANAGER",
    "Nhân viên kho": "WAREHOUSE_STAFF",
    "Nhân viên kho (Staff)": "WAREHOUSE_STAFF",
    "Điều phối / Kế toán kho": "COORDINATOR",
    "Điều phối / Kế toán": "COORDINATOR"
}

# Quyền chi tiết thực tế theo nghiệp vụ khi bấm mũi tên mở rộng từng nhóm
MODULE_SUB_PERMISSIONS = {
    "users": [
        ("view", "Xem danh sách người dùng"),
        ("create", "Thêm người dùng mới"),
        ("edit", "Chỉnh sửa thông tin & vai trò"),
        ("lock", "Khóa / Mở khóa tài khoản"),
        ("reset_pwd", "Đặt lại mật khẩu")
    ],
    "locations": [
        ("view", "Xem sơ đồ kho, kệ, vị trí"),
        ("create", "Thêm kho, kệ, vị trí"),
        ("edit", "Chỉnh sửa thông số vị trí"),
        ("disable", "Ngừng sử dụng vị trí")
    ],
    "products": [
        ("view", "Xem danh mục sản phẩm (SKU)"),
        ("create", "Thêm sản phẩm mới"),
        ("edit", "Chỉnh sửa thông tin sản phẩm"),
        ("disable", "Ngừng kinh doanh sản phẩm")
    ],
    "inbound": [
        ("view", "Xem phiếu nhập kho"),
        ("receive", "Tiếp nhận hàng & ghi nhận vị trí"),
        ("approve", "Xác nhận nhập lên kệ")
    ],
    "outbound": [
        ("view", "Xem đơn & phiếu lấy hàng (Picking)"),
        ("pick", "Thực hiện lấy hàng & đóng gói"),
        ("confirm", "Xác nhận lấy hàng & bàn giao")
    ],
    "stocktake": [
        ("view", "Xem phiên kiểm kê"),
        ("count", "Thực hiện kiểm đếm tồn thực tế"),
        ("request_adj", "Lập yêu cầu điều chỉnh tồn"),
        ("approve", "Phê duyệt điều chỉnh tồn kho")
    ],
    "reports": [
        ("view", "Xem báo cáo tồn kho & biến động"),
        ("export", "Xuất báo cáo Excel / CSV")
    ],
    "settings": [
        ("view", "Xem cấu hình & nhật ký hệ thống"),
        ("edit", "Chỉnh sửa chính sách bảo mật & sao lưu")
    ]
}

def _count_role_users(users_dict, role_code, role_obj):
    r_name = role_obj.get("name") or role_obj.get("role_name", "")
    return sum(
        1 for u in users_dict.values()
        if u.get("role_code") == role_code
        or u.get("role") == r_name
        or ROLE_NAME_TO_KEY.get(u.get("role", "")) == role_code
    )

@app.route("/admin/roles")
@admin_required
def admin_roles_view():
    roles_data = load_role_definitions()
    users = load_users()

    role_user_counts = {}
    total_assigned_accounts = 0
    for r_code, r_obj in roles_data.items():
        cnt = _count_role_users(users, r_code, r_obj)
        role_user_counts[r_code] = cnt
        total_assigned_accounts += cnt

    total_roles = len(roles_data)
    total_system_perms = 32

    selected_code = request.args.get("role", "WAREHOUSE_MANAGER")
    if selected_code not in roles_data:
        selected_code = "WAREHOUSE_MANAGER" if "WAREHOUSE_MANAGER" in roles_data else list(roles_data.keys())[0]

    active_role = roles_data.get(selected_code, {})
    active_perms = active_role.get("permissions", {})
    active_detail_perms = active_role.get("detail_permissions", {})

    active_selected_perms_count = 0
    for mod in PERMISSION_MODULES:
        m_perms = active_perms.get(mod["id"], {})
        if isinstance(m_perms, dict):
            active_selected_perms_count += sum(1 for v in m_perms.values() if v)
        elif isinstance(m_perms, list):
            active_selected_perms_count += len(m_perms)

    active_role_users = [
        {"username": uname, **udata}
        for uname, udata in users.items()
        if udata.get("role_code") == selected_code
        or udata.get("role") == active_role.get("name")
        or ROLE_NAME_TO_KEY.get(udata.get("role", "")) == selected_code
    ]

    return render_template(
        "ADMIN/admin_roles.html",
        current_user=session["user"],
        roles=roles_data,
        roles_data=roles_data,
        modules=PERMISSION_MODULES,
        sub_permissions=MODULE_SUB_PERMISSIONS,
        actions=PERMISSION_ACTIONS,
        selected_code=selected_code,
        active_role=active_role,
        active_perms=active_perms,
        active_detail_perms=active_detail_perms,
        active_selected_perms_count=active_selected_perms_count,
        role_user_counts=role_user_counts,
        total_roles=total_roles,
        total_system_perms=total_system_perms,
        total_assigned_accounts=total_assigned_accounts,
        active_role_users=active_role_users
    )

# --- 1. API THÊM VAI TRÒ MỚI ---
@app.route("/admin/api/roles/create", methods=["POST"])
@admin_required
def api_create_role():
    data = request.get_json() or {}
    role_code = str(data.get("role_code", "")).strip().upper()
    role_name = str(data.get("name", "")).strip()
    description = str(data.get("desc", "")).strip()
    status = str(data.get("status", "Hoạt động")).strip()
    matrix_perms = data.get("permissions", {})
    detail_perms = data.get("detail_permissions", {})

    if not role_code or not role_name:
        return jsonify({"success": False, "message": "Mã vai trò và Tên vai trò là bắt buộc!"}), 400

    if not role_code.replace("_", "").isalnum():
        return jsonify({"success": False, "message": "Mã vai trò chỉ được chứa chữ cái không dấu, số và dấu gạch dưới (_)!"}), 400

    roles_data = load_role_definitions()

    if role_code in roles_data:
        return jsonify({"success": False, "message": f"Mã vai trò '{role_code}' đã tồn tại trong hệ thống!"}), 400

    for r in roles_data.values():
        existing_name = (r.get("name") or r.get("role_name") or "").strip().lower()
        if existing_name == role_name.lower():
            return jsonify({"success": False, "message": f"Tên vai trò '{role_name}' đã trùng với vai trò hiện có!"}), 400

    # Chuẩn hóa ma trận quyền hợp lệ (không tự động cấp toàn quyền Admin)
    valid_mod_ids = {m["id"] for m in PERMISSION_MODULES}
    valid_act_ids = {a[0] for a in PERMISSION_ACTIONS}
    clean_matrix = {}
    has_any_perm = False

    for m_id in valid_mod_ids:
        clean_matrix[m_id] = {}
        raw_m = matrix_perms.get(m_id, {}) if isinstance(matrix_perms, dict) else {}
        for a_id in valid_act_ids:
            val = bool(raw_m.get(a_id, False))
            clean_matrix[m_id][a_id] = val
            if val:
                has_any_perm = True

    if not has_any_perm:
        return jsonify({"success": False, "message": "Vui lòng chọn ít nhất 1 quyền cho vai trò mới!"}), 400

    roles_data[role_code] = {
        "id": role_code,
        "role_code": role_code,
        "name": role_name,
        "role_name": role_name,
        "desc": description or "Vai trò tùy chỉnh trong hệ thống SANOVA",
        "description": description or "Vai trò tùy chỉnh trong hệ thống SANOVA",
        "icon": "🛡️",
        "status": status if status in ("Hoạt động", "Ngừng sử dụng") else "Hoạt động",
        "is_system": False,
        "created_at": datetime.now().strftime("%d/%m/%Y · %H:%M"),
        "created_by": session.get("user", {}).get("name", "Admin"),
        "permissions": clean_matrix,
        "detail_permissions": detail_perms if isinstance(detail_perms, dict) else {}
    }
    save_role_definitions(roles_data)

    add_audit_log(
        category="Phân quyền",
        action=f"Thêm mới vai trò {role_name} ({role_code})",
        target=role_code,
        changes=[
            {"field": "Tên vai trò", "before": "", "after": role_name},
            {"field": "Trạng thái", "before": "", "after": roles_data[role_code]["status"]}
        ],
        result="Thành công"
    )
    create_admin_notification(
        group="role",
        severity="info",
        title="Tạo vai trò mới",
        message=f"Vai trò mới '{role_name}' ({role_code}) vừa được thêm vào hệ thống.",
        account=session.get("user", {}).get("username", "admin"),
        reason="Admin khai báo vai trò mới trong phân hệ Phân quyền",
        impact="Có thể gán vai trò này cho tài khoản người dùng mới.",
        target_url=f"/admin/roles?role={role_code}"
    )

    return jsonify({"success": True, "message": f"Đã tạo vai trò '{role_name}' thành công!", "role_code": role_code})

# --- 2. API SO SÁNH THAY ĐỔI QUYỀN (DIFF PREVIEW) TRƯỚC KHI LƯU ---
@app.route("/admin/api/roles/preview-diff", methods=["POST"])
@admin_required
def api_preview_role_diff():
    data = request.get_json() or {}
    role_code = data.get("role_code")
    new_matrix = data.get("permissions", {})

    roles_data = load_role_definitions()
    if role_code not in roles_data:
        return jsonify({"success": False, "message": "Vai trò không tồn tại!"}), 404

    old_matrix = roles_data[role_code].get("permissions", {})
    mod_map = {m["id"]: m["name"] for m in PERMISSION_MODULES}
    act_map = dict(PERMISSION_ACTIONS)

    added = []
    revoked = []

    for m_id, m_name in mod_map.items():
        old_m = old_matrix.get(m_id, {}) if isinstance(old_matrix.get(m_id), dict) else {}
        new_m = new_matrix.get(m_id, {}) if isinstance(new_matrix.get(m_id), dict) else {}
        for a_id, a_label in act_map.items():
            old_v = bool(old_m.get(a_id, False))
            new_v = bool(new_m.get(a_id, False))
            if not old_v and new_v:
                added.append(f"{a_label} · {m_name}")
            elif old_v and not new_v:
                revoked.append(f"{a_label} · {m_name}")

    users = load_users()
    affected_users = _count_role_users(users, role_code, roles_data[role_code])

    return jsonify({
        "success": True,
        "role_name": roles_data[role_code].get("name", role_code),
        "added": added,
        "revoked": revoked,
        "affected_users": affected_users
    })

# --- 3. API LƯU CHỈNH SỬA VAI TRÒ & QUYỀN ---
@app.route("/admin/api/roles/update", methods=["POST"])
@admin_required
def api_update_role():
    data = request.get_json() or {}
    role_code = data.get("role_code")
    new_name = str(data.get("name", "")).strip()
    new_desc = str(data.get("desc", "")).strip()
    new_status = str(data.get("status", "Hoạt động")).strip()
    new_matrix = data.get("permissions", None)
    new_detail = data.get("detail_permissions", None)

    roles_data = load_role_definitions()
    if role_code not in roles_data:
        return jsonify({"success": False, "message": "Vai trò không tồn tại!"}), 404

    role_obj = roles_data[role_code]
    if not new_name:
        return jsonify({"success": False, "message": "Tên vai trò không được để trống!"}), 400

    # Kiểm tra trùng tên với vai trò khác
    for code, r in roles_data.items():
        if code != role_code and (r.get("name") or "").strip().lower() == new_name.lower():
            return jsonify({"success": False, "message": f"Tên vai trò '{new_name}' đã được sử dụng!"}), 400

    users = load_users()
    used_count = _count_role_users(users, role_code, role_obj)

    # Quy tắc bảo vệ trạng thái & Admin mặc định
    if role_code == "ADMIN":
        new_status = "Hoạt động"
    elif new_status == "Ngừng sử dụng" and used_count > 0:
        return jsonify({
            "success": False,
            "message": f"Không thể ngừng sử dụng vì đang có {used_count} tài khoản sử dụng vai trò này!"
        }), 400

    old_name = role_obj.get("name", "")
    old_desc = role_obj.get("desc", "")
    old_status = role_obj.get("status", "Hoạt động")

    changes = []
    if old_name != new_name:
        changes.append({"field": "Tên vai trò", "before": old_name, "after": new_name})
        # Đồng bộ tên vai trò sang users.json
        for u in users.values():
            if u.get("role") == old_name or u.get("role_code") == role_code:
                u["role"] = new_name
        save_users(users)

    if old_desc != new_desc:
        changes.append({"field": "Mô tả", "before": old_desc, "after": new_desc})
    if old_status != new_status:
        changes.append({"field": "Trạng thái", "before": old_status, "after": new_status})

    role_obj["name"] = new_name
    role_obj["role_name"] = new_name
    role_obj["desc"] = new_desc
    role_obj["description"] = new_desc
    role_obj["status"] = new_status

    if isinstance(new_matrix, dict) and role_code != "ADMIN":
        role_obj["permissions"] = new_matrix
        changes.append({"field": "Phân quyền", "before": "Cũ", "after": "Đã cập nhật ma trận quyền"})

    if isinstance(new_detail, dict) and role_code != "ADMIN":
        role_obj["detail_permissions"] = new_detail

    save_role_definitions(roles_data)

    add_audit_log(
        category="Phân quyền",
        action=f"Chỉnh sửa vai trò {new_name} ({role_code})",
        target=role_code,
        changes=changes,
        result="Thành công"
    )
    create_admin_notification(
        group="role",
        severity="important",
        title="Cập nhật phân quyền vai trò",
        message=f"Vai trò {new_name} vừa được cập nhật thông tin/quyền truy cập (ảnh hưởng {used_count} tài khoản).",
        account=session.get("user", {}).get("username", "admin"),
        reason="Admin điều chỉnh cấu hình phân quyền vai trò",
        impact=f"Áp dụng ngay cho {used_count} tài khoản đang sử dụng vai trò này.",
        target_url=f"/admin/roles?role={role_code}"
    )

    return jsonify({
        "success": True,
        "message": f"Đã lưu thay đổi cho vai trò '{new_name}' (áp dụng cho {used_count} tài khoản)!"
    })

# --- 4. API LƯU MA TRẬN QUYỀN TRỰC TIẾP TRÊN BẢNG CHÍNH ---
@app.route("/admin/api/roles/save-permissions", methods=["POST"])
@admin_required
def api_save_role_permissions():
    data = request.get_json() or {}
    role_code = data.get("role_code") or data.get("role_id")
    new_perms = data.get("permissions", {})
    new_detail = data.get("detail_permissions", {})

    roles_data = load_role_definitions()
    if role_code not in roles_data:
        return jsonify({"success": False, "message": "Vai trò không tồn tại"}), 404

    if role_code == "ADMIN":
        return jsonify({"success": True, "message": "Quản trị viên luôn có toàn quyền hệ thống!"})

    roles_data[role_code]["permissions"] = new_perms
    if isinstance(new_detail, dict):
        roles_data[role_code]["detail_permissions"] = new_detail
    save_role_definitions(roles_data)

    role_name = roles_data[role_code].get("name", role_code)
    users = load_users()
    used_count = _count_role_users(users, role_code, roles_data[role_code])

    add_audit_log(
        category="Phân quyền",
        action=f"Cập nhật ma trận phân quyền vai trò {role_name}",
        target=role_code,
        result="Thành công"
    )
    create_admin_notification(
        group="role",
        severity="important",
        title="Thay đổi quyền truy cập",
        message=f"Quyền của vai trò {role_name} vừa được cập nhật (áp dụng cho {used_count} tài khoản).",
        account=session.get("user", {}).get("username", "admin"),
        reason="Admin lưu thay đổi trên ma trận phân quyền",
        impact=f"Các phiên làm việc của {used_count} tài khoản liên quan sẽ nhận quyền mới ngay lập tức.",
        target_url=f"/admin/roles?role={role_code}"
    )
    return jsonify({"success": True, "message": f"Đã lưu ma trận phân quyền cho vai trò '{role_name}' thành công!"})

# --- 5. API KHÔI PHỤC QUYỀN MẶC ĐỊNH ---
@app.route("/admin/api/roles/reset-default", methods=["POST"])
@admin_required
def api_reset_role_permissions():
    data = request.get_json() or {}
    role_code = data.get("role_code") or data.get("role_id")

    roles_data = load_role_definitions()
    if role_code not in roles_data or role_code not in INITIAL_ROLES:
        return jsonify({"success": False, "message": "Vai trò tự tạo không có cấu hình mặc định hệ thống!"}), 400

    roles_data[role_code]["permissions"] = deepcopy(INITIAL_ROLES[role_code]["permissions"])
    roles_data[role_code]["detail_permissions"] = {}
    save_role_definitions(roles_data)

    r_name = roles_data[role_code].get("name", role_code)
    add_audit_log(
        category="Phân quyền",
        action=f"Khôi phục quyền mặc định cho vai trò {r_name}",
        target=role_code,
        result="Thành công"
    )
    create_admin_notification(
        group="role",
        severity="info",
        title="Khôi phục quyền mặc định",
        message=f"Quyền của vai trò {r_name} vừa được khôi phục về mặc định.",
        target_url=f"/admin/roles?role={role_code}"
    )
    return jsonify({"success": True, "message": "Đã khôi phục quyền mặc định thành công!"})

# --- 6. API NGỪNG SỬ DỤNG (XÓA MỀM) & KÍCH HOẠT LẠI VAI TRÒ ---
@app.route("/admin/api/roles/toggle-status", methods=["POST"])
@admin_required
def api_toggle_role_status():
    data = request.get_json() or {}
    role_code = data.get("role_code")
    target_status = data.get("target_status", "Ngừng sử dụng")

    roles_data = load_role_definitions()
    if role_code not in roles_data:
        return jsonify({"success": False, "message": "Vai trò không tồn tại!"}), 404

    role_obj = roles_data[role_code]
    r_name = role_obj.get("name", role_code)

    # Chặn xóa / ngừng sử dụng 4 vai trò mặc định của hệ thống
    if role_obj.get("is_system") or role_code in ("ADMIN", "WAREHOUSE_MANAGER", "WAREHOUSE_STAFF", "COORDINATOR"):
        return jsonify({
            "success": False,
            "message": f"Không thể ngừng sử dụng vai trò mặc định '{r_name}' của hệ thống SANOVA!"
        }), 400

    users = load_users()
    used_count = _count_role_users(users, role_code, role_obj)

    if target_status == "Ngừng sử dụng" and used_count > 0:
        return jsonify({
            "success": False,
            "message": f"Không thể ngừng sử dụng! Đang có {used_count} tài khoản sử dụng vai trò này. Vui lòng chuyển các tài khoản sang vai trò khác trước."
        }), 400

    old_status = role_obj.get("status", "Hoạt động")
    role_obj["status"] = target_status
    save_role_definitions(roles_data)

    action_label = "Ngừng sử dụng vai trò" if target_status == "Ngừng sử dụng" else "Kích hoạt lại vai trò"
    add_audit_log(
        category="Phân quyền",
        action=f"{action_label} {r_name} ({role_code})",
        target=role_code,
        changes=[{"field": "Trạng thái", "before": old_status, "after": target_status}],
        result="Thành công"
    )
    create_admin_notification(
        group="role",
        severity="important" if target_status == "Ngừng sử dụng" else "info",
        title=action_label,
        message=f"Vai trò '{r_name}' đã chuyển sang trạng thái {target_status}.",
        target_url=f"/admin/roles?role={role_code}"
    )

    return jsonify({"success": True, "message": f"Đã chuyển vai trò '{r_name}' sang trạng thái {target_status}!"})

# ==========================================================
# 10. AUDIT LOGS & EXPORT CSV
_logs_lock = threading.Lock()

def load_logs():
    if not os.path.exists(LOGS_FILE):
        return []
    with _logs_lock:
        try:
            with open(LOGS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

# Thay thế hàm add_audit_log ở Phần 10 bằng phiên bản tương thích ngược cả status và result:
def add_audit_log(category, action, target, changes=None, result=None, status=None, reason=""):
    final_status = result or status or "Thành công"
    now = datetime.now()
    log_id = f"LOG-{now.strftime('%Y%m%d')}-{secrets.token_hex(4).upper()}"
    
    actor_name = session.get("user", {}).get("name", "Hệ thống")
    actor_username = session.get("user", {}).get("username", "system")
    
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    if "," in ip:
        ip = ip.split(",")[0].strip()
    device = request.headers.get("User-Agent", "Mozilla/5.0")[:120]

    entry = {
        "id": log_id,
        "timestamp": now.strftime("%d/%m/%Y – %H:%M:%S"),
        "date": now.strftime("%Y-%m-%d"),
        "time": now.strftime("%H:%M:%S"),
        "actor": actor_name,
        "by": f"{actor_name} ({actor_username})",
        "category": category,
        "action": action,
        "target": str(target),
        "result": final_status,
        "status": final_status,  # Giữ đồng bộ cả 2 trường cho Dashboard cũ & Logs mới
        "ip": ip,
        "device": device,
        "changes": changes or [],
        "reason": reason
    }

    logs = load_logs()
    logs.insert(0, entry)
    write_json(LOGS_FILE, logs)
    return entry

# --- ROUTE HIỂN THỊ GIAO DIỆN NHẬT KÝ HỆ THỐNG ---
@app.route("/admin/logs")
@admin_required
def admin_logs():
    return render_template("ADMIN/admin_logs.html", current_user=session.get("user", {}))

# --- API LỌC, PHÂN TRANG VÀ AUTO-UPDATE POLLING (JSON) ---
@app.route("/admin/api/logs", methods=["GET"])
@admin_required
def get_logs_api():
    all_logs = load_logs()
    
    q = request.args.get("q", "").strip().lower()
    date_from = request.args.get("from", "").strip()
    date_to = request.args.get("to", "").strip()
    category = request.args.get("category", "ALL").strip()
    actor = request.args.get("actor", "ALL").strip()
    result = request.args.get("result", "ALL").strip()
    
    try:
        limit = int(request.args.get("limit", 10))
    except ValueError:
        limit = 10
    try:
        page = int(request.args.get("page", 1))
    except ValueError:
        page = 1

    # Thống kê KPI tổng thể
    today_str = datetime.now().strftime("%Y-%m-%d")
    total_logs_count = len(all_logs)
    today_count = sum(1 for l in all_logs if l.get("date") == today_str)
    success_count = sum(1 for l in all_logs if l.get("result") == "Thành công")
    failed_warn_count = sum(1 for l in all_logs if l.get("result") in ["Thất bại", "Cảnh báo"])

    # Lọc dữ liệu
    filtered = []
    for l in all_logs:
        matches_q = not q or (
            q in l.get("actor", "").lower() or
            q in l.get("by", "").lower() or
            q in l.get("action", "").lower() or
            q in l.get("target", "").lower() or
            q in l.get("id", "").lower()
        )
        matches_cat = (category == "ALL") or (l.get("category") == category)
        matches_actor = (actor == "ALL") or (l.get("actor") == actor)
        matches_res = (result == "ALL") or (l.get("result") == result)
        
        l_date = l.get("date", "")
        matches_date = True
        if date_from and l_date < date_from:
            matches_date = False
        if date_to and l_date > date_to:
            matches_date = False

        if matches_q and matches_cat and matches_actor and matches_res and matches_date:
            filtered.append(l)

    # Phân trang
    total_filtered = len(filtered)
    total_pages = max(1, (total_filtered + limit - 1) // limit)
    page = max(1, min(page, total_pages))
    start = (page - 1) * limit
    paginated_items = filtered[start:start + limit]

    # Danh sách danh mục và danh sách nhân viên phục vụ dropdown
    actors_list = sorted(list(set(l.get("actor") for l in all_logs if l.get("actor"))))

    return jsonify({
        "success": True,
        "kpi": {
            "total": total_logs_count,
            "today": today_count,
            "success": success_count,
            "failed_warn": failed_warn_count
        },
        "items": paginated_items,
        "total_filtered": total_filtered,
        "page": page,
        "limit": limit,
        "total_pages": total_pages,
        "actors": actors_list
    })

# --- XUẤT FILE EXCEL/CSV THEO BỘ LỌC HIỆN TẠI ---
@app.route("/admin/logs/export", methods=["GET"])
@admin_required
def export_logs():
    all_logs = load_logs()
    
    q = request.args.get("q", "").strip().lower()
    date_from = request.args.get("from", "").strip()
    date_to = request.args.get("to", "").strip()
    category = request.args.get("category", "ALL").strip()
    actor = request.args.get("actor", "ALL").strip()
    result = request.args.get("result", "ALL").strip()

    filtered = []
    for l in all_logs:
        matches_q = not q or (
            q in l.get("actor", "").lower() or
            q in l.get("by", "").lower() or
            q in l.get("action", "").lower() or
            q in l.get("target", "").lower() or
            q in l.get("id", "").lower()
        )
        matches_cat = (category == "ALL") or (l.get("category") == category)
        matches_actor = (actor == "ALL") or (l.get("actor") == actor)
        matches_res = (result == "ALL") or (l.get("result") == result)
        
        l_date = l.get("date", "")
        matches_date = True
        if date_from and l_date < date_from:
            matches_date = False
        if date_to and l_date > date_to:
            matches_date = False

        if matches_q and matches_cat and matches_actor and matches_res and matches_date:
            filtered.append(l)

    output = io.StringIO()
    output.write("\ufeff")  # Ký tự UTF-8 BOM để Excel hiển thị đúng dấu tiếng Việt
    writer = csv.writer(output)
    writer.writerow(["Mã sự kiện", "Thời gian", "Người thực hiện", "Nhóm hoạt động", "Hành động", "Đối tượng", "Kết quả", "Địa chỉ IP", "Thiết bị", "Chi tiết thay đổi / Ghi chú"])

    for l in filtered:
        diff_str = "; ".join([f"{c['field']}: {c['before']} -> {c['after']}" for c in l.get("changes", [])])
        if not diff_str:
            diff_str = l.get("reason", "")
        writer.writerow([
            l.get("id"),
            l.get("timestamp"),
            l.get("by"),
            l.get("category"),
            l.get("action"),
            l.get("target"),
            l.get("result"),
            l.get("ip"),
            l.get("device"),
            diff_str
        ])

    response = make_response(output.getvalue().encode("utf-8"))
    filename = f"SANOVA_Audit_Logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    return response

# ==========================================================
# 11. CẤU HÌNH HỆ THỐNG & TÀI KHOẢN CÁ NHÂN
import zipfile
import shutil
from copy import deepcopy

os.makedirs(BACKUP_DIR, exist_ok=True)

DEFAULT_SYSTEM_SETTINGS = {
    "security": {
        "session_timeout": 30,
        "session_warning_enabled": True,
        "session_warning_minutes": 5,
        "max_failed_logins": 5,
        "lockout_duration": 15,
        "log_failed_logins": True,
        "single_session_only": False
    },
    "password": {
        "min_length": 8,
        "require_uppercase": True,
        "require_number": True,
        "require_special": False,
        "force_change_first_login": True,
        "prevent_common_passwords": True,
        "password_expiry_days": 90
    },
    "backup": {
        "auto_backup_enabled": True,
        "backup_frequency": "daily",
        "retention_count": 7,
        "last_backup_time": "Chưa có",
        "history": []
    },
    "notifications": {
        "alert_failed_login": True,
        "alert_account_locked": True,
        "alert_system_error": True,
        "alert_stock_discrepancy": True
    },
    "general": {
        "system_name": "SANOVA WMS",
        "timezone": "Asia/Ho_Chi_Minh (GMT+7)",
        "date_format": "DD/MM/YYYY",
        "log_retention_days": 90
    }
}

def load_system_settings():
    if not os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SYSTEM_SETTINGS, f, ensure_ascii=False, indent=2)
        return deepcopy(DEFAULT_SYSTEM_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Đảm bảo đủ 5 nhóm cấu hình
            for k, v in DEFAULT_SYSTEM_SETTINGS.items():
                if k not in data:
                    data[k] = deepcopy(v)
            return data
    except Exception:
        return deepcopy(DEFAULT_SYSTEM_SETTINGS)

def save_system_settings(data):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# --- ROUTE HIỂN THỊ TRANG CẤU HÌNH HỆ THỐNG ---
@app.route("/admin/settings")
@admin_required
def admin_settings():
    settings = load_system_settings()
    return render_template(
        "ADMIN/admin_settings.html",
        current_user=session.get("user", {}),
        settings=settings
    )

# --- API LƯU CẤU HÌNH THEO TỪNG NHÓM (CÓ VALIDATION & GHI LOG BEFORE/AFTER) ---
@app.route("/admin/api/settings/save", methods=["POST"])
@admin_required
def api_save_settings():
    payload = request.get_json() or {}
    group = payload.get("group")
    new_values = payload.get("values", {})

    if group not in ["security", "password", "backup", "notifications", "general"]:
        return jsonify({"success": False, "message": "Nhóm cấu hình không hợp lệ!"}), 400

    settings = load_system_settings()
    old_group = deepcopy(settings.get(group, {}))
    changes = []

    # 1. Validation & Quy tắc nghiệp vụ từng nhóm
    if group == "security":
        timeout = int(new_values.get("session_timeout", 30))
        max_fail = int(new_values.get("max_failed_logins", 5))
        lock_dur = int(new_values.get("lockout_duration", 15))
        warn_min = int(new_values.get("session_warning_minutes", 5))

        if not (5 <= timeout <= 480):
            return jsonify({"success": False, "message": "Thời gian phiên làm việc phải từ 5 đến 480 phút!"}), 400
        if not (3 <= max_fail <= 10):
            return jsonify({"success": False, "message": "Số lần đăng nhập sai tối đa phải từ 3 đến 10 lần!"}), 400
        if not (1 <= lock_dur <= 1440):
            return jsonify({"success": False, "message": "Thời gian khóa tạm thời phải từ 1 đến 1440 phút!"}), 400
        if warn_min >= timeout:
            return jsonify({"success": False, "message": "Thời gian cảnh báo hết phiên phải nhỏ hơn thời gian phiên!"}), 400

        # Áp dụng ngay session lifetime cho Flask
        app.permanent_session_lifetime = timedelta(minutes=timeout)

    elif group == "password":
        min_len = int(new_values.get("min_length", 8))
        expiry = int(new_values.get("password_expiry_days", 90))
        if not (6 <= min_len <= 32):
            return jsonify({"success": False, "message": "Độ dài mật khẩu tối thiểu phải từ 6 đến 32 ký tự!"}), 400
        if not (0 <= expiry <= 365):
            return jsonify({"success": False, "message": "Chu kỳ đổi mật khẩu phải từ 0 đến 365 ngày!"}), 400

    elif group == "general":
        sys_name = str(new_values.get("system_name", "")).strip()
        retention = int(new_values.get("log_retention_days", 90))
        if not sys_name:
            return jsonify({"success": False, "message": "Tên hệ thống không được để trống!"}), 400
        if not (30 <= retention <= 3650):
            return jsonify({"success": False, "message": "Thời gian lưu trữ nhật ký tối thiểu 30 ngày!"}), 400

    # 2. So sánh Before -> After để ghi Audit Log
    field_labels = {
        "session_timeout": "Thời gian phiên làm việc (phút)",
        "session_warning_enabled": "Bật cảnh báo sắp hết phiên",
        "session_warning_minutes": "Cảnh báo trước khi hết phiên (phút)",
        "max_failed_logins": "Số lần đăng nhập sai tối đa",
        "lockout_duration": "Thời gian khóa tạm thời (phút)",
        "log_failed_logins": "Ghi nhận đăng nhập không thành công",
        "single_session_only": "Giới hạn đăng nhập đồng thời",
        "min_length": "Độ dài mật khẩu tối thiểu",
        "require_uppercase": "Yêu cầu chữ hoa",
        "require_number": "Yêu cầu chữ số",
        "require_special": "Yêu cầu ký tự đặc biệt",
        "force_change_first_login": "Bắt buộc đổi mật khẩu lần đầu",
        "prevent_common_passwords": "Ngăn mật khẩu phổ biến",
        "password_expiry_days": "Chu kỳ đổi mật khẩu (ngày)",
        "auto_backup_enabled": "Sao lưu tự động",
        "backup_frequency": "Tần suất sao lưu",
        "retention_count": "Số bản sao lưu giữ lại",
        "alert_failed_login": "Cảnh báo đăng nhập thất bại",
        "alert_account_locked": "Cảnh báo tài khoản bị khóa",
        "alert_system_error": "Cảnh báo lỗi hệ thống",
        "alert_stock_discrepancy": "Cảnh báo chênh lệch kho",
        "system_name": "Tên hệ thống",
        "timezone": "Múi giờ hiển thị",
        "date_format": "Định dạng ngày giờ",
        "log_retention_days": "Thời gian lưu trữ nhật ký (ngày)"
    }

    group_names = {
        "security": "Bảo mật & đăng nhập",
        "password": "Chính sách mật khẩu",
        "backup": "Sao lưu & khôi phục",
        "notifications": "Thông báo & cảnh báo",
        "general": "Thông tin hệ thống"
    }

    for k, val in new_values.items():
        if k == "history":
            continue
        old_val = old_group.get(k)
        if old_val != val:
            changes.append({
                "field": field_labels.get(k, k),
                "before": "Bật" if old_val is True else ("Tắt" if old_val is False else str(old_val)),
                "after": "Bật" if val is True else ("Tắt" if val is False else str(val))
            })
        settings[group][k] = val

    save_system_settings(settings)

    if changes:
        add_audit_log(
            category="Cấu hình",
            action=f"Cập nhật cấu hình nhóm {group_names.get(group, group)}",
            target=group.upper(),
            changes=changes,
            result="Thành công"
        )
    if group in ["security", "password"]:
            create_admin_notification(
                group="config",
                severity="important",
                title="Thay đổi chính sách bảo mật",
                message=f"Admin vừa cập nhật cấu hình nhóm {group_names.get(group, group)}.",
                target_url="/admin/settings"
            )
    return jsonify({"success": True, "message": f"Đã lưu cấu hình {group_names.get(group)} thành công!"})

# --- API KHÔI PHỤC MẶC ĐỊNH CHO NHÓM CẤU HÌNH ---
@app.route("/admin/api/settings/reset", methods=["POST"])
@admin_required
def api_reset_settings():
    payload = request.get_json() or {}
    group = payload.get("group")
    if group not in DEFAULT_SYSTEM_SETTINGS:
        return jsonify({"success": False, "message": "Nhóm cấu hình không hợp lệ!"}), 400

    settings = load_system_settings()
    if group == "backup":
        # Giữ lại lịch sử sao lưu hiện có
        history = settings["backup"].get("history", [])
        settings["backup"] = deepcopy(DEFAULT_SYSTEM_SETTINGS["backup"])
        settings["backup"]["history"] = history
    else:
        settings[group] = deepcopy(DEFAULT_SYSTEM_SETTINGS[group])

    save_system_settings(settings)
    add_audit_log(
        category="Cấu hình",
        action=f"Khôi phục cấu hình mặc định nhóm {group.upper()}",
        target=group.upper(),
        result="Thành công"
    )
    return jsonify({"success": True, "message": "Đã khôi phục giá trị mặc định!", "values": settings[group]})

# --- API TẠO BẢN SAO LƯU DỮ LIỆU THỦ CÔNG (.ZIP) ---
@app.route("/admin/api/settings/backup/create", methods=["POST"])
@admin_required
def api_create_backup():
    now = datetime.now()
    bk_id = f"BK-{now.strftime('%Y%m%d-%H%M%S')}"
    filename = f"sanova_backup_{now.strftime('%Y%m%d_%H%M%S')}.zip"
    filepath = os.path.join(BACKUP_DIR, filename)

    files_to_backup = [DATA_FILE, ROLES_JSON_FILE, LOGS_FILE, SETTINGS_FILE]
    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in files_to_backup:
            if os.path.exists(fpath):
                zf.write(fpath, arcname=os.path.basename(fpath))

    size_kb = max(1, round(os.path.getsize(filepath) / 1024, 1))
    record = {
        "id": bk_id,
        "filename": filename,
        "created_at": now.strftime("%d/%m/%Y – %H:%M:%S"),
        "size": f"{size_kb} KB",
        "type": "Thủ công",
        "by": session.get("user", {}).get("name", "Admin")
    }

    settings = load_system_settings()
    settings["backup"]["last_backup_time"] = record["created_at"]
    settings["backup"].setdefault("history", []).insert(0, record)
    save_system_settings(settings)

    add_audit_log(
        category="Cấu hình",
        action="Tạo bản sao lưu dữ liệu thủ công",
        target=filename,
        result="Thành công",
        reason=f"Dung lượng bản sao lưu: {size_kb} KB"
    )
    create_admin_notification(
        group="system",
        severity="info",
        title="Sao lưu dữ liệu thành công",
        message=f"Hệ thống đã hoàn tất sao lưu dữ liệu ({filename}).",
        target_url="/admin/settings"
    )
    return jsonify({"success": True, "message": "Tạo bản sao lưu thành công!", "record": record})

# --- API KHÔI PHỤC DỮ LIỆU TỪ BẢN SAO LƯU ---
@app.route("/admin/api/settings/backup/restore", methods=["POST"])
@admin_required
def api_restore_backup():
    payload = request.get_json() or {}
    filename = os.path.basename(payload.get("filename", ""))
    filepath = os.path.join(BACKUP_DIR, filename)

    if not filename or not os.path.exists(filepath):
        return jsonify({"success": False, "message": "Không tìm thấy tệp sao lưu trên máy chủ!"}), 404

    with zipfile.ZipFile(filepath, "r") as zf:
        zf.extractall(".")

    add_audit_log(
        category="Cấu hình",
        action="Khôi phục dữ liệu hệ thống từ bản sao lưu",
        target=filename,
        result="Thành công",
        reason="Khôi phục toàn bộ cấu hình và dữ liệu quản trị"
    )
    return jsonify({"success": True, "message": f"Đã khôi phục dữ liệu từ {filename}!"})

@app.route("/admin/profile", methods=["POST"])
@admin_required
def update_profile():
    username = session["user"]["username"]
    users = load_users()

    if username not in users:
        abort(404)

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()

    if not name or not email:
        abort(400, description="Thiếu thông tin cá nhân")

    old_name = users[username].get("name")
    old_email = users[username].get("email")

    users[username]["name"] = name
    users[username]["email"] = email
    save_users(users)

    session["user"]["name"] = name
    session["user"]["email"] = email

    add_audit_log(
        "TÀI KHOẢN",
        "Cập nhật hồ sơ cá nhân",
        username,
        changes=[
            {"field": "Họ tên", "before": old_name, "after": name},
            {"field": "Email", "before": old_email, "after": email}
        ]
    )

    return redirect("/admin#profile")

@app.route("/admin/change-password", methods=["POST"])
@admin_required
def change_password():
    username = session["user"]["username"]
    users = load_users()

    if username not in users:
        abort(404)

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not verify_password(users[username].get("password"), current_password):
        abort(400, description="Mật khẩu hiện tại không đúng")

    if new_password != confirm_password:
        abort(400, description="Xác nhận mật khẩu không khớp")

    if not validate_password(new_password):
        abort(400, description="Mật khẩu không đủ độ dài")

    if current_password == new_password:
        abort(400, description="Mật khẩu mới phải khác mật khẩu cũ")

    users[username]["password"] = hash_password(new_password)
    save_users(users)

    add_audit_log("BẢO MẬT", "Đổi mật khẩu cá nhân", username, reason="Người dùng tự đổi mật khẩu")
    return redirect("/admin#profile")
# --- ROUTE HIỂN THỊ TRANG TÀI KHOẢN CÁ NHÂN ---
@app.route("/admin/profile", methods=["GET"])
@admin_required
def admin_profile():
    username = session["user"]["username"]
    users = load_users()
    user_data = deepcopy(users.get(username, {}))
    user_data["username"] = username

    # Đọc chính sách bảo mật hiện hành từ system_settings.json
    sys_cfg = load_system_settings()
    sec_policy = sys_cfg.get("security", {
        "session_timeout": 30,
        "max_failed_logins": 5,
        "lockout_duration": 15
    })
    pwd_policy = sys_cfg.get("password", {
        "min_length": 8,
        "require_uppercase": True,
        "require_number": True,
        "require_special": False
    })

    # Lọc lịch sử đăng nhập & hoạt động của chính tài khoản hiện tại
    all_logs = load_logs()
    actor_name = user_data.get("name", "")
    login_history = []
    personal_logs = []

    for l in all_logs:
        by_str = l.get("by", "")
        target_str = l.get("target", "")
        is_mine = (username in by_str) or (actor_name and actor_name in by_str) or (target_str == username)
        if is_mine:
            personal_logs.append(l)
            if "đăng nhập" in l.get("action", "").lower() or "đăng xuất" in l.get("action", "").lower():
                login_history.append(l)

    current_device = request.headers.get("User-Agent", "Windows · Chrome")[:80]
    current_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")

    return render_template(
        "ADMIN/admin_profile.html",
        current_user=session["user"],
        user_info=user_data,
        sec_policy=sec_policy,
        pwd_policy=pwd_policy,
        login_history=login_history[:15],
        personal_logs=personal_logs[:10],
        current_device=current_device,
        current_ip=current_ip
    )

# --- API CẬP NHẬT HỒ SƠ CÁ NHÂN (CHỈ CHO SỬA HỌ TÊN & EMAIL) ---
@app.route("/admin/api/profile/update", methods=["POST"])
@admin_required
def api_update_profile():
    # Lấy username trực tiếp từ session đã xác thực ở Backend, bỏ qua mọi dữ liệu giả mạo
    username = session["user"]["username"]
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "Không tìm thấy tài khoản trong hệ thống!"}), 404

    payload = request.get_json() or {}
    name = str(payload.get("name", "")).strip()
    raw_email = str(payload.get("email", "")).strip()

    if not name:
        return jsonify({"success": False, "message": "Họ và tên không được để trống!"}), 400

    # Chuẩn hóa email
    if raw_email:
        if "@" in raw_email:
            email = raw_email
        else:
            email = f"{raw_email}@sanova.vn"
    else:
        return jsonify({"success": False, "message": "Email liên hệ không được để trống!"}), 400

    old_name = users[username].get("name", "")
    old_email = users[username].get("email", "")

    changes = []
    if old_name != name:
        changes.append({"field": "Họ và tên", "before": old_name, "after": name})
        users[username]["name"] = name
    if old_email != email:
        changes.append({"field": "Email", "before": old_email, "after": email})
        users[username]["email"] = email

    save_users(users)

    # Đồng bộ vào session hiện tại
    session["user"]["name"] = name
    session["user"]["email"] = email
    session.modified = True

    if changes:
        add_audit_log(
            category="Tài khoản",
            action="Cập nhật thông tin tài khoản cá nhân",
            target=username,
            changes=changes,
            result="Thành công"
        )

    return jsonify({
        "success": True,
        "message": "Đã lưu thay đổi thông tin cá nhân!",
        "name": name,
        "email": email
    })

# --- API ĐỔI MẬT KHẨU CÁ NHÂN (XÁC THỰC MẬT KHẨU CŨ & CHÍNH SÁCH HỆ THỐNG) ---
@app.route("/admin/api/profile/change-password", methods=["POST"])
@admin_required
def api_change_profile_password():
    username = session["user"]["username"]
    users = load_users()
    if username not in users:
        return jsonify({"success": False, "message": "Tài khoản không tồn tại!"}), 404

    payload = request.get_json() or {}
    current_password = payload.get("current_password", "")
    new_password = payload.get("new_password", "")
    confirm_password = payload.get("confirm_password", "")

    # 1. Xác thực mật khẩu hiện tại
    if not verify_password(users[username].get("password"), current_password):
        add_audit_log(
            category="Bảo mật",
            action="Đổi mật khẩu cá nhân thất bại (Sai mật khẩu hiện tại)",
            target=username,
            result="Thất bại",
            reason="Nhập sai mật khẩu hiện tại"
        )
        return jsonify({"success": False, "message": "Mật khẩu hiện tại không chính xác!"}), 400

    if new_password != confirm_password:
        return jsonify({"success": False, "message": "Xác nhận mật khẩu mới không khớp!"}), 400

    if current_password == new_password:
        return jsonify({"success": False, "message": "Mật khẩu mới phải khác mật khẩu hiện tại!"}), 400

    # 2. Kiểm tra tuân thủ cấu hình bảo mật hệ thống
    sys_cfg = load_system_settings()
    pwd_cfg = sys_cfg.get("password", {})
    min_len = pwd_cfg.get("min_length", 8)

    if len(new_password) < min_len:
        return jsonify({"success": False, "message": f"Mật khẩu mới phải có ít nhất {min_len} ký tự theo chính sách hệ thống!"}), 400
    if pwd_cfg.get("require_uppercase") and not any(c.isupper() for c in new_password):
        return jsonify({"success": False, "message": "Mật khẩu mới phải chứa ít nhất 1 chữ cái in hoa (A-Z)!"}), 400
    if pwd_cfg.get("require_number") and not any(c.isdigit() for c in new_password):
        return jsonify({"success": False, "message": "Mật khẩu mới phải chứa ít nhất 1 chữ số (0-9)!"}), 400
    if pwd_cfg.get("require_special") and new_password.isalnum():
        return jsonify({"success": False, "message": "Mật khẩu mới phải chứa ít nhất 1 ký tự đặc biệt!"}), 400

    # 3. Lưu mật khẩu hash & ghi log (tuyệt đối không lưu mật khẩu vào audit log)
    users[username]["password"] = hash_password(new_password)
    save_users(users)

    add_audit_log(
        category="Bảo mật",
        action="Đổi mật khẩu tài khoản cá nhân",
        target=username,
        result="Thành công",
        reason="Người dùng tự đổi mật khẩu định kỳ"
    )

    return jsonify({"success": True, "message": "Đổi mật khẩu thành công!"})

# ==========================================================
# 12. ROUTE QUẢN LÝ KHO (WAREHOUSE MANAGER DASHBOARD & APIS)
# ==========================================================

@app.route("/warehouse/manager")
@warehouse_manager_required
def warehouse_manager_dashboard():
    data = load_warehouse_data()

    inventory = data.get("inventory", [])
    pending_queue = data.get("pending_queue", [])
    ops = data.get("operations_summary", {})

    total_inventory_pcs = sum(item.get("total_system", 0) for item in inventory)
    total_skus = len(inventory)
    total_pending_tickets = len(pending_queue)

    inbound_tickets_count = sum(1 for t in pending_queue if t.get("type") == "Nhập lên kệ")
    adjust_tickets_count = sum(1 for t in pending_queue if t.get("type") == "Điều chỉnh")
    overdue_count = sum(1 for t in pending_queue if t.get("is_overdue"))
    urgent_count = sum(1 for t in pending_queue if t.get("priority") == "Khẩn cấp")
    normal_count = sum(
        1 for t in pending_queue
        if t.get("priority") in ("Cao", "Bình thường") and not t.get("is_overdue")
    )

    selected_ticket_id = request.args.get("ticket_id")
    active_ticket = None

    if selected_ticket_id:
        active_ticket = next((t for t in pending_queue if t["id"] == selected_ticket_id), None)

    if not active_ticket and pending_queue:
        active_ticket = pending_queue[0]

    return render_template(
        "MANAGER/warehouse_manager.html",
        current_user=session["user"],
        inventory=inventory,
        pending_queue=pending_queue,
        active_ticket=active_ticket,
        ops=ops,
        total_inventory_pcs=total_inventory_pcs,
        total_skus=total_skus,
        total_pending_tickets=total_pending_tickets,
        inbound_tickets_count=inbound_tickets_count,
        adjust_tickets_count=adjust_tickets_count,
        overdue_count=overdue_count,
        urgent_count=urgent_count,
        normal_count=normal_count
    )

@app.route("/warehouse/api/review-ticket", methods=["POST"])
@warehouse_manager_required
def review_ticket():
    ticket_id = request.form.get("ticket_id")
    action = request.form.get("action")
    note = request.form.get("note", "").strip()

    reviewer_name = session["user"]["name"]

    data = load_warehouse_data()
    queue = data.get("pending_queue", [])

    ticket = next((t for t in queue if t["id"] == ticket_id), None)

    if not ticket:
        return jsonify({
            "success": False,
            "message": "Phiếu không tồn tại hoặc đã được xử lý!"
        }), 404

    if ticket.get("created_by") == reviewer_name:
        return jsonify({
            "success": False,
            "message": "Quy tắc SoD: Không được tự phê duyệt phiếu do chính mình tạo!"
        }), 400

    now_str = datetime.now().strftime("%d/%m/%Y · %H:%M:%S")

    if action == "APPROVE":
        sku_code = ticket.get("sku")
        inv_item = next((i for i in data.get("inventory", []) if i["sku"] == sku_code), None)

        if not inv_item:
            return jsonify({"success": False, "message": f"Không tìm thấy SKU {sku_code}"}), 400

        diff_pcs = ticket.get("diff_pcs", 0)

        if ticket.get("type") == "Nhập lên kệ":
            source_qty = ticket.get("source_current_qty", inv_item.get("off_shelf_processing", 0))

            if source_qty < diff_pcs:
                return jsonify({"success": False, "message": "Số lượng tồn khu đệm không đủ!"}), 400

            inv_item["on_shelf"] += diff_pcs
            inv_item["off_shelf_processing"] = max(0, inv_item.get("off_shelf_processing", 0) - diff_pcs)

        elif ticket.get("type") == "Điều chỉnh":
            inv_item["on_shelf"] += diff_pcs
            inv_item["total_system"] += diff_pcs

        history_item = {
            "ticket_id": ticket_id,
            "type": ticket.get("type"),
            "sku": sku_code,
            "batch_code": ticket.get("batch_code", "LOT-DEFAULT"),
            "source": ticket.get("source_location", "Khu vực đệm"),
            "target": ticket.get("location", ticket.get("target_location")),
            "diff_pcs": diff_pcs,
            "created_by": ticket.get("created_by"),
            "approved_by": reviewer_name,
            "approved_at": now_str,
            "decision": "Đã phê duyệt điều chuyển lên kệ",
            "note": note or ticket.get("reason")
        }
        data.setdefault("transactions_history", []).insert(0, history_item)
        data["pending_queue"] = [t for t in queue if t["id"] != ticket_id]
        save_warehouse_data(data)

        add_audit_log("VỊ TRÍ KHO", "Phê duyệt phiếu kho", ticket_id)
        return jsonify({
            "success": True,
            "message": f"Đã phê duyệt phiếu {ticket_id}. Đã xử lý {diff_pcs} PCS thành công!"
        })

    elif action == "REQUEST_SUPPLEMENT":
        if not note:
            return jsonify({"success": False, "message": "Vui lòng nhập nội dung bổ sung!"}), 400

        ticket["status"] = "Chờ bổ sung"
        ticket["note_review"] = f"Yêu cầu bổ sung từ {reviewer_name} ({now_str}): {note}"
        save_warehouse_data(data)

        add_audit_log("VỊ TRÍ KHO", "Yêu cầu bổ sung phiếu", ticket_id)
        return jsonify({
            "success": True,
            "message": f"Đã chuyển phiếu {ticket_id} sang trạng thái Chờ bổ sung."
        })

    elif action == "REJECT":
        if not note:
            return jsonify({"success": False, "message": "Bắt buộc nhập lý do từ chối!"}), 400

        history_item = {
            "ticket_id": ticket_id,
            "type": ticket.get("type"),
            "sku": ticket.get("sku"),
            "created_by": ticket.get("created_by"),
            "approved_by": reviewer_name,
            "approved_at": now_str,
            "decision": "Từ chối",
            "note": note
        }
        data.setdefault("transactions_history", []).insert(0, history_item)
        data["pending_queue"] = [t for t in queue if t["id"] != ticket_id]
        save_warehouse_data(data)

        add_audit_log("VỊ TRÍ KHO", "Từ chối phiếu kho", ticket_id, reason=note)
        return jsonify({"success": True, "message": f"Đã từ chối phiếu {ticket_id}."})

    return jsonify({"success": False, "message": "Thao tác không hợp lệ!"}), 400

@app.route("/warehouse/api/closeout-day", methods=["POST"])
@warehouse_manager_required
def closeout_day():
    allow_rollover = (request.form.get("allow_rollover") == "true")

    data = load_warehouse_data()
    queue = data.get("pending_queue", [])
    ops = data.get("operations_summary", {})

    if any(t.get("status") == "Chờ duyệt" for t in queue):
        return jsonify({
            "success": False,
            "message": "Không thể chốt tồn khi còn phiếu điều chỉnh chờ duyệt!"
        }), 400

    if ops.get("discrepancy_orders", 0) > 0:
        return jsonify({
            "success": False,
            "message": "Còn đơn hàng chênh lệch đối soát chưa xử lý!"
        }), 400

    if ops.get("pending_outbound_orders", 0) > 0 and not allow_rollover:
        return jsonify({
            "success": False,
            "message": "Vẫn còn đơn chưa xuất! Vui lòng chọn chuyển sang ca sau."
        }), 400

    add_audit_log("VỊ TRÍ KHO", "Chốt tồn kho cuối ngày", "Kho chính - SANOVA")
    return jsonify({"success": True, "message": "Khóa sổ dữ liệu kho cuối ngày thành công!"})

# ==========================================================
# 13. XỬ LÝ LỖI & API DASHBOARD
# ==========================================================

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        "success": False,
        "message": str(error.description)
    }), 400

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        "success": False,
        "message": "Bạn không có quyền thực hiện thao tác này."
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "message": "Không tìm thấy dữ liệu hoặc đường dẫn."
    }), 404

@app.route("/admin/api/dashboard", methods=["GET"])
@admin_required
def admin_dashboard_api():
    users = load_users()
    logs = load_logs()
    roles = load_roles()
    load_system_settings()

    today = datetime.now().strftime("%Y-%m-%d")

    total_users = len(users)
    active_users = sum(u.get("status") == "Hoạt động" for u in users.values())
    locked_count = sum(u.get("status") == "Tạm khóa" for u in users.values())
    pending_count = sum(u.get("status") == "Chờ kích hoạt" for u in users.values())

    role_counts = {role: 0 for role in roles}
    for user in users.values():
        role = user.get("role")
        if role:
            role_counts[role] = role_counts.get(role, 0) + 1

    today_logs = [log for log in logs if log.get("date") == today]
    today_activity = {"created": 0, "updated": 0, "status": 0, "settings": 0}

    action_map = {
        "Tạo tài khoản": "created",
        "Cập nhật tài khoản": "updated",
        "Thay đổi trạng thái tài khoản": "status",
        "Cập nhật cấu hình hệ thống": "settings"
    }
    for log in today_logs:
        key = action_map.get(log.get("action"))
        if key:
            today_activity[key] += 1
    recent_logs = [
        {
            "date": log.get("date", ""),
            "time": log.get("time", ""),
            "action": log.get("action", ""),
            "by": log.get("by", ""),
            "status": log.get("status", "")
        }
        for log in logs[:6]
    ]
    return jsonify({
        "success": True,
        "total_users": total_users,
        "active_users": active_users,
        "locked_count": locked_count,
        "pending_count": pending_count,
        "role_counts": role_counts,
        "today_activity": today_activity,
        "recent_logs": recent_logs,
        "system_settings": {
            "session_timeout": settings.get("session_timeout", 30),
            "max_login_attempts": settings.get("max_login_attempts", 5),
            "minimum_password_length": settings.get("minimum_password_length", 8)
        },
        "server_time": datetime.now().isoformat()
    })
import threading

NOTIFICATIONS_FILE = str(BASE_DIR / "notifications.json")
_noti_lock = threading.Lock()

def load_notifications():
    if not os.path.exists(NOTIFICATIONS_FILE):
        return []
    try:
        with open(NOTIFICATIONS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_notifications(data):
    with open(NOTIFICATIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def format_relative_time(created_at_str):
    try:
        dt = datetime.strptime(created_at_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        seconds = int((now - dt).total_seconds())
        if seconds < 60:
            return "Vừa xong"
        elif seconds < 3600:
            return f"{seconds // 60} phút trước"
        elif seconds < 86400 and dt.date() == now.date():
            return f"{seconds // 3600} giờ trước"
        elif (now.date() - dt.date()).days == 1:
            return "Hôm qua"
        return dt.strftime("%d/%m/%Y")
    except Exception:
        return created_at_str or "Gần đây"

SEVERITY_LABELS = {
    "critical": "Khẩn cấp / Nghiêm trọng",
    "action_required": "Cần xử lý",
    "important": "Quan trọng",
    "info": "Thông tin hệ thống"
}

def create_admin_notification(
    group, title, message, target_url="/admin", severity="info",
    recipient="ALL_ADMINS", dedup_key="",
    account="", reason="", impact=""
):
    with _noti_lock:
        notis = load_notifications()
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if dedup_key:
            for item in notis:
                if item.get("dedup_key") == dedup_key:
                    if item.get("message") != message:
                        item["message"] = message
                        item["account"] = account or item.get("account", "")
                        item["reason"] = reason or item.get("reason", "")
                        item["impact"] = impact or item.get("impact", "")
                        item["created_at"] = now_str
                        item["read_by"] = []
                        save_notifications(notis)
                    return

        new_noti = {
            "id": f"NOTI-{datetime.now().strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2).upper()}",
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
            "dedup_key": dedup_key
        }
        notis.insert(0, new_noti)
        save_notifications(notis[:200])

def sync_system_notifications():
    """Đồng bộ cảnh báo thực tế & loại bỏ các thông báo đăng nhập/đăng xuất bình thường"""
    # 1. Dọn sạch các thông báo đăng nhập/đăng xuất thông thường nếu từng bị tạo nhầm trước đó
    with _noti_lock:
        existing = load_notifications()
        cleaned = [
            n for n in existing
            if n.get("title") not in ("Đăng nhập hệ thống", "Đăng xuất hệ thống")
        ]
        if len(cleaned) != len(existing):
            save_notifications(cleaned)

    # 2. Đồng bộ cảnh báo tài khoản chờ kích hoạt & tạm khóa từ users.json
    users = load_users()
    pending = [u for u in users.values() if u.get("status") == "Chờ kích hoạt"]
    locked = [u for u in users.values() if u.get("status") == "Tạm khóa"]

    if pending:
        create_admin_notification(
            group="account",
            severity="action_required",
            title="Tài khoản chờ kích hoạt",
            message=f"Có {len(pending)} tài khoản mới đang chờ kích hoạt.",
            account=", ".join([u.get("name", k) for k, u in users.items() if u.get("status") == "Chờ kích hoạt"]),
            reason="Tài khoản vừa được tạo ở trạng thái Chờ kích hoạt.",
            impact="Người dùng chưa thể đăng nhập cho đến khi Admin kích hoạt.",
            target_url="/admin/users?status=Chờ+kích+hoạt",
            dedup_key="sync_pending_accounts"
        )
    if locked:
        create_admin_notification(
            group="account",
            severity="important",
            title="Tài khoản đang tạm khóa",
            message=f"Có {len(locked)} tài khoản đang ở trạng thái tạm khóa.",
            account=", ".join([u.get("name", k) for k, u in users.items() if u.get("status") == "Tạm khóa"]),
            reason="Tài khoản bị khóa thủ công hoặc vượt quá số lần đăng nhập sai.",
            impact="Tài khoản bị chặn truy cập toàn bộ hệ thống.",
            target_url="/admin/users?status=Tạm+khóa",
            dedup_key="sync_locked_accounts"
        )

    # 3. Chỉ lấy các sự kiện QUAN TRỌNG từ audit_logs.json (tuyệt đối bỏ qua đăng nhập/đăng xuất thành công)
    if not load_notifications() and os.path.exists(LOGS_FILE):
        try:
            with open(LOGS_FILE, "r", encoding="utf-8") as f:
                logs = json.load(f)
            important_logs = [
                lg for lg in logs
                if lg.get("action") not in ("Đăng nhập hệ thống", "Đăng xuất hệ thống")
                and (
                    lg.get("result") in ("Thất bại", "Cảnh báo")
                    or any(k in lg.get("action", "").lower() for k in ["thất bại", "khóa", "quyền", "cấu hình", "sao lưu", "khôi phục"])
                )
            ]
            for idx, lg in enumerate(important_logs[:5]):
                cat_raw = str(lg.get("category", "")).lower()
                grp = "security" if "bảo mật" in cat_raw else ("role" if "quyền" in cat_raw else ("config" if "cấu hình" in cat_raw else "system"))
                create_admin_notification(
                    group=grp,
                    severity="important" if lg.get("result") == "Thất bại" else "info",
                    title=lg.get("action", "Cảnh báo hệ thống"),
                    message=f"Đối tượng: {lg.get('target', 'Hệ thống')} · Thực hiện bởi {lg.get('by', 'Admin')}",
                    account=lg.get("target", ""),
                    reason=lg.get("reason", "Ghi nhận từ nhật ký kiểm toán hệ thống"),
                    impact="Cần kiểm tra đối chiếu trong Nhật ký hệ thống.",
                    target_url="/admin/logs",
                    dedup_key=f"init_imp_log_{idx}"
                )
        except Exception:
            pass

@app.route("/admin/api/notifications", methods=["GET"])
def api_get_admin_notifications():
    user = session.get("user")
    if not user or user.get("role") != "Quản trị viên":
        return jsonify({"success": False, "message": "Chưa đăng nhập Admin"}), 403

    sync_system_notifications()
    username = user.get("username", "admin")
    all_notis = load_notifications()

    result = []
    unread_count = 0

    for n in all_notis:
        rec = n.get("recipient", "ALL_ADMINS")
        if rec == "ALL_ADMINS" or rec == username:
            is_read = username in n.get("read_by", [])
            if not is_read:
                unread_count += 1
            result.append({
                "id": n["id"],
                "group": n.get("group", "system"),
                "severity": n.get("severity", "info"),
                "severity_label": n.get("severity_label") or SEVERITY_LABELS.get(n.get("severity", "info"), "Thông tin"),
                "title": n["title"],
                "message": n["message"],
                "account": n.get("account", ""),
                "reason": n.get("reason", ""),
                "impact": n.get("impact", ""),
                "target_url": n.get("target_url", "/admin"),
                "time_ago": format_relative_time(n.get("created_at", "")),
                "created_at": n.get("created_at", ""),
                "is_read": is_read
            })

    return jsonify({
        "success": True,
        "total_count": len(result),
        "unread_count": unread_count,
        "notifications": result[:5]
    })
@app.route("/admin/api/notifications/read/<noti_id>", methods=["POST"])
def api_mark_notification_read(noti_id):
    user = session.get("user")
    if not user or user.get("role") != "Quản trị viên":
        return jsonify({"success": False}), 403

    username = user.get("username", "admin")
    with _noti_lock:
        notis = load_notifications()
        for n in notis:
            if n["id"] == noti_id:
                read_by = n.setdefault("read_by", [])
                if username not in read_by:
                    read_by.append(username)
                break
        save_notifications(notis)
    return jsonify({"success": True})

@app.route("/admin/api/notifications/read-all", methods=["POST"])
def api_mark_all_notifications_read():
    user = session.get("user")
    if not user or user.get("role") != "Quản trị viên":
        return jsonify({"success": False}), 403

    username = user.get("username", "admin")
    with _noti_lock:
        notis = load_notifications()
        for n in notis:
            rec = n.get("recipient", "ALL_ADMINS")
            if rec == "ALL_ADMINS" or rec == username:
                read_by = n.setdefault("read_by", [])
                if username not in read_by:
                    read_by.append(username)
        save_notifications(notis)
    return jsonify({"success": True})

# Route riêng cho nút "Xem tất cả thông báo" (không bao giờ bị 404 hay lỗi)
@app.route("/admin/notifications")
@admin_required
def admin_all_notifications_page():
    sync_system_notifications()
    username = session["user"].get("username", "admin")
    notis = load_notifications()
    for n in notis:
        n["is_read"] = username in n.get("read_by", [])
        n["time_ago"] = format_relative_time(n.get("created_at", ""))
    return render_template("ADMIN/admin_notifications.html", notifications=notis)
# ==========================================================
# 14. KHỞI CHẠY ỨNG DỤNG FLASK
# ==========================================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )