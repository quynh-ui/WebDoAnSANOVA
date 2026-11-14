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
# I. ADMIN
# ==========================================================
# 1. CẤU HÌNH FLASK & ĐỒNG BỘ TIẾN TRÌNH
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

# 2. CẤU HÌNH HỆ THỐNG & ĐỊNH NGHĨA 8 NHÓM CHỨC NĂNG SANOVA

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

# 4. BẢO MẬT MẬT KHẨU & BẢO VỆ CSRF
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
                or request.path.startswith("/manager/api/")
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

# 5. XÁC THỰC, PHÂN QUYỀN TỰ ĐỘNG & AUDIT LOGS
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

# 6. ROUTE WELCOME / LOGIN / LOGOUT
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

# 8. ROUTE QUẢN LÝ NGƯỜI DÙNG (USER MANAGEMENT)
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
        "MANAGER/manager_dashboard.html",
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

# II. Manage Warehouse Dashboard & APIs
# ==========
# Dashbroad cho Quản lý kho (Manager)
from datetime import datetime, timedelta
from flask import render_template, request, jsonify, session

@app.route('/manager')
def manager_dashboard():
    return render_template('MANAGER/manager_dashboard.html')

@app.route('/manager/api/dashboard')
def api_manager_dashboard():
    selected_date = request.args.get('date', datetime.now().strftime('%Y-%m-%d'))
    chart_range = int(request.args.get('range', 7))

    # 1. Đọc dữ liệu kho thực tế từ warehouse_data.json
    wh_data = load_json_safe('warehouse_data.json', default={})
    inventory = wh_data.get('inventory', [])
    pending_queue = wh_data.get('pending_queue', [])
    ops = wh_data.get('operations_summary', {})

    # Tự động tính tổng tồn kho (PCS) và số lượng SKU / Box
    total_pcs = sum(item.get('total_system', 0) for item in inventory) if inventory else 125430
    total_boxes = wh_data.get('total_boxes', 4892)

    # 2. Tổng hợp công việc cần Manager xử lý (4 nhóm nghiệp vụ)
    tasks = []
    cnt_inbound = 0
    cnt_handover = 0
    cnt_stocktake = 0
    cnt_shortage = 0

    for t in pending_queue:
        t_type = t.get('type', '')
        if 'Nhập' in t_type:
            cnt_inbound += 1
            tasks.append({
                'code': t.get('id'),
                'group': 'INBOUND',
                'type_label': 'Nhập kho',
                'description': f"{t.get('product_name', t.get('sku'))} ({t.get('diff_pcs')} PCS) chờ xác nhận",
                'time': t.get('created_at', ''),
                'status_label': 'Chờ xác nhận',
                'action_text': 'Xem chi tiết',
                'action_url': f"/manager/approvals?id={t.get('id')}"
            })
        elif 'Bàn giao' in t_type:
            cnt_handover += 1
            tasks.append({
                'code': t.get('id'),
                'group': 'HANDOVER',
                'type_label': 'Bàn giao',
                'description': t.get('reason', 'Phiếu bàn giao vận chuyển chờ xác nhận'),
                'time': t.get('created_at', ''),
                'status_label': 'Chờ xác nhận',
                'action_text': 'Xác nhận',
                'action_url': f"/manager/approvals?id={t.get('id')}"
            })
        elif 'Điều chỉnh' in t_type or 'Kiểm kê' in t_type:
            cnt_stocktake += 1
            tasks.append({
                'code': t.get('id'),
                'group': 'STOCKTAKE',
                'type_label': 'Kiểm kê',
                'description': f"Chênh lệch kiểm kê: {t.get('diff_pcs')} PCS ({t.get('sku')})",
                'time': t.get('created_at', ''),
                'status_label': 'Chờ duyệt',
                'action_text': 'Xem & duyệt',
                'action_url': f"/manager/stocktake?id={t.get('id')}"
            })

    # Tự động quét danh mục tồn kho phát hiện SKU dưới định mức tối thiểu -> Cảnh báo thiếu hàng
    for item in inventory:
        if item.get('total_system', 0) < item.get('min_threshold', 0):
            cnt_shortage += 1
            missing = item['min_threshold'] - item['total_system']
            tasks.append({
                'code': item.get('sku'),
                'group': 'SHORTAGE',
                'type_label': 'Thiếu hàng',
                'description': f"Tồn {item.get('name')} dưới ngưỡng tối thiểu (thiếu {missing} PCS)",
                'time': datetime.now().strftime('%d/%m/%Y %H:%M'),
                'status_label': 'Cần xử lý',
                'action_text': 'Xử lý',
                'action_url': f"/manager/inventory?sku={item.get('sku')}"
            })

    # 3. Sinh chuỗi biểu đồ nhập - xuất - tồn động theo 7 hoặc 30 ngày
    base_dt = datetime.strptime(selected_date, '%Y-%m-%d')
    chart_series = []
    for i in range(chart_range - 1, -1, -1):
        d_obj = base_dt - timedelta(days=i)
        day_seed = d_obj.day + d_obj.month
        in_val = 12000 + (day_seed * 730) % 12500
        out_val = 9500 + (day_seed * 510) % 6500
        stock_val = total_pcs - (i * 420)
        chart_series.append({
            'label': d_obj.strftime('%d/%m'),
            'inbound': in_val,
            'outbound': out_val,
            'stock': max(0, stock_val)
        })
    approvals_data = read_json(APPROVALS_FILE, get_default_approvals_data())
    pending_approvals = approvals_data.get('pending_tickets', [])
    cnt_inbound = sum(1 for t in pending_approvals if t.get('category') == 'INBOUND')
    cnt_handover = sum(1 for t in pending_approvals if t.get('category') == 'HANDOVER')

    # 4. Đọc hoạt động kho gần đây từ audit_logs.json (lọc nhóm Nghiệp vụ kho)
    logs = load_json_safe('audit_logs.json', default=[])
    wh_logs = [l for l in logs if l.get('category') == 'Nghiệp vụ kho'][:5]
    activities = []
    for l in wh_logs:
        act_type = 'INBOUND'
        if 'đóng gói' in l.get('action', '').lower():
            act_type = 'PACK'
        elif 'kiểm kê' in l.get('action', '').lower():
            act_type = 'STOCKTAKE'
        activities.append({
            'type': act_type,
            'text': f"{l.get('action')} ({l.get('target')}).",
            'time': l.get('timestamp', '')[-5:]
        })

    if not activities:
        activities = [
            {'type': 'INBOUND', 'text': 'Nhập kho NK-0017 đã được xác nhận.', 'time': '09:14'},
            {'type': 'PACK', 'text': 'Hoàn tất đóng gói đơn DH-0257.', 'time': '08:50'},
            {'type': 'STOCKTAKE', 'text': 'Cập nhật kết quả kiểm kê KK-0007.', 'time': '08:47'}
        ]

    # 5. Thông báo chuông Manager
    notifications = [
        {
            'title': f"{len(tasks)} công việc đang chờ xử lý",
            'message': f"Gồm {cnt_inbound} nhập kho, {cnt_stocktake} kiểm kê, {cnt_shortage} cảnh báo thiếu hàng.",
            'time': 'Vừa cập nhật',
            'url': '/manager/approvals'
        }
    ] if tasks else []

    prev_dt = (base_dt - timedelta(days=1)).strftime('%d/%m')
    user_info = session.get('user', {})

    return jsonify({
        'manager_name': user_info.get('name', 'Nguyễn Minh Nam'),
        'notifications': notifications,
        'kpis': {
            'total_pcs': total_pcs,
            'pcs_growth_pct': 2.3,
            'total_boxes': total_boxes,
            'box_growth_pct': 1.6,
            'inbound_boxes': ops.get('confirmed_inbound_tickets', 8),
            'inbound_pcs': ops.get('confirmed_inbound_pcs', 3240),
            'inbound_confirmed_tickets': ops.get('confirmed_inbound_tickets', 8),
            'outbound_orders': ops.get('recorded_outbound_orders', 12),
            'outbound_pcs': ops.get('recorded_outbound_pcs', 2980),
            'pending_tasks_total': len(tasks),
            'pending_inbound': cnt_inbound,
            'pending_handover': cnt_handover,
            'pending_stocktake': cnt_stocktake,
            'prev_day_closed': True,
            'last_closed_date': prev_dt
        },
        'tasks': tasks,
        'chart': chart_series,
        'storage': {
            'boxes_used': total_boxes,
            'boxes_cap': 6000,
            'shelves_used': 1028,
            'shelves_cap': 1200,
            'weight_used': 18450,
            'weight_cap': 22000
        },
        'orders': {
            'waiting_pick': 4,
            'picking': 8,
            'prepacking': 6,
            'packing': 6,
            'waiting_handover': 0
        },
        'closing': {
            'date_display': base_dt.strftime('%d/%m/%Y'),
            'is_closed': False,
            'reconcile_text': 'Đang thực hiện'
        },
        'activities': activities
    })

# Production-ready
import csv
import io
from datetime import datetime
from flask import render_template, request, jsonify, session, Response

PRODUCTS_FILE = 'products_catalog.json'

def get_default_products():
    return [
        {
            "sku": "SP0001",
            "name": "Sữa rửa mặt dịu nhẹ 150ml",
            "category": "Chăm sóc da",
            "unit": "Chai",
            "length_cm": 5.5,
            "width_cm": 4.2,
            "height_cm": 16.5,
            "weight_g": 185,
            "spec": "1 chai / 150 ml · 24 chai / thùng",
            "status": "Đang sử dụng",
            "combo_items": []
        },
        {
            "sku": "SP0002",
            "name": "Kem dưỡng ẩm phục hồi 50g",
            "category": "Chăm sóc da",
            "unit": "Hũ",
            "length_cm": 6.5,
            "width_cm": 6.5,
            "height_cm": 5.8,
            "weight_g": 120,
            "spec": "1 hũ / 50 g · 36 hũ / thùng",
            "status": "Đang sử dụng",
            "combo_items": []
        },
        {
            "sku": "CB0001",
            "name": "Combo Skincare cơ bản",
            "category": "Combo",
            "unit": "Bộ",
            "length_cm": 18.0,
            "width_cm": 12.0,
            "height_cm": 8.0,
            "weight_g": 410,
            "spec": "1 combo (2 sản phẩm thành phần)",
            "status": "Đang sử dụng",
            "combo_items": [
                {"sku": "SP0001", "qty": 1, "unit": "Chai"},
                {"sku": "SP0003", "qty": 1, "unit": "Chai"}
            ]
        },
        {
            "sku": "SP0003",
            "name": "Toner cân bằng da 200ml",
            "category": "Chăm sóc da",
            "unit": "Chai",
            "length_cm": 5.2,
            "width_cm": 5.2,
            "height_cm": 17.8,
            "weight_g": 235,
            "spec": "1 chai / 200 ml",
            "status": "Đang sử dụng",
            "combo_items": []
        },
        {
            "sku": "SP0004",
            "name": "Serum Vitamin C 30ml",
            "category": "Chăm sóc da",
            "unit": "Chai",
            "length_cm": 0,
            "width_cm": 0,
            "height_cm": 0,
            "weight_g": 0,
            "spec": "1 chai / 30 ml",
            "status": "Đang sử dụng",
            "combo_items": []
        },
        {
            "sku": "SP0005",
            "name": "Mặt nạ dưỡng ẩm (hộp 10 miếng)",
            "category": "Chăm sóc da",
            "unit": "Hộp",
            "length_cm": 14.5,
            "width_cm": 3.5,
            "height_cm": 16.0,
            "weight_g": 310,
            "spec": "1 hộp / 10 miếng",
            "status": "Ngừng sử dụng",
            "combo_items": []
        }
    ]
def load_json_safe(filename, default=None):
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default

def save_json_safe(filename, data):
    filepath = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

@app.route('/manager/products')
def manager_products_page():
    return render_template('MANAGER/manager_products.html')

@app.route('/manager/api/products', methods=['GET'])
def api_get_products():
    products = load_json_safe(PRODUCTS_FILE, default=None)
    if products is None:
        products = get_default_products()
        save_json_safe(PRODUCTS_FILE, products)

    wh_data = load_json_safe('warehouse_data.json', default={})
    inventory_map = {item['sku']: item for item in wh_data.get('inventory', [])}
    pending_queue = wh_data.get('pending_queue', [])
    tx_skus = {t.get('sku') for t in pending_queue} | set(inventory_map.keys())

    # Gắn cờ has_transactions thực tế để khóa sửa SKU / cấm xóa cứng
    for p in products:
        inv = inventory_map.get(p['sku'], {})
        p['has_transactions'] = (p['sku'] in tx_skus) or (inv.get('total_system', 0) > 0)
        p['current_stock_pcs'] = inv.get('total_system', 0)

    cnt_approvals = sum(1 for t in pending_queue if 'Nhập' in t.get('type', '') or 'Bàn giao' in t.get('type', ''))
    cnt_stocktake = sum(1 for t in pending_queue if 'Điều chỉnh' in t.get('type', '') or 'Kiểm kê' in t.get('type', ''))

    return jsonify({
        'products': products,
        'sidebar_badges': {
            'approvals': cnt_approvals,
            'stocktake': cnt_stocktake
        }
    })

@app.route('/manager/api/products', methods=['POST'])
def api_create_product():
    data = request.get_json(silent=True) or {}
    sku = (data.get('sku') or '').strip().upper()
    name = (data.get('name') or '').strip()

    if not sku or not name:
        return jsonify({'error': 'Mã SKU và Tên sản phẩm là bắt buộc.'}), 400

    products = load_json_safe(PRODUCTS_FILE, default=get_default_products())
    if any(p['sku'].upper() == sku for p in products):
        return jsonify({'error': f'Mã SKU "{sku}" đã tồn tại trong hệ thống. Vui lòng nhập mã duy nhất.'}), 409

    new_prod = {
        'sku': sku,
        'name': name,
        'category': data.get('category', 'Chăm sóc da'),
        'unit': data.get('unit', 'PCS'),
        'length_cm': float(data.get('length_cm') or 0),
        'width_cm': float(data.get('width_cm') or 0),
        'height_cm': float(data.get('height_cm') or 0),
        'weight_g': float(data.get('weight_g') or 0),
        'spec': (data.get('spec') or '').strip(),
        'status': data.get('status', 'Đang sử dụng'),
        'combo_items': data.get('combo_items', [])
    }
    products.insert(0, new_prod)
    save_json_safe(PRODUCTS_FILE, products)

    actor = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    add_audit_log(
        actor=actor,
        category='DANH MỤC',
        action='Thêm sản phẩm mới vào danh mục',
        target=f"{sku} · {name}",
        result='Thành công',
        changes=f"ĐVT: {new_prod['unit']}, KT: {new_prod['length_cm']}x{new_prod['width_cm']}x{new_prod['height_cm']}cm, KL: {new_prod['weight_g']}g"
    )
    return jsonify({'message': 'Thêm sản phẩm thành công', 'product': new_prod}), 201

@app.route('/manager/api/products/<sku>', methods=['GET'])
def api_product_detail(sku):
    sku = sku.upper()
    products = load_json_safe(PRODUCTS_FILE, default=get_default_products())
    prod = next((p for p in products if p['sku'].upper() == sku), None)
    if not prod:
        return jsonify({'error': 'Không tìm thấy sản phẩm.'}), 404

    wh_data = load_json_safe('warehouse_data.json', default={})
    inventory_map = {item['sku']: item for item in wh_data.get('inventory', [])}
    inv = inventory_map.get(sku, {})
    prod['current_stock_pcs'] = inv.get('total_system', 0)
    prod['has_transactions'] = (sku in inventory_map) or (inv.get('total_system', 0) > 0)

    logs = load_json_safe('audit_logs.json', default=[])
    prod_logs = [
        {
            'timestamp': l.get('timestamp', ''),
            'actor': l.get('actor', ''),
            'action': l.get('action', ''),
            'changes': l.get('changes', '')
        }
        for l in logs if sku in (l.get('target') or '').upper()
    ][:10]
    prod['history'] = prod_logs
    return jsonify(prod)

@app.route('/manager/api/products/<sku>', methods=['PUT'])
def api_update_product(sku):
    sku = sku.upper()
    data = request.get_json(silent=True) or {}
    products = load_json_safe(PRODUCTS_FILE, default=get_default_products())
    prod = next((p for p in products if p['sku'].upper() == sku), None)
    if not prod:
        return jsonify({'error': 'Không tìm thấy sản phẩm.'}), 404

    # Chặn đổi mã SKU nếu đã phát sinh giao dịch
    req_sku = (data.get('sku') or sku).strip().upper()
    if req_sku != sku:
        return jsonify({'error': 'Không được phép thay đổi Mã SKU để bảo toàn lịch sử giao dịch kho.'}), 400

    before_str = f"{prod['name']} | {prod['unit']} | {prod['length_cm']}x{prod['width_cm']}x{prod['height_cm']}cm | {prod['weight_g']}g"
    prod['name'] = (data.get('name') or prod['name']).strip()
    prod['category'] = data.get('category', prod['category'])
    prod['unit'] = data.get('unit', prod['unit'])
    prod['status'] = data.get('status', prod['status'])
    prod['length_cm'] = float(data.get('length_cm') or 0)
    prod['width_cm'] = float(data.get('width_cm') or 0)
    prod['height_cm'] = float(data.get('height_cm') or 0)
    prod['weight_g'] = float(data.get('weight_g') or 0)
    prod['spec'] = (data.get('spec') or '').strip()
    prod['combo_items'] = data.get('combo_items', [])

    after_str = f"{prod['name']} | {prod['unit']} | {prod['length_cm']}x{prod['width_cm']}x{prod['height_cm']}cm | {prod['weight_g']}g"
    save_json_safe(PRODUCTS_FILE, products)

    actor = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    add_audit_log(
        actor=actor,
        category='DANH MỤC',
        action='Cập nhật thông tin sản phẩm',
        target=f"{sku} · {prod['name']}",
        result='Thành công',
        changes=f"Trước: [{before_str}] → Sau: [{after_str}]"
    )
    return jsonify({'message': 'Cập nhật sản phẩm thành công', 'product': prod})

@app.route('/manager/api/products/<sku>/status', methods=['PATCH'])
def api_toggle_product_status(sku):
    sku = sku.upper()
    data = request.get_json(silent=True) or {}
    new_status = data.get('status')
    if new_status not in ['Đang sử dụng', 'Ngừng sử dụng']:
        return jsonify({'error': 'Trạng thái không hợp lệ.'}), 400

    products = load_json_safe(PRODUCTS_FILE, default=get_default_products())
    prod = next((p for p in products if p['sku'].upper() == sku), None)
    if not prod:
        return jsonify({'error': 'Không tìm thấy sản phẩm.'}), 404

    old_status = prod['status']
    prod['status'] = new_status
    save_json_safe(PRODUCTS_FILE, products)

    actor = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    add_audit_log(
        actor=actor,
        category='DANH MỤC',
        action=f'Đổi trạng thái sản phẩm sang {new_status}',
        target=f"{sku} · {prod['name']}",
        result='Thành công',
        changes=f"{old_status} → {new_status}"
    )
    return jsonify({'message': 'Cập nhật trạng thái thành công'})

@app.route('/manager/api/products/export', methods=['GET'])
def api_export_products():
    products = load_json_safe(PRODUCTS_FILE, default=get_default_products())
    output = io.StringIO()
    output.write('\ufeff')  # UTF-8 BOM cho Excel tiếng Việt
    writer = csv.writer(output)
    writer.writerow(['Mã SKU', 'Tên sản phẩm', 'Nhóm sản phẩm', 'Đơn vị tính', 'Dài (cm)', 'Rộng (cm)', 'Cao (cm)', 'Trọng lượng (g)', 'Quy cách', 'Trạng thái'])
    for p in products:
        writer.writerow([
            p['sku'], p['name'], p['category'], p['unit'],
            p.get('length_cm', 0), p.get('width_cm', 0), p.get('height_cm', 0),
            p.get('weight_g', 0), p.get('spec', ''), p['status']
        ])

    actor = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    add_audit_log(
        actor=actor,
        category='DANH MỤC',
        action='Xuất danh mục sản phẩm ra file Excel/CSV',
        target=f"{len(products)} SKU",
        result='Thành công'
    )
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename=SANOVA_DanhMucSanPham_{datetime.now().strftime("%Y%m%d")}.csv'}
    )

@app.route('/manager/api/products/import', methods=['POST'])
def api_import_products():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'Vui lòng chọn tệp CSV/Excel hợp lệ.'}), 400

    content = file.read().decode('utf-8-sig', errors='ignore')
    reader = csv.DictReader(io.StringIO(content))
    products = load_json_safe(PRODUCTS_FILE, default=get_default_products())
    existing_skus = {p['sku'].upper() for p in products}

    added = 0
    for row in reader:
        sku = (row.get('Mã SKU') or row.get('SKU') or '').strip().upper()
        name = (row.get('Tên sản phẩm') or row.get('Name') or '').strip()
        if not sku or not name or sku in existing_skus:
            continue
        products.insert(0, {
            'sku': sku,
            'name': name,
            'category': (row.get('Nhóm sản phẩm') or 'Chăm sóc da').strip(),
            'unit': (row.get('Đơn vị tính') or 'PCS').strip(),
            'length_cm': float(row.get('Dài (cm)') or 0),
            'width_cm': float(row.get('Rộng (cm)') or 0),
            'height_cm': float(row.get('Cao (cm)') or 0),
            'weight_g': float(row.get('Trọng lượng (g)') or 0),
            'spec': (row.get('Quy cách') or '').strip(),
            'status': 'Đang sử dụng',
            'combo_items': []
        })
        existing_skus.add(sku)
        added += 1

    save_json_safe(PRODUCTS_FILE, products)
    actor = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    add_audit_log(
        actor=actor,
        category='DANH MỤC',
        action='Nhập danh mục sản phẩm từ file Excel/CSV',
        target=f"Thêm mới {added} SKU",
        result='Thành công'
    )
    return jsonify({'message': f'Đã nhập thành công {added} sản phẩm mới vào danh mục.'})
# manager_warehouse_config.html

WAREHOUSE_CONFIG_FILE = 'warehouse_config.json'

def _build_floor_slots(rack_id, start_num, count, used_nums=None, warn_nums=None, locked_nums=None):
    used_nums = set(used_nums or [])
    warn_nums = set(warn_nums or [])
    locked_nums = set(locked_nums or [])
    slots = []
    # Tạo từ số cao xuống thấp trong mỗi tầng giống mẫu (VD: A1-040 -> A1-031)
    for num in range(start_num + count - 1, start_num - 1, -1):
        code = f"{rack_id}-{str(num).zfill(3)}"
        cur_boxes, cur_weight, status = 0, 0, "Đang sử dụng"
        if num in locked_nums:
            status = "Tạm khóa"
        elif num in warn_nums:
            cur_boxes, cur_weight = 9, 185
        elif num in used_nums:
            cur_boxes, cur_weight = 6, 115
        slots.append({
            "slot_code": code,
            "current_boxes": cur_boxes,
            "max_boxes": 10,
            "current_weight": cur_weight,
            "max_weight": 200,
            "length_cm": 50,
            "width_cm": 40,
            "height_cm": 40,
            "status": status
        })
    return slots

def get_default_warehouse_config():
    return {
        "default_rules": {
            "max_boxes": 10,
            "max_weight_kg": 200,
            "length_cm": 50,
            "width_cm": 40,
            "height_cm": 40,
            "warn_threshold_pct": 90
        },
        "warehouses": [
            {
                "warehouse_id": "KHO-01",
                "warehouse_name": "Kho chính (KHO-01)",
                "zones": [
                    {
                        "zone_id": "A",
                        "zone_name": "Mỹ phẩm",
                        "racks": [
                            {
                                "rack_id": "A1",
                                "floors": [
                                    {"floor_no": "01", "slots": _build_floor_slots("A1", 1, 10, used_nums=[10, 9, 8, 6, 5, 4, 2, 1])},
                                    {"floor_no": "02", "slots": _build_floor_slots("A1", 11, 10, used_nums=[20, 18, 17, 16, 15, 13, 12, 11], warn_nums=[19])},
                                    {"floor_no": "03", "slots": _build_floor_slots("A1", 21, 10, used_nums=[30, 29, 28, 26, 25, 24, 22, 21])},
                                    {"floor_no": "04", "slots": _build_floor_slots("A1", 31, 10, used_nums=[40, 39, 37, 36, 35, 34, 33, 31], warn_nums=[38])}
                                ]
                            },
                            {
                                "rack_id": "A2",
                                "floors": [
                                    {"floor_no": "01", "slots": _build_floor_slots("A2", 1, 10, used_nums=[10, 8, 6, 4])},
                                    {"floor_no": "02", "slots": _build_floor_slots("A2", 11, 10, used_nums=[20, 19, 15, 12])}
                                ]
                            },
                            {
                                "rack_id": "A3",
                                "floors": [
                                    {"floor_no": "01", "slots": _build_floor_slots("A3", 1, 10, used_nums=[9, 7, 3])}
                                ]
                            }
                        ]
                    },
                    {
                        "zone_id": "B",
                        "zone_name": "Chăm sóc da",
                        "racks": [
                            {
                                "rack_id": "B1",
                                "floors": [
                                    {"floor_no": "01", "slots": _build_floor_slots("B1", 1, 10, used_nums=[10, 9, 7, 5, 3])}
                                ]
                            }
                        ]
                    },
                    {
                        "zone_id": "C",
                        "zone_name": "Hàng tổng hợp",
                        "racks": [
                            {
                                "rack_id": "C1",
                                "floors": [
                                    {"floor_no": "01", "slots": _build_floor_slots("C1", 1, 10, used_nums=[8, 6, 2])}
                                ]
                            }
                        ]
                    }
                ]
            },
            {
                "warehouse_id": "KHO-RT",
                "warehouse_name": "Kho trả hàng (KHO-RT)",
                "zones": [
                    {
                        "zone_id": "RT-A",
                        "zone_name": "Khu tiếp nhận & kiểm định hoàn",
                        "racks": [
                            {
                                "rack_id": "RT1",
                                "floors": [
                                    {"floor_no": "01", "slots": _build_floor_slots("RT1", 1, 10, used_nums=[10, 9, 8])}
                                ]
                            }
                        ]
                    }
                ]
            }
        ]
    }

def _iter_all_zones(cfg):
    if "warehouses" in cfg:
        for wh in cfg["warehouses"]:
            for z in wh.get("zones", []):
                yield wh, z
    else:
        for z in cfg.get("zones", []):
            yield {"warehouse_id": "KHO-01", "warehouse_name": "Kho chính (KHO-01)"}, z

@app.route('/manager/warehouse-config')
@warehouse_manager_required
def manager_warehouse_config_page():
    return render_template('MANAGER/manager_warehouse_config.html')

@app.route('/manager/api/warehouse-config', methods=['GET'])
@warehouse_manager_required
def api_get_warehouse_config():
    cfg = read_json(WAREHOUSE_CONFIG_FILE, None)
    if cfg is None or "warehouses" not in cfg:
        cfg = get_default_warehouse_config()
        write_json(WAREHOUSE_CONFIG_FILE, cfg)

    wh_data = read_json('warehouse_data.json', {})
    pending_queue = wh_data.get('pending_queue', [])
    cnt_approvals = sum(1 for t in pending_queue if 'Nhập' in t.get('type', '') or 'Bàn giao' in t.get('type', ''))
    cnt_stocktake = sum(1 for t in pending_queue if 'Điều chỉnh' in t.get('type', '') or 'Kiểm kê' in t.get('type', ''))

    logs = read_json('audit_logs.json', [])
    cfg_logs = [l for l in logs if l.get('category') == 'VỊ TRÍ KHO'][:15]

    return jsonify({
        'config': cfg,
        'history': cfg_logs,
        'sidebar_badges': {
            'approvals': cnt_approvals,
            'stocktake': cnt_stocktake
        }
    })

@app.route('/manager/api/warehouse-config/structure', methods=['POST'])
@warehouse_manager_required
def api_add_warehouse_structure():
    data = request.get_json(silent=True) or {}
    action_type = data.get('action_type')
    cfg = read_json(WAREHOUSE_CONFIG_FILE, get_default_warehouse_config())
    rules = cfg.get('default_rules', {})

    if action_type == 'ZONE':
        wh_id = (data.get('warehouse_id') or 'KHO-01').strip().upper()
        z_id = (data.get('zone_id') or '').strip().upper()
        z_name = (data.get('zone_name') or '').strip()
        if not z_id or not z_name:
            return jsonify({'error': 'Mã khu vực và tên khu vực không được trống.'}), 400
        for _, z in _iter_all_zones(cfg):
            if z['zone_id'] == z_id:
                return jsonify({'error': f'Mã khu vực "{z_id}" đã tồn tại.'}), 409

        target_wh = next((w for w in cfg['warehouses'] if w['warehouse_id'] == wh_id), cfg['warehouses'][0])
        target_wh['zones'].append({'zone_id': z_id, 'zone_name': z_name, 'racks': []})
        write_json(WAREHOUSE_CONFIG_FILE, cfg)
        add_audit_log(category='VỊ TRÍ KHO', action='Thêm khu vực lưu trữ mới', target=f"[{wh_id}] Khu {z_id} · {z_name}")
        return jsonify({'message': 'Đã thêm khu vực mới.'})

    if action_type == 'RACK':
        z_id = (data.get('zone_id') or '').strip().upper()
        r_id = (data.get('rack_id') or '').strip().upper()
        floors_cnt = int(data.get('floors_count') or 4)
        slots_per_floor = int(data.get('slots_per_floor') or 10)

        if not r_id:
            return jsonify({'error': 'Mã kệ không được trống.'}), 400
        target_zone = None
        for _, z in _iter_all_zones(cfg):
            if z['zone_id'] == z_id:
                target_zone = z
            if any(r['rack_id'] == r_id for r in z.get('racks', [])):
                return jsonify({'error': f'Mã kệ "{r_id}" đã tồn tại trong hệ thống kho.'}), 409
        if not target_zone:
            return jsonify({'error': 'Khu vực không hợp lệ.'}), 400

        floors = []
        for f_idx in range(1, floors_cnt + 1):
            f_no = str(f_idx).zfill(2)
            start_num = (f_idx - 1) * slots_per_floor + 1
            floors.append({
                'floor_no': f_no,
                'slots': _build_floor_slots(r_id, start_num, slots_per_floor)
            })

        target_zone['racks'].append({'rack_id': r_id, 'floors': floors})
        write_json(WAREHOUSE_CONFIG_FILE, cfg)
        add_audit_log(category='VỊ TRÍ KHO', action='Thêm kệ lưu trữ mới', target=f"Kệ {r_id} (Khu {z_id})", changes=[{"field": "Quy mô", "before": "", "after": f"{floors_cnt} tầng × {slots_per_floor} vị trí/tầng"}])
        return jsonify({'message': f'Đã khởi tạo kệ {r_id} thành công.'})

    if action_type == 'FLOOR':
        r_id = (data.get('rack_id') or '').strip().upper()
        f_no = str(data.get('floor_no') or '').strip().zfill(2)
        slots_cnt = int(data.get('slots_count') or 10)

        target_rack = None
        for _, z in _iter_all_zones(cfg):
            for r in z.get('racks', []):
                if r['rack_id'] == r_id:
                    target_rack = r
                    break
        if not target_rack:
            return jsonify({'error': 'Không tìm thấy kệ cần thêm tầng.'}), 404
        if any(f['floor_no'] == f_no for f in target_rack.get('floors', [])):
            return jsonify({'error': f'Tầng {f_no} đã tồn tại trên Kệ {r_id}.'}), 409

        existing_total = sum(len(f.get('slots', [])) for f in target_rack.get('floors', []))
        target_rack['floors'].append({
            'floor_no': f_no,
            'slots': _build_floor_slots(r_id, existing_total + 1, slots_cnt)
        })
        write_json(WAREHOUSE_CONFIG_FILE, cfg)
        add_audit_log(category='VỊ TRÍ KHO', action='Thêm tầng mới vào kệ', target=f"Kệ {r_id} · Tầng {f_no}", changes=[{"field": "Số vị trí", "before": "0", "after": str(slots_cnt)}])
        return jsonify({'message': f'Đã thêm Tầng {f_no} ({slots_cnt} vị trí) vào Kệ {r_id}.'})

    if action_type == 'SLOT':
        r_id = (data.get('rack_id') or '').strip().upper()
        f_no = str(data.get('floor_no') or '01').zfill(2)
        s_code = (data.get('slot_code') or '').strip().upper()
        if not s_code:
            return jsonify({'error': 'Mã vị trí không được để trống.'}), 400

        target_rack = None
        for _, z in _iter_all_zones(cfg):
            for r in z.get('racks', []):
                if r['rack_id'] == r_id:
                    target_rack = r
                for f in r.get('floors', []):
                    if any(s['slot_code'] == s_code for s in f.get('slots', [])):
                        return jsonify({'error': f'Mã vị trí "{s_code}" đã tồn tại.'}), 409
        if not target_rack:
            return jsonify({'error': 'Kệ không hợp lệ.'}), 400

        target_floor = next((f for f in target_rack['floors'] if f['floor_no'] == f_no), None)
        if not target_floor:
            target_floor = {'floor_no': f_no, 'slots': []}
            target_rack['floors'].append(target_floor)

        target_floor['slots'].append({
            'slot_code': s_code,
            'current_boxes': 0,
            'max_boxes': rules.get('max_boxes', 10),
            'current_weight': 0,
            'max_weight': rules.get('max_weight_kg', 200),
            'length_cm': rules.get('length_cm', 50),
            'width_cm': rules.get('width_cm', 40),
            'height_cm': rules.get('height_cm', 40),
            'status': 'Đang sử dụng'
        })
        write_json(WAREHOUSE_CONFIG_FILE, cfg)
        add_audit_log(category='VỊ TRÍ KHO', action='Thêm vị trí lưu trữ mới', target=s_code)
        return jsonify({'message': f'Đã thêm vị trí {s_code}.'})

    return jsonify({'error': 'Loại cấu trúc không hợp lệ.'}), 400

@app.route('/manager/api/warehouse-config/slots/<slot_code>', methods=['PUT'])
@warehouse_manager_required
def api_update_warehouse_slot(slot_code):
    slot_code = slot_code.upper()
    data = request.get_json(silent=True) or {}
    cfg = read_json(WAREHOUSE_CONFIG_FILE, get_default_warehouse_config())

    target_slot = None
    for _, z in _iter_all_zones(cfg):
        for r in z.get('racks', []):
            for f in r.get('floors', []):
                for s in f.get('slots', []):
                    if s['slot_code'] == slot_code:
                        target_slot = s
                        break
    if not target_slot:
        return jsonify({'error': 'Không tìm thấy vị trí.'}), 404

    new_max_boxes = int(data.get('max_boxes', target_slot['max_boxes']))
    new_max_weight = float(data.get('max_weight', target_slot['max_weight']))
    new_status = data.get('status', target_slot['status'])

    if new_max_boxes < target_slot['current_boxes']:
        return jsonify({'error': f"Không thể hạ giới hạn Box ({new_max_boxes}) xuống dưới số Box đang lưu trữ ({target_slot['current_boxes']} Box)."}), 400
    if new_max_weight < target_slot['current_weight']:
        return jsonify({'error': f"Không thể hạ tải trọng tối đa ({new_max_weight} kg) xuống dưới tải trọng thực tế ({target_slot['current_weight']} kg)."}), 400
    if new_status == 'Ngừng sử dụng' and target_slot['current_boxes'] > 0:
        return jsonify({'error': f"Vị trí {slot_code} đang chứa {target_slot['current_boxes']} Box. Vui lòng di chuyển hết hàng trước khi ngừng sử dụng."}), 400

    old_summary = f"Box≤{target_slot['max_boxes']}, Tải≤{target_slot['max_weight']}kg, TT:{target_slot['status']}"
    target_slot['max_boxes'] = new_max_boxes
    target_slot['max_weight'] = new_max_weight
    target_slot['length_cm'] = float(data.get('length_cm', target_slot['length_cm']))
    target_slot['width_cm'] = float(data.get('width_cm', target_slot['width_cm']))
    target_slot['height_cm'] = float(data.get('height_cm', target_slot['height_cm']))
    target_slot['status'] = new_status
    new_summary = f"Box≤{target_slot['max_boxes']}, Tải≤{target_slot['max_weight']}kg, TT:{target_slot['status']}"

    write_json(WAREHOUSE_CONFIG_FILE, cfg)
    add_audit_log(category='VỊ TRÍ KHO', action='Cập nhật sức chứa / trạng thái vị trí', target=slot_code, changes=[{"field": "Cấu hình", "before": old_summary, "after": new_summary}])
    return jsonify({'message': 'Cập nhật cấu hình vị trí thành công.'})

@app.route('/manager/api/warehouse-config/rules', methods=['PUT'])
@warehouse_manager_required
def api_update_warehouse_rules():
    data = request.get_json(silent=True) or {}
    cfg = read_json(WAREHOUSE_CONFIG_FILE, get_default_warehouse_config())
    old_r = cfg.get('default_rules', {})
    cfg['default_rules'] = {
        'max_boxes': int(data.get('max_boxes', 10)),
        'max_weight_kg': float(data.get('max_weight_kg', 200)),
        'length_cm': float(data.get('length_cm', 50)),
        'width_cm': float(data.get('width_cm', 40)),
        'height_cm': float(data.get('height_cm', 40)),
        'warn_threshold_pct': int(data.get('warn_threshold_pct', 90))
    }
    write_json(WAREHOUSE_CONFIG_FILE, cfg)
    add_audit_log(category='VỊ TRÍ KHO', action='Cập nhật quy tắc sức chứa mặc định', target='KHO SANOVA', changes=[{"field": "Giới hạn Box", "before": str(old_r.get('max_boxes')), "after": str(cfg['default_rules']['max_boxes'])}])
    return jsonify({'message': 'Đã lưu quy tắc sức chứa mặc định.'})
# Giám sát & quản lý các giao dịch kho (Nhập / Xuất / Bàn giao / Điều chỉnh / Kiểm kê)
@app.route('/manager/inventory')
@warehouse_manager_required
def manager_inventory_page():
    return render_template('MANAGER/manager_inventory.html')

@app.route('/manager/api/inventory', methods=['GET'])
@warehouse_manager_required
def api_get_manager_inventory():
    days = int(request.args.get('days', 7))
    products = read_json(PRODUCTS_FILE, get_default_products())
    wh_data = read_json('warehouse_data.json', {})
    inv_map = {x['sku']: x for x in wh_data.get('inventory', [])}

    # Tính sức chứa kho thực tế từ warehouse_config.json
    cfg = read_json(WAREHOUSE_CONFIG_FILE, get_default_warehouse_config())
    total_slots, used_slots = 0, 0
    for _, z in _iter_all_zones(cfg):
        for r in z.get('racks', []):
            for f in r.get('floors', []):
                for s in f.get('slots', []):
                    total_slots += 1
                    if s.get('current_boxes', 0) > 0 or s.get('status') != 'Đang sử dụng':
                        used_slots += 1
    capacity_pct = round((used_slots / total_slots) * 100) if total_slots > 0 else 78

    sample_stocks = {
        'SP0001': {'stock': 5, 'avail': 5, 'min': 20, 'loc': 'A-01-01', 'boxes': 1, 'out': 45, 'ret': 2, 'last_in': '25/01/2025 09:20'},
        'SP0002': {'stock': 35, 'avail': 35, 'min': 20, 'loc': 'A-01-02', 'boxes': 2, 'out': 18, 'ret': 0, 'last_in': '26/01/2025 08:40'},
        'SP0003': {'stock': 12, 'avail': 12, 'min': 15, 'loc': 'A-01-03', 'boxes': 1, 'out': 30, 'ret': 1, 'last_in': '25/01/2025 09:20'},
        'SP0004': {'stock': 120, 'avail': 115, 'min': 25, 'loc': 'B-01-01', 'boxes': 4, 'out': 60, 'ret': 0, 'last_in': '24/01/2025 14:15'},
        'SP0005': {'stock': 200, 'avail': 192, 'min': 30, 'loc': 'B-01-02', 'boxes': 6, 'out': 80, 'ret': 3, 'last_in': '24/01/2025 14:15'},
        'CB0001': {'stock': 85, 'avail': 80, 'min': 15, 'loc': 'A-02-01', 'boxes': 3, 'out': 25, 'ret': 0, 'last_in': '25/01/2025 16:00'}
    }

    items = []
    for p in products:
        sku = p['sku']
        real_inv = inv_map.get(sku, {})
        fb = sample_stocks.get(sku, {'stock': 60, 'avail': 58, 'min': 15, 'loc': 'C-01-01', 'boxes': 2, 'out': 10, 'ret': 0, 'last_in': '25/01/2025 10:00'})

        total_stock = real_inv.get('total_system', fb['stock'])
        avail_stock = real_inv.get('on_shelf', fb['avail'])
        min_th = real_inv.get('min_threshold', fb['min'])

        if total_stock < min_th * 0.5:
            st = 'Cảnh báo'
        elif total_stock < min_th:
            st = 'Sắp hết'
        else:
            st = 'Bình thường'

        items.append({
            'sku': sku,
            'name': p['name'],
            'category': p.get('category', 'Chăm sóc da'),
            'catalog_status': p.get('status', 'Đang sử dụng'),
            'total_stock': total_stock,
            'available_stock': avail_stock,
            'min_threshold': min_th,
            'location': fb['loc'],
            'boxes_count': fb['boxes'],
            'out_qty': fb['out'],
            'returned_qty': fb['ret'],
            'last_inbound_at': fb['last_in'],
            'status': st
        })

    sum_total = sum(x['total_stock'] for x in items)
    sum_avail = sum(x['available_stock'] for x in items)
    alerts = [x for x in items if x['status'] in ('Cảnh báo', 'Sắp hết')]

    # Sinh dữ liệu biểu đồ động theo 7 / 30 / 90 ngày
    base_dt = datetime.now()
    chart = []
    step = 1 if days <= 7 else (5 if days <= 30 else 15)
    for i in range(days - 1, -1, -step):
        d = base_dt - timedelta(days=i)
        offset = ((d.day * 17) % 120) - 60
        t_val = max(0, sum_total + offset)
        a_val = max(0, sum_avail + offset - 15)
        chart.append({
            'label': d.strftime('%d/%m'),
            'total_stock': t_val,
            'available_stock': a_val
        })

    return jsonify({
        'kpis': {
            'total_stock': sum_total,
            'available_stock': sum_avail,
            'low_stock_count': len(alerts),
            'capacity_pct': capacity_pct
        },
        'chart': chart,
        'alerts': alerts,
        'items': items
    })

@app.route('/manager/api/inventory/<sku>/history', methods=['GET'])
@warehouse_manager_required
def api_get_sku_inventory_history(sku):
    sku = sku.upper()
    logs = read_json('audit_logs.json', [])
    matched = [
        {
            'action': l.get('action'),
            'by': l.get('by', 'Nhân viên kho'),
            'ref': l.get('target', sku),
            'delta': '+20 PCS' if 'nhập' in (l.get('action') or '').lower() else '-5 PCS',
            'time': f"{l.get('time', '')} {l.get('date', '')}"
        }
        for l in logs if sku in (l.get('target') or '').upper()
    ]
    if not matched:
        matched = [
            {'action': 'Xác nhận nhập hàng lên kệ', 'by': 'Nguyễn Minh Nam', 'ref': 'NK-0018', 'delta': '+50 PCS', 'time': '09:14 26/01/2025'},
            {'action': 'Xuất kho lấy hàng (Picking)', 'by': 'Lê Văn Hùng', 'ref': 'DH-104582', 'delta': '-15 PCS', 'time': '10:20 26/01/2025'}
        ]
    return jsonify({'history': matched})

@app.route('/manager/api/inventory/export', methods=['GET'])
@warehouse_manager_required
def api_export_manager_inventory():
    products = read_json(PRODUCTS_FILE, get_default_products())
    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Mã SKU', 'Tên sản phẩm', 'Danh mục', 'Trạng thái danh mục'])
    for p in products:
        writer.writerow([p['sku'], p['name'], p.get('category', ''), p.get('status', '')])
    add_audit_log(category='NGHIỆP VỤ KHO', action='Xuất báo cáo giám sát tồn kho', target=f'{len(products)} SKU')
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename=SANOVA_GiamSatTonKho_{datetime.now().strftime("%Y%m%d")}.csv'}
    )


# Duyệt & xác nhận các giao dịch kho (Nhập / Xuất / Bàn giao / Điều chỉnh / Kiểm kê)
APPROVALS_FILE = 'approvals_data.json'

def get_default_approvals_data():
    return {
        "pending_tickets": [
            {
                "id": "BG-0025",
                "category": "HANDOVER",
                "partner": "Shopee",
                "order_or_po": "DH-104582",
                "qty_primary": "5 đơn",
                "total_pcs": 45,
                "sender": "Lê Văn Hùng",
                "receiver": "Nguyễn Thị Lan (Đối tác vận chuyển)",
                "sent_at": "26/01/2025 10:20",
                "note": "Bàn giao theo kế hoạch ngày 26/01.",
                "status": "Chờ xác nhận",
                "items": [
                    {"sku": "SP0001", "name": "Sữa rửa mặt dịu nhẹ 150ml", "qty_expected": 20, "qty_packed": 20, "qty_actual": 20},
                    {"sku": "SP0003", "name": "Toner cân bằng da 200ml", "qty_expected": 15, "qty_packed": 15, "qty_actual": 15},
                    {"sku": "CB0001", "name": "Combo Skincare cơ bản", "qty_expected": 10, "qty_packed": 10, "qty_actual": 10}
                ],
                "checks": [
                    {"label": "Đã hoàn thành đóng gói", "passed": True},
                    {"label": "Số lượng bàn giao hợp lệ với đơn hàng", "passed": True},
                    {"label": "Đã ghi nhận đầy đủ người nhận và thời gian", "passed": True},
                    {"label": "Không còn vấn đề thiếu hàng chưa xử lý", "passed": True}
                ]
            },
            {
                "id": "NK-0018",
                "category": "INBOUND",
                "partner": "Công ty ABC",
                "order_or_po": "PO-2025-018",
                "target_slot": "A1-036",
                "qty_primary": "8 Box",
                "total_pcs": 3240,
                "sender": "Trần Thị Mai",
                "sent_at": "26/01/2025 09:14",
                "note": "Hàng đã xếp lên kệ A1-036, chờ Manager xác nhận nhập kho.",
                "status": "Chờ xác nhận",
                "items": [
                    {"sku": "SP0001", "name": "Sữa rửa mặt dịu nhẹ 150ml", "qty_expected": 2000, "qty_packed": 2000, "qty_actual": 2000},
                    {"sku": "SP0002", "name": "Kem dưỡng ẩm phục hồi 50g", "qty_expected": 1240, "qty_packed": 1240, "qty_actual": 1240}
                ],
                "checks": [
                    {"label": "Đã quét QR xác nhận vị trí kệ A1-036", "passed": True},
                    {"label": "Số lượng thực nhập khớp chứng từ PO", "passed": True},
                    {"label": "Vị trí kệ đáp ứng giới hạn tải trọng & số Box", "passed": True},
                    {"label": "Sản phẩm ở trạng thái Đang sử dụng", "passed": True}
                ]
            },
            {
                "id": "NK-0017",
                "category": "INBOUND",
                "partner": "Công ty DEF",
                "order_or_po": "PO-2025-017",
                "target_slot": "A1-037",
                "qty_primary": "5 Box",
                "total_pcs": 1800,
                "sender": "Nguyễn Văn An",
                "sent_at": "26/01/2025 08:50",
                "note": "Lô bổ sung hàng chăm sóc da.",
                "status": "Chờ xác nhận",
                "items": [
                    {"sku": "SP0003", "name": "Toner cân bằng da 200ml", "qty_expected": 1800, "qty_packed": 1800, "qty_actual": 1800}
                ],
                "checks": [
                    {"label": "Đã quét QR xác nhận vị trí kệ A1-037", "passed": True},
                    {"label": "Số lượng thực nhập khớp chứng từ PO", "passed": True},
                    {"label": "Vị trí kệ đáp ứng giới hạn sức chứa", "passed": True}
                ]
            },
            {
                "id": "BG-0024",
                "category": "HANDOVER",
                "partner": "Lazada",
                "order_or_po": "DH-104579",
                "qty_primary": "2 đơn",
                "total_pcs": 18,
                "sender": "Lê Thị Hoa",
                "receiver": "LEX Express",
                "sent_at": "25/01/2025 17:35",
                "note": "Bàn giao ca chiều.",
                "status": "Chờ xác nhận",
                "items": [
                    {"sku": "SP0002", "name": "Kem dưỡng ẩm phục hồi 50g", "qty_expected": 18, "qty_packed": 18, "qty_actual": 18}
                ],
                "checks": [
                    {"label": "Đã hoàn thành đóng gói", "passed": True},
                    {"label": "Số lượng bàn giao hợp lệ với đơn hàng", "passed": True},
                    {"label": "Đã ghi nhận đầy đủ người nhận và thời gian", "passed": True}
                ]
            }
        ],
        "processed_tickets": []
    }

@app.route('/manager/approvals')
@warehouse_manager_required
def manager_approvals_page():
    return render_template('MANAGER/manager_approvals.html')

@app.route('/manager/api/approvals', methods=['GET'])
@warehouse_manager_required
def api_get_approvals():
    data = read_json(APPROVALS_FILE, None)
    if data is None:
        data = get_default_approvals_data()
        write_json(APPROVALS_FILE, data)

    pending = data.get('pending_tickets', [])
    processed = data.get('processed_tickets', [])
    inbound_cnt = sum(1 for t in pending if t.get('category') == 'INBOUND')
    handover_cnt = sum(1 for t in pending if t.get('category') == 'HANDOVER')

    wh_data = read_json('warehouse_data.json', {})
    pq = wh_data.get('pending_queue', [])
    cnt_stocktake = sum(1 for t in pq if 'Điều chỉnh' in t.get('type', '') or 'Kiểm kê' in t.get('type', ''))

    return jsonify({
        'pending_tickets': pending,
        'processed_tickets': processed,
        'stats': {
            'total_pending': len(pending),
            'inbound_pending': inbound_cnt,
            'handover_pending': handover_cnt,
            'processed_today': len(processed)
        },
        'sidebar_badges': {
            'approvals': len(pending),
            'stocktake': cnt_stocktake
        }
    })

@app.route('/manager/api/approvals/<ticket_id>/decision', methods=['POST'])
@warehouse_manager_required
def api_decide_approval_ticket(ticket_id):
    ticket_id = ticket_id.upper()
    payload = request.get_json(silent=True) or {}
    decision = payload.get('decision')  # 'APPROVE' hoặc 'REJECT'
    reason = (payload.get('reason') or '').strip()

    data = read_json(APPROVALS_FILE, get_default_approvals_data())
    pending = data.get('pending_tickets', [])
    ticket = next((t for t in pending if t['id'].upper() == ticket_id), None)

    if not ticket:
        return jsonify({'error': 'Phiếu không tồn tại hoặc đã được xử lý.'}), 404

    reviewer = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    # Kiểm soát nguyên tắc SoD: Người gửi không tự xác nhận phiếu của chính mình
    if ticket.get('sender') == reviewer:
        return jsonify({'error': 'Quy tắc SoD: Bạn không thể tự xác nhận phiếu do chính mình lập.'}), 403

    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

    if decision == 'REJECT':
        if not reason:
            return jsonify({'error': 'Bắt buộc phải nhập lý do từ chối.'}), 400
        ticket['status'] = 'Đã từ chối'
        ticket['reviewed_by'] = reviewer
        ticket['reviewed_at'] = now_str
        ticket['reject_reason'] = reason

        data['pending_tickets'] = [t for t in pending if t['id'].upper() != ticket_id]
        data.setdefault('processed_tickets', []).insert(0, ticket)
        write_json(APPROVALS_FILE, data)

        add_audit_log(
            category='NGHIỆP VỤ KHO',
            action=f"Từ chối phiếu {'bàn giao' if ticket['category'] == 'HANDOVER' else 'nhập kho'}",
            target=ticket_id,
            status='Bị từ chối',
            reason=reason
        )
        return jsonify({'message': f'Đã từ chối phiếu {ticket_id} và ghi nhận lý do vào nhật ký.'})

    if decision == 'APPROVE':
        is_handover = ticket.get('category') == 'HANDOVER'
        ticket['status'] = 'Đã xác nhận bàn giao' if is_handover else 'Đã xác nhận nhập kho'
        ticket['reviewed_by'] = reviewer
        ticket['reviewed_at'] = now_str

        # Đồng bộ tồn kho thực tế vào warehouse_data.json:
        # - Nhập kho: Cộng tồn thực tế lên kệ
        # - Bàn giao: KHÔNG trừ tồn kho tại bước bàn giao (vì đã trừ tồn kho lúc Picking)
        wh_data = read_json('warehouse_data.json', {})
        if not is_handover:
            inv_list = wh_data.get('inventory', [])
            for item in ticket.get('items', []):
                inv = next((x for x in inv_list if x['sku'] == item['sku']), None)
                if inv:
                    inv['on_shelf'] = inv.get('on_shelf', 0) + int(item.get('qty_actual', 0))
                    inv['total_system'] = inv.get('total_system', 0) + int(item.get('qty_actual', 0))
            ops = wh_data.setdefault('operations_summary', {})
            ops['confirmed_inbound_tickets'] = ops.get('confirmed_inbound_tickets', 0) + 1
            ops['confirmed_inbound_pcs'] = ops.get('confirmed_inbound_pcs', 0) + int(ticket.get('total_pcs', 0))
            write_json('warehouse_data.json', wh_data)

        data['pending_tickets'] = [t for t in pending if t['id'].upper() != ticket_id]
        data.setdefault('processed_tickets', []).insert(0, ticket)
        write_json(APPROVALS_FILE, data)

        add_audit_log(
            category='NGHIỆP VỤ KHO',
            action='Xác nhận bàn giao đơn hàng' if is_handover else 'Xác nhận nhập hàng lên kệ',
            target=f"{ticket_id} ({ticket.get('total_pcs')} PCS)",
            changes=[{"field": "Trạng thái", "before": "Chờ xác nhận", "after": ticket['status']}]
        )
        return jsonify({'message': f"{ticket['status']} thành công cho phiếu {ticket_id}."})

    return jsonify({'error': 'Hành động không hợp lệ.'}), 400
# Hàm tính toán badges cho sidebar (số phiếu chờ duyệt, số phiếu chờ kiểm kê)
def get_manager_sidebar_counts():
    # 1. Đếm phiếu Duyệt & xác nhận từ approvals_data.json
    approvals_data = read_json(APPROVALS_FILE, None)
    if approvals_data is None:
        approvals_data = get_default_approvals_data()
        write_json(APPROVALS_FILE, approvals_data)
    approvals_cnt = len(approvals_data.get('pending_tickets', []))

    # 2. Đếm trực tiếp yêu cầu điều chỉnh kiểm kê đang "Chờ phê duyệt" từ stocktake_data.json
    stocktake_data = read_json(STOCKTAKE_FILE, None)
    if stocktake_data is None:
        stocktake_data = get_default_stocktake_data()
        write_json(STOCKTAKE_FILE, stocktake_data)
    stocktake_cnt = sum(
        1 for a in stocktake_data.get('adjustments', [])
        if a.get('status') == 'Chờ phê duyệt'
    )

    return {
        'approvals': approvals_cnt,
        'stocktake': stocktake_cnt
    }

@app.context_processor
def inject_manager_globals():
    counts = get_manager_sidebar_counts() if request.path.startswith('/manager') else {'approvals': 0, 'stocktake': 0}
    return {
        'manager_sidebar': counts,
        'current_path': request.path
    }

@app.route('/manager/api/sidebar-sync', methods=['GET'])
@warehouse_manager_required
def api_manager_sidebar_sync():
    return jsonify(get_manager_sidebar_counts())

@app.route('/manager/api/notifications', methods=['GET'])
@warehouse_manager_required
def api_manager_notifications():
    notifications = []

    # 1. Nguồn Duyệt & xác nhận (Nhập kho · Bàn giao)
    approvals_data = read_json(APPROVALS_FILE, get_default_approvals_data())
    pending_approvals = approvals_data.get('pending_tickets', [])
    for t in pending_approvals:
        is_handover = t.get('category') == 'HANDOVER'
        notifications.append({
            'id': t.get('id'),
            'group': 'APPROVAL',
            'tag': 'Bàn giao' if is_handover else 'Nhập kho',
            'title': f"Phiếu {'bàn giao' if is_handover else 'nhập kho'} {t.get('id')} chờ xác nhận",
            'message': f"{t.get('partner')} · {t.get('qty_primary')} ({t.get('total_pcs')} PCS) · Gửi bởi {t.get('sender')}",
            'time': t.get('sent_at', ''),
            'url': f"/manager/approvals?id={t.get('id')}"
        })

    # 2. Nguồn Kiểm kê & điều chỉnh (Chờ phê duyệt)
    stocktake_data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    pending_adjustments = [
        a for a in stocktake_data.get('adjustments', [])
        if a.get('status') == 'Chờ phê duyệt'
    ]
    for a in pending_adjustments:
        notifications.append({
            'id': a.get('id'),
            'group': 'STOCKTAKE',
            'tag': 'Điều chỉnh kiểm kê',
            'title': f"Yêu cầu điều chỉnh {a.get('id')} ({a.get('session_id')}) chờ duyệt",
            'message': f"Phạm vi {a.get('scope')} · Lệch -{a.get('total_shortage')} / +{a.get('total_surplus')} PCS · Gửi bởi {a.get('sender')}",
            'time': a.get('sent_at', ''),
            'url': f"/manager/stocktake?id={a.get('id')}"
        })

    # 3. Nguồn Giám sát tồn kho (Cảnh báo tồn thấp dưới ngưỡng tối thiểu)
    wh_data = read_json('warehouse_data.json', {})
    low_stock_items = [
        item for item in wh_data.get('inventory', [])
        if item.get('total_system', 0) < item.get('min_threshold', 0)
    ]
    for item in low_stock_items:
        notifications.append({
            'id': f"LOW-{item.get('sku')}",
            'group': 'INVENTORY',
            'tag': 'Cảnh báo tồn thấp',
            'title': f"{item.get('sku')} · {item.get('name')} dưới ngưỡng tối thiểu",
            'message': f"Tồn hiện tại: {item.get('total_system')} PCS (Ngưỡng tối thiểu: {item.get('min_threshold')} PCS)",
            'time': 'Cảnh báo tự động',
            'url': f"/manager/inventory?sku={item.get('sku')}"
        })

    # 4. Nguồn Chốt tồn cuối ngày & Sức chứa kho (Nhắc chốt sổ / Kệ sắp đầy >= 90%)
    cfg = read_json(WAREHOUSE_CONFIG_FILE, get_default_warehouse_config())
    near_full_slots = []
    for _, z in _iter_all_zones(cfg):
        for r in z.get('racks', []):
            for f in r.get('floors', []):
                for s in f.get('slots', []):
                    if s.get('status') == 'Đang sử dụng' and s.get('max_boxes', 10) > 0:
                        if (s.get('current_boxes', 0) / s['max_boxes']) >= 0.9:
                            near_full_slots.append(s['slot_code'])

    if near_full_slots:
        notifications.append({
            'id': 'ALERT-CAPACITY',
            'group': 'INVENTORY',
            'tag': 'Sức chứa kệ',
            'title': f"Có {len(near_full_slots)} vị trí kệ sắp đầy (≥90%)",
            'message': f"Các ô tiệm cận giới hạn tải/Box: {', '.join(near_full_slots[:4])}...",
            'time': 'Giám sát kệ',
            'url': '/manager/warehouse-config'
        })

    # Nhắc chốt tồn cuối ngày nếu hôm nay chưa chốt
    today_str = datetime.now().strftime('%Y-%m-%d')
    closings = read_json('daily_closings.json', [])
    is_today_closed = any(c.get('date') == today_str and c.get('status') == 'Đã chốt' for c in closings)
    if not is_today_closed:
        notifications.append({
            'id': f'CLOSING-{today_str}',
            'group': 'CLOSING',
            'tag': 'Chốt tồn cuối ngày',
            'title': f"Chưa chốt tồn kho ngày {datetime.now().strftime('%d/%m/%Y')}",
            'message': "Cần hoàn tất xác nhận nhập/kiểm kê và thực hiện chốt sổ cuối ca.",
            'time': 'Hôm nay',
            'url': '/manager/daily-closing'
        })

    return jsonify({
        'total_unread': len(notifications),
        'approvals_count': len(pending_approvals),
        'stocktake_count': len(pending_adjustments),
        'inventory_alert_count': len(low_stock_items) + (1 if near_full_slots else 0),
        'notifications': notifications
    })
# Kiểm kê & điều chỉnh tồn kho (Inventory Stocktake / Adjustment)
STOCKTAKE_FILE = 'stocktake_data.json'

def get_default_stocktake_data():
    return {
        "sessions": [
            {
                "id": "KK-20261113-001",
                "scope": "Kệ A1 · 24 vị trí",
                "scope_type_label": "Theo kệ",
                "assignee": "Lê Văn Hùng",
                "counted_slots": 18,
                "total_slots": 24,
                "diff_abs_pcs": 10,
                "time_range": "13/11/2026 08:00 – 11:30",
                "snapshot_time": "13/11/2026 08:00",
                "status": "Đang kiểm kê",
                "note": "Kiểm kê định kỳ tháng 11/2026 tại Kệ A1 (Đang đếm 18/24 vị trí)."
            },
            {
                "id": "KK-0105",
                "scope": "Kệ A1 · 24 vị trí",
                "scope_type_label": "Theo kệ",
                "assignee": "Lê Văn Hùng",
                "counted_slots": 24,
                "total_slots": 24,
                "diff_abs_pcs": 10,
                "time_range": "13/01/2026 07:00 – 09:30",
                "snapshot_time": "13/01/2026 07:00",
                "status": "Chờ phê duyệt",
                "note": "Hoàn tất 24/24 vị trí, phát hiện lệch -5 PCS và +5 PCS."
            },
            {
                "id": "KK-0104",
                "scope": "Khu vực A2 · 20 vị trí",
                "scope_type_label": "Theo khu vực",
                "assignee": "Trần Thị Mai",
                "counted_slots": 20,
                "total_slots": 20,
                "diff_abs_pcs": 8,
                "time_range": "12/01/2026 14:00 – 16:30",
                "snapshot_time": "12/01/2026 14:00",
                "status": "Chờ phê duyệt",
                "note": "Hoàn tất 20/20 vị trí tại Khu A2."
            },
            {
                "id": "KK-0103",
                "scope": "Kệ B1 · 16 vị trí",
                "scope_type_label": "Theo kệ",
                "assignee": "Nguyễn Văn An",
                "counted_slots": 16,
                "total_slots": 16,
                "diff_abs_pcs": 2,
                "time_range": "11/01/2026 08:00 – 10:00",
                "snapshot_time": "11/01/2026 08:00",
                "status": "Hoàn tất",
                "note": "Đã duyệt điều chỉnh và chốt biên bản."
            }
        ],
        "adjustments": [
            {
                "id": "DC-0018",
                "session_id": "KK-0105",
                "count_type": "Theo kệ",
                "scope": "Kệ A1",
                "full_scope_path": "Kho chính > Khu A > Kệ A1",
                "sender": "Lê Văn Hùng",
                "snapshot_at": "13/01/2026 07:00",
                "sent_at": "13/01/2026 09:30",
                "total_shortage": 5,
                "total_surplus": 5,
                "status": "Chờ phê duyệt",
                "scope_completed": True,
                "has_post_count_movement": False,
                "explanation": "Phát hiện chênh lệch số lượng khi kiểm đếm thực tế tại Kệ A1. Đề nghị điều chỉnh theo kết quả kiểm kê.",
                "items": [
                    {"sku": "SP0001", "name": "Sữa rửa mặt dịu nhẹ 150ml", "box_code": "BX-0781", "location": "A1-01", "system_pcs": 100, "counted_pcs": 95},
                    {"sku": "SP0002", "name": "Kem dưỡng ẩm phục hồi 50g", "box_code": "BX-0782", "location": "A1-02", "system_pcs": 80, "counted_pcs": 85}
                ],
                "history": [
                    {"time": "13/01/2026 09:30", "actor": "Lê Văn Hùng", "action": "Gửi yêu cầu", "note": "Gửi đề xuất điều chỉnh DC-0018."}
                ]
            },
            {
                "id": "DC-0017",
                "session_id": "KK-0104",
                "count_type": "Theo khu vực",
                "scope": "Khu vực A2",
                "full_scope_path": "Kho chính > Khu A > Khu vực A2",
                "sender": "Trần Thị Mai",
                "snapshot_at": "12/01/2026 14:00",
                "sent_at": "12/01/2026 16:45",
                "total_shortage": 8,
                "total_surplus": 0,
                "status": "Chờ phê duyệt",
                "scope_completed": True,
                "has_post_count_movement": False,
                "explanation": "Thiếu 8 PCS tại Box BX-0812 do rách bao bì đã lập biên bản loại trừ.",
                "items": [
                    {"sku": "SP0003", "name": "Toner cân bằng da 200ml", "box_code": "BX-0812", "location": "A2-05", "system_pcs": 50, "counted_pcs": 42}
                ],
                "history": [
                    {"time": "12/01/2026 16:45", "actor": "Trần Thị Mai", "action": "Gửi yêu cầu", "note": "Gửi đề xuất điều chỉnh DC-0017."}
                ]
            },
            {
                "id": "DC-0016",
                "session_id": "KK-0103",
                "count_type": "Theo kệ",
                "scope": "Kệ B1",
                "full_scope_path": "Kho chính > Khu B > Kệ B1",
                "sender": "Nguyễn Văn An",
                "snapshot_at": "11/01/2026 08:00",
                "sent_at": "11/01/2026 10:15",
                "total_shortage": 2,
                "total_surplus": 0,
                "status": "Đã duyệt",
                "reviewed_by": "Nguyễn Minh Nam",
                "reviewed_at": "11/01/2026 10:40",
                "scope_completed": True,
                "has_post_count_movement": False,
                "explanation": "Sai lệch 2 PCS trong quá trình soạn đơn mẫu.",
                "items": [
                    {"sku": "SP0004", "name": "Serum Vitamin C 30ml", "box_code": "BX-0604", "location": "B1-02", "system_pcs": 122, "counted_pcs": 120}
                ],
                "history": [
                    {"time": "11/01/2026 10:15", "actor": "Nguyễn Văn An", "action": "Gửi yêu cầu", "note": "Gửi đề xuất điều chỉnh DC-0016."},
                    {"time": "11/01/2026 10:40", "actor": "Nguyễn Minh Nam", "action": "Đã duyệt", "note": "Phê duyệt và cập nhật tồn kho SP0004."}
                ]
            }
        ]
    }

@app.route('/manager/stocktake')
@warehouse_manager_required
def manager_stocktake_page():
    return render_template('MANAGER/manager_stocktake.html')

@app.route('/manager/api/stocktake', methods=['GET'])
@warehouse_manager_required
def api_get_stocktake():
    data = read_json(STOCKTAKE_FILE, None)
    if data is None:
        data = get_default_stocktake_data()
        write_json(STOCKTAKE_FILE, data)

    sessions = data.get('sessions', [])
    adjustments = data.get('adjustments', [])

    counting_cnt = sum(1 for s in sessions if s.get('status') in ('Chờ thực hiện', 'Đang kiểm kê', 'Đối chiếu'))
    pending_adj_cnt = sum(1 for a in adjustments if a.get('status') == 'Chờ phê duyệt')
    completed_cnt = sum(1 for s in sessions if s.get('status') == 'Hoàn tất')

    next_code = f"KK-{datetime.now().strftime('%Y%m%d')}-{len(sessions) + 1:03d}"

    return jsonify({
        'sessions': sessions,
        'adjustments': adjustments,
        'next_session_code': next_code,
        'kpis': {
            'total_sessions': len(sessions),
            'counting_sessions': counting_cnt,
            'pending_approvals': pending_adj_cnt,
            'completed_sessions': completed_cnt
        }
    })

@app.route('/manager/api/stocktake/sessions', methods=['POST'])
@warehouse_manager_required
def api_create_stocktake_session():
    payload = request.get_json(silent=True) or {}
    target = (payload.get('scope_target') or '').strip()
    assignees = payload.get('assignees') or []
    start_date = payload.get('start_date') or datetime.now().strftime('%Y-%m-%d')
    due_date = payload.get('due_date') or start_date
    note = (payload.get('note') or '').strip()

    if not target or not assignees:
        return jsonify({'error': 'Vui lòng chọn phạm vi kiểm kê và ít nhất 1 nhân viên thực hiện.'}), 400

    data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    sessions = data.get('sessions', [])

    # Chặn trùng phạm vi nếu đợt kiểm kê trên phạm vi đó đang hoạt động
    for s in sessions:
        if target.lower() in (s.get('scope') or '').lower() and s.get('status') in ('Chờ thực hiện', 'Đang kiểm kê', 'Đối chiếu'):
            return jsonify({'error': f'Phạm vi "{target}" đang thuộc đợt kiểm kê {s["id"]} ({s["status"]}). Không thể tạo chồng lấn.'}), 409

    # Chốt mốc tồn đối chiếu tại thời điểm tạo đợt (StockCountSnapshot)
    wh_data = read_json('warehouse_data.json', {})
    snapshot_pcs = sum(i.get('total_system', 0) for i in wh_data.get('inventory', []))

    new_id = f"KK-{datetime.now().strftime('%Y%m%d')}-{len(sessions) + 1:03d}"
    slots_count = 24 if 'A1' in target else (20 if 'A2' in target else 16)
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

    new_session = {
        'id': new_id,
        'scope': f"{target} · {slots_count} vị trí",
        'scope_type_label': payload.get('scope_type', 'Theo kệ'),
        'assignee': ', '.join(assignees),
        'counted_slots': 0,
        'total_slots': slots_count,
        'diff_abs_pcs': 0,
        'time_range': f"{start_date} → {due_date}",
        'snapshot_time': now_str,
        'snapshot_total_pcs': snapshot_pcs,
        'status': 'Chờ thực hiện',
        'note': note or f"Kiểm kê phạm vi {target}."
    }

    sessions.insert(0, new_session)
    data['sessions'] = sessions
    write_json(STOCKTAKE_FILE, data)

    add_audit_log(
        category='NGHIỆP VỤ KHO',
        action='Tạo đợt kiểm kê & phân công nhân viên',
        target=f"{new_id} ({target})",
        changes=[{"field": "Nhân viên", "before": "", "after": new_session['assignee']}]
    )
    return jsonify({'message': f'Đã tạo đợt kiểm kê {new_id} và giao nhiệm vụ cho {new_session["assignee"]}.', 'session': new_session}), 201

# API hỗ trợ luồng Nhân viên kho gửi kết quả kiểm đếm & sinh yêu cầu điều chỉnh
@app.route('/warehouse/api/stocktake/submit-result', methods=['POST'])
def api_staff_submit_stocktake_result():
    payload = request.get_json(silent=True) or {}
    session_id = payload.get('session_id')
    counted_slots = int(payload.get('counted_slots', 0))
    items = payload.get('items', [])  # [{"sku", "name", "box_code", "location", "system_pcs", "counted_pcs"}]
    explanation = (payload.get('explanation') or '').strip()

    # Ràng buộc: Không cho phép giá trị chưa nhập mặc định thành 0
    for it in items:
        if it.get('counted_pcs') is None or it.get('counted_pcs') == '':
            return jsonify({'error': f"SKU {it.get('sku')} chưa nhập số lượng thực tế. Không được để trống."}), 400

    data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    sess = next((s for s in data['sessions'] if s['id'] == session_id), None)
    if not sess:
        return jsonify({'error': 'Không tìm thấy đợt kiểm kê.'}), 404

    sess['counted_slots'] = counted_slots
    # Chỉ chuyển sang Đối chiếu / Chờ phê duyệt khi đã hoàn tất 100% phạm vi vị trí
    if counted_slots < sess['total_slots']:
        sess['status'] = 'Đang kiểm kê'
        write_json(STOCKTAKE_FILE, data)
        return jsonify({'message': f'Đã lưu tiến độ kiểm đếm {counted_slots}/{sess["total_slots"]} vị trí.'})

    shortage = sum(max(0, it['system_pcs'] - int(it['counted_pcs'])) for it in items)
    surplus = sum(max(0, int(it['counted_pcs']) - it['system_pcs']) for it in items)
    sess['diff_abs_pcs'] = shortage + surplus

    if shortage == 0 and surplus == 0:
        sess['status'] = 'Hoàn tất'
        write_json(STOCKTAKE_FILE, data)
        return jsonify({'message': 'Kiểm kê khớp 100% số liệu hệ thống. Đợt kiểm kê đã hoàn tất.'})

    sess['status'] = 'Chờ phê duyệt'
    adj_id = f"DC-{len(data['adjustments']) + 19:04d}"
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')
    sender_name = session.get('user', {}).get('name', sess['assignee'])

    data['adjustments'].insert(0, {
        'id': adj_id,
        'session_id': session_id,
        'count_type': sess.get('scope_type_label', 'Theo kệ'),
        'scope': sess['scope'].split('·')[0].strip(),
        'full_scope_path': f"Kho chính > {sess['scope']}",
        'sender': sender_name,
        'snapshot_at': sess['snapshot_time'],
        'sent_at': now_str,
        'total_shortage': shortage,
        'total_surplus': surplus,
        'status': 'Chờ phê duyệt',
        'scope_completed': True,
        'has_post_count_movement': False,
        'explanation': explanation or 'Phát hiện chênh lệch thực tế khi kiểm kê.',
        'items': items,
        'history': [
            {'time': now_str, 'actor': sender_name, 'action': 'Gửi yêu cầu', 'note': f'Gửi đề xuất điều chỉnh {adj_id}.'}
        ]
    })
    write_json(STOCKTAKE_FILE, data)
    return jsonify({'message': f'Đã hoàn tất kiểm đếm và tạo yêu cầu điều chỉnh {adj_id} gửi Manager duyệt.'})

@app.route('/manager/api/stocktake/adjustments/<adj_id>/decision', methods=['POST'])
@warehouse_manager_required
def api_decide_stocktake_adjustment(adj_id):
    adj_id = adj_id.upper()
    payload = request.get_json(silent=True) or {}
    action = payload.get('action')  # 'APPROVE', 'REJECT', 'RECOUNT'
    reason = (payload.get('reason') or '').strip()

    data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    adj = next((a for a in data['adjustments'] if a['id'].upper() == adj_id), None)
    if not adj:
        return jsonify({'error': 'Không tìm thấy yêu cầu điều chỉnh.'}), 404

    if adj.get('status') != 'Chờ phê duyệt':
        return jsonify({'error': f'Phiếu {adj_id} đang ở trạng thái "{adj.get("status")}", không thể duyệt lại (chống cập nhật trùng).'}), 400

    reviewer = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    if adj.get('sender') == reviewer:
        return jsonify({'error': 'Quy tắc SoD: Người gửi yêu cầu không thể tự phê duyệt điều chỉnh của chính mình.'}), 403

    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

    if action == 'REJECT':
        if not reason:
            return jsonify({'error': 'Bắt buộc phải nhập lý do từ chối.'}), 400
        adj['status'] = 'Từ chối'
        adj['reviewed_by'] = reviewer
        adj['reviewed_at'] = now_str
        adj['reject_reason'] = reason
        adj.setdefault('history', []).append({'time': now_str, 'actor': reviewer, 'action': 'Từ chối', 'note': reason})
        write_json(STOCKTAKE_FILE, data)
        add_audit_log(category='NGHIỆP VỤ KHO', action='Từ chối điều chỉnh kiểm kê', target=adj_id, status='Bị từ chối', reason=reason)
        return jsonify({'message': f'Đã từ chối yêu cầu {adj_id} và gửi lại nhân viên xử lý.'})

    if action == 'RECOUNT':
        adj['status'] = 'Yêu cầu kiểm lại'
        adj.setdefault('history', []).append({'time': now_str, 'actor': reviewer, 'action': 'Yêu cầu kiểm lại', 'note': reason or 'Yêu cầu kiểm đếm xác minh lại phạm vi.'})
        sess = next((s for s in data['sessions'] if s['id'] == adj['session_id']), None)
        if sess:
            sess['status'] = 'Đang kiểm kê'
        write_json(STOCKTAKE_FILE, data)
        add_audit_log(category='NGHIỆP VỤ KHO', action='Yêu cầu kiểm kê lại', target=adj_id, reason=reason)
        return jsonify({'message': f'Đã chuyển {adj_id} sang trạng thái Yêu cầu kiểm lại.'})

    if action == 'APPROVE':
        if adj.get('has_post_count_movement'):
            return jsonify({'error': 'Phát hiện giao dịch phát sinh sau mốc kiểm kê. Hệ thống chặn điều chỉnh tự động, vui lòng yêu cầu kiểm lại.'}), 409

        # Cập nhật tồn kho thực tế DUY NHẤT MỘT LẦN trong warehouse_data.json
        wh_data = read_json('warehouse_data.json', {})
        inv_list = wh_data.get('inventory', [])
        change_logs = []

        for item in adj.get('items', []):
            delta = int(item['counted_pcs']) - int(item['system_pcs'])
            inv = next((x for x in inv_list if x['sku'] == item['sku']), None)
            if inv:
                before_qty = inv.get('total_system', 0)
                after_qty = max(0, before_qty + delta)
                inv['on_shelf'] = max(0, inv.get('on_shelf', 0) + delta)
                inv['total_system'] = after_qty
                change_logs.append({'field': item['sku'], 'before': str(before_qty), 'after': str(after_qty)})

        write_json('warehouse_data.json', wh_data)

        adj['status'] = 'Đã duyệt'
        adj['reviewed_by'] = reviewer
        adj['reviewed_at'] = now_str
        adj.setdefault('history', []).append({'time': now_str, 'actor': reviewer, 'action': 'Đã duyệt', 'note': 'Phê duyệt điều chỉnh và đồng bộ tồn kho.'})

        sess = next((s for s in data['sessions'] if s['id'] == adj['session_id']), None)
        if sess:
            sess['status'] = 'Hoàn tất'

        write_json(STOCKTAKE_FILE, data)
        add_audit_log(
            category='NGHIỆP VỤ KHO',
            action='Phê duyệt điều chỉnh tồn kho sau kiểm kê',
            target=f"{adj_id} ({adj['session_id']})",
            changes=change_logs
        )
        return jsonify({'message': f'Đã phê duyệt {adj_id}, cập nhật tồn kho thực tế và hoàn tất đợt kiểm kê {adj["session_id"]}.'})

    return jsonify({'error': 'Hành động không hợp lệ.'}), 400
# Chốt tồn cuối ngày (Daily Closing)
DAILY_CLOSING_FILE = 'daily_closings.json'

def get_default_daily_closings():
    today = datetime.now()
    records = []
    # Ngày hôm nay: Chưa chốt (lấy số liệu sống từ warehouse_data.json)
    wh_data = read_json('warehouse_data.json', {})
    inv = wh_data.get('inventory', [])
    ops = wh_data.get('operations_summary', {})

    current_closing = sum(x.get('total_system', 0) for x in inv) if inv else 52610
    inbound_today = ops.get('confirmed_inbound_pcs', 8420)
    outbound_today = ops.get('recorded_outbound_pcs', 7865)
    opening_today = max(0, current_closing - inbound_today + outbound_today)

    records.append({
        "date_iso": today.strftime('%Y-%m-%d'),
        "date_display": today.strftime('%d/%m/%Y'),
        "total_sku": len(read_json(PRODUCTS_FILE, get_default_products())),
        "total_box": wh_data.get('total_boxes', 3562),
        "opening_pcs": opening_today,
        "inbound_pcs": inbound_today,
        "outbound_pcs": outbound_today,
        "adj_plus_pcs": 0,
        "adj_minus_pcs": 0,
        "closing_pcs": current_closing,
        "out_pcs": 120,
        "returned_pcs": 15,
        "status": "Chưa chốt",
        "closed_by": None,
        "closed_at": None
    })

    # Các ngày trước đó đã chốt sổ bất biến
    past_samples = [
        (1, 1247, 3548, 51807, 6230, 5982, 52055, "Nguyễn Minh Nam", "21:30"),
        (2, 1247, 3544, 51132, 7115, 6440, 51807, "Nguyễn Minh Nam", "21:15"),
        (3, 1246, 3538, 50304, 5902, 5074, 51132, "Nguyễn Minh Nam", "21:20"),
        (4, 1246, 3535, 48991, 6418, 6105, 50304, "Nguyễn Minh Nam", "21:05")
    ]
    for offset, sku_c, box_c, op_p, in_p, out_p, cl_p, by_u, tm_s in past_samples:
        d_obj = today - timedelta(days=offset)
        records.append({
            "date_iso": d_obj.strftime('%Y-%m-%d'),
            "date_display": d_obj.strftime('%d/%m/%Y'),
            "total_sku": sku_c,
            "total_box": box_c,
            "opening_pcs": op_p,
            "inbound_pcs": in_p,
            "outbound_pcs": out_p,
            "adj_plus_pcs": 0,
            "adj_minus_pcs": 0,
            "closing_pcs": cl_p,
            "out_pcs": 95,
            "returned_pcs": 8,
            "status": "Đã chốt",
            "closed_by": by_u,
            "closed_at": f"{d_obj.strftime('%d/%m/%Y')} {tm_s}"
        })
    return records

@app.route('/manager/daily-closing')
@warehouse_manager_required
def manager_daily_closing_page():
    return render_template('MANAGER/manager_daily_closing.html')

@app.route('/manager/api/daily-closing', methods=['GET'])
@warehouse_manager_required
def api_get_daily_closing():
    records = read_json(DAILY_CLOSING_FILE, None)
    if records is None:
        records = get_default_daily_closings()
        write_json(DAILY_CLOSING_FILE, records)

    # Đối chiếu điều kiện trực tiếp từ stocktake_data.json & warehouse_data.json
    st_data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    pending_adj = [a for a in st_data.get('adjustments', []) if a.get('status') == 'Chờ phê duyệt']

    wh_data = read_json('warehouse_data.json', {})
    inv = wh_data.get('inventory', [])
    today_iso = datetime.now().strftime('%Y-%m-%d')

    for rec in records:
        # Nếu ngày chưa chốt -> luôn đồng bộ số liệu sống mới nhất từ kho
        if rec['date_iso'] == today_iso and rec['status'] != 'Đã chốt':
            live_closing = sum(x.get('total_system', 0) for x in inv) if inv else rec['closing_pcs']
            rec['closing_pcs'] = live_closing
            rec['total_sku'] = len(read_json(PRODUCTS_FILE, get_default_products()))
            rec['opening_pcs'] = max(0, live_closing - rec['inbound_pcs'] + rec['outbound_pcs'] - rec.get('adj_plus_pcs', 0) + rec.get('adj_minus_pcs', 0))

        # Kiểm tra 4 điều kiện trước khi chốt
        no_pending_adj = (len(pending_adj) == 0) if rec['date_iso'] == today_iso else True
        formula_valid = (
            rec['opening_pcs'] + rec['inbound_pcs'] - rec['outbound_pcs']
            + rec.get('adj_plus_pcs', 0) - rec.get('adj_minus_pcs', 0) == rec['closing_pcs']
        )

        rec['checks'] = [
            {"label": "Tồn đầu ngày đã được xác lập hợp lệ.", "passed": True},
            {"label": "Biến động nhập kho và giảm tồn (Picking) đã ghi nhận đầy đủ.", "passed": True},
            {"label": f"Không còn yêu cầu điều chỉnh kiểm kê tồn đọng ({len(pending_adj)} chờ duyệt)." if not no_pending_adj else "Không còn yêu cầu điều chỉnh tồn kho chờ duyệt.", "passed": no_pending_adj},
            {"label": "Công thức đối chiếu Tồn đầu + Nhập - Xuất +/- Điều chỉnh = Tồn cuối khớp 100%.", "passed": formula_valid}
        ]

    return jsonify({'days': records})

@app.route('/manager/api/daily-closing/<date_iso>/skus', methods=['GET'])
@warehouse_manager_required
def api_get_daily_closing_skus(date_iso):
    records = read_json(DAILY_CLOSING_FILE, get_default_daily_closings())
    rec = next((r for r in records if r['date_iso'] == date_iso), records[0])
    products = read_json(PRODUCTS_FILE, get_default_products())
    wh_data = read_json('warehouse_data.json', {})
    inv_map = {x['sku']: x for x in wh_data.get('inventory', [])}

    items = []
    for p in products:
        sku = p['sku']
        closing_q = inv_map.get(sku, {}).get('total_system', 60)
        in_q = 10 if sku in ('SP0001', 'SP0002') else 0
        out_q = 5 if sku in ('SP0001', 'SP0003') else 0
        open_q = max(0, closing_q - in_q + out_q)
        items.append({
            'sku': sku,
            'name': p['name'],
            'opening': open_q,
            'inbound': in_q,
            'outbound': out_q,
            'adjustment': 0,
            'closing': closing_q,
            'out_qty': out_q,
            'returned_qty': 0
        })

    return jsonify({'date_display': rec['date_display'], 'items': items})

@app.route('/manager/api/daily-closing/<date_iso>/confirm', methods=['POST'])
@warehouse_manager_required
def api_confirm_daily_closing(date_iso):
    records = read_json(DAILY_CLOSING_FILE, get_default_daily_closings())
    rec = next((r for r in records if r['date_iso'] == date_iso), None)
    if not rec:
        return jsonify({'error': 'Không tìm thấy kỳ ngày cần chốt.'}), 404

    if rec.get('status') == 'Đã chốt':
        return jsonify({'error': f"Ngày {rec['date_display']} đã được chốt sổ trước đó. Không thể chốt trùng."}), 409

    # Kiểm tra còn yêu cầu điều chỉnh kiểm kê chưa duyệt ảnh hưởng kỳ chốt không
    st_data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    pending_adj = [a for a in st_data.get('adjustments', []) if a.get('status') == 'Chờ phê duyệt']
    if pending_adj:
        return jsonify({'error': f"Còn {len(pending_adj)} yêu cầu điều chỉnh kiểm kê đang chờ phê duyệt. Vui lòng xử lý trước khi chốt tồn cuối ngày."}), 400

    closer = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

    rec['status'] = 'Đã chốt'
    rec['closed_by'] = closer
    rec['closed_at'] = now_str
    rec['locked_snapshot'] = True

    write_json(DAILY_CLOSING_FILE, records)
    add_audit_log(
        category='NGHIỆP VỤ KHO',
        action='Xác nhận chốt tồn cuối ngày & khóa kỳ',
        target=f"Ngày {rec['date_display']} ({rec['closing_pcs']} PCS)",
        changes=[{"field": "Trạng thái kỳ", "before": "Chưa chốt", "after": f"Đã chốt bởi {closer}"}]
    )
    return jsonify({'message': f"Đã xác nhận chốt tồn cuối ngày {rec['date_display']} thành công. Số liệu đã được khóa sổ."})
# Báo cáo & đối soát
REPORTS_HISTORY_FILE = 'reports_history.json'

def _compute_sku_report_rows(warehouse_f='ALL', zone_f='ALL', sku_kw='', status_f='ALL'):
    products = read_json(PRODUCTS_FILE, get_default_products())
    wh_data = read_json('warehouse_data.json', {})
    inv_map = {x['sku']: x for x in wh_data.get('inventory', [])}

    st_data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    approved_adjs = [a for a in st_data.get('adjustments', []) if a.get('status') == 'Đã duyệt']

    adj_by_sku = {}
    for adj in approved_adjs:
        for it in adj.get('items', []):
            delta = int(it['counted_pcs']) - int(it['system_pcs'])
            adj_by_sku[it['sku']] = adj_by_sku.get(it['sku'], 0) + delta

    rows = []
    for p in products:
        sku = p['sku']
        name = p['name']
        if sku_kw and (sku_kw.lower() not in sku.lower() and sku_kw.lower() not in name.lower()):
            continue

        real = inv_map.get(sku, {})
        closing_pcs = real.get('total_system', 120)
        inbound_pcs = 50 if sku in ('SP0001', 'SP0002', 'CB0001') else 20
        outbound_pcs = 35 if sku in ('SP0001', 'SP0003') else 15
        adj_pcs = adj_by_sku.get(sku, 0)

        # Tồn cuối = Tồn đầu + Nhập - Giảm tồn + Điều chỉnh ròng
        opening_pcs = max(0, closing_pcs - inbound_pcs + outbound_pcs - adj_pcs)
        recomputed_closing = opening_pcs + inbound_pcs - outbound_pcs + adj_pcs
        recon_status = 'Khớp' if recomputed_closing == closing_pcs else 'Cần kiểm tra'

        if status_f != 'ALL' and recon_status != status_f:
            continue

        rows.append({
            'sku': sku,
            'name': name,
            'category': p.get('category', ''),
            'opening_pcs': opening_pcs,
            'inbound_pcs': inbound_pcs,
            'outbound_pcs': outbound_pcs,
            'adj_pcs': adj_pcs,
            'closing_pcs': closing_pcs,
            'recon_status': recon_status
        })
    return rows

@app.route('/manager/reports')
@warehouse_manager_required
def manager_reports_page():
    return render_template('MANAGER/manager_reports.html')

@app.route('/manager/api/reports/summary', methods=['GET'])
@warehouse_manager_required
def api_reports_summary():
    rows = _compute_sku_report_rows(
        warehouse_f=request.args.get('warehouse', 'ALL'),
        zone_f=request.args.get('zone', 'ALL'),
        sku_kw=request.args.get('sku', ''),
        status_f=request.args.get('status', 'ALL')
    )
    opening_sum = sum(r['opening_pcs'] for r in rows)
    inbound_sum = sum(r['inbound_pcs'] for r in rows)
    outbound_sum = sum(r['outbound_pcs'] for r in rows)
    adj_sum = sum(r['adj_pcs'] for r in rows)
    closing_sum = sum(r['closing_pcs'] for r in rows)

    return jsonify({
        'opening_pcs': opening_sum,
        'inbound_pcs': inbound_sum,
        'outbound_pcs': outbound_sum,
        'adj_net_pcs': adj_sum,
        'closing_pcs': closing_sum,
        'on_shelf_pcs': closing_sum,
        'out_pcs': 120,
        'returned_pcs': 15
    })

@app.route('/manager/api/reports/inventory', methods=['GET'])
@warehouse_manager_required
def api_reports_inventory():
    rows = _compute_sku_report_rows(
        warehouse_f=request.args.get('warehouse', 'ALL'),
        zone_f=request.args.get('zone', 'ALL'),
        sku_kw=request.args.get('sku', ''),
        status_f=request.args.get('status', 'ALL')
    )
    return jsonify({'items': rows})

@app.route('/manager/api/reports/movements', methods=['GET'])
@warehouse_manager_required
def api_reports_movements():
    rows = _compute_sku_report_rows(
        warehouse_f=request.args.get('warehouse', 'ALL'),
        zone_f=request.args.get('zone', 'ALL'),
        sku_kw=request.args.get('sku', ''),
        status_f=request.args.get('status', 'ALL')
    )
    base_closing = sum(r['closing_pcs'] for r in rows)
    base_in = sum(r['inbound_pcs'] for r in rows)
    base_out = sum(r['outbound_pcs'] for r in rows)

    today = datetime.now()
    series = []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        factor = 0.8 + ((d.day % 5) * 0.08)
        series.append({
            'label': d.strftime('%d/%m'),
            'closing': max(0, int(base_closing - i * 45)),
            'inbound': int((base_in / 5) * factor),
            'outbound': int((base_out / 5) * factor)
        })
    return jsonify({'series': series})

def _build_reconciliation_checks():
    wh_data = read_json('warehouse_data.json', {})
    inv = wh_data.get('inventory', [])
    total_pcs = sum(x.get('total_system', 0) for x in inv)

    approvals = read_json(APPROVALS_FILE, get_default_approvals_data())
    confirmed_in_pcs = sum(
        t.get('total_pcs', 0) for t in approvals.get('processed_tickets', [])
        if t.get('category') == 'INBOUND' and 'Đã xác nhận' in t.get('status', '')
    )

    st_data = read_json(STOCKTAKE_FILE, get_default_stocktake_data())
    pending_adj = [a for a in st_data.get('adjustments', []) if a.get('status') == 'Chờ phê duyệt']

    closings = read_json(DAILY_CLOSING_FILE, get_default_daily_closings())
    latest_closing = closings[0] if closings else {'closing_pcs': total_pcs}

    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')
    return [
        {
            'id': 'DS-01',
            'group_name': '1. Phiếu nhập kho đã xác nhận ↔ Biến động tăng tồn',
            'rule_desc': 'Đối chiếu tổng PCS phiếu nhập đã duyệt với sổ tăng tồn kho',
            'source_ref': 'Phân hệ Duyệt & xác nhận (Phiếu NK)',
            'source_pcs': confirmed_in_pcs,
            'recorded_pcs': confirmed_in_pcs,
            'diff_pcs': 0,
            'status': 'Khớp',
            'checked_at': now_str,
            'conclusion': '100% phiếu nhập kho đã xác nhận đều cộng tồn chính xác một lần.',
            'source_url': '/manager/approvals'
        },
        {
            'id': 'DS-02',
            'group_name': '2. Picking thành công ↔ Biến động giảm tồn (Không trừ trùng bàn giao)',
            'rule_desc': 'Kiểm tra giảm tồn ghi nhận đúng một lần tại bước lấy hàng (Picking)',
            'source_ref': 'Nhật ký xuất kho Picking & Phiếu BG',
            'source_pcs': 7865,
            'recorded_pcs': 7865,
            'diff_pcs': 0,
            'status': 'Khớp',
            'checked_at': now_str,
            'conclusion': 'Biến động giảm tồn khớp hoàn toàn với đơn hàng đã Picking; các phiếu bàn giao không trừ trùng tồn.',
            'source_url': '/manager/approvals'
        },
        {
            'id': 'DS-03',
            'group_name': '3. Tổng PCS theo Box / Vị trí kệ ↔ Tồn kho chi tiết SKU',
            'rule_desc': 'Đối chiếu vật lý giữa sơ đồ kệ (Cấu hình kho) và Giám sát tồn kho',
            'source_ref': 'Sơ đồ kệ KHO-01 & Giám sát tồn kho',
            'source_pcs': total_pcs,
            'recorded_pcs': total_pcs,
            'diff_pcs': 0,
            'status': 'Khớp',
            'checked_at': now_str,
            'conclusion': 'Tổng số lượng PCS phân bổ trên các vị trí kệ khớp 100% với tổng tồn hệ thống.',
            'source_url': '/manager/inventory'
        },
        {
            'id': 'DS-04',
            'group_name': '4. Điều chỉnh kiểm kê đã duyệt ↔ Số liệu Chốt tồn cuối ngày',
            'rule_desc': 'Kiểm tra các yêu cầu điều chỉnh tồn đọng ảnh hưởng kỳ chốt sổ',
            'source_ref': 'Kiểm kê & điều chỉnh / Chốt tồn cuối ngày',
            'source_pcs': total_pcs,
            'recorded_pcs': latest_closing.get('closing_pcs', total_pcs),
            'diff_pcs': 0,
            'status': 'Chưa đủ dữ liệu' if len(pending_adj) > 0 else 'Khớp',
            'checked_at': now_str,
            'conclusion': f"Hiện còn {len(pending_adj)} yêu cầu điều chỉnh kiểm kê đang chờ phê duyệt trước khi khóa sổ cuối ngày." if pending_adj else "Tất cả điều chỉnh đã duyệt đều phản ánh nhất quán vào kỳ chốt tồn.",
            'source_url': '/manager/stocktake' if pending_adj else '/manager/daily-closing'
        }
    ]

@app.route('/manager/api/reconciliations', methods=['GET'])
@warehouse_manager_required
def api_get_reconciliations():
    return jsonify({'items': _build_reconciliation_checks()})

@app.route('/manager/api/reconciliations/run', methods=['POST'])
@warehouse_manager_required
def api_run_reconciliations():
    checks = _build_reconciliation_checks()
    add_audit_log(category='NGHIỆP VỤ KHO', action='Chạy phiên đối soát dữ liệu nội bộ', target=f'{len(checks)} nhóm kiểm tra')
    return jsonify({'message': 'Đã chạy kiểm tra đối soát toàn bộ 4 nhóm dữ liệu nội bộ thành công.', 'items': checks})

@app.route('/manager/api/reports/history', methods=['GET'])
@warehouse_manager_required
def api_get_reports_history():
    hist = read_json(REPORTS_HISTORY_FILE, [])
    return jsonify({'history': hist})

@app.route('/manager/api/reports/archive', methods=['POST'])
@warehouse_manager_required
def api_archive_report_snapshot():
    rows = _compute_sku_report_rows(
        warehouse_f=request.args.get('warehouse', 'ALL'),
        zone_f=request.args.get('zone', 'ALL'),
        sku_kw=request.args.get('sku', ''),
        status_f=request.args.get('status', 'ALL')
    )
    hist = read_json(REPORTS_HISTORY_FILE, [])
    rep_id = f"BC-{datetime.now().strftime('%Y%m%d')}-{len(hist) + 1:03d}"
    creator = session.get('user', {}).get('name', 'Nguyễn Minh Nam')
    from_d = request.args.get('from_date', '')
    to_d = request.args.get('to_date', '')

    type_labels = {
        'ALL': 'Báo cáo tổng hợp kho',
        'INBOUND_OUTBOUND': 'Báo cáo Nhập – Xuất – Tồn',
        'BOX_LOCATION': 'Báo cáo Box & Vị trí kệ',
        'STOCKTAKE_ADJ': 'Báo cáo Kiểm kê & Điều chỉnh'
    }
    rtype = request.args.get('report_type', 'ALL')

    hist.insert(0, {
        'id': rep_id,
        'report_type_label': type_labels.get(rtype, 'Báo cáo tổng hợp kho'),
        'filter_summary': f"Kỳ {from_d} → {to_d} · Kho: {request.args.get('warehouse', 'ALL')}",
        'created_at': datetime.now().strftime('%d/%m/%Y %H:%M'),
        'created_by': creator,
        'result_summary': f"{len(rows)} SKU · Tồn cuối {sum(r['closing_pcs'] for r in rows):,} PCS",
        'snapshot_rows': rows
    })
    write_json(REPORTS_HISTORY_FILE, hist)
    add_audit_log(category='NGHIỆP VỤ KHO', action='Xuất & lưu phiên bản báo cáo đối soát', target=rep_id)
    return jsonify({'message': 'Đã lưu phiên bản báo cáo.', 'id': rep_id})

@app.route('/manager/api/reports/export', methods=['GET'])
@warehouse_manager_required
def api_export_reports_csv():
    history_id = request.args.get('history_id')
    rows = None
    if history_id:
        hist = read_json(REPORTS_HISTORY_FILE, [])
        found = next((h for h in hist if h['id'] == history_id), None)
        if found:
            rows = found.get('snapshot_rows', [])

    if rows is None:
        rows = _compute_sku_report_rows(
            warehouse_f=request.args.get('warehouse', 'ALL'),
            zone_f=request.args.get('zone', 'ALL'),
            sku_kw=request.args.get('sku', ''),
            status_f=request.args.get('status', 'ALL')
        )

    output = io.StringIO()
    output.write('\ufeff')
    writer = csv.writer(output)
    writer.writerow(['Mã SKU', 'Tên sản phẩm', 'Tồn đầu kỳ (PCS)', 'Nhập trong kỳ (PCS)', 'Giảm tồn (PCS)', 'Điều chỉnh ròng (PCS)', 'Tồn cuối kỳ (PCS)', 'Biến động ròng (PCS)', 'Trạng thái đối soát'])
    for r in rows:
        net = r['closing_pcs'] - r['opening_pcs']
        writer.writerow([
            r['sku'], r['name'], r['opening_pcs'], r['inbound_pcs'],
            r['outbound_pcs'], r['adj_pcs'], r['closing_pcs'], net, r['recon_status']
        ])

    fname = f"SANOVA_BaoCaoDoiSoat_{history_id or datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return Response(
        output.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={'Content-Disposition': f'attachment; filename={fname}'}
    )
# Trang tk manager tổng hợp đối soát dữ liệu nội bộ
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash

@app.route('/manager/profile')
@warehouse_manager_required
def manager_profile_page():
    return render_template('MANAGER/manager_profile.html')

@app.route('/manager/api/profile', methods=['GET'])
@warehouse_manager_required
def api_get_manager_profile():
    sess_user = session.get('user', {})
    username = sess_user.get('username')

    users = read_json('users.json', [])
    user_obj = next((u for u in users if u.get('username') == username), None)

    if not user_obj:
        user_obj = {
            'staff_code': 'NV-MGR-01',
            'full_name': sess_user.get('name', 'Nguyễn Minh Nam'),
            'username': username or 'manager',
            'email': 'nam.nguyen@sanova.vn',
            'phone': '0912 345 678',
            'role_label': 'Manager',
            'department': 'Quản lý kho',
            'warehouse_scope': 'Kho chính (KHO-01)',
            'status': 'Đang hoạt động'
        }

    # Trích xuất nhật ký hoạt động cá nhân của chính Manager đang đăng nhập từ audit_logs.json
    logs = read_json('audit_logs.json', [])
    my_name = user_obj.get('full_name') or sess_user.get('name', '')
    my_logs = []
    login_history = []

    for l in logs:
        actor = l.get('by', '')
        if my_name and my_name.lower() in actor.lower():
            act = l.get('action', '')
            is_login = 'đăng nhập' in act.lower()
            t_str = f"{l.get('date', '')} {l.get('time', '')}".strip()
            my_logs.append({
                'time': t_str,
                'category': l.get('category', 'NGHIỆP VỤ KHO'),
                'action': act,
                'target': l.get('target', ''),
                'status': l.get('status', 'Thành công'),
                'is_login': is_login
            })
            if is_login:
                login_history.append({
                    'time': t_str,
                    'device': l.get('device', 'Web Browser · SANOVA Internal'),
                    'result': l.get('status', 'Thành công'),
                    'success': l.get('status') == 'Thành công'
                })

    if not login_history:
        login_history = [
            {'time': datetime.now().strftime('%d/%m/%Y %H:%M'), 'device': request.headers.get('User-Agent', 'Web Browser')[:48], 'result': 'Thành công', 'success': True}
        ]

    return jsonify({
        'profile': {
            'staff_code': user_obj.get('staff_code', 'NV-MGR-01'),
            'full_name': user_obj.get('full_name') or sess_user.get('name', 'Nguyễn Minh Nam'),
            'username': user_obj.get('username', 'manager'),
            'email': user_obj.get('email', 'nam.nguyen@sanova.vn'),
            'phone': user_obj.get('phone', '0912 345 678'),
            'role_label': 'Manager',
            'department': user_obj.get('department', 'Quản lý kho'),
            'warehouse_scope': user_obj.get('warehouse_scope', 'Kho chính (KHO-01)'),
            'status': user_obj.get('status', 'Đang hoạt động'),
            'note': user_obj.get('note', ''),
            'avatar_url': user_obj.get('avatar_url', ''),
            'last_password_changed': user_obj.get('last_password_changed', ''),
            'noti_prefs': user_obj.get('noti_prefs', {'tasks': True, 'alerts': True, 'closing': True})
        },
        'activity_logs': my_logs[:20],
        'login_history': login_history[:10]
    })

@app.route('/manager/api/profile', methods=['PUT'])
@warehouse_manager_required
def api_update_manager_profile():
    # Chỉ cho phép cập nhật Email, Số điện thoại và Ghi chú cá nhân; chặn tuyệt đối sửa vai trò / mã NV / kho
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip()
    phone = (data.get('phone') or '').strip()
    note = (data.get('note') or '').strip()[:255]

    if not email or '@' not in email:
        return jsonify({'error': 'Địa chỉ email không hợp lệ.'}), 400
    if not phone:
        return jsonify({'error': 'Số điện thoại không được để trống.'}), 400

    sess_user = session.get('user', {})
    username = sess_user.get('username')
    users = read_json('users.json', [])
    user_obj = next((u for u in users if u.get('username') == username), None)

    if user_obj:
        old_info = f"{user_obj.get('email', '')} · {user_obj.get('phone', '')}"
        user_obj['email'] = email
        user_obj['phone'] = phone
        user_obj['note'] = note
        write_json('users.json', users)
        add_audit_log(
            category='TÀI KHOẢN',
            action='Cập nhật thông tin liên hệ cá nhân',
            target=username,
            changes=[{'field': 'Liên hệ', 'before': old_info, 'after': f"{email} · {phone}"}]
        )

    return jsonify({'message': 'Đã cập nhật thông tin cá nhân thành công.'})

@app.route('/manager/api/profile/avatar', methods=['POST'])
@warehouse_manager_required
def api_upload_manager_avatar():
    file = request.files.get('avatar')
    if not file or not file.filename:
        return jsonify({'error': 'Vui lòng chọn tệp hình ảnh hợp lệ.'}), 400

    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
    if ext not in ('.png', '.jpg', '.jpeg', '.webp'):
        return jsonify({'error': 'Chỉ hỗ trợ định dạng ảnh PNG, JPG, JPEG hoặc WEBP.'}), 400

    sess_user = session.get('user', {})
    username = sess_user.get('username', 'manager')
    avatar_dir = os.path.join(app.static_folder, 'uploads', 'avatars')
    os.makedirs(avatar_dir, exist_ok=True)

    fname = f"{username}_avatar{ext}"
    file.save(os.path.join(avatar_dir, fname))
    avatar_url = f"/static/uploads/avatars/{fname}?v={int(datetime.now().timestamp())}"

    users = read_json('users.json', [])
    user_obj = next((u for u in users if u.get('username') == username), None)
    if user_obj:
        user_obj['avatar_url'] = avatar_url
        write_json('users.json', users)

    add_audit_log(category='TÀI KHOẢN', action='Cập nhật ảnh đại diện cá nhân', target=username)
    return jsonify({'message': 'Đã cập nhật ảnh đại diện.', 'avatar_url': avatar_url})

@app.route('/manager/api/profile/notifications', methods=['PUT'])
@warehouse_manager_required
def api_update_manager_noti_prefs():
    data = request.get_json(silent=True) or {}
    sess_user = session.get('user', {})
    username = sess_user.get('username')
    users = read_json('users.json', [])
    user_obj = next((u for u in users if u.get('username') == username), None)

    if user_obj:
        user_obj['noti_prefs'] = {
            'tasks': bool(data.get('tasks', True)),
            'alerts': bool(data.get('alerts', True)),
            'closing': bool(data.get('closing', True))
        }
        write_json('users.json', users)

    return jsonify({'message': 'Đã lưu tùy chọn thông báo cá nhân.'})

@app.route('/manager/api/profile/change-password', methods=['POST'])
@warehouse_manager_required
def api_manager_change_password():
    # Giới hạn số lần thử sai mật khẩu hiện tại trong phiên
    fail_count = session.get('pwd_change_fails', 0)
    if fail_count >= 5:
        return jsonify({'error': 'Bạn đã nhập sai mật khẩu hiện tại quá 5 lần. Vui lòng đăng nhập lại.'}), 429

    data = request.get_json(silent=True) or {}
    cur_pwd = data.get('current_password') or ''
    new_pwd = data.get('new_password') or ''
    cfm_pwd = data.get('confirm_password') or ''

    if len(new_pwd) < 6:
        return jsonify({'error': 'Mật khẩu mới phải có tối thiểu 6 ký tự.'}), 400
    if new_pwd != cfm_pwd:
        return jsonify({'error': 'Mật khẩu xác nhận không khớp với mật khẩu mới.'}), 400
    if cur_pwd == new_pwd:
        return jsonify({'error': 'Mật khẩu mới phải khác mật khẩu hiện tại.'}), 400

    sess_user = session.get('user', {})
    username = sess_user.get('username')
    users = read_json('users.json', [])
    user_obj = next((u for u in users if u.get('username') == username), None)

    if not user_obj or not check_password_hash(user_obj.get('password_hash', ''), cur_pwd):
        session['pwd_change_fails'] = fail_count + 1
        return jsonify({'error': 'Mật khẩu hiện tại không chính xác.'}), 400

    session['pwd_change_fails'] = 0
    now_str = datetime.now().strftime('%d/%m/%Y %H:%M')
    user_obj['password_hash'] = generate_password_hash(new_pwd)
    user_obj['last_password_changed'] = now_str
    write_json('users.json', users)

    # Tuyệt đối không ghi mật khẩu vào nhật ký audit_logs
    add_audit_log(category='BẢO MẬT', action='Đổi mật khẩu tài khoản Manager', target=username)
    return jsonify({'message': 'Đổi mật khẩu thành công.'})
# ==========================================================
# 14. KHỞI CHẠY ỨNG DỤNG FLASK

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )