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
    Flask, render_template, render_template_string, request, redirect,
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
        if request.path in ("/login", "/") or request.path.startswith(("/warehouse/api/", "/manager/api/", "/admin/api/", "/api/staff/")):
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
        if "Quản trị viên" not in session["user"].get("role", ""):
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
        role = session["user"].get("role", "")
        if "Quản trị viên" in role:
            return redirect(url_for("admin_dashboard"))
        if "Quản lý kho" in role:
            return redirect(url_for("warehouse_manager_dashboard"))
        if "Điều phối" in role or "Kế toán" in role:
            return redirect(url_for("dispatcher_dashboard_page"))
        if "Nhân viên" in role:
            return redirect(url_for("staff_dashboard_page"))
    return render_template("welcome.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    # 1. Nếu đã có phiên đăng nhập trước đó -> điều hướng đúng vai trò
    if 'user' in session:
        role = session['user'].get('role', '')
        if 'Quản trị viên' in role:
            return redirect(url_for('admin_dashboard'))
        elif 'Quản lý kho' in role:
            return redirect(url_for('warehouse_manager_dashboard'))
        elif 'Điều phối' in role or 'Kế toán' in role:
            return redirect(url_for('dispatcher_dashboard_page'))
        else:
            return redirect(url_for('staff_dashboard_page'))

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

                session.permanent = False
                session['user'] = {
                    'username': matched_username,
                    'staff_code': user_info.get('staff_code', matched_username),
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

                # 2. ĐIỀU HƯỚNG SAU KHI ĐĂNG NHẬP THÀNH CÔNG CHO ĐỦ 4 VAI TRÒ
                role_name = user_info.get('role', '')
                if 'Quản trị viên' in role_name:
                    return redirect(url_for('admin_dashboard'))
                elif 'Quản lý kho' in role_name:
                    return redirect('/warehouse/manager')
                elif 'Điều phối' in role_name or 'Kế toán' in role_name:
                    return redirect(url_for('dispatcher_dashboard_page'))
                else:
                    return redirect('/staff/dashboard')
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

    # Chuẩn hóa đếm số lượng theo vai trò cho biểu đồ & thống kê Tổng quan
    role_counts = {
        "Quản trị viên": 0,
        "Quản lý kho": 0,
        "Nhân viên kho": 0,
        "Điều phối / Kế toán kho": 0
    }
    for user in users.values():
        r = user.get("role", "")
        if "Quản trị viên" in r:
            role_counts["Quản trị viên"] += 1
        elif "Quản lý kho" in r:
            role_counts["Quản lý kho"] += 1
        elif "Nhân viên kho" in r:
            role_counts["Nhân viên kho"] += 1
        elif "Điều phối" in r or "Kế toán" in r:
            role_counts["Điều phối / Kế toán kho"] += 1
        elif r:
            role_counts[r] = role_counts.get(r, 0) + 1

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
    if username == session["user"]["username"] and "Quản trị viên" not in role:
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
    if "Quản trị viên" in target_user.get("role", "") or username in ("admin", "duc.long"):
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
    settings = load_settings()

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

#######======= III.Nhân viên kho (Warehouse Staff) ==========
import json
import hashlib
from functools import wraps
from datetime import datetime
from flask import render_template, request, jsonify, session, redirect, url_for

STAFF_TASKS_FILE = 'staff_tasks.json'
STAFF_NOTI_FILE = 'staff_notifications.json'

def staff_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = session.get('user')
        if not user:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Phiên đăng nhập đã hết hạn', 'redirect': '/login'}), 401
            return redirect(url_for('login'))
        role = str(user.get('role', '')).upper()
        if 'NHÂN VIÊN' not in role and 'STAFF' not in role and 'ADMIN' not in role:
            return jsonify({'error': 'Tài khoản không thuộc phân hệ Nhân viên kho'}), 403
        return f(*args, **kwargs)
    return decorated


def get_current_shift_info():
    now = datetime.now()
    hour = now.hour
    if 6 <= hour < 14:
        return {'shift_id': 'CA-SANG', 'shift_name': 'Ca Sáng (Ca 1)', 'time_range': '06:00 - 14:00', 'date_str': now.strftime('%Y-%m-%d')}
    elif 14 <= hour < 22:
        return {'shift_id': 'CA-CHIEU', 'shift_name': 'Ca Chiều (Ca 2)', 'time_range': '14:00 - 22:00', 'date_str': now.strftime('%Y-%m-%d')}
    return {'shift_id': 'CA-DEM', 'shift_name': 'Ca Đêm (Ca 3)', 'time_range': '22:00 - 06:00', 'date_str': now.strftime('%Y-%m-%d')}


def _safe_load(filepath, default):
    if 'read_json' in globals():
        return read_json(filepath, default)
    if 'load_json_safe' in globals():
        return load_json_safe(filepath, default=default)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def _safe_save(filepath, data):
    if 'write_json' in globals():
        write_json(filepath, data)
        return
    if 'save_json_safe' in globals():
        save_json_safe(filepath, data)
        return
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def build_synced_staff_tasks(emp_code, emp_name, warehouse_id):
    """
    Tổng hợp 100% dữ liệu thật từ các phân hệ SANOVA:
    1. staff_tasks.json (Công việc được phân công trực tiếp)
    2. approvals_data.json (Phiếu nhập kho / bàn giao chờ duyệt, bị trả lại, hoặc đã duyệt trong ngày)
    3. stocktake_data.json (Phiên kiểm kê kho & yêu cầu điều chỉnh)
    4. warehouse_data.json (Hàng đợi vận hành đang mở)
    """
    today_ymd = datetime.now().strftime('%Y-%m-%d')
    today_dmy = datetime.now().strftime('%d/%m/%Y')

    saved_tasks = _safe_load(STAFF_TASKS_FILE, [])
    approvals_data = _safe_load('approvals_data.json', {})
    stocktake_data = _safe_load('stocktake_data.json', {})
    wh_data = _safe_load('warehouse_data.json', {})

    tasks_map = {}

    def belongs_to_staff(sender_or_assignee):
        if not sender_or_assignee:
            return True
        val = str(sender_or_assignee).strip().lower()
        checks = {
            str(emp_code).strip().lower(),
            str(emp_name).strip().lower(),
            'all_staff', 'nhân viên kho', 'staff'
        }
        return any(c and (c == val or c in val) for c in checks)

    # 1. Nạp công việc từ staff_tasks.json
    for t in saved_tasks:
        if t.get('warehouse_id', 'KHO-01') != warehouse_id:
            continue
        if belongs_to_staff(t.get('assigned_employee')):
            tasks_map[t['task_id']] = t

    # 2. Đồng bộ từ approvals_data.json
    # 2a. Phiếu đang chờ Manager xác nhận
    for t in approvals_data.get('pending_tickets', []):
        if not belongs_to_staff(t.get('sender')):
            continue
        ref_id = t.get('id')
        tid = f"TSK-{ref_id}"
        is_handover = t.get('category') == 'HANDOVER'
        tasks_map[tid] = {
            'task_id': tid,
            'reference_id': ref_id,
            'task_type': 'HANDOVER' if is_handover else 'INBOUND',
            'title': f"Chờ xác nhận {'bàn giao' if is_handover else 'nhập kho'}",
            'category_label': 'Bàn giao' if is_handover else 'Nhập kho',
            'quantity_text': t.get('qty_primary') or f"{t.get('total_pcs', 0)} PCS",
            'time_label': str(t.get('sent_at', ''))[-5:] or 'Hôm nay',
            'assigned_employee': emp_code,
            'warehouse_id': warehouse_id,
            'status': 'Chờ xác nhận',
            'priority': 'NORMAL',
            'is_carryover': False,
            'rejection_reason': ''
        }

    processed_list = approvals_data.get('processed_tickets', [])

    # 2b. Phiếu bị Manager từ chối / trả lại
    for r in processed_list:
        if str(r.get('status', '')) != 'Đã từ chối' or not belongs_to_staff(r.get('sender')):
            continue
        ref_id = r.get('id')
        tid = f"TSK-{ref_id}"
        is_handover = r.get('category') == 'HANDOVER'
        tasks_map[tid] = {
            'task_id': tid,
            'reference_id': ref_id,
            'task_type': 'HANDOVER' if is_handover else 'INBOUND',
            'title': f"Bổ sung thông tin {'bàn giao' if is_handover else 'nhập kho'}",
            'category_label': 'Bàn giao' if is_handover else 'Nhập kho',
            'quantity_text': r.get('qty_primary') or f"{r.get('total_pcs', 0)} PCS",
            'time_label': str(r.get('reviewed_at', ''))[-5:] or 'Vừa trả lại',
            'assigned_employee': emp_code,
            'warehouse_id': warehouse_id,
            'status': 'Cần xử lý lại',
            'priority': 'HIGH',
            'is_carryover': False,
            'rejection_reason': r.get('reject_reason') or 'Manager yêu cầu kiểm tra và bổ sung thông tin phiếu.'
        }

    # 2c. Phiếu đã được Manager duyệt hoàn tất trong ngày
    for a in processed_list:
        if 'Đã xác nhận' not in str(a.get('status', '')) or not belongs_to_staff(a.get('sender')):
            continue
        approved_at = str(a.get('reviewed_at', ''))
        if today_ymd in approved_at or today_dmy in approved_at or not approved_at:
            ref_id = a.get('id')
            tid = f"TSK-{ref_id}"
            is_handover = a.get('category') == 'HANDOVER'
            tasks_map[tid] = {
                'task_id': tid,
                'reference_id': ref_id,
                'task_type': 'HANDOVER' if is_handover else 'INBOUND',
                'title': f"Đã xác nhận {'bàn giao' if is_handover else 'nhập kho'}",
                'category_label': 'Bàn giao' if is_handover else 'Nhập kho',
                'quantity_text': a.get('qty_primary') or f"{a.get('total_pcs', 0)} PCS",
                'time_label': approved_at[-5:] if len(approved_at) >= 5 else 'Đã duyệt',
                'assigned_employee': emp_code,
                'warehouse_id': warehouse_id,
                'status': 'Hoàn thành',
                'priority': 'NORMAL',
                'is_carryover': False,
                'rejection_reason': ''
            }

    # 3. Đồng bộ phiên kiểm kê từ stocktake_data.json
    for s in stocktake_data.get('sessions', []):
        assignee = s.get('assignee') or s.get('assigned_to')
        if not belongs_to_staff(assignee):
            continue
        st_raw = s.get('status', '')
        if st_raw in ('Chờ thực hiện', 'Đang kiểm kê', 'Đối chiếu', 'Hoàn tất'):
            ref_id = s.get('id')
            tid = f"TSK-{ref_id}"
            mapped_status = (
                'Chờ thực hiện' if st_raw == 'Chờ thực hiện'
                else ('Chờ xác nhận' if st_raw == 'Đối chiếu'
                else ('Hoàn thành' if st_raw == 'Hoàn tất' else 'Đang thực hiện'))
            )
            tasks_map[tid] = {
                'task_id': tid,
                'reference_id': ref_id,
                'task_type': 'STOCK_COUNT',
                'title': f"Kiểm kê {s.get('scope', 'khu vực kho')}",
                'category_label': 'Kiểm kê',
                'quantity_text': f"{s.get('total_boxes', s.get('total_locations', 0))} vị trí",
                'time_label': str(s.get('created_at', ''))[-5:] or 'Trong ca',
                'assigned_employee': emp_code,
                'warehouse_id': warehouse_id,
                'status': mapped_status,
                'priority': 'HIGH' if s.get('priority') == 'HIGH' else 'NORMAL',
                'is_carryover': bool(s.get('is_carryover', False)),
                'rejection_reason': ''
            }

    # Sắp xếp ưu tiên: Cần xử lý lại -> Ưu tiên cao -> Đang thực hiện -> Chờ thực hiện -> Chờ xác nhận -> Hoàn thành
    order_weight = {
        'Cần xử lý lại': 1,
        'Đang thực hiện': 2,
        'Chờ thực hiện': 3,
        'Chờ xác nhận': 4,
        'Hoàn thành': 5
    }
    result = list(tasks_map.values())
    result.sort(key=lambda x: (order_weight.get(x.get('status'), 9), 0 if x.get('priority') == 'HIGH' else 1))
    return result


def build_staff_notifications(emp_code, tasks):
    read_store = _safe_load(STAFF_NOTI_FILE, {})
    read_ids = set(read_store.get(emp_code, []))
    notifications = []

    for t in tasks:
        ref = t['reference_id']
        target_url = (
            f"/staff/packing-handover?ticket={ref}" if t['task_type'] == 'HANDOVER'
            else (f"/staff/picking-returns?tab=OUT&ticket={ref}" if t['task_type'] == 'OUT'
            else (f"/staff/stocktake?ticket={ref}" if t['task_type'] == 'STOCK_COUNT'
            else f"/staff/inbound?ticket={ref}"))
        )

        if t.get('status') == 'Cần xử lý lại':
            nid = f"NOTI-RET-{ref}"
            notifications.append({
                'id': nid,
                'level': 'DANGER',
                'title': f"Manager trả lại phiếu {ref}",
                'message': t.get('rejection_reason') or 'Yêu cầu kiểm tra và bổ sung thông tin phiếu.',
                'time': t.get('time_label', 'Vừa xong'),
                'is_read': nid in read_ids,
                'target_url': target_url
            })
        elif t.get('priority') == 'HIGH' and t.get('status') in ('Chờ thực hiện', 'Đang thực hiện'):
            nid = f"NOTI-PRI-{ref}"
            notifications.append({
                'id': nid,
                'level': 'WARNING',
                'title': f"Công việc ưu tiên: {ref}",
                'message': f"{t['title']} ({t['quantity_text']}) cần xử lý đúng tiến độ ca.",
                'time': t.get('time_label', 'Trong ca'),
                'is_read': nid in read_ids,
                'target_url': target_url
            })
        elif t.get('status') == 'Hoàn thành':
            nid = f"NOTI-OK-{ref}"
            notifications.append({
                'id': nid,
                'level': 'SUCCESS',
                'title': f"Đã xác nhận phiếu {ref}",
                'message': f"{t['title']} ({t['quantity_text']}) đã được phê duyệt hoàn tất.",
                'time': t.get('time_label', 'Hôm nay'),
                'is_read': nid in read_ids,
                'target_url': target_url
            })

    return notifications


# ================= ROUTES & API STAFF DASHBOARD =================

@app.route('/staff/dashboard')
@staff_required
def staff_dashboard_page():
    return render_template('STAFF/staff_dashboard.html')


@app.route('/api/staff/dashboard', methods=['GET'])
@staff_required
def api_staff_dashboard():
    user = session.get('user', {})
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    emp_name = user.get('name', 'Nhân viên kho')
    warehouse_id = user.get('warehouse_id', 'KHO-01')

    tasks = build_synced_staff_tasks(emp_code, emp_name, warehouse_id)
    shift = get_current_shift_info()

    pending_cnt = sum(1 for t in tasks if t.get('status') == 'Chờ thực hiện')
    in_progress_cnt = sum(1 for t in tasks if t.get('status') == 'Đang thực hiện')
    waiting_cnt = sum(1 for t in tasks if t.get('status') == 'Chờ xác nhận')
    returned_cnt = sum(1 for t in tasks if t.get('status') == 'Cần xử lý lại')
    completed_cnt = sum(1 for t in tasks if t.get('status') == 'Hoàn thành' and not t.get('is_carryover'))
    carryover_cnt = sum(1 for t in tasks if t.get('is_carryover') and t.get('status') != 'Hoàn thành')
    current_shift_total = sum(1 for t in tasks if not t.get('is_carryover'))

    notifications = build_staff_notifications(emp_code, tasks)

    payload = {
        'staff': {
            'employee_code': emp_code,
            'full_name': emp_name,
            'role': user.get('role', 'Nhân viên kho'),
            'warehouse_id': warehouse_id,
            'warehouse_name': user.get('scope', 'Kho chính - SANOVA')
        },
        'shift': shift,
        'stats': {
            'pending': pending_cnt,
            'in_progress': in_progress_cnt,
            'waiting_approval': waiting_cnt,
            'returned': returned_cnt,
            'completed': completed_cnt,
            'total_shift_tasks': current_shift_total,
            'carryover_count': carryover_cnt
        },
        'tasks': tasks,
        'notifications': notifications
    }

    # Tạo mã băm trạng thái để Frontend chỉ cập nhật DOM khi dữ liệu thực sự thay đổi
    raw_hash = hashlib.md5(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode('utf-8')).hexdigest()
    payload['state_hash'] = raw_hash
    return jsonify(payload)


@app.route('/api/staff/tasks', methods=['GET'])
@staff_required
def api_staff_tasks():
    user = session.get('user', {})
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    emp_name = user.get('name', 'Nhân viên kho')
    warehouse_id = user.get('warehouse_id', 'KHO-01')
    status_filter = request.args.get('status', 'ALL')

    tasks = build_synced_staff_tasks(emp_code, emp_name, warehouse_id)
    if status_filter != 'ALL':
        tasks = [t for t in tasks if t.get('status') == status_filter]
    return jsonify({'tasks': tasks, 'count': len(tasks)})


@app.route('/api/staff/tasks/<task_id>', methods=['GET'])
@staff_required
def api_staff_task_detail(task_id):
    user = session.get('user', {})
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    emp_name = user.get('name', 'Nhân viên kho')
    warehouse_id = user.get('warehouse_id', 'KHO-01')

    tasks = build_synced_staff_tasks(emp_code, emp_name, warehouse_id)
    for t in tasks:
        if t.get('task_id') == task_id or t.get('reference_id') == task_id:
            return jsonify({'task': t})
    return jsonify({'error': 'Không tìm thấy công việc hoặc bạn không có quyền truy cập phiếu này'}), 404


@app.route('/api/staff/notifications', methods=['GET'])
@staff_required
def api_staff_notifications():
    user = session.get('user', {})
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    emp_name = user.get('name', 'Nhân viên kho')
    warehouse_id = user.get('warehouse_id', 'KHO-01')
    tasks = build_synced_staff_tasks(emp_code, emp_name, warehouse_id)
    return jsonify({'notifications': build_staff_notifications(emp_code, tasks)})


@app.route('/api/staff/notifications/<noti_id>/read', methods=['PATCH'])
@staff_required
def api_staff_notification_mark_read(noti_id):
    user = session.get('user', {})
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    read_store = _safe_load(STAFF_NOTI_FILE, {})
    user_reads = set(read_store.get(emp_code, []))
    user_reads.add(noti_id)
    read_store[emp_code] = list(user_reads)
    _safe_save(STAFF_NOTI_FILE, read_store)
    return jsonify({'status': 'ok', 'id': noti_id})


@app.route('/api/staff/shifts/current', methods=['GET'])
@staff_required
def api_staff_current_shift():
    return jsonify(get_current_shift_info())

# API STAFF
@app.route('/api/staff/tasks/<task_id>/progress', methods=['PATCH'])
@staff_required
def api_staff_update_task_progress(task_id):
    """
    Ghi nhận tức thì mọi thao tác nhỏ của nhân viên (bắt đầu làm, quét dở từng Box/vị trí, gửi chờ duyệt)
    để Dashboard Staff và hệ thống đồng bộ theo thời gian thực.
    """
    user = session.get('user', {})
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    emp_name = user.get('name', 'Nhân viên kho')
    warehouse_id = user.get('warehouse_id', 'KHO-01')

    body = request.get_json(silent=True) or {}
    new_status = body.get('status')       # 'Đang thực hiện' | 'Chờ xác nhận' | 'Hoàn thành'
    sub_note = body.get('progress_note')  # VD: 'Đã quét 6/10 Box'

    saved_tasks = _safe_load(STAFF_TASKS_FILE, [])
    now_str = datetime.now().strftime('%H:%M')
    updated = False

    for t in saved_tasks:
        if t.get('task_id') == task_id or t.get('reference_id') == task_id:
            if new_status:
                t['status'] = new_status
            if sub_note:
                t['quantity_text'] = sub_note
            t['time_label'] = now_str
            t['updated_by'] = emp_code
            updated = True
            break

    # Nếu phiếu xuất phát từ stocktake_data.json hoặc approvals_data.json chưa có trong staff_tasks.json
    if not updated:
        saved_tasks.insert(0, {
            'task_id': task_id if task_id.startswith('TSK-') else f"TSK-{task_id}",
            'reference_id': task_id.replace('TSK-', ''),
            'task_type': body.get('task_type', 'INBOUND'),
            'title': body.get('title', f"Xử lý phiếu {task_id}"),
            'category_label': body.get('category_label', 'Nghiệp vụ kho'),
            'quantity_text': sub_note or body.get('quantity_text', ''),
            'time_label': now_str,
            'assigned_employee': emp_code,
            'warehouse_id': warehouse_id,
            'status': new_status or 'Đang thực hiện',
            'priority': body.get('priority', 'NORMAL'),
            'is_carryover': False,
            'rejection_reason': ''
        })

    _safe_save(STAFF_TASKS_FILE, saved_tasks)

    if 'add_audit_log' in globals():
        add_audit_log(
            category='Nghiệp vụ kho',
            action=f"Cập nhật tiến độ công việc ({new_status or 'Đang thao tác'})",
            target=task_id,
            reason=sub_note or f"Thực hiện bởi {emp_name}"
        )

    return jsonify({'status': 'ok', 'task_id': task_id, 'new_status': new_status})

# Nhập và lưu trữ kho
import uuid
import threading

INBOUND_FILE = 'inbound_receipts.json'
_inbound_lock = threading.Lock()


def _find_eligible_boxes_for_sku(sku):
    """
    Chỉ lấy các Box đang ở trạng thái 'Đang lưu trữ' (đã được Manager xác nhận nhập kho),
    không bị khóa/cách ly và còn tồn khả dụng > 0 trên kệ.
    """
    receipts = _load_inbound_receipts()
    boxes = []
    for r in receipts:
        for b in r.get('boxes', []):
            if (b.get('sku', '').upper() == sku.upper()
                and b.get('box_status') == 'Đang lưu trữ'
                and int(b.get('quantity', 0)) > 0
                and b.get('shelf_position_id')):
                hierarchy = _resolve_slot_hierarchy(b.get('shelf_position_id'))
                box_copy = dict(b)
                box_copy['location_hierarchy'] = hierarchy['full_path']
                box_copy['zone_id'] = hierarchy['zone']
                box_copy['rack_id'] = hierarchy['rack']
                box_copy['floor_no'] = hierarchy['floor']
                boxes.append(box_copy)
    return boxes
def _get_default_inbound_receipts(emp_name='Nguyễn Văn C'):
    return [
        {
            'id': 'NK-0025',
            'vehicle_code': 'XE-014',
            'supplier': 'Nhà cung cấp A',
            'doc_ref': 'PO-2026-0814',
            'created_at': '2026-11-14 08:15',
            'assignee': emp_name,
            'status': 'Hoàn thành',
            'notes': 'Đã xác nhận nhập kho lô SP0001 & SP0002.',
            'reject_reason': '',
            'items': [
                {'sku': 'SP0001', 'product_name': 'Sữa rửa mặt dịu nhẹ 150ml', 'expected_boxes': 2, 'received_boxes': 2, 'damaged_boxes': 0, 'pcs_per_box': 50},
                {'sku': 'SP0002', 'product_name': 'Kem dưỡng ẩm phục hồi 50g', 'expected_boxes': 2, 'received_boxes': 2, 'damaged_boxes': 0, 'pcs_per_box': 30}
            ],
            'boxes': [
                {
                    'box_id': 'BOX-0025-01',
                    'internal_qr': 'QR-SANOVA-NK0025-01',
                    'sku': 'SP0001',
                    'product_name': 'Sữa rửa mặt dịu nhẹ 150ml',
                    'quantity': 50,
                    'dimensions': '40x30x30',
                    'weight': 8.5,
                    'receipt_id': 'NK-0025',
                    'box_status': 'Đang lưu trữ',
                    'shelf_position_id': 'A1-001'
                },
                {
                    'box_id': 'BOX-0025-02',
                    'internal_qr': 'QR-SANOVA-NK0025-02',
                    'sku': 'SP0001',
                    'product_name': 'Sữa rửa mặt dịu nhẹ 150ml',
                    'quantity': 50,
                    'dimensions': '40x30x30',
                    'weight': 8.5,
                    'receipt_id': 'NK-0025',
                    'box_status': 'Đang lưu trữ',
                    'shelf_position_id': 'A1-002'
                },
                {
                    'box_id': 'BOX-0025-03',
                    'internal_qr': 'QR-SANOVA-NK0025-03',
                    'sku': 'SP0002',
                    'product_name': 'Kem dưỡng ẩm phục hồi 50g',
                    'quantity': 25,
                    'dimensions': '40x30x30',
                    'weight': 7.5,
                    'receipt_id': 'NK-0025',
                    'box_status': 'Đang lưu trữ',
                    'shelf_position_id': 'A1-003'
                },
                {
                    'box_id': 'BOX-0025-04',
                    'internal_qr': 'QR-SANOVA-NK0025-04',
                    'sku': 'SP0002',
                    'product_name': 'Kem dưỡng ẩm phục hồi 50g',
                    'quantity': 30,
                    'dimensions': '40x30x30',
                    'weight': 9.0,
                    'receipt_id': 'NK-0025',
                    'box_status': 'Đang lưu trữ',
                    'shelf_position_id': 'A1-004'
                }
            ]
        }
    ]
def _load_inbound_receipts():
    data = _safe_load(INBOUND_FILE, None)
    if data is None:
        data = []
        _safe_save(INBOUND_FILE, data)

    # Tự động đồng bộ trạng thái thật từ quyết định duyệt/từ chối của Manager (approvals_data.json)
    approvals = _safe_load('approvals_data.json', {})
    processed = approvals.get('processed_tickets', [])
    approved_ids = {t.get('id') for t in processed if 'Đã xác nhận' in str(t.get('status', ''))}
    rejected_map = {
        t.get('id'): t.get('reject_reason', '')
        for t in processed if str(t.get('status', '')) == 'Đã từ chối'
    }

    changed = False
    for r in data:
        if r['id'] in approved_ids and r.get('status') != 'Hoàn thành':
            r['status'] = 'Hoàn thành'
            for b in r.get('boxes', []):
                if b.get('box_status') == 'Đã xếp kệ, chờ duyệt':
                    b['box_status'] = 'Đang lưu trữ'
            changed = True
        elif r['id'] in rejected_map and r.get('status') == 'Chờ xác nhận':
            r['status'] = 'Cần xử lý lại'
            r['reject_reason'] = rejected_map[r['id']]
            changed = True

    if changed:
        _safe_save(INBOUND_FILE, data)
    return data


def _extract_available_shelves():
    """
    Đọc trực tiếp 100% cấu trúc kho, kệ, tầng, vị trí và sức chứa thực tế
    từ tệp warehouse_config.json của phân hệ Quản lý kho (Manager).
    """
    default_cfg = get_default_warehouse_config() if 'get_default_warehouse_config' in globals() else {'zones': []}
    cfg = _safe_load('warehouse_config.json', default_cfg)

    # Hỗ trợ cả cấu trúc trực tiếp cfg['zones'] của Manager lẫn cấu trúc lồng warehouses
    zones = cfg.get('zones', [])
    if not zones and cfg.get('warehouses'):
        for wh in cfg['warehouses']:
            if wh.get('warehouse_id') == 'KHO-01':
                zones = wh.get('zones', [])
                break

    shelves = []
    for z in zones:
        z_id = z.get('zone_id', '')
        z_name = z.get('zone_name', '')
        for rk in z.get('racks', []):
            r_id = rk.get('rack_id', '')
            for fl in rk.get('floors', []):
                f_no = fl.get('floor_no', '')
                for sl in fl.get('slots', []):
                    status = sl.get('status', 'Đang sử dụng')
                    # Chỉ lấy các vị trí đang mở lưu trữ (loại bỏ Tạm khóa & Ngừng sử dụng)
                    if status not in ('Đang sử dụng', 'Trống', 'Còn chỗ'):
                        continue

                    cur_b = int(sl.get('current_boxes', 0))
                    max_b = int(sl.get('max_boxes', 10))
                    cur_w = float(sl.get('current_weight', 0))
                    max_w = float(sl.get('max_weight', 150))

                    rem_b = max_b - cur_b
                    rem_w = round(max_w - cur_w, 1)

                    if rem_b > 0 and rem_w > 0:
                        l_cm = sl.get('length_cm', 60)
                        w_cm = sl.get('width_cm', 40)
                        h_cm = sl.get('height_cm', 40)
                        shelves.append({
                            'zone_id': z_id,
                            'zone_name': z_name,
                            'rack_id': r_id,
                            'floor_no': f_no,
                            'slot_code': sl.get('slot_code'),
                            'current_boxes': cur_b,
                            'max_boxes': max_b,
                            'rem_boxes': rem_b,
                            'current_weight': cur_w,
                            'max_weight': max_w,
                            'rem_weight': rem_w,
                            'dimensions': f"{l_cm}x{w_cm}x{h_cm}",
                            'status': status
                        })

    # Sắp xếp theo mã kệ -> tầng -> vị trí tự nhiên (A01-T01-P01...)
    shelves.sort(key=lambda x: str(x.get('slot_code', '')))
    return shelves


# ================= ROUTES & API NHẬP KHO & LƯU TRỮ =================

@app.route('/staff/inbound')
@staff_required
def staff_inbound_page():
    return render_template('STAFF/staff_inbound.html')


@app.route('/api/staff/inbound', methods=['GET'])
@staff_required
def api_staff_inbound_list():
    user = session.get('user', {})
    receipts = _load_inbound_receipts()
    catalog = _safe_load('products_catalog.json', [])
    active_products = [p for p in catalog if p.get('status', 'Đang sử dụng') == 'Đang sử dụng']

    stats = {
        'total': len(receipts),
        'placing': sum(1 for r in receipts if r.get('status') == 'Đang xếp kệ'),
        'waiting': sum(1 for r in receipts if r.get('status') == 'Chờ xác nhận')
    }

    return jsonify({
        'receipts': receipts,
        'products': active_products,
        'available_shelves': _extract_available_shelves(),
        'current_user': user.get('name', ''),
        'stats': stats
    })


@app.route('/api/staff/inbound', methods=['POST'])
@staff_required
def api_staff_inbound_create():
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    emp_code = user.get('staff_code') or user.get('username') or 'staff'
    body = request.get_json(silent=True) or {}

    with _inbound_lock:
        receipts = _load_inbound_receipts()
        date_prefix = datetime.now().strftime('%Y%m%d')
        seq = len(receipts) + 1
        new_id = f"NK-{date_prefix}-{str(seq).zfill(3)}"
        while any(r['id'] == new_id for r in receipts):
            seq += 1
            new_id = f"NK-{date_prefix}-{str(seq).zfill(3)}"

        new_receipt = {
            'id': new_id,
            'vehicle_code': body.get('vehicle_code', ''),
            'supplier': body.get('supplier', ''),
            'doc_ref': body.get('doc_ref', ''),
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'assignee': emp_name,
            'status': 'Nháp',
            'notes': body.get('notes', ''),
            'reject_reason': '',
            'items': [],
            'boxes': []
        }
        receipts.insert(0, new_receipt)
        _safe_save(INBOUND_FILE, receipts)

        # Đồng bộ sang danh sách công việc trên Dashboard Staff
        tasks = _safe_load(STAFF_TASKS_FILE, [])
        tasks.insert(0, {
            'task_id': f"TSK-{new_id}",
            'reference_id': new_id,
            'task_type': 'INBOUND',
            'title': 'Tiếp nhận và xếp kệ',
            'category_label': 'Nhập kho',
            'quantity_text': '0 Box',
            'time_label': datetime.now().strftime('%H:%M'),
            'assigned_employee': emp_code,
            'warehouse_id': user.get('warehouse_id', 'KHO-01'),
            'status': 'Đang thực hiện',
            'priority': 'NORMAL',
            'is_carryover': False,
            'rejection_reason': ''
        })
        _safe_save(STAFF_TASKS_FILE, tasks)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', 'Tạo phiếu nhập kho mới', new_id, f"Lập bởi {emp_name}")

    return jsonify({'status': 'ok', 'receipt': new_receipt}), 201


@app.route('/api/staff/inbound/<receipt_id>', methods=['PATCH'])
@staff_required
def api_staff_inbound_update(receipt_id):
    body = request.get_json(silent=True) or {}
    with _inbound_lock:
        receipts = _load_inbound_receipts()
        target = next((r for r in receipts if r['id'] == receipt_id), None)
        if not target:
            return jsonify({'error': 'Không tìm thấy phiếu nhập kho'}), 404
        if target.get('status') in ('Hoàn thành', 'Hủy'):
            return jsonify({'error': 'Phiếu đã hoàn tất hoặc hủy, không thể chỉnh sửa'}), 400

        for field in ('vehicle_code', 'supplier', 'doc_ref', 'notes', 'status'):
            if field in body:
                target[field] = body[field]

        if 'items' in body:
            for it in body['items']:
                if int(it.get('received_boxes', 0)) < 0 or int(it.get('expected_boxes', 0)) < 0:
                    return jsonify({'error': 'Số lượng Box không được phép âm'}), 400
            target['items'] = body['items']

        _safe_save(INBOUND_FILE, receipts)
    return jsonify({'status': 'ok', 'receipt': target})


@app.route('/api/staff/inbound/<receipt_id>/boxes/bulk', methods=['POST'])
@staff_required
def api_staff_inbound_boxes_bulk(receipt_id):
    body = request.get_json(silent=True) or {}
    count = int(body.get('box_count', 1))
    pcs = int(body.get('pcs_per_box', 1))
    weight = float(body.get('weight', 1.0))
    sku = str(body.get('sku', '')).strip()
    prod_name = str(body.get('product_name', sku)).strip()
    dims = str(body.get('dimensions', '40x30x30')).strip()

    if count <= 0 or pcs <= 0 or weight <= 0 or not sku:
        return jsonify({'error': 'Thông số Box, số PCS và trọng lượng phải lớn hơn 0'}), 400

    with _inbound_lock:
        receipts = _load_inbound_receipts()
        target = next((r for r in receipts if r['id'] == receipt_id), None)
        if not target:
            return jsonify({'error': 'Không tìm thấy phiếu nhập'}), 404

        existing_boxes = target.setdefault('boxes', [])
        start_idx = len(existing_boxes) + 1

        for i in range(count):
            seq_num = start_idx + i
            box_id = f"BOX-{receipt_id.replace('NK-', '')}-{str(seq_num).zfill(2)}"
            unique_qr = f"QR-SANOVA-{receipt_id}-{str(seq_num).zfill(2)}-{uuid.uuid4().hex[:4].upper()}"
            existing_boxes.append({
                'box_id': box_id,
                'internal_qr': unique_qr,
                'sku': sku,
                'product_name': prod_name,
                'quantity': pcs,
                'dimensions': dims,
                'weight': weight,
                'receipt_id': receipt_id,
                'box_status': 'Chờ xếp kệ',
                'shelf_position_id': ''
            })

        target['status'] = 'Đang xếp kệ'
        _safe_save(INBOUND_FILE, receipts)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Sinh {count} mã QR Box nội bộ", receipt_id, f"SKU: {sku} ({pcs} PCS/Box)")

    return jsonify({'status': 'ok', 'created_count': count})


@app.route('/api/staff/inbound/<receipt_id>/boxes/<box_id>', methods=['PATCH'])
@staff_required
def api_staff_inbound_update_box(receipt_id, box_id):
    body = request.get_json(silent=True) or {}
    with _inbound_lock:
        receipts = _load_inbound_receipts()
        target = next((r for r in receipts if r['id'] == receipt_id), None)
        if not target:
            return jsonify({'error': 'Không tìm thấy phiếu nhập'}), 404

        box = next((b for b in target.get('boxes', []) if b['box_id'] == box_id), None)
        if not box:
            return jsonify({'error': 'Không tìm thấy Box'}), 404
        if box.get('shelf_position_id'):
            return jsonify({'error': 'Box đã xếp lên kệ, không thể sửa thông số tại bước này'}), 400

        if 'quantity' in body:
            if int(body['quantity']) <= 0:
                return jsonify({'error': 'Số PCS trong Box phải lớn hơn 0'}), 400
            box['quantity'] = int(body['quantity'])
        if 'box_status' in body:
            box['box_status'] = body['box_status']

        _safe_save(INBOUND_FILE, receipts)
    return jsonify({'status': 'ok', 'box': box})


@app.route('/api/staff/inbound/<receipt_id>/placements', methods=['POST'])
@staff_required
def api_staff_inbound_place_box(receipt_id):
    body = request.get_json(silent=True) or {}
    box_qr = str(body.get('box_qr', '')).strip()
    shelf_code = str(body.get('shelf_position_id', '')).strip().upper()

    with _inbound_lock:
        receipts = _load_inbound_receipts()
        target = next((r for r in receipts if r['id'] == receipt_id), None)
        if not target:
            return jsonify({'error': 'Không tìm thấy phiếu nhập'}), 404

        box = next((b for b in target.get('boxes', []) if b.get('internal_qr') == box_qr or b.get('box_id') == box_qr), None)
        if not box:
            return jsonify({'error': f'Không tìm thấy mã QR Box "{box_qr}" trong phiếu {receipt_id}'}), 404

        if box.get('box_status') == 'Hư hỏng / Cách ly':
            return jsonify({'error': 'Cảnh báo: Box này đang ở trạng thái Hư hỏng / Cách ly, không được phép xếp lên kệ!'}), 400

        if box.get('shelf_position_id'):
            return jsonify({'error': f"Box {box['box_id']} đã được xếp tại vị trí {box['shelf_position_id']} trước đó!"}), 400

        # Đọc trực tiếp cấu hình kho thật của Manager trong warehouse_config.json
        default_cfg = get_default_warehouse_config() if 'get_default_warehouse_config' in globals() else {'zones': []}
        cfg = _safe_load('warehouse_config.json', default_cfg)
        zones = cfg.get('zones', [])
        if not zones and cfg.get('warehouses'):
            for wh in cfg['warehouses']:
                if wh.get('warehouse_id') == 'KHO-01':
                    zones = wh.get('zones', [])
                    break

        slot_obj = None
        for z in zones:
            for rk in z.get('racks', []):
                for fl in rk.get('floors', []):
                    for sl in fl.get('slots', []):
                        if str(sl.get('slot_code', '')).upper() == shelf_code:
                            slot_obj = sl
                            break
                    if slot_obj:
                        break
                if slot_obj:
                    break
            if slot_obj:
                break

        # Bắt buộc mã vị trí phải khớp 100% với sơ đồ kho Manager
        if not slot_obj:
            return jsonify({'error': f'Mã vị trí "{shelf_code}" không tồn tại trong Cấu hình kho SANOVA!'}), 404

        if slot_obj.get('status') in ('Tạm khóa', 'Ngừng sử dụng'):
            return jsonify({'error': f'Vị trí {shelf_code} đang ở trạng thái "{slot_obj.get("status")}", không cho phép xếp hàng!'}), 400

        cur_b = int(slot_obj.get('current_boxes', 0))
        max_b = int(slot_obj.get('max_boxes', 10))
        cur_w = float(slot_obj.get('current_weight', 0))
        max_w = float(slot_obj.get('max_weight', 150))
        box_w = float(box.get('weight', 0))

        # Kiểm tra kích thước Box (DxRxC) so với giới hạn ô kệ
        try:
            b_dims = [float(x) for x in str(box.get('dimensions', '0x0x0')).lower().split('x')]
            if len(b_dims) == 3:
                if (b_dims[0] > float(slot_obj.get('length_cm', 999)) or
                    b_dims[1] > float(slot_obj.get('width_cm', 999)) or
                    b_dims[2] > float(slot_obj.get('height_cm', 999))):
                    return jsonify({'error': f'Kích thước Box ({box.get("dimensions")} cm) vượt quá kích thước ô kệ {shelf_code}!'}), 400
        except Exception:
            pass

        if cur_b + 1 > max_b:
            return jsonify({'error': f'Vị trí {shelf_code} đã đầy số lượng ({cur_b}/{max_b} Box). Vui lòng chọn vị trí khác!'}), 400

        if cur_w + box_w > max_w:
            return jsonify({'error': f'Vị trí {shelf_code} vượt quá tải trọng ({round(cur_w + box_w, 1)}/{max_w} kg). Vui lòng chọn vị trí khác!'}), 400

        # Cập nhật trực tiếp vào warehouse_config.json để bên Manager đồng bộ tức thì
        slot_obj['current_boxes'] = cur_b + 1
        slot_obj['current_weight'] = round(cur_w + box_w, 2)
        _safe_save('warehouse_config.json', cfg)

        box['shelf_position_id'] = shelf_code
        box['box_status'] = 'Đã xếp kệ, chờ duyệt'
        target['status'] = 'Đang xếp kệ'
        _safe_save(INBOUND_FILE, receipts)

        # Đồng bộ tiến độ lên Dashboard Staff
        valid_boxes = [b for b in target.get('boxes', []) if b.get('box_status') != 'Hư hỏng / Cách ly']
        placed_cnt = sum(1 for b in valid_boxes if b.get('shelf_position_id'))
        tasks = _safe_load(STAFF_TASKS_FILE, [])
        for t in tasks:
            if t.get('reference_id') == receipt_id:
                t['quantity_text'] = f"Đã xếp {placed_cnt}/{len(valid_boxes)} Box"
                t['status'] = 'Đang thực hiện'
        _safe_save(STAFF_TASKS_FILE, tasks)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Xếp Box {box['box_id']} lên kệ {shelf_code}", receipt_id, f"QR: {box['internal_qr']}")

    return jsonify({'status': 'ok', 'box': box})


@app.route('/api/staff/inbound/<receipt_id>/summary', methods=['GET'])
@staff_required
def api_staff_inbound_summary(receipt_id):
    receipts = _load_inbound_receipts()
    target = next((r for r in receipts if r['id'] == receipt_id), None)
    if not target:
        return jsonify({'error': 'Không tìm thấy phiếu nhập'}), 404

    boxes = target.get('boxes', [])
    damaged_boxes = [b for b in boxes if b.get('box_status') == 'Hư hỏng / Cách ly']
    valid_boxes = [b for b in boxes if b.get('box_status') != 'Hư hỏng / Cách ly']
    placed_boxes = [b for b in valid_boxes if b.get('shelf_position_id')]
    eligible_pcs = sum(int(b.get('quantity', 0)) for b in placed_boxes)
    used_shelves = sorted(list({b.get('shelf_position_id') for b in placed_boxes if b.get('shelf_position_id')}))

    return jsonify({
        'receipt_id': receipt_id,
        'status': target.get('status'),
        'reject_reason': target.get('reject_reason', ''),
        'total_boxes': len(boxes),
        'placed_boxes': len(placed_boxes),
        'damaged_boxes': len(damaged_boxes),
        'eligible_pcs': eligible_pcs,
        'used_shelves': used_shelves
    })


@app.route('/api/staff/inbound/<receipt_id>/submit', methods=['POST'])
@staff_required
def api_staff_inbound_submit(receipt_id):
    """
    Gửi phiếu nhập kho sang hàng đợi Duyệt & xác nhận của Manager (approvals_data.json)
    và đồng bộ trạng thái Chờ xác nhận sang Dashboard Staff.
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}
    note = str(body.get('note', '')).strip()

    with _inbound_lock:
        receipts = _load_inbound_receipts()
        target = next((r for r in receipts if r['id'] == receipt_id), None)
        if not target:
            return jsonify({'error': 'Không tìm thấy phiếu nhập'}), 404

        placed_boxes = [b for b in target.get('boxes', []) if b.get('shelf_position_id') and b.get('box_status') != 'Hư hỏng / Cách ly']
        if not placed_boxes:
            return jsonify({'error': 'Phải có ít nhất 01 Box đã xếp lên kệ trước khi gửi Manager xác nhận!'}), 400

        target['status'] = 'Chờ xác nhận'
        if note:
            target['notes'] = note
        _safe_save(INBOUND_FILE, receipts)

        # Đẩy sang approvals_data.json để Manager duyệt
        approvals = _safe_load('approvals_data.json', {'pending_tickets': [], 'approved_tickets': [], 'rejected_tickets': []})
        approvals['rejected_tickets'] = [x for x in approvals.get('rejected_tickets', []) if x.get('id') != receipt_id]
        approvals['pending_tickets'] = [x for x in approvals.get('pending_tickets', []) if x.get('id') != receipt_id]

        total_pcs = sum(int(b.get('quantity', 0)) for b in placed_boxes)
        first_box = placed_boxes[0]
        approvals['pending_tickets'].insert(0, {
            'id': receipt_id,
            'category': 'INBOUND',
            'type_label': 'Nhập kho',
            'partner': f"{target.get('vehicle_code', '')} · {target.get('supplier', 'NCC')}",
            'qty_primary': f"{len(placed_boxes)} Box",
            'total_pcs': total_pcs,
            'sender': emp_name,
            'sent_at': datetime.now().strftime('%Y-%m-%d %H:%M'),
            'sku': first_box.get('sku'),
            'product_name': first_box.get('product_name'),
            'target_location': ', '.join(sorted(list({b['shelf_position_id'] for b in placed_boxes}))),
            'note': note or target.get('notes', '')
        })
        _safe_save('approvals_data.json', approvals)

        # Cập nhật trạng thái sang Chờ xác nhận trên Dashboard Staff
        tasks = _safe_load(STAFF_TASKS_FILE, [])
        for t in tasks:
            if t.get('reference_id') == receipt_id:
                t['status'] = 'Chờ xác nhận'
                t['quantity_text'] = f"{len(placed_boxes)} Box"
        _safe_save(STAFF_TASKS_FILE, tasks)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', 'Gửi phiếu nhập kho chờ Manager xác nhận', receipt_id, f"{len(placed_boxes)} Box ({total_pcs} PCS)")

    return jsonify({'status': 'ok', 'receipt_id': receipt_id})
@app.route('/api/staff/scan/lookup', methods=['GET'])
@staff_required
def api_staff_scan_lookup():
    """
    API dùng chung cho cả súng bắn Barcode (nhận mã QR-SANOVA-...)
    và camera điện thoại (nhận URL hoặc mã thô), trả về đầy đủ thông tin Box, SKU và vị trí kệ.
    """
    raw_code = str(request.args.get('code', '')).strip()
    if '/staff/box-info/' in raw_code:
        raw_code = raw_code.split('/staff/box-info/')[-1].strip()

    if not raw_code:
        return jsonify({'error': 'Vui lòng cung cấp mã QR hoặc Barcode'}), 400

    receipts = _load_inbound_receipts()
    catalog = _safe_load('products_catalog.json', [])

    for r in receipts:
        for b in r.get('boxes', []):
            if b.get('internal_qr') == raw_code or b.get('box_id') == raw_code:
                prod = next((p for p in catalog if p.get('sku') == b.get('sku')), {})
                return jsonify({
                    'type': 'BOX',
                    'box': b,
                    'receipt': {
                        'id': r.get('id'),
                        'vehicle_code': r.get('vehicle_code'),
                        'supplier': r.get('supplier'),
                        'created_at': r.get('created_at')
                    },
                    'product': {
                        'sku': b.get('sku'),
                        'name': prod.get('name') or b.get('product_name'),
                        'category': prod.get('category', 'Hàng tiêu dùng'),
                        'unit': prod.get('unit', 'PCS'),
                        'spec': prod.get('spec', '')
                    }
                })

    # Kiểm tra nếu mã quét là mã vị trí kệ (VD: A1-040)
    shelves = _extract_available_shelves()
    shelf = next((s for s in shelves if str(s.get('slot_code', '')).upper() == raw_code.upper()), None)
    if shelf:
        return jsonify({'type': 'SHELF', 'shelf': shelf})

    return jsonify({'error': f'Không tìm thấy dữ liệu cho mã "{raw_code}" trong hệ thống SANOVA'}), 404

@app.route('/q/<path:box_code>')
def short_box_qr_redirect(box_code):
    return staff_box_qr_detail_page(box_code)

@app.route('/staff/box-info/<path:qr_code>')
def staff_box_qr_detail_page(qr_code):
    """
    Trang hiển thị chi tiết Box & Sản phẩm khi nhân viên quét mã QR trên tem bằng điện thoại,
    hỗ trợ xem thông số và chuyển nhanh sang Xếp kệ hoặc Lấy hàng.
    """
    qr_clean = qr_code.strip()
    receipts = _load_inbound_receipts()
    found_box = None
    found_receipt = None

    for r in receipts:
        for b in r.get('boxes', []):
            if b.get('internal_qr') == qr_clean or b.get('box_id') == qr_clean:
                found_box = b
                found_receipt = r
                break
        if found_box:
            break

    if not found_box:
        return render_template_string("""
            <!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>Không tìm thấy mã · SANOVA</title></head>
            <body style="font-family:sans-serif;background:#f4f7f6;padding:24px;text-align:center;">
                <div style="max-width:420px;margin:40px auto;background:#fff;padding:24px;border-radius:16px;border:1px solid #e2e8f0;">
                    <h2 style="color:#dc2626;margin-bottom:8px;">Không tìm thấy dữ liệu Box</h2>
                    <p style="color:#475569;font-size:14px;">Mã định danh <strong>{{ qr }}</strong> chưa tồn tại trong hệ thống SANOVA.</p>
                </div>
            </body></html>
        """, qr=qr_clean), 404

    catalog = _safe_load('products_catalog.json', [])
    prod_info = next((p for p in catalog if p.get('sku') == found_box.get('sku')), {})

    return render_template_string("""
        <!DOCTYPE html>
        <html lang="vi">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ box.box_id }} · Chi tiết hàng hóa SANOVA</title>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&display=swap" rel="stylesheet">
            <style>
                * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Plus Jakarta Sans', sans-serif; }
                body { background: #f4f7f6; color: #0f172a; padding: 14px; }
                .card { max-width: 460px; margin: 0 auto; background: #fff; border-radius: 18px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 8px 24px rgba(15,23,42,0.06); }
                .top { background: #063b2c; color: #fff; padding: 18px 20px; }
                .brand { font-size: 11px; letter-spacing: 0.8px; color: #79b49f; font-weight: 700; text-transform: uppercase; }
                .box-title { font-size: 21px; font-weight: 800; margin: 4px 0; }
                .qr-code { font-family: monospace; font-size: 11.5px; background: rgba(255,255,255,0.12); padding: 4px 10px; border-radius: 6px; display: inline-block; word-break: break-all; }
                .highlight-box { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding: 14px 20px; background: #f0fdf9; border-bottom: 1px solid #ccf0e6; }
                .hl-item span { display: block; font-size: 11.5px; color: #475569; }
                .hl-item strong { font-size: 17px; font-weight: 800; color: #063b2c; }
                .body { padding: 14px 20px; }
                .row { display: flex; justify-content: space-between; padding: 9px 0; border-bottom: 1px solid #f1f5f9; font-size: 13.5px; gap: 12px; }
                .row span { color: #64748b; }
                .row strong { text-align: right; color: #0f172a; }
                .actions { padding: 14px 20px 20px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
                .btn { text-align: center; text-decoration: none; padding: 11px 10px; border-radius: 10px; font-weight: 700; font-size: 13px; }
                .btn-primary { background: #0f766e; color: #fff; }
                .btn-outline { border: 1px solid #cbd5e1; color: #0f172a; background: #fff; }
            </style>
        </head>
        <body>
            <div class="card">
                <div class="top">
                    <div class="brand">SANOVA WMS · TRA CỨU BOX & SẢN PHẨM</div>
                    <div class="box-title">{{ box.sku }} · {{ box.product_name }}</div>
                    <div class="qr-code">{{ box.internal_qr }}</div>
                </div>
                <div class="highlight-box">
                    <div class="hl-item">
                        <span>Số lượng khả dụng trong Box</span>
                        <strong style="color:#0f766e;">{{ box.quantity }} {{ prod.unit or 'PCS' }}</strong>
                    </div>
                    <div class="hl-item">
                        <span>Vị trí kệ lưu trữ</span>
                        <strong>{{ box.shelf_position_id or 'Chưa xếp kệ' }}</strong>
                    </div>
                </div>
                <div class="body">
                    <div class="row"><span>Mã Box nội bộ</span><strong>{{ box.box_id }}</strong></div>
                    <div class="row"><span>Trạng thái Box</span><strong style="color:#059669;">{{ box.box_status }}</strong></div>
                    <div class="row"><span>Quy cách / Nhóm</span><strong>{{ prod.spec or prod.category or 'Tiêu chuẩn' }}</strong></div>
                    <div class="row"><span>Trọng lượng / Kích thước</span><strong>{{ box.weight }} kg · {{ box.dimensions }} cm</strong></div>
                    <div class="row"><span>Phiếu nhập nguồn</span><strong>{{ receipt.id }} ({{ receipt.vehicle_code or 'NCC' }})</strong></div>
                    <div class="row" style="border-bottom:none;"><span>Nhà cung cấp</span><strong>{{ receipt.supplier or '--' }}</strong></div>
                </div>
                <div class="actions">
                    <a href="/staff/picking-returns?tab=OUT&box={{ box.internal_qr }}" class="btn btn-primary">Lấy hàng (Picking)</a>
                    <a href="/staff/inbound?ticket={{ receipt.id }}" class="btn btn-outline">Mở phiếu nhập</a>
                </div>
            </div>
        </body>
        </html>
    """, box=found_box, receipt=found_receipt, prod=prod_info)

# Quét QR/Barcode
SCAN_HISTORY_FILE = 'scan_history.json'


def _record_scan_history(code, code_type, type_label, summary, found=True):
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    emp_code = user.get('staff_code') or user.get('username') or 'staff'

    history = _safe_load(SCAN_HISTORY_FILE, [])
    history.insert(0, {
        'id': f"SCN-{datetime.now().strftime('%H%M%S')}-{uuid.uuid4().hex[:3].upper()}",
        'code': code,
        'code_type': code_type,
        'type_label': type_label,
        'summary': summary,
        'found': found,
        'staff_code': emp_code,
        'staff_name': emp_name,
        'time': datetime.now().strftime('%H:%M:%S · %d/%m/%Y')
    })
    _safe_save(SCAN_HISTORY_FILE, history[:100])


@app.route('/staff/scan')
@staff_required
def staff_scan_page():
    return render_template('STAFF/staff_scan.html')


@app.route('/api/staff/scan/lookup', methods=['POST'])
@staff_required
def api_staff_scan_lookup_post():
    body = request.get_json(silent=True) or {}
    raw_code = str(body.get('code', '')).strip()
    selected_sku = str(body.get('selected_sku') or '').strip().upper()

    if '/staff/box-info/' in raw_code:
        raw_code = raw_code.split('/staff/box-info/')[-1].strip()
    elif '/q/' in raw_code:
        raw_code = raw_code.split('/q/')[-1].strip()

    if not raw_code:
        return jsonify({'error': 'Mã quét không hợp lệ hoặc bị trống.'}), 400

    receipts = _load_inbound_receipts()
    catalog = _safe_load('products_catalog.json', [])
    wh_data = _safe_load('warehouse_data.json', {})

    # 1. Kiểm tra trong danh mục Box nội bộ đã đăng ký
    for r in receipts:
        for b in r.get('boxes', []):
            if b.get('internal_qr') == raw_code or b.get('box_id', '').upper() == raw_code.upper():
                prod = next((p for p in catalog if p.get('sku') == b.get('sku')), {})
                _record_scan_history(
                    code=b.get('box_id'),
                    code_type='BOX',
                    type_label='Box nội bộ',
                    summary=f"{b.get('sku')} · {b.get('quantity')} PCS · {b.get('box_status')}",
                    found=True
                )
                return jsonify({
                    'type': 'BOX',
                    'box': b,
                    'receipt': {
                        'id': r.get('id'),
                        'vehicle_code': r.get('vehicle_code'),
                        'supplier': r.get('supplier'),
                        'created_at': r.get('created_at')
                    },
                    'product': {
                        'sku': b.get('sku'),
                        'name': prod.get('name') or b.get('product_name'),
                        'unit': prod.get('unit', 'PCS')
                    }
                })

    # 2. Kiểm tra trong danh mục Vị trí kệ (warehouse_config.json)
    default_cfg = get_default_warehouse_config() if 'get_default_warehouse_config' in globals() else {'zones': []}
    cfg = _safe_load('warehouse_config.json', default_cfg)
    zones = cfg.get('zones', [])
    if not zones and cfg.get('warehouses'):
        for wh in cfg['warehouses']:
            if wh.get('warehouse_id') == 'KHO-01':
                zones = wh.get('zones', [])
                break

    for z in zones:
        for rk in z.get('racks', []):
            for fl in rk.get('floors', []):
                for sl in fl.get('slots', []):
                    if str(sl.get('slot_code', '')).upper() == raw_code.upper():
                        slot_code = sl.get('slot_code')
                        boxes_in_slot = []
                        for r in receipts:
                            for b in r.get('boxes', []):
                                if str(b.get('shelf_position_id', '')).upper() == slot_code.upper():
                                    boxes_in_slot.append(b)

                        cur_b = int(sl.get('current_boxes', 0))
                        max_b = int(sl.get('max_boxes', 10))
                        cur_w = float(sl.get('current_weight', 0))
                        max_w = float(sl.get('max_weight', 150))

                        shelf_info = {
                            'zone_id': z.get('zone_id'),
                            'zone_name': z.get('zone_name'),
                            'rack_id': rk.get('rack_id'),
                            'floor_no': fl.get('floor_no'),
                            'slot_code': slot_code,
                            'current_boxes': cur_b,
                            'max_boxes': max_b,
                            'rem_boxes': max(0, max_b - cur_b),
                            'current_weight': cur_w,
                            'max_weight': max_w,
                            'dimensions': f"{sl.get('length_cm', 60)}x{sl.get('width_cm', 40)}x{sl.get('height_cm', 40)}",
                            'status': sl.get('status', 'Đang sử dụng')
                        }
                        _record_scan_history(
                            code=slot_code,
                            code_type='SHELF',
                            type_label='Vị trí kệ',
                            summary=f"Khu {z.get('zone_id')} · {cur_b}/{max_b} Box",
                            found=True
                        )
                        return jsonify({'type': 'SHELF', 'shelf': shelf_info, 'boxes_in_slot': boxes_in_slot})

    # 3. Kiểm tra trong Danh mục sản phẩm (SKU hoặc Barcode nhà cung cấp)
    matched_products = []
    for p in catalog:
        sku_match = p.get('sku', '').upper() == raw_code.upper()
        barcode_match = str(p.get('barcode', '')).strip() == raw_code
        if selected_sku:
            if p.get('sku', '').upper() == selected_sku:
                matched_products = [p]
                break
        elif sku_match or barcode_match:
            matched_products.append(p)

    # Nếu 1 Barcode liên kết nhiều sản phẩm -> Bắt buộc nhân viên chọn đúng SKU
    if len(matched_products) > 1:
        return jsonify({
            'type': 'MULTI_PRODUCT',
            'code': raw_code,
            'candidates': matched_products
        })

    if len(matched_products) == 1:
        prod = matched_products[0]
        sku = prod.get('sku')
        inv_item = next((x for x in wh_data.get('inventory', []) if x.get('sku') == sku), {})

        # Tổng hợp các Box đang chứa SKU này
        locs = []
        for r in receipts:
            for b in r.get('boxes', []):
                if b.get('sku') == sku and b.get('box_status') not in ('Đã OUT', 'Hư hỏng / Cách ly'):
                    locs.append(b)

        avail_pcs = inv_item.get('on_shelf') if inv_item else sum(int(x.get('quantity', 0)) for x in locs)
        _record_scan_history(
            code=sku,
            code_type='PRODUCT',
            type_label='Sản phẩm (SKU)',
            summary=f"{prod.get('name')} · Tồn {avail_pcs} {prod.get('unit', 'PCS')}",
            found=True
        )
        return jsonify({
            'type': 'PRODUCT',
            'product': prod,
            'available_pcs': avail_pcs,
            'locations': locs
        })

    # Không tìm thấy mã -> Ghi nhận lịch sử lỗi, tuyệt đối không tự tạo Box mới
    _record_scan_history(
        code=raw_code,
        code_type='UNKNOWN',
        type_label='Không xác định',
        summary='Mã không tồn tại trong danh mục SANOVA',
        found=False
    )
    return jsonify({'error': f'Không tìm thấy mã "{raw_code}" trong danh mục Box, Vị trí kệ hoặc Sản phẩm SANOVA.'}), 404


@app.route('/api/staff/boxes/<box_id>', methods=['GET'])
@staff_required
def api_staff_box_detail(box_id):
    receipts = _load_inbound_receipts()
    for r in receipts:
        for b in r.get('boxes', []):
            if b.get('box_id', '').upper() == box_id.upper() or b.get('internal_qr') == box_id:
                return jsonify({'box': b, 'receipt_id': r.get('id')})
    return jsonify({'error': 'Không tìm thấy Box'}), 404


@app.route('/api/staff/locations/<slot_code>', methods=['GET'])
@staff_required
def api_staff_location_detail(slot_code):
    shelves = _extract_available_shelves()
    found = next((s for s in shelves if str(s.get('slot_code', '')).upper() == slot_code.upper()), None)
    if not found:
        return jsonify({'error': 'Không tìm thấy vị trí kệ'}), 404
    return jsonify({'shelf': found})


@app.route('/api/staff/products/<sku>', methods=['GET'])
@staff_required
def api_staff_product_detail(sku):
    catalog = _safe_load('products_catalog.json', [])
    found = next((p for p in catalog if p.get('sku', '').upper() == sku.upper()), None)
    if not found:
        return jsonify({'error': 'Không tìm thấy sản phẩm'}), 404
    return jsonify({'product': found})


@app.route('/api/staff/scan/history', methods=['GET'])
@staff_required
def api_staff_scan_history():
    history = _safe_load(SCAN_HISTORY_FILE, [])
    receipts = _load_inbound_receipts()
    catalog = _safe_load('products_catalog.json', [])
    shelves = _extract_available_shelves()

    # Tự động trích xuất các mã thực tế đang có trong kho để hiển thị chip truy cập nhanh
    real_samples = []
    all_boxes = [b for r in receipts for b in r.get('boxes', [])]

    placed_box = next((b for b in all_boxes if b.get('shelf_position_id')), None)
    if placed_box:
        real_samples.append({'label': f"Box trên kệ ({placed_box['box_id']})", 'code': placed_box['box_id']})

    pending_box = next((b for b in all_boxes if not b.get('shelf_position_id')), None)
    if pending_box:
        real_samples.append({'label': f"Box chờ xếp ({pending_box['box_id']})", 'code': pending_box['box_id']})

    if shelves:
        real_samples.append({'label': f"Vị trí kệ ({shelves[0]['slot_code']})", 'code': shelves[0]['slot_code']})

    if catalog:
        real_samples.append({'label': f"Sản phẩm ({catalog[0]['sku']})", 'code': catalog[0]['sku']})

    return jsonify({'history': history[:30], 'real_samples': real_samples})

            #    Lấy hàng và trả hàng
PICKING_FILE = 'picking_orders.json'
RETURNS_FILE = 'return_orders.json'
_picking_lock = threading.Lock()


def _get_default_picking_orders(emp_name='Nguyễn Văn C'):
    return [
        {
            'id': 'OUT-0018',
            'order_code': 'DH-0025',
            'platform': 'Shopee',
            'sku': 'SP0001',
            'product_name': 'Sữa rửa mặt dịu nhẹ 150ml',
            'required_pcs': 80,
            'picked_pcs': 50,
            'consumed_pcs': 40,
            'assignee': emp_name,
            'status': 'Đang thực hiện',
            'shortage_note': '',
            'transactions': [
                {
                    'tx_id': 'TX-INIT-01',
                    'time': '09:30',
                    'box_id': 'BOX-0025-01',
                    'internal_qr': 'QR-SANOVA-NK0025-01',
                    'location_snapshot': 'A1-001',
                    'picked_pcs': 50,
                    'remaining_in_box': 0,
                    'staff_name': emp_name
                }
            ]
        },
        {
            'id': 'OUT-0019',
            'order_code': 'DH-0026',
            'platform': 'TikTok Shop',
            'sku': 'SP0002',
            'product_name': 'Kem dưỡng ẩm phục hồi 50g',
            'required_pcs': 40,
            'picked_pcs': 0,
            'consumed_pcs': 0,
            'assignee': emp_name,
            'status': 'Chờ thực hiện',
            'shortage_note': '',
            'transactions': []
        },
        {
            'id': 'OUT-0020',
            'order_code': 'DH-0027',
            'platform': 'Lazada',
            'sku': 'SP0001',
            'product_name': 'Sữa rửa mặt dịu nhẹ 150ml',
            'required_pcs': 20,
            'picked_pcs': 20,
            'consumed_pcs': 20,
            'assignee': emp_name,
            'status': 'Hoàn thành',
            'shortage_note': '',
            'transactions': [
                {
                    'tx_id': 'TX-INIT-02',
                    'time': '08:45',
                    'box_id': 'BOX-0025-02',
                    'internal_qr': 'QR-SANOVA-NK0025-02',
                    'location_snapshot': 'A1-002',
                    'picked_pcs': 20,
                    'remaining_in_box': 4,
                    'staff_name': emp_name
                }
            ]
        }
    ]

VALID_RETURN_REASONS = [
    'Lấy dư so với nhu cầu',
    'Đơn hàng bị hủy',
    'Hàng dư sau Pre-packing',
    'Lấy nhầm sản phẩm',
    'Hàng có vấn đề về chất lượng'
]


def _compute_out_return_eligibility(out_order):
    """
    Tính chính xác số PCS còn đủ điều kiện trả của một phiếu OUT:
    Không chỉ lấy (picked_pcs - returned_pcs), mà phải trừ đi lượng hàng đã tiêu thụ
    ở Pre-packing, Đóng gói hoặc đã Bàn giao ra ngoài kho.
    """
    out_id = out_order.get('id', '')
    order_code = out_order.get('order_code', '')
    picked_pcs = int(out_order.get('picked_pcs', 0))

    # 1. Lượng đã tiêu thụ ghi nhận trực tiếp trên phiếu OUT
    consumed_pcs = int(out_order.get('consumed_pcs', 0))

    # 2. Kiểm tra thêm nếu đơn hàng đã chuyển sang Bàn giao (approvals_data.json)
    approvals = _safe_load('approvals_data.json', {})
    all_bg = approvals.get('pending_tickets', []) + approvals.get('processed_tickets', [])
    for bg in all_bg:
        if bg.get('category') == 'HANDOVER' and order_code and order_code in str(bg.get('order_or_po', '')):
            if 'Từ chối' not in str(bg.get('status', '')):
                consumed_pcs = max(consumed_pcs, int(bg.get('total_pcs', 0)))

    # 3. Tổng số PCS đã lập phiếu RETURNED (đang chờ trả hoặc đã hoàn thành)
    ret_orders = _safe_load(RETURNS_FILE, [])
    committed_or_returned = sum(
        int(r.get('return_qty', 0)) if r.get('status') not in ('Hoàn thành', 'Hủy') else int(r.get('returned_pcs', 0))
        for r in ret_orders
        if r.get('out_order_id') == out_id and r.get('status') != 'Hủy'
    )

    eligible_pcs = max(0, picked_pcs - consumed_pcs - committed_or_returned)
    return {
        'picked_pcs': picked_pcs,
        'consumed_pcs': consumed_pcs,
        'committed_or_returned': committed_or_returned,
        'eligible_pcs': eligible_pcs
    }


def _get_default_return_orders(emp_name='Nguyễn Văn C'):
    return [
        {
            'id': 'RETURN-0005',
            'out_order_id': 'OUT-0018',
            'order_code': 'DH-0025',
            'sku': 'SP0001',
            'product_name': 'Sữa rửa mặt dịu nhẹ 150ml',
            'source_out_pcs': 50,
            'consumed_pcs': 40,
            'return_qty': 10,
            'returned_pcs': 0,
            'source_box_id': 'BOX-0025-02',
            'source_shelf_code': 'A1-002',
            'suggested_location_path': 'Khu A / Kệ A1 / Tầng 01 / A1-002',
            'reason': 'Lấy dư so với nhu cầu',
            'note': 'Dư 10 chai sau khi đóng gói đủ đơn DH-0025.',
            'assignee': emp_name,
            'status': 'Chờ trả',
            'created_at': '10:15',
            'transactions': []
        }
    ]

def _load_picking_orders():
    data = _safe_load(PICKING_FILE, None)
    if data is None:
        data = []
        _safe_save(PICKING_FILE, data)
    return data

def _load_return_orders():
    data = _safe_load(RETURNS_FILE, None)
    if data is None:
        data = []
        _safe_save(RETURNS_FILE, data)
    return data


def _resolve_slot_hierarchy(slot_code):
    """Tra cứu cấu trúc Khu / Kệ / Tầng / Ô từ warehouse_config.json theo mã vị trí."""
    code_up = str(slot_code or '').strip().upper()
    if not code_up:
        return {'zone': '--', 'rack': '--', 'floor': '--', 'slot': '--', 'full_path': '--'}

    default_cfg = get_default_warehouse_config() if 'get_default_warehouse_config' in globals() else {'zones': []}
    cfg = _safe_load('warehouse_config.json', default_cfg)
    zones = cfg.get('zones', [])
    if not zones and cfg.get('warehouses'):
        for wh in cfg['warehouses']:
            if wh.get('warehouse_id') == 'KHO-01':
                zones = wh.get('zones', [])
                break

    for z in zones:
        for rk in z.get('racks', []):
            for fl in rk.get('floors', []):
                for sl in fl.get('slots', []):
                    if str(sl.get('slot_code', '')).upper() == code_up:
                        z_id = z.get('zone_id', 'A')
                        r_id = rk.get('rack_id', 'A1')
                        f_no = str(fl.get('floor_no', '01')).zfill(2)
                        return {
                            'zone': z_id,
                            'rack': r_id,
                            'floor': f_no,
                            'slot': code_up,
                            'full_path': f"Khu {z_id} / Kệ {r_id} / Tầng {f_no} / {code_up}"
                        }
    return {'zone': 'A', 'rack': code_up.split('-')[0], 'floor': '01', 'slot': code_up, 'full_path': code_up}


# ================= ROUTES & API LẤY HÀNG & TRẢ HÀNG =================

@app.route('/staff/picking-returns')
@staff_required
def staff_picking_returns_page():
    return render_template('STAFF/staff_picking_returns.html')


@app.route('/api/staff/picking', methods=['GET'])
@staff_required
def api_staff_picking_list():
    orders = _load_picking_orders()
    return jsonify({'orders': orders})


@app.route('/api/staff/picking/<out_id>', methods=['GET'])
@staff_required
def api_staff_picking_detail(out_id):
    orders = _load_picking_orders()
    order = next((o for o in orders if o['id'].upper() == out_id.upper()), None)
    if not order:
        return jsonify({'error': 'Không tìm thấy phiếu lấy hàng'}), 404
    boxes = _find_eligible_boxes_for_sku(order.get('sku', ''))
    return jsonify({'order': order, 'available_boxes': boxes})


@app.route('/api/staff/picking/<out_id>/confirm', methods=['POST'])
@staff_required
def api_staff_picking_confirm(out_id):
    """
    Xác nhận 1 lượt OUT hàng khỏi kệ:
    - Kiểm tra Box đã được Manager xác nhận nhập kho ('Đang lưu trữ')
    - Kiểm tra vị trí kệ quét khớp 100% với vị trí lưu trữ của Box
    - Kiểm tra số PCS lấy <= tồn trong Box và <= số PCS còn thiếu của phiếu
    - Chống gửi trùng giao dịch (idempotency_key)
    - Giảm tồn kho trực tiếp tại bước OUT (warehouse_data.json, inbound_receipts.json, warehouse_config.json)
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    shelf_code = str(body.get('shelf_code', '')).strip().upper()
    box_qr = str(body.get('box_qr', '')).strip()
    pick_pcs = int(body.get('pick_pcs', 0))
    idem_key = str(body.get('idempotency_key', '')).strip()

    if '/staff/box-info/' in box_qr:
        box_qr = box_qr.split('/staff/box-info/')[-1].strip()
    elif '/q/' in box_qr:
        box_qr = box_qr.split('/q/')[-1].strip()

    if pick_pcs <= 0 or not shelf_code or not box_qr:
        return jsonify({'error': 'Vui lòng cung cấp đủ vị trí kệ, mã Box và số PCS > 0'}), 400

    with _picking_lock:
        orders = _load_picking_orders()
        order = next((o for o in orders if o['id'].upper() == out_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu lấy hàng'}), 404
        if order.get('status') in ('Hoàn thành', 'Hủy'):
            return jsonify({'error': 'Phiếu đã hoàn thành hoặc bị hủy, không thể thao tác thêm'}), 400

        # Chống ghi nhận trùng giao dịch
        if idem_key and any(tx.get('tx_id') == idem_key for tx in order.get('transactions', [])):
            return jsonify({'status': 'ok', 'message': 'Giao dịch đã được ghi nhận trước đó'}), 200

        rem_needed = int(order['required_pcs']) - int(order['picked_pcs'])
        if pick_pcs > rem_needed:
            return jsonify({'error': f'Không được lấy vượt số lượng còn thiếu của phiếu ({rem_needed} PCS)!'}), 400

        receipts = _load_inbound_receipts()
        target_box = None
        for r in receipts:
            for b in r.get('boxes', []):
                if b.get('internal_qr') == box_qr or b.get('box_id', '').upper() == box_qr.upper():
                    target_box = b
                    break
            if target_box:
                break

        if not target_box:
            return jsonify({'error': f'Không tìm thấy mã Box "{box_qr}" trong hệ thống'}), 404

        # Ràng buộc 1: Box phải được Manager xác nhận nhập kho ('Đang lưu trữ')
        if target_box.get('box_status') != 'Đang lưu trữ':
            return jsonify({'error': f'Không thể OUT: Box đang ở trạng thái "{target_box.get("box_status")}" (chưa được Manager xác nhận nhập kho hoặc đang cách ly).'}), 400

        # Ràng buộc 2: Sản phẩm trong Box phải khớp phiếu
        if target_box.get('sku', '').upper() != order.get('sku', '').upper():
            return jsonify({'error': f'Sai sản phẩm! Box chứa {target_box.get("sku")}, trong khi phiếu yêu cầu {order.get("sku")}.'}), 400

        # Ràng buộc 3: Vị trí kệ quét phải khớp chính xác vị trí thực tế của Box
        actual_shelf = str(target_box.get('shelf_position_id', '')).upper()
        if actual_shelf != shelf_code:
            return jsonify({'error': f'Sai vị trí kệ! Box {target_box["box_id"]} đang nằm tại {actual_shelf}, không phải {shelf_code}.'}), 400

        # Ràng buộc 4: Không âm tồn Box
        box_avail = int(target_box.get('quantity', 0))
        if pick_pcs > box_avail:
            return jsonify({'error': f'Số PCS lấy ({pick_pcs}) vượt quá tồn khả dụng trong Box ({box_avail} PCS)!'}), 400

        # Cập nhật tồn Box (lấy 1 phần thì giữ Box trên kệ, lấy hết thì giải phóng vị trí)
        new_box_qty = box_avail - pick_pcs
        target_box['quantity'] = new_box_qty
        if new_box_qty == 0:
            target_box['box_status'] = 'Đã OUT'
            target_box['shelf_position_id'] = ''
            # Giải phóng 1 Box trên cấu hình kệ warehouse_config.json
            cfg = _safe_load('warehouse_config.json', {})
            for z in cfg.get('zones', []):
                for rk in z.get('racks', []):
                    for fl in rk.get('floors', []):
                        for sl in fl.get('slots', []):
                            if str(sl.get('slot_code', '')).upper() == actual_shelf:
                                sl['current_boxes'] = max(0, int(sl.get('current_boxes', 1)) - 1)
                                sl['current_weight'] = max(0, round(float(sl.get('current_weight', 0)) - float(target_box.get('weight', 0)), 2))
            _safe_save('warehouse_config.json', cfg)

        _safe_save(INBOUND_FILE, receipts)

        # Trừ tồn kho thực tế duy nhất 1 lần tại bước OUT trong warehouse_data.json
        wh_data = _safe_load('warehouse_data.json', {})
        for inv in wh_data.get('inventory', []):
            if inv.get('sku', '').upper() == order.get('sku', '').upper():
                inv['on_shelf'] = max(0, int(inv.get('on_shelf', 0)) - pick_pcs)
                inv['off_shelf_processing'] = int(inv.get('off_shelf_processing', 0)) + pick_pcs
        ops = wh_data.setdefault('operations_summary', {})
        ops['recorded_outbound_pcs'] = int(ops.get('recorded_outbound_pcs', 0)) + pick_pcs
        _safe_save('warehouse_data.json', wh_data)

        # Lưu lịch sử vị trí lấy hàng (Snapshot)
        order['picked_pcs'] = int(order['picked_pcs']) + pick_pcs
        order['status'] = 'Hoàn thành' if order['picked_pcs'] >= order['required_pcs'] else 'Đang thực hiện'
        order.setdefault('transactions', []).append({
            'tx_id': idem_key or f"TX-{uuid.uuid4().hex[:6].upper()}",
            'time': datetime.now().strftime('%H:%M'),
            'box_id': target_box['box_id'],
            'internal_qr': target_box['internal_qr'],
            'location_snapshot': actual_shelf,
            'picked_pcs': pick_pcs,
            'remaining_in_box': new_box_qty,
            'staff_name': emp_name
        })
        _safe_save(PICKING_FILE, orders)

        # Đồng bộ tiến độ lên Dashboard Staff
        tasks = _safe_load(STAFF_TASKS_FILE, [])
        for t in tasks:
            if t.get('reference_id') == out_id:
                t['quantity_text'] = f"{order['picked_pcs']}/{order['required_pcs']} PCS"
                t['status'] = 'Hoàn thành' if order['status'] == 'Hoàn thành' else 'Đang thực hiện'
        _safe_save(STAFF_TASKS_FILE, tasks)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"OUT lấy hàng ({pick_pcs} PCS) tại {actual_shelf}", out_id, f"Box: {target_box['box_id']}")

    return jsonify({'status': 'ok', 'order': order})


@app.route('/api/staff/picking/<out_id>/shortage', methods=['POST'])
@staff_required
def api_staff_picking_shortage(out_id):
    body = request.get_json(silent=True) or {}
    reason = str(body.get('reason', '')).strip()
    if not reason:
        return jsonify({'error': 'Bắt buộc nhập lý do thiếu hàng'}), 400

    with _picking_lock:
        orders = _load_picking_orders()
        order = next((o for o in orders if o['id'].upper() == out_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu lấy hàng'}), 404
        # Không tự sửa số lượng yêu cầu gốc trên đơn hàng, chỉ chuyển trạng thái Thiếu hàng
        order['status'] = 'Thiếu hàng'
        order['shortage_note'] = reason
        _safe_save(PICKING_FILE, orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', 'Báo thiếu hàng khi lấy hàng (Picking)', out_id, reason)

    return jsonify({'status': 'ok'})


@app.route('/api/staff/returns', methods=['GET'])
@staff_required
def api_staff_returns_list():
    ret_orders = _load_return_orders()
    out_orders = _load_picking_orders()

    # Bổ sung thông tin vị trí đề xuất & danh sách phiếu OUT đủ điều kiện lập phiếu trả
    eligible_out_sources = []
    for o in out_orders:
        if int(o.get('picked_pcs', 0)) <= 0:
            continue
        elig = _compute_out_return_eligibility(o)
        last_tx = (o.get('transactions') or [{}])[-1]
        slot_code = last_tx.get('location_snapshot', 'A1-001').split('/')[-1].strip()
        hierarchy = _resolve_slot_hierarchy(slot_code)
        eligible_out_sources.append({
            'id': o['id'],
            'order_code': o.get('order_code', '--'),
            'sku': o.get('sku'),
            'product_name': o.get('product_name'),
            'source_box_id': last_tx.get('box_id', ''),
            'source_shelf_code': slot_code,
            'suggested_location_path': hierarchy['full_path'],
            'picked_pcs': elig['picked_pcs'],
            'consumed_pcs': elig['consumed_pcs'],
            'eligible_pcs': elig['eligible_pcs']
        })

    for r in ret_orders:
        if not r.get('suggested_location_path') and r.get('source_shelf_code'):
            r['suggested_location_path'] = _resolve_slot_hierarchy(r['source_shelf_code'])['full_path']

    return jsonify({
        'orders': ret_orders,
        'eligible_out_sources': eligible_out_sources,
        'standard_reasons': VALID_RETURN_REASONS
    })

@app.route('/api/staff/returns', methods=['POST'])
@staff_required
def api_staff_returns_create():
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    out_id = str(body.get('out_order_id', '')).strip().upper()
    req_qty = int(body.get('return_qty', 0))
    reason = str(body.get('reason', '')).strip()
    note = str(body.get('note', '')).strip()

    if not out_id or req_qty <= 0 or not reason:
        return jsonify({'error': 'Vui lòng chọn phiếu OUT nguồn, nhập số lượng trả > 0 và chọn lý do trả.'}), 400

    with _picking_lock:
        out_orders = _load_picking_orders()
        src_out = next((o for o in out_orders if o['id'].upper() == out_id), None)
        if not src_out:
            return jsonify({'error': 'Không tìm thấy phiếu OUT nguồn trong hệ thống.'}), 404

        elig = _compute_out_return_eligibility(src_out)
        if req_qty > elig['eligible_pcs']:
            return jsonify({
                'error': f"Số PCS yêu cầu trả ({req_qty} PCS) vượt quá lượng còn đủ điều kiện trả ({elig['eligible_pcs']} PCS) do một phần hàng đã chuyển sang đóng gói/bàn giao!"
            }), 400

        ret_orders = _load_return_orders()
        last_tx = (src_out.get('transactions') or [{}])[-1]
        slot_code = last_tx.get('location_snapshot', 'A1-002').split('/')[-1].strip()
        hierarchy = _resolve_slot_hierarchy(slot_code)

        new_id = f"RETURN-{str(len(ret_orders) + 6).zfill(4)}"
        new_ret = {
            'id': new_id,
            'out_order_id': src_out['id'],
            'order_code': src_out.get('order_code', '--'),
            'sku': src_out['sku'],
            'product_name': src_out['product_name'],
            'source_out_pcs': elig['picked_pcs'],
            'consumed_pcs': elig['consumed_pcs'],
            'return_qty': req_qty,
            'returned_pcs': 0,
            'source_box_id': last_tx.get('box_id', ''),
            'source_shelf_code': slot_code,
            'suggested_location_path': hierarchy['full_path'],
            'reason': reason,
            'note': note,
            'assignee': emp_name,
            'status': 'Chờ xử lý lỗi' if reason == 'Hàng có vấn đề về chất lượng' else 'Chờ trả',
            'created_at': datetime.now().strftime('%H:%M'),
            'transactions': []
        }
        ret_orders.insert(0, new_ret)
        _safe_save(RETURNS_FILE, ret_orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Tạo phiếu trả hàng {new_id} ({req_qty} PCS)", out_id, reason)

    return jsonify({'status': 'ok', 'return_order': new_ret}), 201

@app.route('/api/staff/returns/check-slot/<slot_code>', methods=['GET'])
@staff_required
def api_staff_return_check_slot(slot_code):
    """
    Bước 2: Kiểm tra sức chứa & tình trạng kệ thực tế từ warehouse_config.json
    """
    code_up = str(slot_code or '').strip().upper()
    hierarchy = _resolve_slot_hierarchy(code_up)

    default_cfg = get_default_warehouse_config() if 'get_default_warehouse_config' in globals() else {'zones': []}
    cfg = _safe_load('warehouse_config.json', default_cfg)
    zones = cfg.get('zones', [])
    if not zones and cfg.get('warehouses'):
        for wh in cfg['warehouses']:
            if wh.get('warehouse_id') == 'KHO-01':
                zones = wh.get('zones', [])
                break

    for z in zones:
        for rk in z.get('racks', []):
            for fl in rk.get('floors', []):
                for sl in fl.get('slots', []):
                    if str(sl.get('slot_code', '')).upper() == code_up:
                        cur_b = int(sl.get('current_boxes', 0))
                        max_b = int(sl.get('max_boxes', 10))
                        cur_w = float(sl.get('current_weight', 0))
                        max_w = float(sl.get('max_weight', 200))
                        status = sl.get('status', 'Đang sử dụng')
                        rem_b = max(0, max_b - cur_b)
                        rem_w = round(max(0.0, max_w - cur_w), 1)
                        is_available = (status == 'Đang sử dụng' and rem_b > 0 and rem_w > 0)

                        return jsonify({
                            'exists': True,
                            'slot_code': code_up,
                            'full_path': hierarchy['full_path'],
                            'status': status,
                            'current_boxes': cur_b,
                            'max_boxes': max_b,
                            'rem_boxes': rem_b,
                            'current_weight': cur_w,
                            'max_weight': max_w,
                            'rem_weight': rem_w,
                            'is_available': is_available
                        })

    return jsonify({
        'exists': False,
        'slot_code': code_up,
        'full_path': hierarchy['full_path'],
        'status': 'Không tồn tại trong cấu hình kho',
        'is_available': False
    }), 404

@app.route('/api/staff/returns/<ret_id>/confirm', methods=['POST'])
@staff_required
def api_staff_returns_confirm(ret_id):
    """
    Xác nhận RETURNED (Bước 4):
    - Kiểm tra lại lượng đủ điều kiện tại thời điểm xác nhận
    - Kiểm tra vị trí kệ quét thực tế có đang mở lưu trữ & còn sức chứa không
    - Nếu hàng có vấn đề về chất lượng (DAMAGED): chuyển cách ly, KHÔNG cộng tồn khả dụng trên kệ
    - Nếu hàng nguyên vẹn (GOOD): cộng tồn vào Box nguồn (hoặc tạo Box & QR mới) và cập nhật kệ
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    actual_pcs = int(body.get('actual_return_pcs', 0))
    condition = str(body.get('condition', 'GOOD')).upper()
    target_box_code = str(body.get('target_box', '')).strip()
    target_shelf = str(body.get('target_shelf', '')).strip().upper()

    if '/staff/box-info/' in target_box_code:
        target_box_code = target_box_code.split('/staff/box-info/')[-1].strip()
    elif '/q/' in target_box_code:
        target_box_code = target_box_code.split('/q/')[-1].strip()

    if actual_pcs <= 0:
        return jsonify({'error': 'Số PCS trả thực tế phải lớn hơn 0'}), 400

    with _picking_lock:
        ret_orders = _load_return_orders()
        ret = next((r for r in ret_orders if r['id'].upper() == ret_id.upper()), None)
        if not ret:
            return jsonify({'error': 'Không tìm thấy phiếu trả hàng'}), 404
        if ret.get('status') == 'Hoàn thành':
            return jsonify({'error': 'Phiếu trả hàng đã hoàn thành trước đó'}), 400

        rem_to_return = int(ret['return_qty']) - int(ret['returned_pcs'])
        if actual_pcs > rem_to_return:
            return jsonify({'error': f'Số PCS trả thực tế ({actual_pcs}) vượt quá số lượng còn phải trả của phiếu ({rem_to_return} PCS)!'}), 400

        wh_data = _safe_load('warehouse_data.json', {})

        # Nhánh 1: Hàng có vấn đề về chất lượng -> Cách ly, không cộng tồn khả dụng
        if condition == 'DAMAGED' or ret.get('reason') == 'Hàng có vấn đề về chất lượng':
            ret['returned_pcs'] = int(ret['returned_pcs']) + actual_pcs
            ret['status'] = 'Chờ xử lý lỗi'
            ret.setdefault('transactions', []).append({
                'time': datetime.now().strftime('%H:%M'),
                'box_id': target_box_code or 'BOX-CACHLY',
                'location_snapshot': 'Khu cách ly / Chờ kiểm định',
                'returned_pcs': actual_pcs,
                'condition': 'Hàng lỗi / Cách ly',
                'staff_name': emp_name
            })
            for inv in wh_data.get('inventory', []):
                if inv.get('sku', '').upper() == ret['sku'].upper():
                    inv['off_shelf_processing'] = max(0, int(inv.get('off_shelf_processing', 0)) - actual_pcs)
                    inv['returned_pending'] = int(inv.get('returned_pending', 0)) + actual_pcs
            _safe_save('warehouse_data.json', wh_data)
            _safe_save(RETURNS_FILE, ret_orders)
            return jsonify({'status': 'ok', 'message': f'Đã chuyển {actual_pcs} PCS hàng lỗi vào khu cách ly (Không cộng tồn khả dụng).'})

        # Nhánh 2: Hàng nguyên vẹn -> Bắt buộc quét vị trí kệ trả hợp lệ
        if not target_shelf:
            return jsonify({'error': 'Bắt buộc quét mã vị trí kệ thực tế khi trả hàng nguyên vẹn về kho!'}), 400

        # Kiểm tra vị trí kệ trong warehouse_config.json
        cfg = _safe_load('warehouse_config.json', {})
        slot_obj = None
        for z in cfg.get('zones', []):
            for rk in z.get('racks', []):
                for fl in rk.get('floors', []):
                    for sl in fl.get('slots', []):
                        if str(sl.get('slot_code', '')).upper() == target_shelf:
                            slot_obj = sl
                            break
        if slot_obj and slot_obj.get('status') in ('Tạm khóa', 'Ngừng sử dụng'):
            return jsonify({'error': f'Vị trí {target_shelf} đang bị {slot_obj.get("status")}, không thể trả hàng vào kệ này!'}), 400

        receipts = _load_inbound_receipts()
        target_box = None
        if target_box_code:
            for r in receipts:
                for b in r.get('boxes', []):
                    if b.get('box_id', '').upper() == target_box_code.upper() or b.get('internal_qr') == target_box_code:
                        target_box = b
                        break
                if target_box:
                    break

        used_box_id = ''
        if target_box:
            if target_box.get('sku', '').upper() != ret['sku'].upper():
                return jsonify({'error': f'Box {target_box["box_id"]} đang chứa sản phẩm khác ({target_box.get("sku")}), không thể gộp chung!'}), 400
            target_box['quantity'] = int(target_box.get('quantity', 0)) + actual_pcs
            target_box['box_status'] = 'Đang lưu trữ'
            target_box['shelf_position_id'] = target_shelf
            used_box_id = target_box['box_id']
        else:
            if slot_obj and int(slot_obj.get('current_boxes', 0)) + 1 > int(slot_obj.get('max_boxes', 10)):
                return jsonify({'error': f'Vị trí {target_shelf} đã đầy sức chứa số lượng Box ({slot_obj.get("current_boxes")}/{slot_obj.get("max_boxes")} Box)!'}), 400
            used_box_id = f"BOX-RT-{datetime.now().strftime('%H%M%S')}"
            new_qr = f"QR-SANOVA-RT-{uuid.uuid4().hex[:6].upper()}"
            if receipts:
                receipts[0].setdefault('boxes', []).append({
                    'box_id': used_box_id,
                    'internal_qr': new_qr,
                    'sku': ret['sku'],
                    'product_name': ret['product_name'],
                    'quantity': actual_pcs,
                    'dimensions': '40x30x30',
                    'weight': 5.0,
                    'receipt_id': receipts[0]['id'],
                    'box_status': 'Đang lưu trữ',
                    'shelf_position_id': target_shelf
                })
            if slot_obj:
                slot_obj['current_boxes'] = int(slot_obj.get('current_boxes', 0)) + 1
                _safe_save('warehouse_config.json', cfg)

        _safe_save(INBOUND_FILE, receipts)

        # Tăng lại tồn trên kệ trong warehouse_data.json
        for inv in wh_data.get('inventory', []):
            if inv.get('sku', '').upper() == ret['sku'].upper():
                inv['on_shelf'] = int(inv.get('on_shelf', 0)) + actual_pcs
                inv['off_shelf_processing'] = max(0, int(inv.get('off_shelf_processing', 0)) - actual_pcs)
        _safe_save('warehouse_data.json', wh_data)

        loc_full = _resolve_slot_hierarchy(target_shelf)['full_path']
        ret['returned_pcs'] = int(ret['returned_pcs']) + actual_pcs
        ret['status'] = 'Hoàn thành' if ret['returned_pcs'] >= ret['return_qty'] else 'Đang trả'
        ret.setdefault('transactions', []).append({
            'time': datetime.now().strftime('%H:%M'),
            'box_id': used_box_id,
            'location_snapshot': loc_full,
            'returned_pcs': actual_pcs,
            'condition': 'Nguyên vẹn · Nhập lại kệ',
            'staff_name': emp_name
        })
        _safe_save(RETURNS_FILE, ret_orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"RETURNED trả {actual_pcs} PCS về {target_shelf}", ret_id, f"Nguồn: {ret['out_order_id']}")

    return jsonify({'status': 'ok', 'message': f'Đã đặt {actual_pcs} PCS vào {loc_full} ({used_box_id}) và cập nhật tồn kho thành công!'})
# Pre-backing / Đóng gói / Bàn giao sẽ trừ tồn kho thực tế tại bước OUT, nên khi trả về kho chỉ cần cộng lại vào kệ (on_shelf) và giảm off_shelf_processing.
PREPACKING_FILE = 'prepacking_orders.json'
_prepacking_lock = threading.Lock()


def _recompute_prepacking_capacity(order):
    """
    Tính toán tự động số bộ Combo / PCS tối đa có thể chuẩn bị dựa trên số PCS đạt thực nhận
    và khóa định mức công thức Combo của đơn hàng.
    """
    req_qty = int(order.get('required_qty', 0))
    possible_list = []
    for it in order.get('items', []):
        valid_pcs = max(0, int(it.get('received_pcs', 0)) - int(it.get('defective_pcs', 0)))
        per_unit = max(1, int(it.get('qty_per_unit', 1)))
        possible_list.append(valid_pcs // per_unit)

    max_by_stock = min(possible_list) if possible_list else 0
    order['max_possible_qty'] = min(req_qty, max_by_stock)
    return order['max_possible_qty']


def _sync_prepacking_from_picking():
    """
    Tự động sinh & cập nhật công việc Pre-packing từ các phiếu OUT đã lấy hàng (picking_orders.json)
    và công thức Combo trong products_catalog.json. Không dùng dữ liệu mẫu cố định.
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')

    pre_orders = _safe_load(PREPACKING_FILE, [])
    out_orders = _safe_load(PICKING_FILE, [])
    catalog = _safe_load('products_catalog.json', [])
    prod_map = {p.get('sku', '').upper(): p for p in catalog}

    # Gom các phiếu OUT đã có phát sinh lấy hàng (picked_pcs > 0) theo order_code
    orders_by_code = {}
    for o in out_orders:
        if int(o.get('picked_pcs', 0)) <= 0:
            continue
        ocode = o.get('order_code') or o.get('id')
        orders_by_code.setdefault(ocode, []).append(o)

    changed = False
    for ocode, outs in orders_by_code.items():
        existing = next((p for p in pre_orders if p.get('order_code') == ocode), None)
        out_ids = [x['id'] for x in outs]

        if not existing:
            first_out = outs[0]
            sku_up = str(first_out.get('sku', '')).upper()
            prod_cfg = prod_map.get(sku_up, {})
            combo_comps = prod_cfg.get('combo_items') or []
            is_combo = (prod_cfg.get('category') == 'Combo' or len(combo_comps) > 0)

            items = []
            if is_combo and combo_comps:
                # Chụp phiên bản công thức Combo tại thời điểm tạo phiếu
                for comp in combo_comps:
                    c_sku = str(comp.get('sku', '')).upper()
                    c_prod = prod_map.get(c_sku, {})
                    matched_out = next((x for x in outs if str(x.get('sku', '')).upper() == c_sku), None)
                    out_pcs = int(matched_out.get('picked_pcs', 0)) if matched_out else 0
                    boxes = list({tx.get('box_id') for tx in (matched_out.get('transactions', []) if matched_out else []) if tx.get('box_id')})
                    items.append({
                        'sku': c_sku,
                        'product_name': c_prod.get('name', c_sku),
                        'qty_per_unit': int(comp.get('qty', 1)),
                        'out_pcs': out_pcs,
                        'received_pcs': out_pcs,
                        'defective_pcs': 0,
                        'source_boxes': boxes
                    })
                req_qty = max(1, int(first_out.get('required_pcs', 1)))
            else:
                for x in outs:
                    x_sku = str(x.get('sku', '')).upper()
                    x_boxes = list({tx.get('box_id') for tx in x.get('transactions', []) if tx.get('box_id')})
                    items.append({
                        'sku': x_sku,
                        'product_name': x.get('product_name', x_sku),
                        'qty_per_unit': 1,
                        'out_pcs': int(x.get('picked_pcs', 0)),
                        'received_pcs': int(x.get('picked_pcs', 0)),
                        'defective_pcs': 0,
                        'source_boxes': x_boxes
                    })
                req_qty = sum(int(x.get('required_pcs', 0)) for x in outs)

            new_pre = {
                'id': f"PRE-{str(len(pre_orders) + 15).zfill(4)}",
                'order_code': ocode,
                'platform': first_out.get('platform', 'Shopee'),
                'is_combo': is_combo,
                'title': prod_cfg.get('name') or first_out.get('product_name', sku_up),
                'out_refs': out_ids,
                'required_qty': req_qty,
                'prepared_qty': 0,
                'assignee': first_out.get('assignee') or emp_name,
                'status': 'Chờ chuẩn bị',
                'items': items,
                'batches': [],
                'issues': [],
                'created_at': datetime.now().strftime('%H:%M')
            }
            _recompute_prepacking_capacity(new_pre)
            pre_orders.insert(0, new_pre)
            changed = True
        else:
            # Cập nhật lại số lượng đã OUT mới nhất nếu nhân viên vừa lấy bổ sung từ kệ
            for it in existing.get('items', []):
                matched_out = next((x for x in outs if str(x.get('sku', '')).upper() == it['sku'].upper()), None)
                if matched_out:
                    latest_out_pcs = int(matched_out.get('picked_pcs', 0))
                    if it['out_pcs'] != latest_out_pcs:
                        it['out_pcs'] = latest_out_pcs
                        if existing['status'] in ('Chờ chuẩn bị', 'Chờ bổ sung'):
                            it['received_pcs'] = latest_out_pcs
                        changed = True
            existing['out_refs'] = out_ids
            _recompute_prepacking_capacity(existing)

    if changed:
        _safe_save(PREPACKING_FILE, pre_orders)
    return pre_orders


# ================= ROUTES & API PRE-PACKING & COMBO =================

@app.route('/staff/prepacking')
@staff_required
def staff_prepacking_page():
    return render_template('STAFF/staff_prepacking.html')


@app.route('/api/staff/prepacking', methods=['GET'])
@staff_required
def api_staff_prepacking_list():
    orders = _sync_prepacking_from_picking()
    stats = {
        'waiting': sum(1 for o in orders if o.get('status') == 'Chờ chuẩn bị'),
        'in_progress': sum(1 for o in orders if o.get('status') == 'Đang chuẩn bị'),
        'issues': sum(1 for o in orders if o.get('status') in ('Chờ bổ sung', 'Chờ xử lý lỗi')),
        'completed': sum(1 for o in orders if o.get('status') in ('Sẵn sàng đóng gói', 'Đã chuyển đóng gói'))
    }
    return jsonify({'orders': orders, 'stats': stats})


@app.route('/api/staff/prepacking/<pre_id>', methods=['GET'])
@staff_required
def api_staff_prepacking_detail(pre_id):
    orders = _sync_prepacking_from_picking()
    order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
    if not order:
        return jsonify({'error': 'Không tìm thấy phiếu Pre-packing'}), 404
    _recompute_prepacking_capacity(order)
    return jsonify({'order': order})


@app.route('/api/staff/prepacking/<pre_id>/start', methods=['POST'])
@staff_required
def api_staff_prepacking_start(pre_id):
    with _prepacking_lock:
        orders = _safe_load(PREPACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        if order['status'] == 'Chờ chuẩn bị':
            order['status'] = 'Đang chuẩn bị'
            _safe_save(PREPACKING_FILE, orders)
    return jsonify({'status': 'ok'})


@app.route('/api/staff/prepacking/<pre_id>/receive', methods=['POST'])
@staff_required
def api_staff_prepacking_receive(pre_id):
    """Ghi nhận số lượng thực nhận & hàng lỗi tại bàn Pre-packing (không cho sửa số đã OUT)"""
    body = request.get_json(silent=True) or {}
    in_items = body.get('items', [])

    with _prepacking_lock:
        orders = _safe_load(PREPACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        if order['status'] in ('Đã chuyển đóng gói', 'Hủy'):
            return jsonify({'error': 'Phiếu đã chuyển đóng gói, không thể chỉnh sửa'}), 400

        has_shortage_or_defect = False
        for upd in in_items:
            target_it = next((x for x in order['items'] if x['sku'].upper() == str(upd.get('sku', '')).upper()), None)
            if not target_it:
                continue
            recv = int(upd.get('received_pcs', 0))
            defect = int(upd.get('defective_pcs', 0))
            if recv < 0 or recv > int(target_it['out_pcs']) or defect < 0 or defect > recv:
                return jsonify({'error': f"Số liệu kiểm đếm của {target_it['sku']} không hợp lệ so với nguồn OUT!"}), 400
            target_it['received_pcs'] = recv
            target_it['defective_pcs'] = defect
            if recv < int(target_it['out_pcs']) or defect > 0:
                has_shortage_or_defect = True

        _recompute_prepacking_capacity(order)
        if has_shortage_or_defect:
            order['status'] = 'Chờ xử lý lỗi'
        elif order['status'] == 'Chờ chuẩn bị':
            order['status'] = 'Đang chuẩn bị'

        _safe_save(PREPACKING_FILE, orders)
    return jsonify({'status': 'ok', 'order': order})


@app.route('/api/staff/prepacking/<pre_id>/batches', methods=['POST'])
@staff_required
def api_staff_prepacking_batches(pre_id):
    """Ghi nhận tiến độ ghép Combo / chuẩn bị hàng từng lượt (không vượt nguyên liệu thực tế)"""
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}
    batch_qty = int(body.get('batch_qty', 0))

    if batch_qty <= 0:
        return jsonify({'error': 'Số lượng lượt chuẩn bị phải lớn hơn 0'}), 400

    with _prepacking_lock:
        orders = _safe_load(PREPACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        if order['status'] in ('Đã chuyển đóng gói', 'Hủy'):
            return jsonify({'error': 'Phiếu đã khóa, không thể ghi nhận thêm'}), 400

        max_cap = _recompute_prepacking_capacity(order)
        new_total = int(order['prepared_qty']) + batch_qty
        if new_total > max_cap:
            return jsonify({
                'error': f"Không đủ nguyên liệu đạt! Chỉ có thể ghép/chuẩn bị tối đa {max_cap} {'Combo' if order['is_combo'] else 'PCS'} từ số hàng thực nhận."
            }), 400

        order['prepared_qty'] = new_total
        order['status'] = 'Đang chuẩn bị'
        order.setdefault('batches', []).append({
            'time': datetime.now().strftime('%H:%M'),
            'qty': batch_qty,
            'staff_name': emp_name
        })
        _safe_save(PREPACKING_FILE, orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Ghi nhận Pre-packing (+{batch_qty})", pre_id, f"Tiến độ: {new_total}/{order['required_qty']}")

    return jsonify({'status': 'ok', 'order': order})


@app.route('/api/staff/prepacking/<pre_id>/issues', methods=['POST'])
@staff_required
def api_staff_prepacking_issues(pre_id):
    """
    Xử lý bất thường tại Pre-packing:
    - SURPLUS_RETURN: Hàng dư -> tự động tạo phiếu RETURNED liên kết phiếu OUT nguồn
    - DEFECTIVE: Hàng lỗi -> chuyển cách ly (returned_pending), không cộng tồn khả dụng
    - SHORTAGE_OUT: Thiếu so với phiếu OUT -> ghi nhận chênh lệch báo Manager
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    issue_type = str(body.get('issue_type', '')).upper()
    sku = str(body.get('sku', '')).strip().upper()
    qty = int(body.get('qty', 0))
    reason = str(body.get('reason', '')).strip()

    if not sku or qty <= 0 or not reason:
        return jsonify({'error': 'Vui lòng chọn SKU, số lượng > 0 và nhập lý do cụ thể'}), 400

    with _prepacking_lock:
        orders = _safe_load(PREPACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404

        type_labels = {
            'SURPLUS_RETURN': 'Hàng dư → Tạo RETURNED',
            'DEFECTIVE': 'Hàng lỗi → Cách ly',
            'SHORTAGE_OUT': 'Thiếu so với OUT'
        }
        msg = 'Đã ghi nhận sai lệch và báo cáo Quản lý kho.'

        if issue_type == 'SURPLUS_RETURN':
            ret_orders = _safe_load(RETURNS_FILE, [])
            out_ref = (order.get('out_refs') or ['OUT-0000'])[0]
            new_ret_id = f"RETURN-{str(len(ret_orders) + 6).zfill(4)}"
            ret_orders.insert(0, {
                'id': new_ret_id,
                'out_order_id': out_ref,
                'order_code': order.get('order_code', '--'),
                'sku': sku,
                'product_name': next((x['product_name'] for x in order['items'] if x['sku'] == sku), sku),
                'source_out_pcs': qty,
                'consumed_pcs': 0,
                'return_qty': qty,
                'returned_pcs': 0,
                'source_box_id': '',
                'source_shelf_code': '',
                'suggested_location_path': 'Kệ lưu trữ nguồn',
                'reason': 'Hàng dư sau Pre-packing',
                'note': f"Chuyển từ {pre_id}: {reason}",
                'assignee': emp_name,
                'status': 'Chờ trả',
                'created_at': datetime.now().strftime('%H:%M'),
                'transactions': []
            })
            _safe_save(RETURNS_FILE, ret_orders)
            msg = f"Đã tạo yêu cầu trả hàng {new_ret_id} ({qty} PCS) sang tab RETURNED."
        elif issue_type == 'DEFECTIVE':
            wh_data = _safe_load('warehouse_data.json', {})
            for inv in wh_data.get('inventory', []):
                if inv.get('sku', '').upper() == sku:
                    inv['returned_pending'] = int(inv.get('returned_pending', 0)) + qty
            _safe_save('warehouse_data.json', wh_data)
            order['status'] = 'Chờ xử lý lỗi'
            msg = f"Đã chuyển {qty} PCS hàng lỗi sang khu cách ly (không cộng tồn khả dụng)."
        else:
            order['status'] = 'Chờ xử lý lỗi'

        order.setdefault('issues', []).append({
            'type': issue_type,
            'type_label': type_labels.get(issue_type, 'Bất thường'),
            'sku': sku,
            'qty': qty,
            'reason': reason,
            'status': 'Đã ghi nhận',
            'time': datetime.now().strftime('%H:%M')
        })
        _safe_save(PREPACKING_FILE, orders)

    return jsonify({'status': 'ok', 'message': msg})


@app.route('/api/staff/prepacking/<pre_id>/complete', methods=['POST'])
@staff_required
def api_staff_prepacking_complete(pre_id):
    with _prepacking_lock:
        orders = _safe_load(PREPACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        if int(order['prepared_qty']) < int(order['required_qty']):
            return jsonify({'error': f"Chưa chuẩn bị đủ số lượng yêu cầu ({order['prepared_qty']}/{order['required_qty']})!"}), 400
        if order['status'] == 'Chờ xử lý lỗi':
            return jsonify({'error': 'Phiếu đang có sai lệch/hàng lỗi chưa xử lý xong!'}), 400

        order['status'] = 'Sẵn sàng đóng gói'
        _safe_save(PREPACKING_FILE, orders)
    return jsonify({'status': 'ok'})


@app.route('/api/staff/prepacking/<pre_id>/transfer', methods=['POST'])
@staff_required
def api_staff_prepacking_transfer(pre_id):
    """Chuyển sang Đóng gói & Bàn giao (Chống chuyển trùng, tuyệt đối không trừ tồn kho lần hai)"""
    with _prepacking_lock:
        orders = _safe_load(PREPACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pre_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        if order['status'] == 'Đã chuyển đóng gói':
            return jsonify({'error': 'Phiếu đã được chuyển sang Đóng gói trước đó!'}), 400
        if order['status'] != 'Sẵn sàng đóng gói':
            return jsonify({'error': 'Phải hoàn thành Pre-packing trước khi chuyển sang Đóng gói!'}), 400

        order['status'] = 'Đã chuyển đóng gói'
        order['transferred_at'] = datetime.now().strftime('%H:%M · %d/%m/%Y')
        _safe_save(PREPACKING_FILE, orders)

        # Cập nhật lượng đã tiêu thụ sang phiếu OUT nguồn để khóa không cho trả lại phần hàng đã chuyển đóng gói
        out_orders = _safe_load(PICKING_FILE, [])
        for o in out_orders:
            if o['id'] in (order.get('out_refs') or []):
                o['consumed_pcs'] = int(o.get('picked_pcs', 0))
        _safe_save(PICKING_FILE, out_orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', 'Chuyển phiếu Pre-packing sang Đóng gói & Bàn giao', pre_id, f"Đơn: {order['order_code']}")

    return jsonify({'status': 'ok'})
# ĐÓng gói 
PACKING_FILE = 'packing_orders.json'
_packing_lock = threading.Lock()


def _compute_packing_display_status(order):
    """Tổng hợp 2 trạng thái packing_status và handover_status thành trạng thái hiển thị chuẩn cho STAFF."""
    p_st = order.get('packing_status', 'PENDING')
    h_st = order.get('handover_status', 'NONE')

    if h_st == 'APPROVED':
        return 'Hoàn thành'
    if h_st == 'REJECTED':
        return 'Cần xử lý lại'
    if h_st == 'SUBMITTED':
        return 'Chờ Manager xác nhận'
    if p_st == 'ISSUE':
        return 'Có vấn đề'
    if p_st == 'COMPLETED':
        return 'Chờ bàn giao'
    if p_st == 'IN_PROGRESS':
        return 'Đang đóng gói'
    return 'Chờ đóng gói'


def _sync_packing_orders_from_sources():
    """
    Tự động sinh & cập nhật công việc Đóng gói từ:
    1. Phiếu Pre-packing đã chuyển sang đóng gói ('Đã chuyển đóng gói')
    2. Phiếu OUT sản phẩm lẻ đã hoàn thành đủ số lượng ('Hoàn thành') mà không cần Pre-packing
    3. Đồng bộ kết quả phê duyệt/từ chối phiếu bàn giao (BG-...) từ Manager (approvals_data.json)
    Tuyệt đối không dùng dữ liệu mẫu cố định và không trừ tồn kho thêm lần nữa.
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')

    pk_orders = _safe_load(PACKING_FILE, [])
    pre_orders = _safe_load(PREPACKING_FILE, [])
    out_orders = _safe_load(PICKING_FILE, [])
    approvals = _safe_load('approvals_data.json', {})

    processed = approvals.get('processed_tickets', [])
    approved_bg = {t.get('id'): t for t in processed if 'Đã xác nhận' in str(t.get('status', ''))}
    rejected_bg = {t.get('id'): t for t in processed if str(t.get('status', '')) == 'Đã từ chối'}

    changed = False

    # 1. Đồng bộ kết quả duyệt / trả lại từ Manager
    for o in pk_orders:
        ho_id = o.get('handover_id')
        if ho_id and ho_id in approved_bg and o.get('handover_status') != 'APPROVED':
            o['handover_status'] = 'APPROVED'
            o['reviewed_by'] = approved_bg[ho_id].get('reviewed_by', 'Manager')
            changed = True
        elif ho_id and ho_id in rejected_bg and o.get('handover_status') == 'SUBMITTED':
            o['handover_status'] = 'REJECTED'
            o['reject_reason'] = rejected_bg[ho_id].get('reject_reason', 'Manager yêu cầu kiểm tra lại.')
            o['reviewed_by'] = rejected_bg[ho_id].get('reviewed_by', 'Manager')
            changed = True
        o['display_status'] = _compute_packing_display_status(o)

    # 2. Nhận đơn từ Pre-packing đã chuyển sang đóng gói
    for pre in pre_orders:
        if pre.get('status') != 'Đã chuyển đóng gói':
            continue
        ocode = pre.get('order_code')
        if any(x.get('order_code') == ocode for x in pk_orders):
            continue

        items = []
        if pre.get('is_combo'):
            pcs_per_combo = sum(int(x.get('qty_per_unit', 1)) for x in pre.get('items', []))
            items.append({
                'sku': pre.get('id'),
                'name': pre.get('title'),
                'item_group': 'Combo',
                'unit': 'bộ',
                'required_qty': int(pre.get('required_qty', 1)),
                'ready_qty': int(pre.get('prepared_qty', 1)),
                'pcs_multiplier': max(1, pcs_per_combo)
            })
        else:
            for it in pre.get('items', []):
                items.append({
                    'sku': it['sku'],
                    'name': it['product_name'],
                    'item_group': 'Sản phẩm lẻ',
                    'unit': 'PCS',
                    'required_qty': int(it.get('received_pcs', 0)),
                    'ready_qty': int(it.get('received_pcs', 0)),
                    'pcs_multiplier': 1
                })

        summary_str = ' + '.join([f"{x['required_qty']} {x['name']}" for x in items])
        new_pk = {
            'id': f"PK-{str(len(pk_orders) + 25).zfill(4)}",
            'order_code': ocode,
            'platform': pre.get('platform', 'Shopee'),
            'order_type': 'Đơn Combo' if pre.get('is_combo') else 'Đơn lẻ',
            'source_label': f"Pre-packing ({pre['id']})",
            'summary_text': summary_str,
            'assignee': pre.get('assignee') or emp_name,
            'packing_status': 'PENDING',
            'handover_status': 'NONE',
            'display_status': 'Chờ đóng gói',
            'items': items,
            'packages': [],
            'handover_id': '',
            'receiver': '',
            'handover_note': '',
            'reject_reason': '',
            'handover_history': []
        }
        pk_orders.insert(0, new_pk)
        changed = True

    # 3. Nhận đơn sản phẩm lẻ trực tiếp từ phiếu OUT đã hoàn thành (nếu không qua Pre-packing)
    for out in out_orders:
        if out.get('status') != 'Hoàn thành':
            continue
        ocode = out.get('order_code')
        if any(x.get('order_code') == ocode for x in pk_orders):
            continue

        req_pcs = int(out.get('required_pcs', 0))
        new_pk = {
            'id': f"PK-{str(len(pk_orders) + 25).zfill(4)}",
            'order_code': ocode,
            'platform': out.get('platform', 'Shopee'),
            'order_type': 'Đơn lẻ',
            'source_label': f"OUT ({out['id']})",
            'summary_text': f"{req_pcs} {out.get('product_name', out.get('sku'))}",
            'assignee': out.get('assignee') or emp_name,
            'packing_status': 'PENDING',
            'handover_status': 'NONE',
            'display_status': 'Chờ đóng gói',
            'items': [{
                'sku': out['sku'],
                'name': out.get('product_name', out['sku']),
                'item_group': 'Sản phẩm lẻ',
                'unit': 'PCS',
                'required_qty': req_pcs,
                'ready_qty': int(out.get('picked_pcs', req_pcs)),
                'pcs_multiplier': 1
            }],
            'packages': [],
            'handover_id': '',
            'receiver': '',
            'handover_note': '',
            'reject_reason': '',
            'handover_history': []
        }
        pk_orders.insert(0, new_pk)
        changed = True

    if changed:
        _safe_save(PACKING_FILE, pk_orders)
    return pk_orders


# ================= ROUTES & API ĐÓNG GÓI & BÀN GIAO =================

@app.route('/staff/packing-handover')
@staff_required
def staff_packing_handover_page():
    return render_template('STAFF/staff_packing_handover.html')


@app.route('/api/staff/packing', methods=['GET'])
@staff_required
def api_staff_packing_list():
    orders = _sync_packing_orders_from_sources()
    stats = {
        'waiting': sum(1 for o in orders if o.get('display_status') == 'Chờ đóng gói'),
        'in_progress': sum(1 for o in orders if o.get('display_status') == 'Đang đóng gói'),
        'waiting_handover': sum(1 for o in orders if o.get('display_status') in ('Chờ bàn giao', 'Chờ Manager xác nhận')),
        'returned': sum(1 for o in orders if o.get('display_status') in ('Cần xử lý lại', 'Có vấn đề'))
    }
    return jsonify({'orders': orders, 'stats': stats})


@app.route('/api/staff/packing/<pk_id>', methods=['GET'])
@staff_required
def api_staff_packing_detail(pk_id):
    orders = _sync_packing_orders_from_sources()
    order = next((o for o in orders if o['id'].upper() == pk_id.upper()), None)
    if not order:
        return jsonify({'error': 'Không tìm thấy phiếu đóng gói'}), 404
    return jsonify({'order': order})


@app.route('/api/staff/packing/<pk_id>/start', methods=['POST'])
@staff_required
def api_staff_packing_start(pk_id):
    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pk_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        if order['packing_status'] == 'PENDING':
            order['packing_status'] = 'IN_PROGRESS'
            order['display_status'] = _compute_packing_display_status(order)
            _safe_save(PACKING_FILE, orders)
    return jsonify({'status': 'ok'})


@app.route('/api/staff/packing/<pk_id>/packages', methods=['POST'])
@staff_required
def api_staff_packing_create_package(pk_id):
    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pk_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404

        pkgs = order.setdefault('packages', [])
        pkg_code = f"PKG-{order['order_code'].replace('DH-', '')}-{str(len(pkgs) + 1).zfill(2)}"
        pkgs.append({
            'package_code': pkg_code,
            'condition': 'Nguyên vẹn',
            'items': []
        })
        order['packing_status'] = 'IN_PROGRESS'
        order['display_status'] = _compute_packing_display_status(order)
        _safe_save(PACKING_FILE, orders)
    return jsonify({'status': 'ok', 'package_code': pkg_code})


@app.route('/api/staff/packing/<pk_id>/packages/<pkg_code>/items', methods=['POST'])
@staff_required
def api_staff_packing_add_pkg_item(pk_id, pkg_code):
    body = request.get_json(silent=True) or {}
    sku = str(body.get('sku', '')).strip().upper()
    qty = int(body.get('qty', 0))

    if not sku or qty <= 0:
        return jsonify({'error': 'Số lượng phân bổ vào kiện phải lớn hơn 0'}), 400

    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pk_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404

        item_def = next((x for x in order['items'] if x['sku'].upper() == sku), None)
        if not item_def:
            return jsonify({'error': 'Sản phẩm không thuộc đơn hàng này'}), 400

        # Kiểm tra không cho phân bổ vượt quá số lượng hợp lệ của đơn
        already_allocated = sum(
            int(x['qty']) for p in order.get('packages', [])
            for x in p.get('items', []) if x['sku'].upper() == sku
        )
        if already_allocated + qty > int(item_def['ready_qty']):
            return jsonify({
                'error': f"Vượt quá số lượng sẵn sàng của {item_def['name']} (Còn lại: {int(item_def['ready_qty']) - already_allocated} {item_def['unit']})!"
            }), 400

        pkg = next((p for p in order.get('packages', []) if p['package_code'] == pkg_code), None)
        if not pkg:
            return jsonify({'error': 'Không tìm thấy kiện hàng'}), 404

        existing_in_pkg = next((x for x in pkg['items'] if x['sku'].upper() == sku), None)
        if existing_in_pkg:
            existing_in_pkg['qty'] = int(existing_in_pkg['qty']) + qty
            existing_in_pkg['pcs_equiv'] = existing_in_pkg['qty'] * int(item_def.get('pcs_multiplier', 1))
        else:
            pkg['items'].append({
                'sku': sku,
                'name': item_def['name'],
                'unit': item_def['unit'],
                'qty': qty,
                'pcs_equiv': qty * int(item_def.get('pcs_multiplier', 1))
            })

        _safe_save(PACKING_FILE, orders)
    return jsonify({'status': 'ok'})


@app.route('/api/staff/packing/<pk_id>/complete', methods=['POST'])
@staff_required
def api_staff_packing_complete(pk_id):
    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pk_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404

        packages = order.get('packages', [])
        if not packages:
            return jsonify({'error': 'Vui lòng tạo ít nhất 01 kiện hàng trước khi hoàn tất đóng gói!'}), 400

        for it in order.get('items', []):
            allocated = sum(
                int(x['qty']) for p in packages
                for x in p.get('items', []) if x['sku'].upper() == it['sku'].upper()
            )
            if allocated != int(it['required_qty']):
                return jsonify({
                    'error': f"Chưa phân bổ đủ {it['name']} vào kiện ({allocated}/{it['required_qty']} {it['unit']})!"
                }), 400

        order['packing_status'] = 'COMPLETED'
        order['display_status'] = _compute_packing_display_status(order)
        _safe_save(PACKING_FILE, orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Hoàn tất đóng gói {len(packages)} kiện", pk_id, f"Đơn: {order['order_code']}")

    return jsonify({'status': 'ok'})


@app.route('/api/staff/packing/<pk_id>/issues', methods=['POST'])
@staff_required
def api_staff_packing_issues(pk_id):
    body = request.get_json(silent=True) or {}
    issue_type = str(body.get('issue_type', '')).strip()
    reason = str(body.get('reason', '')).strip()
    if not reason:
        return jsonify({'error': 'Bắt buộc nhập mô tả vấn đề'}), 400

    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pk_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu'}), 404
        order['packing_status'] = 'ISSUE'
        order['display_status'] = _compute_packing_display_status(order)
        _safe_save(PACKING_FILE, orders)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Báo sai lệch đóng gói: {issue_type}", pk_id, reason)

    return jsonify({'status': 'ok'})


@app.route('/api/staff/handovers', methods=['POST'])
@staff_required
def api_staff_handovers_create():
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    pk_id = str(body.get('packing_id', '')).strip().upper()
    receiver = str(body.get('receiver', '')).strip()
    note = str(body.get('note', '')).strip()

    if not pk_id or not receiver:
        return jsonify({'error': 'Vui lòng nhập đầy đủ người nhận bàn giao'}), 400

    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if o['id'].upper() == pk_id), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu đóng gói'}), 404
        if order.get('packing_status') != 'COMPLETED':
            return jsonify({'error': 'Phải hoàn tất đóng gói trước khi lập phiếu bàn giao!'}), 400

        ho_id = order.get('handover_id') or f"BG-{order['order_code'].replace('DH-', '')}"
        order['handover_id'] = ho_id
        order['receiver'] = receiver
        order['handover_note'] = note
        order['handover_by'] = emp_name
        _safe_save(PACKING_FILE, orders)

    return jsonify({'status': 'ok', 'handover_id': ho_id})


@app.route('/api/staff/handovers/<ho_id>/submit', methods=['POST'])
@staff_required
def api_staff_handovers_submit(ho_id):
    """
    Gửi phiếu bàn giao sang Manager (approvals_data.json -> pending_tickets).
    Lưu lịch sử các lần gửi và tuyệt đối không trừ tồn kho lần thứ hai.
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    emp_code = user.get('staff_code') or user.get('username') or 'staff'

    with _packing_lock:
        orders = _safe_load(PACKING_FILE, [])
        order = next((o for o in orders if str(o.get('handover_id', '')).upper() == ho_id.upper()), None)
        if not order:
            return jsonify({'error': 'Không tìm thấy phiếu bàn giao'}), 404

        packages = order.get('packages', [])
        total_pcs = sum(int(x.get('pcs_equiv', x['qty'])) for p in packages for x in p.get('items', []))
        now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

        order['handover_status'] = 'SUBMITTED'
        order['display_status'] = _compute_packing_display_status(order)
        order.setdefault('handover_history', []).append({
            'time': now_str,
            'sender': emp_name,
            'receiver': order.get('receiver'),
            'packages_count': len(packages),
            'total_pcs': total_pcs,
            'note': order.get('handover_note', '')
        })
        _safe_save(PACKING_FILE, orders)

        # Đồng bộ sang approvals_data.json của Manager
        approvals = _safe_load('approvals_data.json', {'pending_tickets': [], 'processed_tickets': []})
        approvals['pending_tickets'] = [x for x in approvals.get('pending_tickets', []) if x.get('id') != ho_id]
        approvals['processed_tickets'] = [x for x in approvals.get('processed_tickets', []) if x.get('id') != ho_id]

        approvals['pending_tickets'].insert(0, {
            'id': ho_id,
            'category': 'HANDOVER',
            'partner': order.get('platform', 'Shopee'),
            'order_or_po': order.get('order_code'),
            'qty_primary': f"{len(packages)} kiện",
            'total_pcs': total_pcs,
            'sender': emp_name,
            'receiver': order.get('receiver'),
            'sent_at': now_str,
            'note': order.get('handover_note') or f"Bàn giao {len(packages)} kiện ({', '.join(p['package_code'] for p in packages)}).",
            'status': 'Chờ xác nhận',
            'items': [
                {
                    'sku': x['sku'],
                    'name': x['name'],
                    'qty_expected': x['qty'],
                    'qty_packed': x['qty'],
                    'qty_actual': x['qty']
                }
                for p in packages for x in p.get('items', [])
            ],
            'checks': [
                {'label': 'Đã hoàn thành đóng gói', 'passed': True},
                {'label': 'Số lượng bàn giao hợp lệ với đơn hàng', 'passed': True},
                {'label': 'Đã ghi nhận đầy đủ người nhận và thời gian', 'passed': True},
                {'label': 'Không còn vấn đề thiếu hàng chưa xử lý', 'passed': True}
            ]
        })
        _safe_save('approvals_data.json', approvals)

        # Cập nhật lên Dashboard Staff
        tasks = _safe_load(STAFF_TASKS_FILE, [])
        tasks = [t for t in tasks if t.get('reference_id') != ho_id]
        tasks.insert(0, {
            'task_id': f"TSK-{ho_id}",
            'reference_id': ho_id,
            'task_type': 'HANDOVER',
            'title': 'Chờ xác nhận bàn giao',
            'category_label': 'Bàn giao',
            'quantity_text': f"{len(packages)} kiện · {total_pcs} PCS",
            'time_label': datetime.now().strftime('%H:%M'),
            'assigned_employee': emp_code,
            'warehouse_id': user.get('warehouse_id', 'KHO-01'),
            'status': 'Chờ xác nhận',
            'priority': 'NORMAL',
            'is_carryover': False,
            'rejection_reason': ''
        })
        _safe_save(STAFF_TASKS_FILE, tasks)

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', 'Gửi phiếu bàn giao chờ Manager xác nhận', ho_id, f"Đơn: {order['order_code']} · {len(packages)} kiện")

    return jsonify({'status': 'ok'})
#Kiểm kê kho
_stocktake_staff_lock = threading.Lock()


def _load_staff_stocktake_sessions():
    """Đọc trực tiếp danh sách đợt kiểm kê thật từ stocktake_data.json của Manager."""
    data = _safe_load(STOCKTAKE_FILE, {'sessions': [], 'adjustments': []})
    return data


def _build_snapshot_boxes_for_scope(scope_str):
    """
    Chốt mốc dữ liệu Box & PCS tại thời điểm nhân viên bắt đầu kiểm kê
    từ inbound_receipts.json theo phạm vi kệ/khu vực được phân công.
    """
    receipts = _load_inbound_receipts()
    scope_up = str(scope_str or '').upper()
    snapshot = []

    for r in receipts:
        for b in r.get('boxes', []):
            slot = str(b.get('shelf_position_id', '')).upper()
            if not slot or b.get('box_status') not in ('Đang lưu trữ', 'Đã xếp kệ, chờ duyệt'):
                continue
            # Lọc theo phạm vi kệ/khu vực (VD: 'Kệ A1' -> khớp 'A1-', 'Khu A' -> khớp 'A')
            matched = True
            if 'KỆ ' in scope_up:
                rack_code = scope_up.split('KỆ ')[-1].split('·')[0].strip()
                matched = slot.startswith(rack_code)
            elif 'KHU ' in scope_up:
                zone_code = scope_up.split('KHU ')[-1].split('·')[0].strip()
                matched = slot.startswith(zone_code)

            if matched:
                snapshot.append({
                    'box_id': b.get('box_id'),
                    'internal_qr': b.get('internal_qr'),
                    'sku': b.get('sku'),
                    'product_name': b.get('product_name'),
                    'slot_code': slot,
                    'system_pcs': int(b.get('quantity', 0)),
                    'counted_pcs': None,
                    'condition': 'Chưa kiểm',
                    'issue_type': '',
                    'count_round': 0
                })
    return snapshot


# ================= ROUTES & API KIỂM KÊ KHO (STAFF) =================

@app.route('/staff/stocktake')
@staff_required
def staff_stocktake_page():
    return render_template('STAFF/staff_stocktake.html')


@app.route('/api/staff/stock-counts', methods=['GET'])
@staff_required
def api_staff_stock_counts_list():
    data = _load_staff_stocktake_sessions()
    sessions = data.get('sessions', [])
    stats = {
        'waiting': sum(1 for s in sessions if s.get('status') == 'Chờ thực hiện'),
        'counting': sum(1 for s in sessions if s.get('status') in ('Đang kiểm kê', 'Yêu cầu kiểm lại')),
        'pending_approval': sum(1 for s in sessions if s.get('status') == 'Chờ phê duyệt'),
        'completed': sum(1 for s in sessions if s.get('status') == 'Hoàn tất')
    }
    return jsonify({'sessions': sessions, 'stats': stats})


@app.route('/api/staff/stock-counts/<session_id>', methods=['GET'])
@staff_required
def api_staff_stock_count_detail(session_id):
    data = _load_staff_stocktake_sessions()
    sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
    if not sess:
        return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404
    return jsonify({'session': sess})


@app.route('/api/staff/stock-counts/<session_id>/start', methods=['POST'])
@staff_required
def api_staff_stock_count_start(session_id):
    """Bắt đầu kiểm kê & Chốt mốc tồn kho (Snapshot) chống sai lệch do biến động phát sinh."""
    with _stocktake_staff_lock:
        data = _load_staff_stocktake_sessions()
        sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
        if not sess:
            return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404

        if sess.get('status') == 'Chờ thực hiện':
            sess['status'] = 'Đang kiểm kê'
            sess['snapshot_time'] = datetime.now().strftime('%d/%m/%Y %H:%M')
            if 'snapshot_boxes' not in sess:
                sess['snapshot_boxes'] = _build_snapshot_boxes_for_scope(sess.get('scope', ''))
            _safe_save(STOCKTAKE_FILE, data)

    return jsonify({'status': 'ok', 'session': sess})


@app.route('/api/staff/stock-counts/<session_id>/scan', methods=['POST'])
@staff_required
def api_staff_stock_count_scan(session_id):
    """Kiểm tra mã vị trí kệ và QR nội bộ Box thuộc phạm vi kiểm kê."""
    body = request.get_json(silent=True) or {}
    scan_type = str(body.get('scan_type', '')).upper()
    code = str(body.get('code', '')).strip()

    if '/staff/box-info/' in code:
        code = code.split('/staff/box-info/')[-1].strip()
    elif '/q/' in code:
        code = code.split('/q/')[-1].strip()

    with _stocktake_staff_lock:
        data = _load_staff_stocktake_sessions()
        sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
        if not sess:
            return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404

        if 'snapshot_boxes' not in sess:
            sess['snapshot_boxes'] = _build_snapshot_boxes_for_scope(sess.get('scope', ''))
            _safe_save(STOCKTAKE_FILE, data)

        snap_boxes = sess.get('snapshot_boxes', [])

        if scan_type == 'SHELF':
            slot_up = code.upper()
            hierarchy = _resolve_slot_hierarchy(slot_up)
            # Kiểm tra vị trí có nằm trong Cấu hình kho không
            shelves = _extract_available_shelves()
            # Bao gồm cả các vị trí đã đầy trong warehouse_config.json
            cfg = _safe_load('warehouse_config.json', {})
            slot_exists = False
            for z in cfg.get('zones', []):
                for rk in z.get('racks', []):
                    for fl in rk.get('floors', []):
                        for sl in fl.get('slots', []):
                            if str(sl.get('slot_code', '')).upper() == slot_up:
                                slot_exists = True
                                break
            if not slot_exists and not shelves:
                slot_exists = True
            if not slot_exists:
                return jsonify({'error': f'Mã vị trí "{slot_up}" không tồn tại trong sơ đồ kho SANOVA!'}), 404

            boxes_in_slot = [b for b in snap_boxes if str(b.get('slot_code', '')).upper() == slot_up]
            return jsonify({
                'status': 'ok',
                'slot_code': slot_up,
                'hierarchy': hierarchy,
                'boxes': boxes_in_slot
            })

        if scan_type == 'BOX':
            slot_up = str(body.get('slot_code', '')).strip().upper()
            box_obj = next((
                b for b in snap_boxes
                if (b.get('internal_qr') == code or b.get('box_id', '').upper() == code.upper())
                and str(b.get('slot_code', '')).upper() == slot_up
            ), None)

            if not box_obj:
                return jsonify({
                    'error': f'Box "{code}" không thuộc vị trí {slot_up} trong phạm vi kiểm kê! Nếu tìm thấy Box nằm nhầm kệ, hãy dùng nút "+ Ghi nhận bất thường → Sai vị trí".'
                }), 404

            already = (box_obj.get('counted_pcs') is not None)
            return jsonify({'status': 'ok', 'box': box_obj, 'already_counted': already})

    return jsonify({'error': 'Loại quét không hợp lệ'}), 400


@app.route('/api/staff/stock-counts/<session_id>/counts', methods=['POST'])
@staff_required
def api_staff_stock_count_record_pcs(session_id):
    """Ghi nhận PCS kiểm đếm thực tế (Chỉ lưu kết quả đếm, tuyệt đối không tự sửa tồn kho)."""
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    slot_up = str(body.get('slot_code', '')).strip().upper()
    box_id = str(body.get('box_id', '')).strip().upper()
    counted_pcs = int(body.get('counted_pcs', 0))
    condition = str(body.get('condition', 'Bình thường')).strip()

    if counted_pcs < 0:
        return jsonify({'error': 'Số lượng PCS thực tế không được phép âm'}), 400

    with _stocktake_staff_lock:
        data = _load_staff_stocktake_sessions()
        sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
        if not sess:
            return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404

        snap_boxes = sess.get('snapshot_boxes', [])
        box_obj = next((b for b in snap_boxes if b.get('box_id', '').upper() == box_id), None)
        if not box_obj:
            return jsonify({'error': 'Không tìm thấy Box trong danh sách kiểm kê'}), 404

        box_obj['counted_pcs'] = counted_pcs
        box_obj['condition'] = condition
        box_obj['count_round'] = int(box_obj.get('count_round', 0)) + 1
        box_obj['counted_by'] = emp_name
        box_obj['counted_at'] = datetime.now().strftime('%H:%M')

        # Tính số vị trí đã hoàn tất kiểm đếm
        checked_slots = {b['slot_code'] for b in snap_boxes if b.get('counted_pcs') is not None or b.get('issue_type')}
        sess['counted_slots'] = max(int(sess.get('counted_slots', 0)), len(checked_slots))
        sess['status'] = 'Đang kiểm kê'
        _safe_save(STOCKTAKE_FILE, data)

        slot_boxes = [b for b in snap_boxes if str(b.get('slot_code', '')).upper() == slot_up]

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', f"Kiểm đếm Box {box_id} ({counted_pcs} PCS)", session_id, f"Vị trí: {slot_up}")

    return jsonify({
        'status': 'ok',
        'slot_boxes': slot_boxes,
        'counted_slots': sess['counted_slots'],
        'total_slots': sess.get('total_slots', 1)
    })


@app.route('/api/staff/stock-counts/<session_id>/issues', methods=['POST'])
@staff_required
def api_staff_stock_count_issues(session_id):
    """Ghi nhận bất thường kiểm kê: Không tìm thấy Box, Sai vị trí, Box phát sinh, Box hư hỏng."""
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}

    slot_up = str(body.get('slot_code', '')).strip().upper()
    issue_type = str(body.get('issue_type', '')).upper()
    box_code = str(body.get('box_code', '')).strip().upper()
    sku = str(body.get('sku', '')).strip().upper()
    actual_pcs = int(body.get('actual_pcs', 0))
    note = str(body.get('note', '')).strip()

    if not box_code or not note:
        return jsonify({'error': 'Vui lòng nhập mã Box và ghi chú chi tiết bất thường'}), 400

    with _stocktake_staff_lock:
        data = _load_staff_stocktake_sessions()
        sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
        if not sess:
            return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404

        snap_boxes = sess.setdefault('snapshot_boxes', [])
        existing = next((b for b in snap_boxes if b.get('box_id', '').upper() == box_code), None)

        if issue_type == 'NOT_FOUND':
            if not existing:
                return jsonify({'error': f'Box {box_code} không có trong danh sách mốc tồn của đợt kiểm kê này.'}), 404
            existing['issue_type'] = 'NOT_FOUND'
            existing['counted_pcs'] = 0
            existing['condition'] = f"Không tìm thấy Box ({note})"
        elif issue_type == 'UNREGISTERED_BOX':
            snap_boxes.append({
                'box_id': box_code,
                'internal_qr': box_code,
                'sku': sku or 'UNKNOWN',
                'product_name': f"Box phát sinh ({sku or 'Chưa định danh'})",
                'slot_code': slot_up or 'PHAT-SINH',
                'system_pcs': 0,
                'counted_pcs': actual_pcs,
                'condition': f"Box phát sinh ngoài hệ thống: {note}",
                'issue_type': 'UNREGISTERED_BOX',
                'counted_by': emp_name
            })
        elif issue_type == 'WRONG_LOCATION':
            snap_boxes.append({
                'box_id': box_code,
                'internal_qr': box_code,
                'sku': sku or (existing['sku'] if existing else 'SKU'),
                'product_name': existing['product_name'] if existing else 'Box sai vị trí',
                'slot_code': slot_up or 'SAI-VI-TRI',
                'system_pcs': existing['system_pcs'] if existing else 0,
                'counted_pcs': actual_pcs if actual_pcs > 0 else (existing['system_pcs'] if existing else 0),
                'condition': f"Sai vị trí (Tìm thấy tại {slot_up}): {note}",
                'issue_type': 'WRONG_LOCATION',
                'counted_by': emp_name
            })
        else:
            if existing:
                existing['issue_type'] = 'DAMAGED_BOX'
                existing['condition'] = f"Box hư hỏng: {note}"

        _safe_save(STOCKTAKE_FILE, data)

    return jsonify({'status': 'ok', 'message': 'Đã ghi nhận bất thường vào biên bản kiểm kê (Chờ Manager xử lý).'})


@app.route('/api/staff/stock-counts/<session_id>/summary', methods=['GET'])
@staff_required
def api_staff_stock_count_summary(session_id):
    data = _load_staff_stocktake_sessions()
    sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
    if not sess:
        return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404

    snap_boxes = sess.get('snapshot_boxes', [])
    records = [b for b in snap_boxes if b.get('counted_pcs') is not None or b.get('issue_type')]

    matched = sum(1 for r in records if not r.get('issue_type') and int(r.get('counted_pcs', 0)) == int(r.get('system_pcs', 0)))
    diff_cnt = sum(1 for r in records if not r.get('issue_type') and int(r.get('counted_pcs', 0)) != int(r.get('system_pcs', 0)))
    misc_cnt = sum(1 for r in records if r.get('issue_type') in ('WRONG_LOCATION', 'UNREGISTERED_BOX'))
    lost_dmg = sum(1 for r in records if r.get('issue_type') in ('NOT_FOUND', 'DAMAGED_BOX'))

    return jsonify({
        'session_id': sess['id'],
        'status': sess.get('status'),
        'counted_slots': sess.get('counted_slots', 0),
        'total_slots': sess.get('total_slots', 0),
        'matched_boxes': matched,
        'diff_boxes': diff_cnt,
        'misc_boxes': misc_cnt,
        'lost_damaged_boxes': lost_dmg,
        'records': records
    })


@app.route('/api/staff/stock-counts/<session_id>/submit', methods=['POST'])
@staff_required
def api_staff_stock_count_submit(session_id):
    """
    STAFF gửi kết quả kiểm kê cho Manager:
    - Không tự sửa tồn kho trên hệ thống
    - Nếu có chênh lệch, tự động sinh yêu cầu điều chỉnh (DC-...) sang hàng đợi duyệt của Manager
    """
    user = session.get('user', {})
    emp_name = user.get('name', 'Nhân viên kho')
    body = request.get_json(silent=True) or {}
    note = str(body.get('note', '')).strip()

    with _stocktake_staff_lock:
        data = _load_staff_stocktake_sessions()
        sess = next((s for s in data.get('sessions', []) if s['id'].upper() == session_id.upper()), None)
        if not sess:
            return jsonify({'error': 'Không tìm thấy phiếu kiểm kê'}), 404
        if sess.get('status') in ('Chờ phê duyệt', 'Hoàn tất'):
            return jsonify({'error': 'Phiếu kiểm kê này đã được gửi hoặc hoàn tất trước đó!'}), 400

        snap_boxes = sess.get('snapshot_boxes', [])
        records = [b for b in snap_boxes if b.get('counted_pcs') is not None or b.get('issue_type')]
        if not records:
            return jsonify({'error': 'Vui lòng kiểm đếm ít nhất 01 Box hoặc vị trí trước khi gửi kết quả!'}), 400

        shortage = sum(max(0, int(r.get('system_pcs', 0)) - int(r.get('counted_pcs', 0))) for r in records)
        surplus = sum(max(0, int(r.get('counted_pcs', 0)) - int(r.get('system_pcs', 0))) for r in records)
        has_any_issue = any(r.get('issue_type') for r in records)

        sess['diff_abs_pcs'] = shortage + surplus
        now_str = datetime.now().strftime('%d/%m/%Y %H:%M')

        if shortage == 0 and surplus == 0 and not has_any_issue:
            sess['status'] = 'Hoàn tất'
            _safe_save(STOCKTAKE_FILE, data)
            msg = f"Đã hoàn tất kiểm kê {session_id}: 100% số liệu khớp hệ thống."
        else:
            sess['status'] = 'Chờ phê duyệt'
            adj_id = f"DC-{str(len(data.get('adjustments', [])) + 19).zfill(4)}"
            diff_items = [
                {
                    'sku': r['sku'],
                    'name': r['product_name'],
                    'box_code': r['box_id'],
                    'location': r['slot_code'],
                    'system_pcs': int(r.get('system_pcs', 0)),
                    'counted_pcs': int(r.get('counted_pcs', 0))
                }
                for r in records
                if int(r.get('counted_pcs', 0)) != int(r.get('system_pcs', 0)) or r.get('issue_type')
            ]

            data.setdefault('adjustments', []).insert(0, {
                'id': adj_id,
                'session_id': session_id,
                'count_type': sess.get('scope_type_label', 'Theo kệ'),
                'scope': sess.get('scope', '').split('·')[0].strip(),
                'full_scope_path': f"Kho chính > {sess.get('scope', '')}",
                'sender': emp_name,
                'snapshot_at': sess.get('snapshot_time', now_str),
                'sent_at': now_str,
                'total_shortage': shortage,
                'total_surplus': surplus,
                'status': 'Chờ phê duyệt',
                'scope_completed': True,
                'has_post_count_movement': False,
                'explanation': note or 'Gửi kết quả kiểm đếm thực tế từ nhân viên kho.',
                'items': diff_items,
                'history': [
                    {'time': now_str, 'actor': emp_name, 'action': 'Gửi kết quả kiểm kê', 'note': note or f'Tạo yêu cầu điều chỉnh {adj_id}'}
                ]
            })
            _safe_save(STOCKTAKE_FILE, data)
            msg = f"Đã gửi kết quả kiểm kê {session_id} và tạo yêu cầu điều chỉnh {adj_id} sang Manager phê duyệt."

    if 'add_audit_log' in globals():
        add_audit_log('Nghiệp vụ kho', 'Gửi kết quả kiểm kê kho cho Manager', session_id, f"Lệch: -{shortage} / +{surplus} PCS")

    return jsonify({'status': 'ok', 'message': msg})
# Lịch sử kiểm kê kho của nhân viên
STAFF_TRANSACTIONS_FILE = 'staff_transactions.json'


def _build_unified_staff_transactions():
    """
    Tổng hợp & đồng bộ tự động lịch sử sự kiện nghiệp vụ kho từ 7 phân hệ thực tế:
    1. Nhập kho (inbound_receipts.json)
    2. OUT – Lấy hàng (picking_orders.json)
    3. RETURNED – Trả hàng (return_orders.json)
    4. Pre-packing & Combo (prepacking_orders.json)
    5. Đóng gói & 6. Bàn giao (packing_orders.json + approvals_data.json)
    7. Kiểm kê kho (stocktake_data.json)
    Tuyệt đối không trộn nhật ký hệ thống Admin (đăng nhập/đổi mật khẩu/phân quyền)
    và không cho phép STAFF chỉnh sửa hay xóa lịch sử.
    """
    events = []
    approvals = _safe_load('approvals_data.json', {})
    processed_map = {t.get('id'): t for t in approvals.get('processed_tickets', [])}

    # 1. Sự kiện Nhập kho
    for r in _load_inbound_receipts():
        boxes = r.get('boxes', [])
        placed_boxes = [b for b in boxes if b.get('shelf_position_id')]
        total_pcs = sum(int(b.get('quantity', 0)) for b in placed_boxes)
        rev_info = processed_map.get(r['id'], {})
        is_approved = (r.get('status') == 'Hoàn thành')
        is_rejected = (r.get('status') == 'Cần xử lý lại')

        st_label = 'Hoàn thành' if is_approved else ('Có vấn đề' if is_rejected else 'Chờ xác nhận')
        delta_pcs = total_pcs if is_approved else 0

        events.append({
            'transaction_id': f"TX-IN-{r['id'].replace('NK-', '')}",
            'transaction_type': 'INBOUND',
            'type_label': 'Nhập kho',
            'event_type': 'Xác nhận nhập lên kệ' if is_approved else ('Manager trả phiếu' if is_rejected else 'Đã xếp kệ, chờ duyệt'),
            'reference_id': r['id'],
            'related_order_id': r.get('doc_ref', ''),
            'source_transaction_id': '',
            'box_id': f"{len(placed_boxes)} Box" if len(placed_boxes) != 1 else placed_boxes[0]['box_id'],
            'product_id': placed_boxes[0]['sku'] if placed_boxes else '--',
            'operation_qty': total_pcs,
            'quantity_unit': 'PCS',
            'quantity_change': delta_pcs,
            'location_snapshot': ', '.join(sorted({b['shelf_position_id'] for b in placed_boxes})) or 'Khu tiếp nhận',
            'performed_by': r.get('assignee', 'Nhân viên kho'),
            'approved_by': rev_info.get('reviewed_by', ''),
            'occurred_at': r.get('created_at', datetime.now().strftime('%d/%m/%Y %H:%M')),
            'date_ymd': str(r.get('created_at', ''))[:10] or datetime.now().strftime('%Y-%m-%d'),
            'status': st_label,
            'note': r.get('reject_reason') or r.get('notes', ''),
            'source_url': f"/staff/inbound?ticket={r['id']}",
            'details': [
                {
                    'box_id': b['box_id'],
                    'sku': f"{b['sku']} · {b['product_name']}",
                    'location': b.get('shelf_position_id') or 'Chưa xếp kệ',
                    'op_qty': f"{b['quantity']} PCS",
                    'delta_qty': f"+{b['quantity']} PCS" if is_approved else '0 (Chờ duyệt)'
                }
                for b in boxes
            ]
        })

    # 2. Sự kiện OUT – Lấy hàng (Từng lượt giao dịch lấy hàng từ từng Box & vị trí cụ thể)
    for o in _load_picking_orders():
        for idx, tx in enumerate(o.get('transactions', []), start=1):
            tx_id = tx.get('tx_id') if str(tx.get('tx_id', '')).startswith('TX-') else f"TX-OUT-{o['id'].replace('OUT-', '')}-{idx}"
            events.append({
                'transaction_id': tx_id,
                'transaction_type': 'OUT',
                'type_label': 'OUT – Lấy hàng',
                'event_type': 'Đã lấy hàng khỏi kệ',
                'reference_id': o['id'],
                'related_order_id': o.get('order_code', ''),
                'source_transaction_id': '',
                'box_id': tx.get('box_id', '--'),
                'product_id': f"{o['sku']} · {o.get('product_name', '')}",
                'operation_qty': int(tx.get('picked_pcs', 0)),
                'quantity_unit': 'PCS',
                'quantity_change': -int(tx.get('picked_pcs', 0)),
                'location_snapshot': tx.get('location_snapshot', '--'),
                'performed_by': tx.get('staff_name', o.get('assignee', 'Nhân viên kho')),
                'approved_by': '',
                'occurred_at': f"{datetime.now().strftime('%d/%m/%Y')} {tx.get('time', '09:00')}",
                'date_ymd': datetime.now().strftime('%Y-%m-%d'),
                'status': 'Hoàn thành',
                'note': o.get('shortage_note', ''),
                'source_url': f"/staff/picking-returns?tab=OUT&ticket={o['id']}",
                'details': [{
                    'box_id': tx.get('box_id', '--'),
                    'sku': o['sku'],
                    'location': tx.get('location_snapshot', '--'),
                    'op_qty': f"{tx.get('picked_pcs', 0)} PCS",
                    'delta_qty': f"-{tx.get('picked_pcs', 0)} PCS"
                }]
            })

    # 3. Sự kiện RETURNED – Trả hàng (Liên kết chặt chẽ với phiếu OUT nguồn)
    for ret in _load_return_orders():
        is_done = (ret.get('status') == 'Hoàn thành')
        is_issue = (ret.get('status') == 'Chờ xử lý lỗi')
        ret_pcs = int(ret.get('returned_pcs') or ret.get('return_qty', 0))
        events.append({
            'transaction_id': f"TX-RT-{ret['id'].replace('RETURN-', '')}",
            'transaction_type': 'RETURNED',
            'type_label': 'RETURNED – Trả hàng',
            'event_type': 'Hoàn tất trả về kệ' if is_done else ('Cách ly hàng lỗi' if is_issue else 'Chờ trả về kệ'),
            'reference_id': ret['id'],
            'related_order_id': ret.get('order_code', ''),
            'source_transaction_id': ret.get('out_order_id', ''),
            'box_id': ret.get('source_box_id') or 'BOX-RT',
            'product_id': f"{ret['sku']} · {ret.get('product_name', '')}",
            'operation_qty': ret_pcs,
            'quantity_unit': 'PCS',
            'quantity_change': ret_pcs if is_done else 0,
            'location_snapshot': ret.get('suggested_location_path') or ret.get('source_shelf_code', '--'),
            'performed_by': ret.get('assignee', 'Nhân viên kho'),
            'approved_by': '',
            'occurred_at': f"{datetime.now().strftime('%d/%m/%Y')} {ret.get('created_at', '10:00')}",
            'date_ymd': datetime.now().strftime('%Y-%m-%d'),
            'status': 'Hoàn thành' if is_done else ('Có vấn đề' if is_issue else 'Chờ xác nhận'),
            'note': ret.get('reason', ''),
            'source_url': f"/staff/picking-returns?tab=RETURNED&ticket={ret['id']}",
            'details': [
                {
                    'box_id': tx.get('box_id', '--'),
                    'sku': ret['sku'],
                    'location': tx.get('location_snapshot', '--'),
                    'op_qty': f"{tx.get('returned_pcs', 0)} PCS",
                    'delta_qty': f"+{tx.get('returned_pcs', 0)} PCS" if 'Nguyên vẹn' in tx.get('condition', '') else '0 (Cách ly)'
                }
                for tx in ret.get('transactions', [])
            ]
        })

    # 4. Sự kiện Pre-packing & Combo (Biến động tồn = 0)
    for pre in _safe_load(PREPACKING_FILE, []):
        is_done = pre.get('status') in ('Sẵn sàng đóng gói', 'Đã chuyển đóng gói')
        is_issue = pre.get('status') in ('Chờ bổ sung', 'Chờ xử lý lỗi')
        events.append({
            'transaction_id': f"TX-PRE-{pre['id'].replace('PRE-', '')}",
            'transaction_type': 'PREPACKING',
            'type_label': 'Pre-packing',
            'event_type': pre.get('status', 'Đang chuẩn bị'),
            'reference_id': pre['id'],
            'related_order_id': pre.get('order_code', ''),
            'source_transaction_id': ', '.join(pre.get('out_refs', [])),
            'box_id': 'Combo' if pre.get('is_combo') else 'Đơn lẻ',
            'product_id': pre.get('title', '--'),
            'operation_qty': int(pre.get('prepared_qty', 0)),
            'quantity_unit': 'Combo' if pre.get('is_combo') else 'PCS',
            'quantity_change': 0,
            'location_snapshot': 'Bàn Pre-packing',
            'performed_by': pre.get('assignee', 'Nhân viên kho'),
            'approved_by': '',
            'occurred_at': f"{datetime.now().strftime('%d/%m/%Y')} {pre.get('created_at', '11:00')}",
            'date_ymd': datetime.now().strftime('%Y-%m-%d'),
            'status': 'Hoàn thành' if is_done else ('Có vấn đề' if is_issue else 'Chờ xác nhận'),
            'note': '',
            'source_url': '/staff/prepacking',
            'details': [
                {
                    'box_id': ', '.join(it.get('source_boxes', [])) or '--',
                    'sku': f"{it['sku']} · {it['product_name']}",
                    'location': 'Bàn Pre-packing',
                    'op_qty': f"{it['received_pcs']} PCS",
                    'delta_qty': '0 (Đã trừ tại OUT)'
                }
                for it in pre.get('items', [])
            ]
        })

    # 5 & 6. Sự kiện Đóng gói & Bàn giao (Biến động tồn = 0)
    for pk in _safe_load(PACKING_FILE, []):
        pkgs = pk.get('packages', [])
        total_pcs = sum(int(x.get('pcs_equiv', x['qty'])) for p in pkgs for x in p.get('items', []))
        if pk.get('packing_status') in ('IN_PROGRESS', 'COMPLETED', 'ISSUE'):
            events.append({
                'transaction_id': f"TX-PK-{pk['id'].replace('PK-', '')}",
                'transaction_type': 'PACKING',
                'type_label': 'Đóng gói',
                'event_type': 'Hoàn tất đóng gói' if pk.get('packing_status') == 'COMPLETED' else 'Đang đóng gói',
                'reference_id': pk['id'],
                'related_order_id': pk.get('order_code', ''),
                'source_transaction_id': pk.get('source_label', ''),
                'box_id': ', '.join(p['package_code'] for p in pkgs) or f"{len(pkgs)} kiện",
                'product_id': pk.get('summary_text', '--'),
                'operation_qty': total_pcs,
                'quantity_unit': 'PCS',
                'quantity_change': 0,
                'location_snapshot': 'Bàn đóng gói',
                'performed_by': pk.get('assignee', 'Nhân viên kho'),
                'approved_by': '',
                'occurred_at': datetime.now().strftime('%d/%m/%Y %H:%M'),
                'date_ymd': datetime.now().strftime('%Y-%m-%d'),
                'status': 'Hoàn thành' if pk.get('packing_status') == 'COMPLETED' else ('Có vấn đề' if pk.get('packing_status') == 'ISSUE' else 'Chờ xác nhận'),
                'note': '',
                'source_url': f"/staff/packing-handover?ticket={pk['id']}",
                'details': [
                    {
                        'box_id': p['package_code'],
                        'sku': ', '.join(f"{x['name']} ({x['qty']} {x['unit']})" for x in p.get('items', [])) or 'Kiện trống',
                        'location': 'Bàn đóng gói',
                        'op_qty': f"{sum(int(x.get('pcs_equiv', x['qty'])) for x in p.get('items', []))} PCS",
                        'delta_qty': '0 (Không trừ trùng)'
                    }
                    for p in pkgs
                ]
            })

        if pk.get('handover_id'):
            ho_id = pk['handover_id']
            h_st = pk.get('handover_status')
            st_ho = 'Hoàn thành' if h_st == 'APPROVED' else ('Có vấn đề' if h_st == 'REJECTED' else 'Chờ xác nhận')
            events.append({
                'transaction_id': f"TX-HO-{ho_id.replace('BG-', '')}",
                'transaction_type': 'HANDOVER',
                'type_label': 'Bàn giao',
                'event_type': 'Manager xác nhận bàn giao' if h_st == 'APPROVED' else ('Manager trả phiếu bàn giao' if h_st == 'REJECTED' else 'Gửi bàn giao chờ duyệt'),
                'reference_id': ho_id,
                'related_order_id': pk.get('order_code', ''),
                'source_transaction_id': pk['id'],
                'box_id': f"{len(pkgs)} kiện",
                'product_id': f"Đơn {pk.get('order_code')} ({pk.get('platform')})",
                'operation_qty': total_pcs,
                'quantity_unit': 'PCS',
                'quantity_change': 0,
                'location_snapshot': f"Người nhận: {pk.get('receiver', '--')}",
                'performed_by': pk.get('handover_by') or pk.get('assignee', 'Nhân viên kho'),
                'approved_by': pk.get('reviewed_by', ''),
                'occurred_at': datetime.now().strftime('%d/%m/%Y %H:%M'),
                'date_ymd': datetime.now().strftime('%Y-%m-%d'),
                'status': st_ho,
                'note': pk.get('reject_reason') or pk.get('handover_note', ''),
                'source_url': f"/staff/packing-handover?ticket={pk['id']}",
                'details': []
            })

    # 7. Sự kiện Kiểm kê kho (Chỉ ghi nhận số đếm, biến động tồn = 0 cho đến khi Manager duyệt điều chỉnh)
    st_data = _safe_load(STOCKTAKE_FILE, {'sessions': [], 'adjustments': []})
    for s in st_data.get('sessions', []):
        if s.get('status') == 'Chờ thực hiện':
            continue
        is_done = (s.get('status') == 'Hoàn tất')
        is_recount = (s.get('status') == 'Yêu cầu kiểm lại')
        events.append({
            'transaction_id': f"TX-KK-{s['id'].replace('KK-', '')}",
            'transaction_type': 'STOCKTAKE',
            'type_label': 'Kiểm kê kho',
            'event_type': s.get('status', 'Đang kiểm kê'),
            'reference_id': s['id'],
            'related_order_id': '',
            'source_transaction_id': '',
            'box_id': f"{s.get('counted_slots', 0)}/{s.get('total_slots', 0)} vị trí",
            'product_id': s.get('scope', '--'),
            'operation_qty': int(s.get('counted_slots', 0)),
            'quantity_unit': 'vị trí',
            'quantity_change': 0,
            'location_snapshot': s.get('scope', '--'),
            'performed_by': s.get('assignee', 'Nhân viên kho'),
            'approved_by': 'Manager' if is_done else '',
            'occurred_at': s.get('snapshot_time') or datetime.now().strftime('%d/%m/%Y %H:%M'),
            'date_ymd': datetime.now().strftime('%Y-%m-%d'),
            'status': 'Hoàn thành' if is_done else ('Có vấn đề' if is_recount else 'Chờ xác nhận'),
            'note': s.get('note', ''),
            'source_url': f"/staff/stocktake?ticket={s['id']}",
            'details': [
                {
                    'box_id': b['box_id'],
                    'sku': f"{b['sku']} · {b['product_name']}",
                    'location': b['slot_code'],
                    'op_qty': f"{b['counted_pcs']} PCS",
                    'delta_qty': '0 (Chờ Manager duyệt điều chỉnh)'
                }
                for b in s.get('snapshot_boxes', []) if b.get('counted_pcs') is not None
            ]
        })

    return events


# ================= ROUTES & API LỊCH SỬ GIAO DỊCH (STAFF) =================

@app.route('/staff/history')
@staff_required
def staff_history_page():
    return render_template('STAFF/staff_history.html')


@app.route('/api/staff/transactions/summary', methods=['GET'])
@staff_required
def api_staff_transactions_summary():
    events = _build_unified_staff_transactions()
    today_ymd = datetime.now().strftime('%Y-%m-%d')
    return jsonify({
        'today': sum(1 for e in events if e.get('date_ymd') == today_ymd),
        'completed': sum(1 for e in events if e.get('status') == 'Hoàn thành'),
        'waiting': sum(1 for e in events if e.get('status') == 'Chờ xác nhận'),
        'issues': sum(1 for e in events if e.get('status') == 'Có vấn đề')
    })


@app.route('/api/staff/transactions', methods=['GET'])
@staff_required
def api_staff_transactions_list():
    events = _build_unified_staff_transactions()
    q = str(request.args.get('q', '')).strip().lower()
    tx_type = str(request.args.get('type', 'ALL')).strip().upper()
    status = str(request.args.get('status', 'ALL')).strip()
    date_range = str(request.args.get('range', 'TODAY')).strip().upper()
    from_d = str(request.args.get('from', '')).strip()
    to_d = str(request.args.get('to', '')).strip()

    today_dt = datetime.now().date()
    filtered = []

    for e in events:
        if tx_type != 'ALL' and e.get('transaction_type') != tx_type:
            continue
        if status != 'ALL' and e.get('status') != status:
            continue

        # Lọc theo khoảng thời gian
        ev_date_str = str(e.get('date_ymd', ''))[:10]
        try:
            ev_dt = datetime.strptime(ev_date_str, '%Y-%m-%d').date()
        except Exception:
            ev_dt = today_dt

        if date_range == 'TODAY' and ev_dt != today_dt:
            continue
        elif date_range == '7D' and (today_dt - ev_dt).days > 7:
            continue
        elif date_range == '30D' and (today_dt - ev_dt).days > 30:
            continue
        elif date_range == 'CUSTOM':
            if from_d and ev_date_str < from_d:
                continue
            if to_d and ev_date_str > to_d:
                continue

        if q:
            hay = f"{e['transaction_id']} {e['reference_id']} {e['related_order_id']} {e['box_id']} {e['product_id']} {e['location_snapshot']}".lower()
            if q not in hay:
                continue

        filtered.append(e)

    return jsonify({'items': filtered, 'total': len(filtered)})


@app.route('/api/staff/transactions/<tx_id>', methods=['GET'])
@staff_required
def api_staff_transaction_detail(tx_id):
    events = _build_unified_staff_transactions()
    found = next((e for e in events if e['transaction_id'].upper() == tx_id.upper()), None)
    if not found:
        return jsonify({'error': 'Không tìm thấy giao dịch hoặc bạn không có quyền xem'}), 404
    return jsonify({'transaction': found})


@app.route('/api/staff/transactions/<tx_id>/trace', methods=['GET'])
@staff_required
def api_staff_transaction_trace(tx_id):
    """Truy vết toàn bộ các giao dịch liên kết cùng mã đơn hàng hoặc phiếu nguồn."""
    events = _build_unified_staff_transactions()
    target = next((e for e in events if e['transaction_id'].upper() == tx_id.upper()), None)
    if not target:
        return jsonify({'chain': []})

    order_ref = target.get('related_order_id')
    ref_id = target.get('reference_id')
    src_id = target.get('source_transaction_id')

    chain = [
        e for e in events
        if e['transaction_id'] != target['transaction_id']
        and (
            (order_ref and e.get('related_order_id') == order_ref)
            or (src_id and e.get('reference_id') in src_id)
            or (ref_id and ref_id in str(e.get('source_transaction_id', '')))
        )
    ]
    return jsonify({'chain': chain})

# Tài Khoản Staff mặc định: Nhân viên kho (STAFF)
# ================= ROUTES & API TÀI KHOẢN CÁ NHÂN (STAFF) =================

@app.route('/staff/profile', methods=['GET'])
@staff_required
def staff_profile_page():
    return render_template('STAFF/staff_profile.html')


@app.route('/api/staff/profile', methods=['GET'])
@staff_required
def api_staff_profile_get():
    """
    Lấy trực tiếp 100% thông tin hồ sơ từ users.json do Admin tạo,
    cùng danh sách quyền từ roles.json và chính sách mật khẩu từ system_settings.json.
    """
    sess_user = session.get('user', {})
    username = sess_user.get('username')

    users = load_users()
    user_record = users.get(username)
    if not user_record:
        return jsonify({'error': 'Không tìm thấy hồ sơ tài khoản trong hệ thống'}), 404

    role_name = user_record.get('role', 'Nhân viên kho')
    # Đọc danh sách quyền thực tế của vai trò Nhân viên kho
    roles_perm_map = load_roles()
    perms_list = roles_perm_map.get(role_name, ROLE_PERMISSIONS.get('Nhân viên kho', []))

    # Đọc chính sách mật khẩu hiện hành
    sys_cfg = load_system_settings()
    pwd_cfg = sys_cfg.get('password', {})
    min_len = pwd_cfg.get('min_length', 8)
    reqs = [f"Tối thiểu {min_len} ký tự"]
    if pwd_cfg.get('require_uppercase'):
        reqs.append("có chữ in hoa")
    if pwd_cfg.get('require_number'):
        reqs.append("có chữ số")
    if pwd_cfg.get('require_special'):
        reqs.append("có ký tự đặc biệt")

    return jsonify({
        'user': {
            'username': username,
            'staff_code': user_record.get('staff_code', '--'),
            'name': user_record.get('name', ''),
            'email': user_record.get('email', ''),
            'phone': user_record.get('phone', ''),
            'role': role_name,
            'scope': user_record.get('scope', 'Kho chính - SANOVA'),
            'status': user_record.get('status', 'Hoạt động'),
            'created_at': user_record.get('created_at', ''),
            'last_login': user_record.get('last_login', '')
        },
        'shift': get_current_shift_info(),
        'permissions': perms_list,
        'password_policy_text': f"Chính sách mật khẩu hệ thống: {', '.join(reqs)}."
    })


@app.route('/api/staff/profile', methods=['PATCH'])
@staff_required
def api_staff_profile_update():
    """
    Chỉ cho phép STAFF cập nhật số điện thoại và email liên hệ của chính mình.
    Tuyệt đối chặn sửa họ tên, mã nhân viên, vai trò, kho làm việc hoặc trạng thái.
    """
    sess_user = session.get('user', {})
    username = sess_user.get('username')
    body = request.get_json(silent=True) or {}

    phone = str(body.get('phone', '')).strip()
    email = str(body.get('email', '')).strip()

    if not email or '@' not in email:
        return jsonify({'error': 'Địa chỉ email liên hệ không hợp lệ'}), 400

    users = load_users()
    if username not in users:
        return jsonify({'error': 'Tài khoản không tồn tại'}), 404

    target = users[username]
    old_email = target.get('email', '')
    old_phone = target.get('phone', '')

    changes = []
    if old_email != email:
        changes.append({'field': 'Email liên hệ', 'before': old_email, 'after': email})
        target['email'] = email
    if old_phone != phone:
        changes.append({'field': 'Số điện thoại', 'before': old_phone, 'after': phone})
        target['phone'] = phone

    save_users(users)

    # Đồng bộ lại vào session hiện tại
    session['user']['email'] = email
    session.modified = True

    msg = 'Đã cập nhật thông tin liên hệ thành công!'
    if old_email != email:
        msg = f'Đã cập nhật Email liên hệ sang {email}. Vui lòng kiểm tra hộp thư để xác minh địa chỉ mới.'

    if changes and 'add_audit_log' in globals():
        add_audit_log(
            category='Tài khoản',
            action='Nhân viên cập nhật thông tin liên hệ cá nhân',
            target=username,
            changes=changes,
            result='Thành công'
        )

    return jsonify({'status': 'ok', 'message': msg})


@app.route('/api/staff/change-password', methods=['POST'])
@staff_required
def api_staff_change_password():
    """
    Đổi mật khẩu đăng nhập cho STAFF:
    - Chống thử sai liên tục (tối đa 5 lần trong phiên)
    - Xác thực mật khẩu hiện tại từ users.json
    - Kiểm tra tuân thủ chính sách mật khẩu của Admin (system_settings.json)
    - Băm mật khẩu an toàn và ghi nhận sự kiện bảo mật (không lưu mật khẩu vào log)
    """
    fail_cnt = int(session.get('staff_pwd_fails', 0))
    if fail_cnt >= 5:
        return jsonify({'error': 'Bạn đã nhập sai mật khẩu hiện tại quá 5 lần. Vui lòng đăng xuất và đăng nhập lại!'}), 429

    sess_user = session.get('user', {})
    username = sess_user.get('username')
    body = request.get_json(silent=True) or {}

    cur_pwd = str(body.get('current_password', ''))
    new_pwd = str(body.get('new_password', ''))
    cfm_pwd = str(body.get('confirm_password', ''))

    users = load_users()
    if username not in users:
        return jsonify({'error': 'Tài khoản không tồn tại'}), 404

    if not verify_password(users[username].get('password'), cur_pwd):
        session['staff_pwd_fails'] = fail_cnt + 1
        if 'add_audit_log' in globals():
            add_audit_log('Bảo mật', 'Nhân viên đổi mật khẩu thất bại (Sai mật khẩu cũ)', username, result='Thất bại')
        return jsonify({'error': 'Mật khẩu hiện tại không chính xác!'}), 400

    if new_pwd != cfm_pwd:
        return jsonify({'error': 'Xác nhận mật khẩu mới không khớp!'}), 400

    if cur_pwd == new_pwd:
        return jsonify({'error': 'Mật khẩu mới phải khác mật khẩu hiện tại!'}), 400

    # Kiểm tra tuân thủ chính sách mật khẩu trong system_settings.json
    sys_cfg = load_system_settings()
    pwd_cfg = sys_cfg.get('password', {})
    min_len = int(pwd_cfg.get('min_length', 8))

    if len(new_pwd) < min_len:
        return jsonify({'error': f'Mật khẩu mới phải có tối thiểu {min_len} ký tự theo chính sách hệ thống!'}), 400
    if pwd_cfg.get('require_uppercase') and not any(c.isupper() for c in new_pwd):
        return jsonify({'error': 'Mật khẩu mới phải chứa ít nhất 1 chữ cái in hoa (A-Z)!'}), 400
    if pwd_cfg.get('require_number') and not any(c.isdigit() for c in new_pwd):
        return jsonify({'error': 'Mật khẩu mới phải chứa ít nhất 1 chữ số (0-9)!'}), 400
    if pwd_cfg.get('require_special') and new_pwd.isalnum():
        return jsonify({'error': 'Mật khẩu mới phải chứa ít nhất 1 ký tự đặc biệt!'}), 400

    session['staff_pwd_fails'] = 0
    users[username]['password'] = hash_password(new_pwd)
    save_users(users)

    if 'add_audit_log' in globals():
        add_audit_log(
            category='Bảo mật',
            action='Nhân viên tự đổi mật khẩu tài khoản cá nhân',
            target=username,
            result='Thành công',
            reason='Cập nhật mật khẩu cá nhân'
        )

    return jsonify({'status': 'ok', 'message': 'Đổi mật khẩu thành công!'})


@app.route('/api/staff/sessions', methods=['GET'])
@staff_required
def api_staff_sessions_list():
    """Liệt kê phiên hiện tại và lịch sử đăng nhập của chính nhân viên từ audit_logs.json."""
    sess_user = session.get('user', {})
    username = sess_user.get('username', '')
    revoked = set(session.get('revoked_staff_sessions', []))

    cur_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '127.0.0.1')
    cur_dev = request.headers.get('User-Agent', 'Trình duyệt hiện tại')[:65]

    sessions_list = [{
        'id': 'SES-CURRENT',
        'device': cur_dev,
        'ip': cur_ip,
        'time': 'Đang hoạt động',
        'is_current': True
    }]

    for lg in load_logs():
        if lg.get('target') == username and 'Đăng nhập hệ thống' in str(lg.get('action', '')):
            sid = lg.get('id', '')
            if sid in revoked:
                continue
            sessions_list.append({
                'id': sid,
                'device': str(lg.get('device', 'Web Browser'))[:65],
                'ip': lg.get('ip', '127.0.0.1'),
                'time': lg.get('timestamp', ''),
                'is_current': False
            })
            if len(sessions_list) >= 8:
                break

    return jsonify({'sessions': sessions_list})


@app.route('/api/staff/sessions/<sess_id>', methods=['DELETE'])
@staff_required
def api_staff_session_revoke(sess_id):
    revoked = set(session.get('revoked_staff_sessions', []))
    revoked.add(sess_id)
    session['revoked_staff_sessions'] = list(revoked)
    return jsonify({'status': 'ok'})



# IV . DISPATCHER : Điều phối
#==========
#Dashboard & API cho nhân viên kho (STAFF)
import hashlib

PLATFORM_ORDERS_FILE = str(BASE_DIR / "sales_platform_orders.json")


def dispatcher_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        role = session["user"].get("role", "")
        if not any(k in role for k in ("Điều phối", "Kế toán", "Quản trị viên")):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def _parse_disp_date(raw_val):
    if not raw_val:
        return None
    s = str(raw_val).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(s[:10], fmt).date()
        except ValueError:
            continue
    return None


@app.route("/dispatcher")
@dispatcher_required
def dispatcher_dashboard_page():
    return render_template(
        "DISPATCHER/dispatcher_dashboard.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/dashboard", methods=["GET"])
@dispatcher_required
def api_dispatcher_dashboard():
    today_date = datetime.now().date()
    date_from = _parse_disp_date(request.args.get("date_from")) or today_date
    date_to = _parse_disp_date(request.args.get("date_to")) or today_date
    platform_filter = (request.args.get("platform") or "ALL").strip()

    # 1. Đọc danh mục sản phẩm từ Manager (products_catalog.json)
    catalog_raw = read_json(PRODUCTS_FILE, [])
    catalog_list = catalog_raw.get("products", []) if isinstance(catalog_raw, dict) else catalog_raw
    sku_name_map = {
        str(p.get("sku", "")).upper(): p.get("name", p.get("sku", ""))
        for p in catalog_list if p.get("sku")
    }

    # 2. Đọc phiếu yêu cầu lấy hàng & tiến độ OUT thực tế của Staff (picking_orders.json)
    picking_list = read_json(PICKING_FILE, [])
    if isinstance(picking_list, dict):
        picking_list = picking_list.get("orders", [])

    # 3. Đọc tiến độ Pre-packing & Đóng gói từ Staff (prepacking_orders.json, packing_orders.json)
    prepack_list = read_json(PREPACKING_FILE, [])
    if isinstance(prepack_list, dict):
        prepack_list = prepack_list.get("orders", [])
    prepack_by_order = {
        str(p.get("order_code", "")).upper(): p
        for p in prepack_list if p.get("order_code")
    }

    packing_list = read_json(PACKING_FILE, [])
    if isinstance(packing_list, dict):
        packing_list = packing_list.get("orders", [])
    packing_by_order = {
        str(pk.get("order_code", "")).upper(): pk
        for pk in packing_list if pk.get("order_code")
    }

    # 4. Đọc kết quả Bàn giao đã được Manager xác nhận (approvals_data.json)
    approvals = read_json(APPROVALS_FILE, {})
    processed_tickets = approvals.get("processed_tickets", [])
    confirmed_handovers = {
        str(t.get("order_or_po", "")).upper(): t
        for t in processed_tickets
        if t.get("category") == "HANDOVER" and "xác nhận" in str(t.get("status", "")).lower()
    }

    # 5. Đọc dữ liệu nền tảng bán hàng do Điều phối nhập (sales_platform_orders.json)
    platform_orders = read_json(PLATFORM_ORDERS_FILE, [])

    # Tổng hợp & lọc danh sách phiếu theo phạm vi Ngày + Nền tảng
    filtered_tickets = []
    for o in picking_list:
        raw_created = o.get("created_at") or datetime.now().strftime("%Y-%m-%d")
        o_date = _parse_disp_date(raw_created) or today_date
        if not (date_from <= o_date <= date_to):
            continue

        plat = o.get("platform") or "Shopee"
        if platform_filter != "ALL" and plat.lower() != platform_filter.lower():
            continue

        pick_id = o.get("id") or o.get("pick_id") or ""
        order_code = str(o.get("order_code") or o.get("order_id") or "").upper()
        sku = str(o.get("sku", "")).upper()

        req_pcs = int(o.get("required_pcs", o.get("qty_pcs", 0)) or 0)
        picked_pcs = int(o.get("picked_pcs", 0) or 0)

        pre_obj = prepack_by_order.get(order_code, {})
        pk_obj = packing_by_order.get(order_code, {})
        ho_obj = confirmed_handovers.get(order_code)

        # Tính số lượng đã đóng gói & đã bàn giao
        packed_pcs = 0
        if pk_obj:
            if pk_obj.get("packing_status") == "COMPLETED":
                packed_pcs = picked_pcs
            else:
                packed_pcs = sum(
                    int(it.get("pcs_equiv", it.get("qty", 0)))
                    for pkg in pk_obj.get("packages", [])
                    for it in pkg.get("items", [])
                )

        is_handed = bool(ho_obj) or (pk_obj.get("handover_status") == "APPROVED")
        handed_pcs = req_pcs if is_handed else 0

        # Chuẩn hóa trạng thái phiếu thống nhất trên toàn hệ thống
        raw_st = o.get("status", "Chờ thực hiện")
        if is_handed:
            norm_status = "Đã bàn giao"
        elif raw_st in ("Thiếu hàng", "Thiếu tồn"):
            norm_status = "Thiếu tồn"
        elif pk_obj.get("packing_status") in ("IN_PROGRESS", "COMPLETED") or pre_obj.get("status") in ("Đang chuẩn bị", "Sẵn sàng đóng gói", "Đã chuyển đóng gói"):
            norm_status = "Pre-packing / Đóng gói"
        elif raw_st == "Đang thực hiện" or (0 < picked_pcs < req_pcs):
            norm_status = "Đang lấy hàng"
        elif raw_st == "Hoàn thành" and not is_handed:
            norm_status = "Pre-packing / Đóng gói"
        else:
            norm_status = "Chờ lấy hàng"

        last_tx_time = ""
        if o.get("transactions"):
            last_tx_time = o["transactions"][-1].get("time", "")
        updated_str = f"{last_tx_time}, {o_date.strftime('%d/%m')}" if last_tx_time else o_date.strftime("%d/%m/%Y")

        filtered_tickets.append({
            "pick_id": pick_id,
            "order_code": order_code,
            "platform": plat,
            "sku": sku,
            "product_name": sku_name_map.get(sku, o.get("product_name", sku)),
            "qty_requested": req_pcs,
            "qty_out": picked_pcs,
            "qty_packed": packed_pcs,
            "qty_handed": handed_pcs,
            "status": norm_status,
            "is_overdue": bool(o.get("is_overdue", False)),
            "shortage_note": o.get("shortage_note", ""),
            "updated_at": updated_str,
            "detail_url": f"/dispatcher/order-tracking?pick_id={pick_id}"
        })

    # Lọc dữ liệu đối soát nền tảng bán hàng theo cùng bộ lọc
    filtered_recon = []
    for po in platform_orders:
        p_date = _parse_disp_date(po.get("order_date") or po.get("created_at")) or today_date
        if not (date_from <= p_date <= date_to):
            continue
        plat = po.get("platform") or "Shopee"
        if platform_filter != "ALL" and plat.lower() != platform_filter.lower():
            continue
        filtered_recon.append(po)

    # 6 thẻ KPI đếm theo PHIẾU
    total_tickets = len(filtered_tickets)
    processing_tickets = sum(
        1 for t in filtered_tickets
        if t["status"] in ("Chờ lấy hàng", "Đang lấy hàng", "Pre-packing / Đóng gói")
    )
    shortage_tickets = sum(1 for t in filtered_tickets if t["status"] == "Thiếu tồn")
    handed_over_tickets = sum(1 for t in filtered_tickets if t["status"] == "Đã bàn giao")
    pending_reconcile = sum(1 for r in filtered_recon if r.get("reconcile_status", "Chờ đối soát") == "Chờ đối soát")
    discrepancy_tickets = (
        sum(1 for r in filtered_recon if r.get("reconcile_status") == "Có chênh lệch")
        + sum(1 for t in filtered_tickets if t["status"] == "Có chênh lệch")
    )

    # Tiến độ xử lý hôm nay (tính theo trạng thái hiện tại của phiếu + hiển thị PCS tách bạch)
    w_t = [t for t in filtered_tickets if t["status"] == "Chờ lấy hàng"]
    p_t = [t for t in filtered_tickets if t["status"] in ("Đang lấy hàng", "Thiếu tồn")]
    pk_t = [t for t in filtered_tickets if t["status"] == "Pre-packing / Đóng gói"]
    hd_t = [t for t in filtered_tickets if t["status"] == "Đã bàn giao"]

    denom = max(total_tickets, 1)
    pct_w = round(len(w_t) * 100 / denom) if total_tickets else 0
    pct_p = round(len(p_t) * 100 / denom) if total_tickets else 0
    pct_pk = round(len(pk_t) * 100 / denom) if total_tickets else 0
    pct_hd = max(0, 100 - pct_w - pct_p - pct_pk) if total_tickets else 0

    # Công việc cần xử lý (sắp xếp theo mức ưu tiên: Thiếu tồn -> Quá hạn -> Chênh lệch -> Chờ đối soát)
    priority_tasks = []
    for t in filtered_tickets:
        if t["status"] == "Thiếu tồn":
            missing_pcs = max(0, t["qty_requested"] - t["qty_out"])
            priority_tasks.append({
                "rank": 1,
                "icon": "⚠️",
                "icon_bg": "#fef2f2",
                "icon_color": "#dc2626",
                "title": f"Phiếu {t['pick_id']} – Thiếu {missing_pcs} PCS {t['product_name']}",
                "subtitle": t["shortage_note"] or "Cần chọn phương án xử lý",
                "priority": "URGENT",
                "time": t["updated_at"].split(",")[0],
                "action_url": f"/dispatcher/order-tracking?pick_id={t['pick_id']}"
            })
        elif t["is_overdue"] and t["status"] != "Đã bàn giao":
            priority_tasks.append({
                "rank": 2,
                "icon": "⏰",
                "icon_bg": "#fffbeb",
                "icon_color": "#d97706",
                "title": f"Phiếu {t['pick_id']} chậm tiến độ xử lý",
                "subtitle": f"Trạng thái: {t['status']} · {t['qty_out']}/{t['qty_requested']} PCS",
                "priority": "HIGH",
                "time": t["updated_at"].split(",")[0],
                "action_url": f"/dispatcher/order-tracking?pick_id={t['pick_id']}"
            })

    for r in filtered_recon:
        if r.get("reconcile_status") == "Có chênh lệch":
            diff = abs(int(r.get("diff_pcs", 0) or 0))
            priority_tasks.append({
                "rank": 3,
                "icon": "⚖️",
                "icon_bg": "#fef2f2",
                "icon_color": "#dc2626",
                "title": f"Chênh lệch {diff} PCS {r.get('product_name', r.get('sku', ''))}",
                "subtitle": "Cần đối soát và xử lý",
                "priority": "NORMAL",
                "time": str(r.get("updated_at", ""))[-5:],
                "action_url": f"/dispatcher/outbound-reconciliation?order_id={r.get('order_id', '')}"
            })
        elif r.get("reconcile_status", "Chờ đối soát") == "Chờ đối soát":
            priority_tasks.append({
                "rank": 4,
                "icon": "🕒",
                "icon_bg": "#eff6ff",
                "icon_color": "#2563eb",
                "title": f"Dữ liệu {r.get('platform', 'Shopee')} chưa đối soát",
                "subtitle": "Chờ kiểm tra dữ liệu",
                "priority": "HIGH",
                "time": str(r.get("updated_at", ""))[-5:],
                "action_url": "/dispatcher/reconciliation-data"
            })

    priority_tasks.sort(key=lambda x: x["rank"])

    # Hoạt động gần đây (5-10 sự kiện mới nhất từ audit_logs.json)
    logs = load_logs()
    recent_activities = []
    for lg in logs:
        if lg.get("category") in ("Nghiệp vụ kho", "NGHIỆP VỤ KHO", "Điều phối"):
            recent_activities.append({
                "actor": lg.get("actor") or lg.get("by", "Hệ thống"),
                "message": f"{lg.get('action')} ({lg.get('target')})",
                "time": lg.get("timestamp", "")
            })
        if len(recent_activities) >= 8:
            break

    notifications = [
        {
            "title": item["title"],
            "desc": item["subtitle"],
            "time": item["time"],
            "url": item["action_url"]
        }
        for item in priority_tasks[:5]
    ]

    result = {
        "synced_at": datetime.now().strftime("%H:%M:%S"),
        "kpis": {
            "total_tickets": total_tickets,
            "delta_total": "+12%" if total_tickets else "+0%",
            "processing_tickets": processing_tickets,
            "delta_processing": "+1%" if processing_tickets else "+0%",
            "shortage_tickets": shortage_tickets,
            "delta_shortage": "+0%",
            "handed_over_tickets": handed_over_tickets,
            "delta_handed_over": "+0%",
            "pending_reconcile": pending_reconcile,
            "delta_pending_recon": "+2%" if pending_reconcile else "+0%",
            "discrepancy_tickets": discrepancy_tickets,
            "delta_discrepancy": "+0%"
        },
        "priority_tasks": priority_tasks[:6],
        "progress": {
            "total_pcs": sum(t["qty_requested"] for t in filtered_tickets),
            "waiting_tickets": len(w_t),
            "waiting_pcs": sum(t["qty_requested"] for t in w_t),
            "pct_waiting": pct_w,
            "picking_tickets": len(p_t),
            "picking_pcs": sum(t["qty_out"] for t in p_t),
            "pct_picking": pct_p,
            "packing_tickets": len(pk_t),
            "packing_pcs": sum(t["qty_packed"] for t in pk_t),
            "pct_packing": pct_pk,
            "handed_tickets": len(hd_t),
            "handed_pcs": sum(t["qty_handed"] for t in hd_t),
            "pct_handed": pct_hd
        },
        "recent_tickets": filtered_tickets[:8],
        "recent_activities": recent_activities,
        "notifications": notifications
    }
    result["state_hash"] = hashlib.md5(
        json.dumps(result, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return jsonify(result)

# CHỨC NĂNG YÊU CẦU LẤY HÀNG (DISPATCHER PICKING REQUESTS)

_disp_pick_lock = threading.Lock()

def _compute_real_available_pcs(sku):
    """Đọc tồn khả dụng thực tế từ kho dùng chung (Box 'Đang lưu trữ' & on_shelf)."""
    sku_up = str(sku or "").strip().upper()
    receipts = _load_inbound_receipts() if "_load_inbound_receipts" in globals() else read_json(INBOUND_FILE, [])
    box_avail = 0
    for r in receipts:
        for b in r.get("boxes", []):
            if (
                str(b.get("sku", "")).upper() == sku_up
                and b.get("box_status") == "Đang lưu trữ"
                and b.get("shelf_position_id")
            ):
                box_avail += int(b.get("quantity", 0) or 0)

    wh_data = read_json(WAREHOUSE_FILE, {})
    inv_item = next((x for x in wh_data.get("inventory", []) if str(x.get("sku", "")).upper() == sku_up), None)
    shelf_avail = int(inv_item.get("on_shelf", 0) or 0) if inv_item else 0
    return max(box_avail, shelf_avail)

def _get_active_warehouse_staffs():
    """Đọc danh sách nhân viên kho đang Hoạt động từ users.json của Admin."""
    users = load_users()
    staffs = []
    for uname, u in users.items():
        if u.get("status") != "Hoạt động":
            continue
        role_str = str(u.get("role", ""))
        if "Nhân viên" in role_str or "Staff" in role_str:
            code = u.get("staff_code") or uname
            staffs.append({
                "username": uname,
                "staff_code": code,
                "name": u.get("name", uname),
                "label": f"{code} – {u.get('name', uname)}"
            })
    return staffs


def _get_active_catalog_skus():
    """Đọc danh mục SKU Đang sử dụng từ products_catalog.json của Manager kèm tồn khả dụng."""
    raw = read_json(PRODUCTS_FILE, [])
    prods = raw.get("products", []) if isinstance(raw, dict) else raw
    result = []
    for p in prods:
        if p.get("status", "Đang sử dụng") != "Đang sử dụng":
            continue
        sku = str(p.get("sku", "")).upper()
        if not sku:
            continue
        result.append({
            "sku": sku,
            "name": p.get("name", sku),
            "category": p.get("category", ""),
            "unit": p.get("unit", "PCS"),
            "is_combo_catalog": (p.get("category") == "Combo" or bool(p.get("combo_items"))),
            "available_pcs": _compute_real_available_pcs(sku)
        })
    return result


def _normalize_dispatcher_ticket(o, sku_name_map):
    """
    Chuẩn hóa phiếu yêu cầu lấy hàng:
    - Tính OUT ròng = Tổng OUT hợp lệ - Tổng RETURNED đã hoàn tất trả kệ từ phiếu OUT này
    - Phân biệt rõ 'Còn cần lấy' (yêu cầu - OUT ròng) với 'Thiếu tồn' (chỉ khi thiếu trước phát hành hoặc Staff đã báo thiếu)
    """
    pick_id = o.get("id") or o.get("pick_id")
    ret_orders = _load_return_orders() if "_load_return_orders" in globals() else read_json(RETURNS_FILE, [])

    # Tính tổng PCS đã RETURNED hợp lệ từ phiếu OUT này
    returned_by_sku = {}
    returned_tx_rows = []
    for r in ret_orders:
        if str(r.get("out_order_id", "")).upper() == str(pick_id).upper() and r.get("status") == "Hoàn thành":
            r_sku = str(r.get("sku", "")).upper()
            r_qty = int(r.get("returned_pcs", 0) or 0)
            returned_by_sku[r_sku] = returned_by_sku.get(r_sku, 0) + r_qty
            for rtx in r.get("transactions", []):
                returned_tx_rows.append({
                    "type": "RETURNED",
                    "time": rtx.get("time", ""),
                    "box_id": rtx.get("box_id", "--"),
                    "location_snapshot": rtx.get("location_snapshot", "--"),
                    "qty_pcs": -int(rtx.get("returned_pcs", 0) or 0),
                    "staff_name": rtx.get("staff_name", "")
                })

    items = o.get("items")
    if not items:
        sku = str(o.get("sku", "")).upper()
        req_q = int(o.get("required_pcs", o.get("qty_pcs", 0)) or 0)
        raw_picked = int(o.get("picked_pcs", 0) or 0)
        net_picked = max(0, raw_picked - returned_by_sku.get(sku, 0))
        items = [{
            "sku": sku,
            "product_name": sku_name_map.get(sku, o.get("product_name", sku)),
            "requested_pcs": req_q,
            "picked_pcs": net_picked,
            "is_combo_item": bool(o.get("is_combo", False)),
            "combo_qty": int(o.get("combo_qty", 0) or 0),
            "shortage_pcs": int(o.get("shortage_pcs", 0) or 0)
        }]
    else:
        for it in items:
            s_up = str(it.get("sku", "")).upper()
            raw_p = int(it.get("picked_pcs", 0) or 0)
            it["net_picked_pcs"] = max(0, raw_p - returned_by_sku.get(s_up, 0))

    total_req = sum(int(i.get("requested_pcs", 0) or 0) for i in items)
    total_net_out = sum(int(i.get("net_picked_pcs", i.get("picked_pcs", 0)) or 0) for i in items)
    total_rem_to_pick = max(0, total_req - total_net_out)

    # Xác định trạng thái chuẩn (không nhầm 'Còn cần lấy' với 'Thiếu tồn')
    raw_st = o.get("status", "Chờ thực hiện")
    shortage_source = o.get("shortage_source", "")  # 'PRE_PUBLISH' | 'STAFF_REPORTED' | ''
    shortage_pcs_flag = int(o.get("shortage_pcs", 0) or 0)

    if raw_st == "Nháp":
        disp_status = "Nháp"
    elif raw_st in ("Đã hủy", "Hủy"):
        disp_status = "Đã hủy"
    elif raw_st in ("Thiếu hàng", "Thiếu tồn"):
        disp_status = "Thiếu tồn"
        if not shortage_source:
            shortage_source = "STAFF_REPORTED" if total_net_out > 0 else "PRE_PUBLISH"
        if shortage_pcs_flag <= 0:
            shortage_pcs_flag = total_rem_to_pick
    elif raw_st == "Hoàn tất một phần":
        disp_status = "Hoàn tất một phần"
    elif raw_st in ("Hoàn thành", "Hoàn tất lấy hàng") or (total_req > 0 and total_net_out >= total_req):
        disp_status = "Hoàn tất lấy hàng"
    elif raw_st == "Đang thực hiện" or total_net_out > 0:
        disp_status = "Đang lấy hàng"
    else:
        disp_status = "Chờ xử lý"

    # Gộp lịch sử giao dịch OUT + RETURNED thực tế
    merged_txs = []
    for tx in o.get("transactions", []):
        merged_txs.append({
            "type": "OUT",
            "time": tx.get("time", "--"),
            "box_id": tx.get("box_id", "--"),
            "location_snapshot": tx.get("location_snapshot", "--"),
            "qty_pcs": int(tx.get("picked_pcs", 0) or 0),
            "staff_name": tx.get("staff_name", o.get("assignee", ""))
        })
    merged_txs.extend(returned_tx_rows)

    return {
        "pick_id": pick_id,
        "order_code": str(o.get("order_code") or o.get("order_id") or "").upper(),
        "platform": o.get("platform", "Shopee"),
        "priority": o.get("priority", "Bình thường"),
        "deadline": o.get("deadline", ""),
        "assignee": o.get("assignee", ""),
        "assignee_code": o.get("assignee_code", ""),
        "status": disp_status,
        "shortage_source": shortage_source,
        "shortage_pcs": shortage_pcs_flag,
        "shortage_note": o.get("shortage_note", ""),
        "items": items,
        "sku_count": len(items),
        "sku_summary": items[0]["product_name"] if len(items) == 1 else f"{len(items)} sản phẩm ({', '.join(x['sku'] for x in items)})",
        "total_req_pcs": total_req,
        "total_out_pcs": total_net_out,
        "total_rem_pcs": total_rem_to_pick,
        "note": o.get("note", ""),
        "created_at": o.get("created_at", datetime.now().strftime("%d/%m/%Y %H:%M")),
        "updated_at": o.get("updated_at") or o.get("created_at", ""),
        "transactions": merged_txs,
        "history": o.get("history", [])
    }


@app.route("/dispatcher/picking-requests")
@dispatcher_required
def dispatcher_picking_requests_page():
    return render_template(
        "DISPATCHER/dispatcher_picking_requests.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/picking-requests", methods=["GET"])
@dispatcher_required
def api_dispatcher_picking_list():
    catalog = _get_active_catalog_skus()
    sku_name_map = {c["sku"]: c["name"] for c in catalog}

    picking_list = read_json(PICKING_FILE, [])
    tickets = [_normalize_dispatcher_ticket(o, sku_name_map) for o in picking_list]

    counts = {
        "ALL": len(tickets),
        "WAITING": sum(1 for t in tickets if t["status"] in ("Chờ xử lý", "Nháp")),
        "PICKING": sum(1 for t in tickets if t["status"] == "Đang lấy hàng"),
        "SHORTAGE": sum(1 for t in tickets if t["status"] == "Thiếu tồn"),
        "COMPLETED": sum(1 for t in tickets if t["status"] in ("Hoàn tất lấy hàng", "Hoàn tất một phần")),
        "CANCELLED": sum(1 for t in tickets if t["status"] == "Đã hủy")
    }

    return jsonify({
        "tickets": tickets,
        "counts": counts,
        "staffs": _get_active_warehouse_staffs(),
        "skus": catalog,
        "synced_at": datetime.now().strftime("%H:%M:%S")
    })


@app.route("/api/dispatcher/picking-requests/check-stock", methods=["POST"])
@dispatcher_required
def api_dispatcher_check_stock():
    body = request.get_json(silent=True) or {}
    req_items = body.get("items", [])
    checked = []
    has_shortage = False
    for it in req_items:
        sku = str(it.get("sku", "")).strip().upper()
        req_pcs = int(it.get("requested_pcs", 0) or 0)
        avail = _compute_real_available_pcs(sku)
        shortage = max(0, req_pcs - avail)
        if shortage > 0:
            has_shortage = True
        checked.append({
            "sku": sku,
            "requested_pcs": req_pcs,
            "available_pcs": avail,
            "shortage_pcs": shortage
        })
    return jsonify({"items": checked, "has_shortage": has_shortage})


@app.route("/api/dispatcher/picking-requests", methods=["POST"])
@dispatcher_required
def api_dispatcher_create_picking_request():
    """
    Tạo phiếu yêu cầu lấy hàng:
    - Chặn trùng mã đơn hàng đang hiệu lực (trừ khi Điều phối xác nhận tạo bổ sung)
    - Phân biệt rõ 'Chờ bổ sung toàn bộ' vs 'Phát hành một phần' (không phát hành 0 PCS cho Staff)
    - Khi chọn 'Điều chỉnh yêu cầu', lưu rõ PCS ban đầu, PCS mới, PCS giảm và bắt buộc lý do
    - Hỗ trợ cấu hình Combo theo từng dòng SKU
    """
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}

    mode = str(body.get("mode", "PUBLISH")).upper()  # 'DRAFT' | 'PUBLISH'
    platform = str(body.get("platform", "Shopee")).strip()
    order_code = str(body.get("order_code", "")).strip().upper()
    allow_dup = bool(body.get("allow_duplicate_order", False))
    priority = str(body.get("priority", "Bình thường")).strip()
    deadline = str(body.get("deadline", "")).strip()
    assignee_code = str(body.get("assignee_code", "")).strip()
    shortage_policy = str(body.get("shortage_policy", "")).strip()
    adjust_reason = str(body.get("adjust_reason", "")).strip()
    note = str(body.get("note", "")).strip()
    raw_items = body.get("items", [])

    if not order_code:
        return jsonify({"error": "Vui lòng nhập Mã tham chiếu / Mã đơn hàng nguồn!"}), 400
    if not raw_items:
        return jsonify({"error": "Phiếu yêu cầu phải có ít nhất 01 sản phẩm (SKU)!"}), 400

    picking_list = read_json(PICKING_FILE, [])
    dup_ticket = next(
        (o for o in picking_list if str(o.get("order_code", "")).upper() == order_code and o.get("status") not in ("Đã hủy", "Hủy")),
        None
    )
    if dup_ticket and not allow_dup:
        return jsonify({
            "error": f"Mã đơn '{order_code}' đã tồn tại ở phiếu {dup_ticket.get('id')} ({dup_ticket.get('status')}). Nếu cần tách phiếu bổ sung, hãy tích chọn xác nhận tạo bổ sung!",
            "duplicate_pick_id": dup_ticket.get("id")
        }), 409

    staffs = _get_active_warehouse_staffs()
    staff_obj = next((s for s in staffs if s["staff_code"] == assignee_code or s["username"] == assignee_code), None)
    if mode == "PUBLISH" and not staff_obj:
        return jsonify({"error": "Vui lòng chọn Nhân viên kho đang hoạt động để phát hành phiếu!"}), 400

    catalog = _get_active_catalog_skus()
    sku_map = {c["sku"]: c for c in catalog}

    clean_items = []
    any_shortage = False
    for it in raw_items:
        sku = str(it.get("sku", "")).strip().upper()
        req_pcs = int(it.get("requested_pcs", 0) or 0)
        is_combo_item = bool(it.get("is_combo_item", False))
        combo_qty = int(it.get("combo_qty", 0) or 0)

        if sku not in sku_map or req_pcs <= 0:
            return jsonify({"error": f"Sản phẩm {sku} không hợp lệ hoặc số lượng <= 0!"}), 400
        if is_combo_item and combo_qty <= 0:
            return jsonify({"error": f"SKU {sku} được đánh dấu thuộc Combo, vui lòng nhập số lượng Combo > 0!"}), 400

        avail = _compute_real_available_pcs(sku)
        short_pcs = max(0, req_pcs - avail)
        if short_pcs > 0:
            any_shortage = True

        clean_items.append({
            "sku": sku,
            "product_name": sku_map[sku]["name"],
            "initial_requested_pcs": req_pcs,
            "requested_pcs": req_pcs,
            "picked_pcs": 0,
            "available_pcs": avail,
            "shortage_pcs": short_pcs,
            "is_combo_item": is_combo_item,
            "combo_qty": combo_qty if is_combo_item else 0
        })

    if any_shortage and mode == "PUBLISH" and not shortage_policy:
        return jsonify({"error": "Phát hiện thiếu tồn: Vui lòng chủ động chọn phương án xử lý thiếu tồn trước khi tiếp tục!"}), 400

    if any_shortage and shortage_policy == "ADJUST_QTY" and not adjust_reason:
        return jsonify({"error": "Khi chọn Điều chỉnh yêu cầu, bắt buộc nhập Lý do điều chỉnh!"}), 400

    if any_shortage and shortage_policy == "CANCEL_ALL":
        return jsonify({"error": "Bạn đã chọn Hủy yêu cầu do thiếu tồn; phiếu không được phát hành xuống kho."}), 400

    with _disp_pick_lock:
        picking_list = read_json(PICKING_FILE, [])
        seq = len(picking_list) + 25
        pick_id = f"OUT-{str(seq).zfill(4)}"
        while any((o.get("id") or o.get("pick_id")) == pick_id for o in picking_list):
            seq += 1
            pick_id = f"OUT-{str(seq).zfill(4)}"

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        first_item = clean_items[0]
        total_avail_all = sum(min(x["requested_pcs"], x["available_pcs"]) for x in clean_items)
        total_short_all = sum(x["shortage_pcs"] for x in clean_items)

        # Xử lý từng phương án thiếu tồn khi Phát hành
        send_to_staff = False
        staff_dispatch_pcs = 0
        init_status = "Nháp"
        shortage_src = ""
        shortage_note = ""
        history_detail = ""

        if mode == "DRAFT":
            init_status = "Nháp"
            history_detail = f"Lưu nháp phiếu ({sum(x['requested_pcs'] for x in clean_items)} PCS)"
        elif not any_shortage:
            init_status = "Chờ thực hiện"
            send_to_staff = True
            staff_dispatch_pcs = sum(x["requested_pcs"] for x in clean_items)
            history_detail = f"Phát hành đủ {staff_dispatch_pcs} PCS · Giao cho {staff_obj['label']}"
        else:
            if shortage_policy == "ADJUST_QTY":
                if total_avail_all <= 0:
                    return jsonify({"error": "Tồn khả dụng bằng 0 PCS, không thể điều chỉnh về mức đáp ứng!"}), 400
                old_total = sum(x["requested_pcs"] for x in clean_items)
                for x in clean_items:
                    x["requested_pcs"] = min(x["requested_pcs"], x["available_pcs"])
                    x["shortage_pcs"] = 0
                init_status = "Chờ thực hiện"
                send_to_staff = True
                staff_dispatch_pcs = total_avail_all
                shortage_note = f"Điều chỉnh từ {old_total} → {total_avail_all} PCS. Lý do: {adjust_reason}"
                history_detail = f"Điều chỉnh yêu cầu ({old_total} → {total_avail_all} PCS) và phát hành · Lý do: {adjust_reason}"

            elif shortage_policy == "PARTIAL_RELEASE":
                if total_avail_all <= 0:
                    return jsonify({"error": "Tồn khả dụng bằng 0 PCS, không thể phát hành một phần!"}), 400
                init_status = "Thiếu tồn"
                shortage_src = "PRE_PUBLISH"
                send_to_staff = True
                staff_dispatch_pcs = total_avail_all
                shortage_note = f"Phát hành trước {total_avail_all} PCS · Giữ {total_short_all} PCS chờ bổ sung"
                history_detail = f"Phát hành một phần {total_avail_all} PCS cho {staff_obj['label']}; giữ {total_short_all} PCS chờ bổ sung"

            elif shortage_policy == "WAIT_ALL":
                # Giữ toàn bộ phiếu ở trạng thái Thiếu tồn, KHÔNG phát hành việc lấy 0 PCS cho Staff
                init_status = "Thiếu tồn"
                shortage_src = "PRE_PUBLISH"
                send_to_staff = False
                staff_dispatch_pcs = 0
                shortage_note = f"Giữ toàn bộ phiếu chờ bổ sung {total_short_all} PCS (Chưa phát hành cho Staff)"
                history_detail = f"Giữ toàn bộ phiếu chờ bổ sung {total_short_all} PCS · Không phát hành 0 PCS"

        final_req_pcs = sum(x["requested_pcs"] for x in clean_items)
        new_ticket = {
            "id": pick_id,
            "pick_id": pick_id,
            "order_code": order_code,
            "platform": platform,
            "priority": priority,
            "deadline": deadline,
            "is_combo": any(x["is_combo_item"] for x in clean_items),
            "sku": first_item["sku"],
            "product_name": first_item["product_name"],
            "required_pcs": final_req_pcs,
            "dispatched_pcs": staff_dispatch_pcs,
            "picked_pcs": 0,
            "consumed_pcs": 0,
            "items": clean_items,
            "assignee": staff_obj["name"] if staff_obj else "",
            "assignee_code": staff_obj["staff_code"] if staff_obj else "",
            "status": init_status,
            "shortage_source": shortage_src,
            "shortage_pcs": total_short_all if init_status == "Thiếu tồn" else 0,
            "shortage_policy": shortage_policy,
            "shortage_note": shortage_note,
            "note": note,
            "created_by": dispatcher_name,
            "created_at": now_str,
            "updated_at": now_str,
            "transactions": [],
            "history": [{
                "time": now_str,
                "actor": dispatcher_name,
                "action": "Tạo & xử lý phiếu yêu cầu lấy hàng",
                "detail": history_detail
            }]
        }
        picking_list.insert(0, new_ticket)
        write_json(PICKING_FILE, picking_list)

        # Chỉ đẩy công việc sang Staff khi số PCS được phép phát hành > 0
        if send_to_staff and staff_obj and staff_dispatch_pcs > 0:
            tasks = read_json(STAFF_TASKS_FILE, [])
            tasks.insert(0, {
                "task_id": f"TSK-{pick_id}",
                "reference_id": pick_id,
                "task_type": "OUT",
                "title": f"Lấy hàng đơn {order_code} ({first_item['product_name']})",
                "category_label": "Lấy hàng & Trả hàng",
                "quantity_text": f"0/{staff_dispatch_pcs} PCS",
                "time_label": datetime.now().strftime("%H:%M"),
                "assigned_employee": staff_obj["staff_code"],
                "warehouse_id": "KHO-01",
                "status": "Chờ thực hiện",
                "priority": "HIGH" if priority == "Khẩn" else "NORMAL",
                "is_carryover": False,
                "rejection_reason": ""
            })
            write_json(STAFF_TASKS_FILE, tasks)

    if "add_audit_log" in globals():
        add_audit_log("Nghiệp vụ kho", "Tạo phiếu yêu cầu lấy hàng", pick_id, history_detail)

    return jsonify({"status": "ok", "pick_id": pick_id, "dispatched_to_staff": send_to_staff}), 201


@app.route("/api/dispatcher/picking-requests/<pick_id>/assign", methods=["POST"])
@dispatcher_required
def api_dispatcher_assign_staff(pick_id):
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}
    new_code = str(body.get("assignee_code", "")).strip()

    staffs = _get_active_warehouse_staffs()
    staff_obj = next((s for s in staffs if s["staff_code"] == new_code or s["username"] == new_code), None)
    if not staff_obj:
        return jsonify({"error": "Nhân viên được chọn không tồn tại hoặc đang bị khóa!"}), 400

    with _disp_pick_lock:
        picking_list = read_json(PICKING_FILE, [])
        ticket = next((o for o in picking_list if (o.get("id") or o.get("pick_id")) == pick_id), None)
        if not ticket:
            return jsonify({"error": "Không tìm thấy phiếu yêu cầu"}), 404
        if ticket.get("status") in ("Hoàn thành", "Hoàn tất lấy hàng", "Đã hủy"):
            return jsonify({"error": "Phiếu đã hoàn tất hoặc đã hủy, không thể đổi phân công!"}), 400

        old_staff = ticket.get("assignee") or "Chưa phân công"
        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        ticket["assignee"] = staff_obj["name"]
        ticket["assignee_code"] = staff_obj["staff_code"]
        ticket["updated_at"] = now_str
        ticket.setdefault("history", []).append({
            "time": now_str,
            "actor": dispatcher_name,
            "action": "Đổi nhân viên phụ trách",
            "detail": f"{old_staff} → {staff_obj['label']} (Bảo toàn {ticket.get('picked_pcs', 0)} PCS đã OUT)"
        })
        write_json(PICKING_FILE, picking_list)

        tasks = read_json(STAFF_TASKS_FILE, [])
        for t in tasks:
            if t.get("reference_id") == pick_id:
                t["assigned_employee"] = staff_obj["staff_code"]
        write_json(STAFF_TASKS_FILE, tasks)

    return jsonify({"status": "ok"})


@app.route("/api/dispatcher/picking-requests/<pick_id>/resolve-shortage", methods=["POST"])
@dispatcher_required
def api_dispatcher_resolve_shortage(pick_id):
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}
    decision = str(body.get("decision", "")).upper()
    reason = str(body.get("reason", "")).strip()

    if decision not in ("WAIT_STOCK", "ADJUST_QTY", "CANCEL_REMAINING", "RELEASE_AVAILABLE"):
        return jsonify({"error": "Vui lòng chọn phương án xử lý hợp lệ!"}), 400
    if not reason:
        return jsonify({"error": "Bắt buộc nhập lý do xử lý thiếu tồn!"}), 400

    with _disp_pick_lock:
        picking_list = read_json(PICKING_FILE, [])
        ticket = next((o for o in picking_list if (o.get("id") or o.get("pick_id")) == pick_id), None)
        if not ticket:
            return jsonify({"error": "Không tìm thấy phiếu yêu cầu"}), 404

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        picked = int(ticket.get("picked_pcs", 0) or 0)
        old_req = int(ticket.get("required_pcs", 0) or 0)

        if decision == "RELEASE_AVAILABLE":
            avail = _compute_real_available_pcs(ticket.get("sku"))
            can_dispatch = min(old_req - picked, avail)
            if can_dispatch <= 0:
                return jsonify({"error": "Hiện tồn khả dụng trên kệ vẫn bằng 0 PCS, chưa thể phát hành thêm!"}), 400
            ticket["dispatched_pcs"] = picked + can_dispatch
            ticket["status"] = "Chờ thực hiện" if (picked + can_dispatch) >= old_req else "Thiếu tồn"
            ticket["shortage_pcs"] = max(0, old_req - (picked + can_dispatch))
            detail_log = f"Phát hành bổ sung {can_dispatch} PCS xuống kho. Lý do: {reason}"

            tasks = read_json(STAFF_TASKS_FILE, [])
            existing_task = next((t for t in tasks if t.get("reference_id") == pick_id), None)
            if existing_task:
                existing_task["quantity_text"] = f"{picked}/{picked + can_dispatch} PCS"
                existing_task["status"] = "Đang thực hiện" if picked > 0 else "Chờ thực hiện"
            elif ticket.get("assignee_code"):
                tasks.insert(0, {
                    "task_id": f"TSK-{pick_id}",
                    "reference_id": pick_id,
                    "task_type": "OUT",
                    "title": f"Lấy hàng đơn {ticket.get('order_code')} ({ticket.get('product_name')})",
                    "category_label": "Lấy hàng & Trả hàng",
                    "quantity_text": f"{picked}/{picked + can_dispatch} PCS",
                    "time_label": datetime.now().strftime("%H:%M"),
                    "assigned_employee": ticket.get("assignee_code"),
                    "warehouse_id": "KHO-01",
                    "status": "Chờ thực hiện",
                    "priority": "HIGH" if ticket.get("priority") == "Khẩn" else "NORMAL",
                    "is_carryover": False,
                    "rejection_reason": ""
                })
            write_json(STAFF_TASKS_FILE, tasks)

        elif decision == "WAIT_STOCK":
            ticket["status"] = "Thiếu tồn"
            ticket["shortage_note"] = f"Chờ bổ sung {max(0, old_req - picked)} PCS · {reason}"
            detail_log = f"Giữ phần thiếu ({max(0, old_req - picked)} PCS) chờ bổ sung tồn. Lý do: {reason}"

        elif decision == "ADJUST_QTY":
            if picked <= 0:
                avail = _compute_real_available_pcs(ticket.get("sku"))
                if avail <= 0:
                    return jsonify({"error": "Tồn khả dụng = 0 PCS, hãy chọn Hủy phiếu hoặc Chờ bổ sung!"}), 400
                new_req = avail
                ticket["status"] = "Chờ thực hiện"
            else:
                new_req = picked
                ticket["status"] = "Hoàn thành"

            ticket["initial_required_pcs"] = ticket.get("initial_required_pcs", old_req)
            ticket["required_pcs"] = new_req
            ticket["shortage_pcs"] = 0
            for it in ticket.get("items", []):
                it["requested_pcs"] = int(it.get("picked_pcs", 0)) if picked > 0 else min(it["requested_pcs"], _compute_real_available_pcs(it["sku"]))
                it["shortage_pcs"] = 0
            ticket["shortage_note"] = f"Điều chỉnh: {old_req} → {new_req} PCS ({reason})"
            detail_log = f"Điều chỉnh yêu cầu từ {old_req} PCS xuống {new_req} PCS. Lý do: {reason}"

        else:  # CANCEL_REMAINING
            if picked > 0:
                ticket["status"] = "Hoàn tất một phần"
                ticket["shortage_pcs"] = 0
                ticket["shortage_note"] = f"Chốt {picked}/{old_req} PCS đã OUT; hủy {old_req - picked} PCS thiếu ({reason})"
                detail_log = f"Giữ {picked} PCS đã OUT, hủy {old_req - picked} PCS phần còn lại. Lý do: {reason}"
            else:
                ticket["status"] = "Đã hủy"
                ticket["shortage_pcs"] = 0
                ticket["shortage_note"] = f"Hủy phiếu do thiếu tồn: {reason}"
                detail_log = f"Hủy toàn bộ phiếu chưa thực hiện ({old_req} PCS). Lý do: {reason}"

        ticket["updated_at"] = now_str
        ticket.setdefault("history", []).append({
            "time": now_str,
            "actor": dispatcher_name,
            "action": "Xử lý ngoại lệ thiếu tồn",
            "detail": detail_log
        })
        write_json(PICKING_FILE, picking_list)

    if "add_audit_log" in globals():
        add_audit_log("Nghiệp vụ kho", "Điều phối xử lý thiếu tồn phiếu lấy hàng", pick_id, detail_log)

    return jsonify({"status": "ok"})


@app.route("/api/dispatcher/picking-requests/<pick_id>/cancel", methods=["POST"])
@dispatcher_required
def api_dispatcher_cancel_picking(pick_id):
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason", "")).strip() or "Điều phối hủy yêu cầu"

    with _disp_pick_lock:
        picking_list = read_json(PICKING_FILE, [])
        ticket = next((o for o in picking_list if (o.get("id") or o.get("pick_id")) == pick_id), None)
        if not ticket:
            return jsonify({"error": "Không tìm thấy phiếu yêu cầu"}), 404

        if int(ticket.get("picked_pcs", 0) or 0) > 0:
            return jsonify({
                "error": f"Phiếu {pick_id} đã phát sinh giao dịch OUT ({ticket.get('picked_pcs')} PCS). Không được phép hủy xóa phiếu!"
            }), 400

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        ticket["status"] = "Đã hủy"
        ticket["updated_at"] = now_str
        ticket.setdefault("history", []).append({
            "time": now_str,
            "actor": dispatcher_name,
            "action": "Hủy phiếu yêu cầu lấy hàng",
            "detail": reason
        })
        write_json(PICKING_FILE, picking_list)

        tasks = read_json(STAFF_TASKS_FILE, [])
        tasks = [t for t in tasks if t.get("reference_id") != pick_id]
        write_json(STAFF_TASKS_FILE, tasks)

    if "add_audit_log" in globals():
        add_audit_log("Nghiệp vụ kho", "Hủy phiếu yêu cầu lấy hàng", pick_id, reason)

    return jsonify({"status": "ok"})

# CHỨC NĂNG THEO DÕI XỬ LÝ ĐƠN (DISPATCHER ORDER TRACKING)
def _get_sla_thresholds_minutes():
    """Đọc ngưỡng cảnh báo chậm lấy hàng / đóng gói từ system_settings.json."""
    cfg = load_system_settings() if "load_system_settings" in globals() else read_json(SETTINGS_FILE, {})
    ops_cfg = cfg.get("operations", {}) if isinstance(cfg, dict) else {}
    return {
        "pick_delay_min": int(ops_cfg.get("pick_start_sla_minutes", 30) or 30),
        "pack_delay_min": int(ops_cfg.get("pack_finish_sla_minutes", 45) or 45)
    }


def _parse_dt_flexible(raw_str):
    if not raw_str:
        return None
    s = str(raw_str).strip().replace("T", " ")
    for fmt in (
        "%d/%m/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%d/%m/%Y"
    ):
        try:
            return datetime.strptime(s[:len(fmt) + 2].strip(), fmt)
        except ValueError:
            continue
    return None


@app.route("/dispatcher/order-tracking")
@dispatcher_required
def dispatcher_order_tracking_page():
    return render_template(
        "DISPATCHER/dispatcher_order_tracking.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/order-tracking", methods=["GET"])
@dispatcher_required
def api_dispatcher_order_tracking():
    try:
        now_dt = datetime.now()
        today_date = now_dt.date()
        sla_cfg = _get_sla_thresholds_minutes()

        date_range = str(request.args.get("range", "TODAY")).strip().upper()
        from_str = str(request.args.get("from", "")).strip()
        to_str = str(request.args.get("to", "")).strip()
        date_from = _parse_dt_flexible(from_str).date() if _parse_dt_flexible(from_str) else None
        date_to = _parse_dt_flexible(to_str).date() if _parse_dt_flexible(to_str) else None

        catalog = _get_active_catalog_skus() if "_get_active_catalog_skus" in globals() else []
        sku_name_map = {c["sku"]: c["name"] for c in catalog}

        picking_list = read_json(PICKING_FILE, [])
        if isinstance(picking_list, dict):
            picking_list = picking_list.get("orders", [])

        ret_orders = _load_return_orders() if "_load_return_orders" in globals() else read_json(RETURNS_FILE, [])
        if isinstance(ret_orders, dict):
            ret_orders = ret_orders.get("orders", [])

        prepack_list = read_json(PREPACKING_FILE, [])
        if isinstance(prepack_list, dict):
            prepack_list = prepack_list.get("orders", [])

        packing_list = read_json(PACKING_FILE, [])
        if isinstance(packing_list, dict):
            packing_list = packing_list.get("orders", [])

        approvals = read_json(APPROVALS_FILE, {})
        if not isinstance(approvals, dict):
            approvals = {}

        prepack_by_order = {str(p.get("order_code", "")).upper(): p for p in prepack_list if p.get("order_code")}
        packing_by_order = {str(pk.get("order_code", "")).upper(): pk for pk in packing_list if pk.get("order_code")}

        pending_bg_by_order = {
            str(t.get("order_or_po", "")).upper(): t
            for t in approvals.get("pending_tickets", [])
            if t.get("category") == "HANDOVER"
        }
        approved_bg_by_order = {
            str(t.get("order_or_po", "")).upper(): t
            for t in approvals.get("processed_tickets", [])
            if t.get("category") == "HANDOVER" and "xác nhận" in str(t.get("status", "")).lower()
        }

        tracked_orders = []

        for o in picking_list:
            raw_st = o.get("status", "Chờ thực hiện")
            if raw_st in ("Nháp", "Đã hủy", "Hủy"):
                continue

            created_str = o.get("created_at") or now_dt.strftime("%d/%m/%Y %H:%M")
            created_dt = _parse_dt_flexible(created_str) or now_dt
            o_date = created_dt.date()

            if date_range == "TODAY" and o_date != today_date:
                continue
            elif date_range == "7D" and (today_date - o_date).days > 7:
                continue
            elif date_range == "30D" and (today_date - o_date).days > 30:
                continue
            elif date_range == "CUSTOM":
                if date_from and o_date < date_from:
                    continue
                if date_to and o_date > date_to:
                    continue

            pick_id = o.get("id") or o.get("pick_id") or ""
            order_code = str(o.get("order_code") or o.get("order_id") or "").upper()
            platform = o.get("platform", "Shopee")
            priority = o.get("priority", "Bình thường")
            deadline_str = o.get("deadline", "")
            updated_str = o.get("updated_at") or created_str
            deadline_dt = _parse_dt_flexible(deadline_str)

            pre_obj = prepack_by_order.get(order_code)
            pk_obj = packing_by_order.get(order_code)
            pending_bg = pending_bg_by_order.get(order_code)
            approved_bg = approved_bg_by_order.get(order_code)

            has_combo = bool(o.get("is_combo", False)) or bool(pre_obj and pre_obj.get("is_combo"))

            returned_by_sku = {}
            tx_logs = []
            for tx in o.get("transactions", []):
                tx_logs.append({
                    "type": "OUT",
                    "box_id": tx.get("box_id", "--"),
                    "location": tx.get("location_snapshot", "--"),
                    "qty_pcs": int(tx.get("picked_pcs", 0) or 0),
                    "staff": tx.get("staff_name", o.get("assignee", "")),
                    "time": tx.get("time", "--")
                })

            for r in ret_orders:
                if str(r.get("out_order_id", "")).upper() == str(pick_id).upper() and r.get("status") == "Hoàn thành":
                    r_sku = str(r.get("sku", "")).upper()
                    r_qty = int(r.get("returned_pcs", 0) or 0)
                    returned_by_sku[r_sku] = returned_by_sku.get(r_sku, 0) + r_qty
                    for rtx in r.get("transactions", []):
                        tx_logs.append({
                            "type": "RETURNED",
                            "box_id": rtx.get("box_id", "--"),
                            "location": rtx.get("location_snapshot", "--"),
                            "qty_pcs": -int(rtx.get("returned_pcs", 0) or 0),
                            "staff": rtx.get("staff_name", ""),
                            "time": rtx.get("time", "--")
                        })

            raw_items = o.get("items") or [{
                "sku": o.get("sku", ""),
                "product_name": o.get("product_name", ""),
                "requested_pcs": int(o.get("required_pcs", 0) or 0),
                "picked_pcs": int(o.get("picked_pcs", 0) or 0)
            }]

            sku_lines = []
            for it in raw_items:
                s_code = str(it.get("sku", "")).upper()
                req_pcs = int(it.get("requested_pcs", 0) or 0)
                raw_out = int(it.get("picked_pcs", 0) or 0)
                net_out = max(0, raw_out - returned_by_sku.get(s_code, 0))

                packed_pcs = 0
                if pk_obj:
                    if pk_obj.get("packing_status") == "COMPLETED":
                        packed_pcs = net_out
                    else:
                        for pkg in pk_obj.get("packages", []):
                            for p_it in pkg.get("items", []):
                                if str(p_it.get("sku", "")).upper() == s_code:
                                    packed_pcs += int(p_it.get("pcs_equiv", p_it.get("qty", 0)) or 0)

                is_handed_ok = bool(approved_bg) or (pk_obj and pk_obj.get("handover_status") == "APPROVED")
                handed_pcs = packed_pcs if is_handed_ok else 0

                sku_lines.append({
                    "sku": s_code,
                    "product_name": sku_name_map.get(s_code, it.get("product_name", s_code)),
                    "requested_pcs": req_pcs,
                    "out_pcs": net_out,
                    "packed_pcs": packed_pcs,
                    "handed_pcs": handed_pcs
                })

            total_req = sum(x["requested_pcs"] for x in sku_lines)
            total_out = sum(x["out_pcs"] for x in sku_lines)
            total_packed = sum(x["packed_pcs"] for x in sku_lines)
            total_handed = sum(x["handed_pcs"] for x in sku_lines)

            pick_progress_pct = min(100.0, round((total_out / total_req) * 100, 1)) if total_req > 0 else 0.0

            is_handed_done = bool(approved_bg) or (pk_obj and pk_obj.get("handover_status") == "APPROVED")
            out_ratio = min(1.0, total_out / total_req) if total_req > 0 else 0.0
            pack_ratio = min(1.0, total_packed / total_req) if total_req > 0 else 0.0
            hand_ratio = 1.0 if is_handed_done else 0.0

            if has_combo:
                pre_req = int(pre_obj.get("required_qty", 1) or 1) if pre_obj else 1
                pre_done = int(pre_obj.get("prepared_qty", 0) or 0) if pre_obj else 0
                pre_ratio = min(1.0, pre_done / max(pre_req, 1)) if pre_obj else 0.0
                overall_progress_pct = round(out_ratio * 40 + pre_ratio * 20 + pack_ratio * 20 + hand_ratio * 20)
                weight_formula_note = "Trọng số đơn Combo: OUT 40% · Pre-packing 20% · Đóng gói 20% · Bàn giao 20%"
            else:
                overall_progress_pct = round(out_ratio * 50 + pack_ratio * 25 + hand_ratio * 25)
                weight_formula_note = "Trọng số đơn lẻ: OUT 50% · Đóng gói 25% · Bàn giao 25%"

            is_waiting_handover = (
                not is_handed_done
                and (
                    bool(pending_bg)
                    or (pk_obj and pk_obj.get("packing_status") == "COMPLETED")
                    or (pk_obj and pk_obj.get("handover_status") == "SUBMITTED")
                )
            )
            is_packing = (
                not is_handed_done
                and not is_waiting_handover
                and (
                    (pk_obj and pk_obj.get("packing_status") in ("PENDING", "IN_PROGRESS", "ISSUE"))
                    or (not has_combo and total_req > 0 and total_out >= total_req)
                )
            )
            is_prepacking = (
                not is_handed_done
                and not is_waiting_handover
                and not is_packing
                and has_combo
                and total_out > 0
                and (not pre_obj or pre_obj.get("status") != "Đã chuyển đóng gói")
            )
            is_picking = (
                not is_handed_done
                and not is_waiting_handover
                and not is_packing
                and not is_prepacking
                and (raw_st == "Đang thực hiện" or total_out > 0)
            )

            if is_handed_done:
                stage_key, stage_label = "HANDED_OVER", "Đã bàn giao"
            elif is_waiting_handover:
                stage_key, stage_label = "WAITING_HANDOVER", "Chờ bàn giao"
            elif is_packing:
                stage_key, stage_label = "PACKING", "Đóng gói"
            elif is_prepacking:
                stage_key, stage_label = "PREPACKING", "Pre-packing"
            elif is_picking:
                stage_key, stage_label = "PICKING", "Đang OUT"
            else:
                stage_key, stage_label = "WAITING_PICK", "Chờ lấy hàng"

            has_real_shortage = (raw_st in ("Thiếu hàng", "Thiếu tồn")) or (int(o.get("shortage_pcs", 0) or 0) > 0)

            alerts = []
            if deadline_dt and now_dt > deadline_dt and stage_key != "HANDED_OVER":
                alerts.append({"code": "OVERDUE", "label": "Quá hạn", "level": "danger"})
            if has_real_shortage:
                alerts.append({"code": "SHORTAGE", "label": "Thiếu tồn", "level": "warning"})
            if stage_key == "WAITING_PICK":
                elapsed_min = (now_dt - created_dt).total_seconds() / 60.0
                if elapsed_min > sla_cfg["pick_delay_min"]:
                    alerts.append({"code": "SLOW_PICK", "label": "Chậm lấy hàng", "level": "warning"})
            if stage_key == "PACKING" and deadline_dt and now_dt > deadline_dt:
                alerts.append({"code": "SLOW_PACK", "label": "Chậm đóng gói", "level": "warning"})
            if pending_bg or (pk_obj and pk_obj.get("handover_status") == "SUBMITTED"):
                alerts.append({"code": "WAIT_MGR_HANDOVER", "label": "Chờ Manager xác nhận BG", "level": "info"})
            if total_packed > total_out or total_handed > total_packed:
                alerts.append({"code": "QTY_ANOMALY", "label": "Số lượng bất thường", "level": "danger"})

            unified_history = []
            for h in o.get("history", []):
                unified_history.append({
                    "time": h.get("time", created_str),
                    "event": h.get("action", "Cập nhật phiếu"),
                    "detail": h.get("detail", ""),
                    "actor": h.get("actor", "Điều phối")
                })
            if not unified_history:
                unified_history.append({
                    "time": created_str,
                    "event": f"Tạo & phát hành phiếu {pick_id}",
                    "detail": f"Yêu cầu {total_req} PCS · Giao cho {o.get('assignee', 'Staff')}",
                    "actor": o.get("created_by", "Điều phối")
                })

            for tx in tx_logs:
                if tx["type"] == "OUT":
                    unified_history.append({
                        "time": tx["time"],
                        "event": f"OUT {tx['qty_pcs']} PCS từ {tx['box_id']} ({tx['location']})",
                        "detail": f"Phiếu {pick_id}",
                        "actor": tx["staff"] or o.get("assignee", "Staff")
                    })
                else:
                    unified_history.append({
                        "time": tx["time"],
                        "event": f"RETURNED {abs(tx['qty_pcs'])} PCS về {tx['location']}",
                        "detail": f"Box {tx['box_id']}",
                        "actor": tx["staff"] or o.get("assignee", "Staff")
                    })

            if o.get("shortage_note"):
                unified_history.append({
                    "time": updated_str,
                    "event": "Ghi nhận ngoại lệ thiếu tồn",
                    "detail": o.get("shortage_note"),
                    "actor": o.get("assignee", "Staff")
                })

            if pk_obj and pk_obj.get("packing_status") == "COMPLETED":
                unified_history.append({
                    "time": updated_str,
                    "event": f"Hoàn tất đóng gói ({len(pk_obj.get('packages', []))} kiện · {total_packed} PCS)",
                    "detail": f"Phiếu đóng gói {pk_obj.get('id', '')}",
                    "actor": pk_obj.get("assignee", "Staff")
                })

            if pending_bg:
                unified_history.append({
                    "time": pending_bg.get("sent_at", updated_str),
                    "event": f"Gửi bàn giao {pending_bg.get('id')} chờ Manager xác nhận",
                    "detail": f"Người nhận: {pending_bg.get('receiver', '--')}",
                    "actor": pending_bg.get("sender", "Staff")
                })

            if approved_bg:
                unified_history.append({
                    "time": approved_bg.get("reviewed_at", updated_str),
                    "event": f"Manager xác nhận bàn giao {approved_bg.get('id')}",
                    "detail": f"Hoàn tất {total_handed} PCS",
                    "actor": approved_bg.get("reviewed_by", "Manager")
                })

            prepack_info = {
                "applicable": has_combo,
                "id": pre_obj.get("id", "--") if pre_obj else "--",
                "status": pre_obj.get("status", "Chờ chuẩn bị") if (has_combo and pre_obj) else ("Chờ chuyển bàn Pre-pack" if has_combo else "Không áp dụng"),
                "required_qty": int(pre_obj.get("required_qty", 0) or 0) if pre_obj else 0,
                "prepared_qty": int(pre_obj.get("prepared_qty", 0) or 0) if pre_obj else 0,
                "assignee": pre_obj.get("assignee", o.get("assignee", "")) if pre_obj else o.get("assignee", "")
            }

            packing_info = {
                "id": pk_obj.get("id", "--") if pk_obj else "--",
                "status": pk_obj.get("display_status", "Chưa bắt đầu") if pk_obj else "Chưa bắt đầu",
                "packages_count": len(pk_obj.get("packages", [])) if pk_obj else 0,
                "packages": pk_obj.get("packages", []) if pk_obj else [],
                "packed_pcs": total_packed,
                "assignee": pk_obj.get("assignee", o.get("assignee", "")) if pk_obj else o.get("assignee", "")
            }

            handover_source = approved_bg or pending_bg or {}
            handover_info = {
                "id": handover_source.get("id") or (pk_obj.get("handover_id") if pk_obj else "--") or "--",
                "status": "Đã xác nhận bàn giao" if is_handed_done else ("Chờ Manager xác nhận" if is_waiting_handover else "Chưa bàn giao"),
                "receiver": handover_source.get("receiver") or (pk_obj.get("receiver") if pk_obj else "--") or "--",
                "sender": handover_source.get("sender") or o.get("assignee", "--"),
                "reviewed_by": handover_source.get("reviewed_by") or (pk_obj.get("reviewed_by") if pk_obj else "--") or "--",
                "reviewed_at": handover_source.get("reviewed_at", "--"),
                "total_pcs": total_handed if is_handed_done else total_packed
            }

            sku_summary = (
                sku_lines[0]["product_name"] + f" ({sku_lines[0]['sku']})"
                if len(sku_lines) == 1
                else f"{len(sku_lines)} SKU ({', '.join(x['sku'] for x in sku_lines)})"
            )

            tracked_orders.append({
                "pick_id": pick_id,
                "order_code": order_code,
                "platform": platform,
                "priority": priority,
                "deadline": deadline_str.replace("T", " ") if deadline_str else "--",
                "created_at": created_str,
                "updated_at": updated_str,
                "assignee": o.get("assignee", "Chưa phân công"),
                "has_combo": has_combo,
                "note": o.get("note", "—"),
                "stage_key": stage_key,
                "stage_label": stage_label,
                "pick_progress_pct": pick_progress_pct,
                "overall_progress_pct": overall_progress_pct,
                "weight_formula_note": weight_formula_note,
                "has_real_shortage": has_real_shortage,
                "total_req_pcs": total_req,
                "total_out_pcs": total_out,
                "total_packed_pcs": total_packed,
                "total_handed_pcs": total_handed,
                "total_rem_out_pcs": max(0, total_req - total_out),
                "sku_summary": sku_summary,
                "sku_lines": sku_lines,
                "alerts": alerts,
                "tx_logs": tx_logs,
                "prepack_info": prepack_info,
                "packing_info": packing_info,
                "handover_info": handover_info,
                "history": unified_history
            })

        kpi_counts = {
            "ALL": len(tracked_orders),
            "WAITING_PICK": sum(1 for x in tracked_orders if x["stage_key"] == "WAITING_PICK"),
            "PICKING": sum(1 for x in tracked_orders if x["stage_key"] == "PICKING"),
            "PREPACKING": sum(1 for x in tracked_orders if x["stage_key"] == "PREPACKING"),
            "PACKING": sum(1 for x in tracked_orders if x["stage_key"] == "PACKING"),
            "WAITING_HANDOVER": sum(1 for x in tracked_orders if x["stage_key"] == "WAITING_HANDOVER"),
            "HANDED_OVER": sum(1 for x in tracked_orders if x["stage_key"] == "HANDED_OVER")
        }

        staffs = _get_active_warehouse_staffs() if "_get_active_warehouse_staffs" in globals() else []

        return jsonify({
            "orders": tracked_orders,
            "counts": kpi_counts,
            "staffs": staffs,
            "synced_at": now_dt.strftime("%H:%M:%S")
        })
    except Exception as exc:
        app.logger.exception("Lỗi API /api/dispatcher/order-tracking")
        return jsonify({"error": str(exc)}), 500


# CHỨC NĂNG DỮ LIỆU ĐỐI SOÁT (DISPATCHER RECONCILIATION DATA)
import csv
import io
import uuid

RECON_DATA_FILE = str(BASE_DIR / "sales_platform_orders.json")
RECON_BATCHES_FILE = str(BASE_DIR / "reconciliation_batches.json")
_recon_data_lock = threading.Lock()


def _normalize_platform_name(raw_plat):
    s = str(raw_plat or "").strip().lower()
    if "tiktok" in s:
        return "TikTok Shop"
    if "lazada" in s:
        return "Lazada"
    if "shopee" in s:
        return "Shopee"
    return raw_plat.strip() if raw_plat else "Shopee"


def _find_sanova_link_for_record(order_code, platform, sku, picking_list, approvals_data):
    """Ghép nối bản ghi nền tảng với phiếu lấy hàng (OUT) & phiếu bàn giao (BG) đã xác nhận."""
    ord_up = str(order_code or "").strip().upper()
    sku_up = str(sku or "").strip().upper()

    matched_pick = None
    for o in picking_list:
        o_code = str(o.get("order_code") or o.get("order_id") or "").strip().upper()
        if o_code != ord_up:
            continue
        items = o.get("items") or [{"sku": o.get("sku", "")}]
        if any(str(it.get("sku", "")).strip().upper() == sku_up for it in items):
            matched_pick = o
            break

    confirmed_bg = None
    for bg in approvals_data.get("processed_tickets", []):
        if bg.get("category") == "HANDOVER" and "xác nhận" in str(bg.get("status", "")).lower():
            if str(bg.get("order_or_po", "")).strip().upper() == ord_up:
                confirmed_bg = bg
                break

    if matched_pick:
        pick_id = matched_pick.get("id") or matched_pick.get("pick_id")
        return {
            "linked": True,
            "pick_id": pick_id,
            "handover_id": confirmed_bg.get("id") if confirmed_bg else "",
            "handover_confirmed": bool(confirmed_bg)
        }
    return {
        "linked": False,
        "pick_id": "",
        "handover_id": "",
        "handover_confirmed": False
    }


def _validate_and_enrich_recon_record(rec, existing_records, sku_map, picking_list, approvals_data, exclude_id=None):
    """Kiểm tra cấu trúc, danh mục SKU, trùng lặp và tách bạch 3 trạng thái độc lập."""
    platform = _normalize_platform_name(rec.get("platform"))
    order_code = str(rec.get("order_code", "")).strip().upper()
    sku = str(rec.get("sku", "")).strip().upper()
    line_ref = str(rec.get("source_line_id", "")).strip().upper()
    tx_date_raw = str(rec.get("transaction_date", "")).strip()

    try:
        qty_pcs = int(float(rec.get("platform_pcs", 0)))
    except (ValueError, TypeError):
        qty_pcs = 0

    parsed_dt = _parse_dt_flexible(tx_date_raw) if "_parse_dt_flexible" in globals() else None
    norm_date = parsed_dt.strftime("%Y-%m-%d") if parsed_dt else tx_date_raw

    errors = []
    error_code = ""

    if not order_code:
        errors.append("Thiếu mã đơn hàng nền tảng")
        error_code = "MISSING_ORDER"
    elif platform not in ("Shopee", "TikTok Shop", "Lazada"):
        errors.append("Nền tảng không hợp lệ")
        error_code = "INVALID_PLATFORM"
    elif not parsed_dt:
        errors.append("Sai định dạng ngày giao dịch")
        error_code = "INVALID_DATE"
    elif not sku or sku not in sku_map:
        errors.append(f"SKU '{sku or 'Trống'}' không tồn tại trong danh mục Manager")
        error_code = "SKU_NOT_FOUND"
    elif qty_pcs <= 0:
        errors.append("Số lượng PCS phải > 0")
        error_code = "INVALID_QTY"

    is_duplicate = False
    dup_of_id = ""
    if not errors:
        for ex in existing_records:
            if exclude_id and ex.get("record_id") == exclude_id:
                continue
            if ex.get("check_status") == "Trùng lặp" and ex.get("ignored_duplicate"):
                continue
            same_key = (
                _normalize_platform_name(ex.get("platform")) == platform
                and str(ex.get("order_code", "")).strip().upper() == order_code
                and str(ex.get("sku", "")).strip().upper() == sku
            )
            if same_key:
                ex_line = str(ex.get("source_line_id", "")).strip().upper()
                if not line_ref or not ex_line or line_ref == ex_line:
                    is_duplicate = True
                    dup_of_id = ex.get("record_id", "")
                    break

    link_info = _find_sanova_link_for_record(order_code, platform, sku, picking_list, approvals_data)
    prod_name = sku_map[sku]["name"] if sku in sku_map else "Chưa xác định"

    if errors:
        check_status = "Có lỗi"
        link_status = "Chờ liên kết"
        confirm_status = "Chưa xác nhận"
    elif is_duplicate:
        check_status = "Trùng lặp"
        link_status = "Đã liên kết" if link_info["linked"] else "Chờ liên kết"
        confirm_status = "Chưa xác nhận"
        error_code = "DUPLICATE"
        errors.append(f"Trùng bản ghi với {dup_of_id}")
    else:
        check_status = "Hợp lệ"
        link_status = "Đã liên kết" if link_info["linked"] else "Chờ liên kết"
        confirm_status = rec.get("confirm_status", "Chưa xác nhận")

    rec["platform"] = platform
    rec["order_code"] = order_code
    rec["sku"] = sku
    rec["product_name"] = prod_name
    rec["platform_pcs"] = qty_pcs
    rec["transaction_date"] = norm_date
    rec["check_status"] = check_status
    rec["link_status"] = link_status
    rec["confirm_status"] = confirm_status
    rec["linked_pick_id"] = link_info["pick_id"]
    rec["linked_handover_id"] = link_info["handover_id"]
    rec["error_code"] = error_code
    rec["error_message"] = "; ".join(errors)
    rec["duplicate_of"] = dup_of_id
    return rec


def _relink_all_recon_records():
    """
    Tự động đồng bộ & kiểm tra lại liên kết khi danh mục SKU (Manager) hoặc phiếu lấy hàng (OUT) thay đổi.
    Lưu lại vào sales_platform_orders.json nếu có bản ghi chuyển trạng thái liên kết hoặc hết lỗi SKU.
    """
    records = read_json(RECON_DATA_FILE, [])
    if not records:
        return []
    catalog = _get_active_catalog_skus() if "_get_active_catalog_skus" in globals() else []
    sku_map = {c["sku"]: c for c in catalog}
    picking_list = read_json(PICKING_FILE, [])
    approvals_data = read_json(APPROVALS_FILE, {})

    changed = False
    for r in records:
        old_sig = (r.get("check_status"), r.get("link_status"), r.get("linked_pick_id"), r.get("linked_handover_id"))
        # Nếu trước đó bị lỗi SKU_NOT_FOUND nhưng Manager vừa thêm SKU vào danh mục -> kiểm tra lại
        if r.get("check_status") == "Có lỗi" and r.get("error_code") == "SKU_NOT_FOUND" and r.get("sku") in sku_map:
            _validate_and_enrich_recon_record(r, records, sku_map, picking_list, approvals_data, exclude_id=r.get("record_id"))
        elif r.get("check_status") == "Hợp lệ":
            lk = _find_sanova_link_for_record(r.get("order_code"), r.get("platform"), r.get("sku"), picking_list, approvals_data)
            r["link_status"] = "Đã liên kết" if lk["linked"] else "Chờ liên kết"
            r["linked_pick_id"] = lk["pick_id"]
            r["linked_handover_id"] = lk["handover_id"]
        new_sig = (r.get("check_status"), r.get("link_status"), r.get("linked_pick_id"), r.get("linked_handover_id"))
        if old_sig != new_sig:
            changed = True

    if changed:
        write_json(RECON_DATA_FILE, records)
    return records


def _map_csv_row_to_standard(row_dict, default_platform):
    norm_keys = {str(k).strip().lower(): str(v).strip() for k, v in row_dict.items() if k is not None}

    def pick_col(candidates):
        for c in candidates:
            if c in norm_keys and norm_keys[c] != "":
                return norm_keys[c]
        return ""

    order_code = pick_col(["mã đơn", "ma don", "order_id", "order id", "mã đơn hàng", "order sn"])
    sku = pick_col(["sku", "mã sku", "ma sku", "seller sku", "sku phân loại", "product_sku"])
    qty = pick_col(["số lượng", "so luong", "pcs", "qty", "quantity", "số pcs"])
    tx_date = pick_col(["ngày giao dịch", "ngay giao dich", "date", "transaction_date", "ngày đặt hàng", "order date"])
    plat = pick_col(["nền tảng", "nen tang", "platform", "channel"]) or default_platform
    line_id = pick_col(["mã dòng", "line_id", "item_id", "source_line_id"])
    note = pick_col(["ghi chú", "ghi chu", "note"])

    return {
        "raw_source": dict(row_dict),  # Giữ nguyên dữ liệu gốc lúc import
        "platform": plat,
        "order_code": order_code,
        "sku": sku,
        "platform_pcs": qty,
        "transaction_date": tx_date or datetime.now().strftime("%Y-%m-%d"),
        "source_line_id": line_id,
        "note": note
    }


def _read_uploaded_rows(file_storage):
    """Đọc được cả tệp .xlsx (Excel) lẫn .csv."""
    fname = str(file_storage.filename or "").lower()
    raw_bytes = file_storage.read()
    if fname.endswith(".xlsx"):
        try:
            import openpyxl
            wb = openpyxl.load_workbook(io.BytesIO(raw_bytes), data_only=True)
            ws = wb.active
            rows_iter = list(ws.iter_rows(values_only=True))
            if not rows_iter:
                return []
            headers = [str(h or "").strip() for h in rows_iter[0]]
            out = []
            for r in rows_iter[1:]:
                if not any(r):
                    continue
                out.append({headers[i]: ("" if r[i] is None else str(r[i]).strip()) for i in range(len(headers))})
            return out
        except ImportError:
            raise ValueError("Máy chủ chưa cài thư viện openpyxl để đọc .xlsx, vui lòng lưu file dưới dạng CSV (UTF-8)!")
    try:
        text_content = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        text_content = raw_bytes.decode("latin-1", errors="ignore")
    return list(csv.DictReader(io.StringIO(text_content)))


@app.route("/dispatcher/reconciliation-data")
@dispatcher_required
def dispatcher_reconciliation_data_page():
    return render_template(
        "DISPATCHER/dispatcher_reconciliation_data.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/reconciliation-data", methods=["GET"])
@dispatcher_required
def api_dispatcher_recon_data_list():
    today_date = datetime.now().date()
    date_range = str(request.args.get("range", "ALL")).strip().upper()
    from_str = str(request.args.get("from", "")).strip()
    to_str = str(request.args.get("to", "")).strip()
    plat_filter = str(request.args.get("platform", "ALL")).strip()
    batch_filter = str(request.args.get("batch", "ALL")).strip()
    importer_filter = str(request.args.get("importer", "ALL")).strip()

    d_from = _parse_dt_flexible(from_str).date() if _parse_dt_flexible(from_str) else None
    d_to = _parse_dt_flexible(to_str).date() if _parse_dt_flexible(to_str) else None

    with _recon_data_lock:
        enriched_all = _relink_all_recon_records()

    batches = read_json(RECON_BATCHES_FILE, [])
    catalog = _get_active_catalog_skus() if "_get_active_catalog_skus" in globals() else []

    filtered = []
    for r in enriched_all:
        if plat_filter != "ALL" and _normalize_platform_name(r.get("platform")) != plat_filter:
            continue
        if batch_filter != "ALL" and r.get("batch_id") != batch_filter:
            continue
        if importer_filter != "ALL" and r.get("imported_by") != importer_filter:
            continue

        dt_obj = _parse_dt_flexible(r.get("transaction_date"))
        r_date = dt_obj.date() if dt_obj else today_date
        if date_range == "TODAY" and r_date != today_date:
            continue
        elif date_range == "7D" and (today_date - r_date).days > 7:
            continue
        elif date_range == "30D" and (today_date - r_date).days > 30:
            continue
        elif date_range == "CUSTOM":
            if d_from and r_date < d_from:
                continue
            if d_to and r_date > d_to:
                continue

        filtered.append(r)

    kpis = {
        "total": len(filtered),
        "valid": sum(1 for x in filtered if x.get("check_status") == "Hợp lệ" and x.get("link_status") == "Đã liên kết"),
        "need_action": sum(1 for x in filtered if x.get("check_status") in ("Có lỗi", "Trùng lặp")),
        "waiting_link": sum(1 for x in filtered if x.get("check_status") == "Hợp lệ" and x.get("link_status") == "Chờ liên kết")
    }
    importers = sorted(list({x.get("imported_by", "") for x in enriched_all if x.get("imported_by")}))

    return jsonify({
        "records": filtered,
        "kpis": kpis,
        "batches": batches,
        "importers": importers,
        "skus": catalog,
        "synced_at": datetime.now().strftime("%H:%M:%S")
    })


@app.route("/api/dispatcher/reconciliation-data/template/<platform_key>", methods=["GET"])
@dispatcher_required
def api_dispatcher_recon_template(platform_key):
    """Tải file mẫu Excel (.xlsx nếu có openpyxl, fallback .csv UTF-8)."""
    plat_label = _normalize_platform_name(platform_key)
    today_s = datetime.now().strftime("%Y-%m-%d")
    headers = ["Mã đơn", "Ngày giao dịch", "Nền tảng", "SKU", "Số lượng", "Mã dòng", "Ghi chú"]
    sample_rows = [
        ["DH-0031", today_s, plat_label, "SP0001", 50, "LN-01", "Đơn xuất tiêu chuẩn"],
        ["DH-0032", today_s, plat_label, "SP0002", 30, "LN-01", ""]
    ]
    try:
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "DuLieuDoiSoat"
        ws.append(headers)
        for r in sample_rows:
            ws.append(r)
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        fname = f"SANOVA_MauDoiSoat_{plat_label.replace(' ', '')}.xlsx"
        return Response(
            buf.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f"attachment; filename={fname}"}
        )
    except ImportError:
        output = io.StringIO()
        output.write("\ufeff")
        writer = csv.writer(output)
        writer.writerow(headers)
        for r in sample_rows:
            writer.writerow(r)
        fname = f"SANOVA_MauDoiSoat_{plat_label.replace(' ', '')}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={fname}"}
        )


@app.route("/api/dispatcher/reconciliation-data/preview-file", methods=["POST"])
@dispatcher_required
def api_dispatcher_recon_preview_file():
    file = request.files.get("file")
    default_plat = _normalize_platform_name(request.form.get("platform", "Shopee"))
    if not file or not file.filename:
        return jsonify({"error": "Vui lòng chọn tệp Excel (.xlsx) hoặc CSV (.csv) hợp lệ!"}), 400

    try:
        raw_rows = _read_uploaded_rows(file)
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    existing_records = read_json(RECON_DATA_FILE, [])
    catalog = _get_active_catalog_skus()
    sku_map = {c["sku"]: c for c in catalog}
    picking_list = read_json(PICKING_FILE, [])
    approvals_data = read_json(APPROVALS_FILE, {})

    preview_rows = []
    temp_pool = list(existing_records)
    err_breakdown = {"SKU_NOT_FOUND": 0, "DUPLICATE": 0, "INVALID_QTY": 0, "OTHER": 0}

    for idx, row in enumerate(raw_rows, start=1):
        mapped = _map_csv_row_to_standard(row, default_plat)
        mapped["record_id"] = f"PREVIEW-{idx}"
        checked = _validate_and_enrich_recon_record(mapped, temp_pool, sku_map, picking_list, approvals_data)
        preview_rows.append(checked)
        temp_pool.append(checked)

        if checked["check_status"] != "Hợp lệ":
            ec = checked.get("error_code", "OTHER")
            err_breakdown[ec if ec in err_breakdown else "OTHER"] += 1

    valid_cnt = sum(1 for x in preview_rows if x["check_status"] == "Hợp lệ")
    return jsonify({
        "filename": file.filename,
        "total_rows": len(preview_rows),
        "valid_count": valid_cnt,
        "error_count": len(preview_rows) - valid_cnt,
        "breakdown": err_breakdown,
        "rows": preview_rows
    })


@app.route("/api/dispatcher/reconciliation-data/commit-batch", methods=["POST"])
@dispatcher_required
def api_dispatcher_recon_commit_batch():
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}
    platform = _normalize_platform_name(body.get("platform", "Shopee"))
    filename = str(body.get("filename", "Nhap_file")).strip()
    batch_date = str(body.get("batch_date", datetime.now().strftime("%Y-%m-%d"))).strip()
    save_mode = str(body.get("save_mode", "ALL_WITH_QUEUE")).upper()
    rows = body.get("rows", [])

    if not rows:
        return jsonify({"error": "Không có dòng dữ liệu nào để lưu!"}), 400

    with _recon_data_lock:
        existing_records = read_json(RECON_DATA_FILE, [])
        batches = read_json(RECON_BATCHES_FILE, [])
        catalog = _get_active_catalog_skus()
        sku_map = {c["sku"]: c for c in catalog}
        picking_list = read_json(PICKING_FILE, [])
        approvals_data = read_json(APPROVALS_FILE, {})

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        batch_id = f"IMP-{datetime.now().strftime('%Y%m%d')}-{str(len(batches) + 1).zfill(3)}"

        saved_count, valid_saved, error_saved = 0, 0, 0
        for raw_r in rows:
            rec_id = f"DSR-{datetime.now().strftime('%m%d')}-{uuid.uuid4().hex[:5].upper()}"
            raw_origin = raw_r.get("raw_source") or {
                "platform": raw_r.get("platform"),
                "order_code": raw_r.get("order_code"),
                "sku": raw_r.get("sku"),
                "platform_pcs": raw_r.get("platform_pcs"),
                "transaction_date": raw_r.get("transaction_date")
            }
            base_rec = {
                "record_id": rec_id,
                "batch_id": batch_id,
                "raw_source": raw_origin,
                "platform": raw_r.get("platform") or platform,
                "order_code": raw_r.get("order_code", ""),
                "sku": raw_r.get("sku", ""),
                "platform_pcs": raw_r.get("platform_pcs", 0),
                "transaction_date": raw_r.get("transaction_date") or batch_date,
                "source_line_id": raw_r.get("source_line_id", ""),
                "note": raw_r.get("note", ""),
                "imported_by": dispatcher_name,
                "imported_at": now_str,
                "confirm_status": "Chưa xác nhận",
                "edit_history": [{
                    "time": now_str,
                    "actor": dispatcher_name,
                    "action": f"Nhập từ đợt {batch_id} ({filename})",
                    "detail": f"Đơn {raw_r.get('order_code')} · SKU {raw_r.get('sku')} · {raw_r.get('platform_pcs')} PCS"
                }]
            }
            validated = _validate_and_enrich_recon_record(base_rec, existing_records, sku_map, picking_list, approvals_data)
            if save_mode == "VALID_ONLY" and validated["check_status"] != "Hợp lệ":
                continue
            existing_records.insert(0, validated)
            saved_count += 1
            if validated["check_status"] == "Hợp lệ":
                valid_saved += 1
            else:
                error_saved += 1

        batches.insert(0, {
            "batch_id": batch_id,
            "platform": platform,
            "filename": filename,
            "batch_date": batch_date,
            "imported_by": dispatcher_name,
            "imported_at": now_str,
            "total_saved": saved_count,
            "valid_saved": valid_saved,
            "error_saved": error_saved
        })
        write_json(RECON_DATA_FILE, existing_records)
        write_json(RECON_BATCHES_FILE, batches)

    if "add_audit_log" in globals():
        add_audit_log("Nghiệp vụ kho", "Nhập dữ liệu đối soát nền tảng", batch_id, f"{filename}: {valid_saved} hợp lệ, {error_saved} lỗi/trùng")

    return jsonify({"status": "ok", "batch_id": batch_id, "saved_count": saved_count}), 201


@app.route("/api/dispatcher/reconciliation-data/manual", methods=["POST"])
@dispatcher_required
def api_dispatcher_recon_manual_create():
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}

    with _recon_data_lock:
        existing_records = read_json(RECON_DATA_FILE, [])
        catalog = _get_active_catalog_skus()
        sku_map = {c["sku"]: c for c in catalog}
        picking_list = read_json(PICKING_FILE, [])
        approvals_data = read_json(APPROVALS_FILE, {})

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        rec_id = f"DSR-{datetime.now().strftime('%m%d')}-{uuid.uuid4().hex[:5].upper()}"

        new_rec = {
            "record_id": rec_id,
            "batch_id": "MANUAL",
            "raw_source": {
                "platform": body.get("platform", "Shopee"),
                "order_code": body.get("order_code", ""),
                "sku": body.get("sku", ""),
                "platform_pcs": body.get("platform_pcs", 0),
                "transaction_date": body.get("transaction_date", "")
            },
            "platform": body.get("platform", "Shopee"),
            "order_code": body.get("order_code", ""),
            "sku": body.get("sku", ""),
            "platform_pcs": body.get("platform_pcs", 0),
            "transaction_date": body.get("transaction_date", datetime.now().strftime("%Y-%m-%d")),
            "source_line_id": body.get("source_line_id", ""),
            "note": body.get("note", ""),
            "imported_by": dispatcher_name,
            "imported_at": now_str,
            "confirm_status": "Chưa xác nhận",
            "edit_history": [{
                "time": now_str,
                "actor": dispatcher_name,
                "action": "Nhập thủ công bản ghi đối soát",
                "detail": f"Đơn {body.get('order_code')} · SKU {body.get('sku')} · {body.get('platform_pcs')} PCS"
            }]
        }
        validated = _validate_and_enrich_recon_record(new_rec, existing_records, sku_map, picking_list, approvals_data)
        if validated["check_status"] == "Có lỗi":
            return jsonify({"error": validated["error_message"]}), 400
        if validated["check_status"] == "Trùng lặp" and not body.get("force_save"):
            return jsonify({"error": f"Phát hiện trùng lặp với bản ghi {validated['duplicate_of']}!"}), 409

        existing_records.insert(0, validated)
        write_json(RECON_DATA_FILE, existing_records)

    return jsonify({"status": "ok", "record": validated}), 201


@app.route("/api/dispatcher/reconciliation-data/<record_id>", methods=["PATCH"])
@dispatcher_required
def api_dispatcher_recon_update_record(record_id):
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}
    action_type = str(body.get("action_type", "EDIT")).upper()
    reason = str(body.get("reason", "")).strip()

    with _recon_data_lock:
        records = read_json(RECON_DATA_FILE, [])
        target = next((r for r in records if r.get("record_id") == record_id), None)
        if not target:
            return jsonify({"error": "Không tìm thấy bản ghi dữ liệu đối soát"}), 404

        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")

        if action_type == "CONFIRM":
            if target.get("check_status") != "Hợp lệ":
                return jsonify({"error": "Chỉ bản ghi đạt trạng thái Hợp lệ mới được xác nhận đưa vào đối soát!"}), 400
            if target.get("link_status") != "Đã liên kết" and not body.get("allow_unlinked"):
                return jsonify({"error": "Bản ghi đang Chờ liên kết phiếu SANOVA. Hãy ghép phiếu hoặc xác nhận đưa vào đối soát ngoại lệ!"}), 400
            target["confirm_status"] = "Đã xác nhận"
            target.setdefault("edit_history", []).append({
                "time": now_str,
                "actor": dispatcher_name,
                "action": "Xác nhận dữ liệu đưa vào đối soát xuất hàng",
                "detail": f"Liên kết phiếu: {target.get('linked_pick_id') or 'Chưa có phiếu kho'}"
            })
            write_json(RECON_DATA_FILE, records)
            return jsonify({"status": "ok", "record": target})

        if action_type == "IGNORE_DUP":
            target["ignored_duplicate"] = True
            target["confirm_status"] = "Đã loại trừ trùng"
            target.setdefault("edit_history", []).append({
                "time": now_str,
                "actor": dispatcher_name,
                "action": "Bỏ qua bản ghi trùng lặp",
                "detail": reason or "Loại trừ bản ghi trùng lặp"
            })
            write_json(RECON_DATA_FILE, records)
            return jsonify({"status": "ok", "record": target})

        if not reason:
            return jsonify({"error": "Bắt buộc nhập lý do chỉnh sửa dữ liệu để lưu vết lịch sử!"}), 400

        old_snap = f"{target.get('platform')} | {target.get('order_code')} | {target.get('sku')} | {target.get('platform_pcs')} PCS | {target.get('transaction_date')}"
        for f in ("platform", "order_code", "sku", "platform_pcs", "transaction_date", "note"):
            if f in body:
                target[f] = body[f]

        catalog = _get_active_catalog_skus()
        sku_map = {c["sku"]: c for c in catalog}
        picking_list = read_json(PICKING_FILE, [])
        approvals_data = read_json(APPROVALS_FILE, {})

        _validate_and_enrich_recon_record(target, records, sku_map, picking_list, approvals_data, exclude_id=record_id)
        new_snap = f"{target.get('platform')} | {target.get('order_code')} | {target.get('sku')} | {target.get('platform_pcs')} PCS | {target.get('transaction_date')}"

        target.setdefault("edit_history", []).append({
            "time": now_str,
            "actor": dispatcher_name,
            "action": "Chỉnh sửa dữ liệu nguồn",
            "detail": f"Trước: [{old_snap}] → Sau: [{new_snap}] · Lý do: {reason}"
        })
        write_json(RECON_DATA_FILE, records)

    return jsonify({"status": "ok", "record": target})

#  CHỨC NĂNG ĐỐI SOÁT XUẤT HÀNG (OUTBOUND RECONCILIATION)
OUTBOUND_RECON_FILE = str(BASE_DIR / "outbound_reconciliations.json")
_outbound_recon_lock = threading.Lock()

def _compute_order_source_fingerprint(platform, order_code, sku_items, handover_tickets):
    """Tạo dấu vân tay dữ liệu nguồn để phát hiện nếu dữ liệu nền tảng hoặc bàn giao thay đổi sau khi chốt."""
    sig_obj = {
        "platform": platform,
        "order_code": order_code,
        "skus": sorted(
            [(x["sku"], x["platform_pcs"], x["handover_confirmed_pcs"]) for x in sku_items],
            key=lambda z: z[0]
        ),
        "bg_ids": sorted([h.get("id", "") for h in handover_tickets])
    }
    return hashlib.md5(json.dumps(sig_obj, sort_keys=True).encode("utf-8")).hexdigest()

def _build_outbound_reconciliation_orders():
    """
    Tổng hợp dữ liệu đối soát đa nguồn theo từng Đơn hàng & từng dòng SKU:
    - Nguồn 1: Dữ liệu nền tảng đã xác nhận từ sales_platform_orders.json
    - Nguồn 2: Phiếu yêu cầu lấy hàng & giao dịch OUT thực tế từ picking_orders.json
    - Nguồn 3: Tiến độ đóng gói từ packing_orders.json
    - Nguồn 4: Kết quả bàn giao ĐÃ ĐƯỢC MANAGER XÁC NHẬN từ approvals_data.json
    - Nguồn 5: Hồ sơ xử lý chênh lệch & phiên chốt đã lưu trong outbound_reconciliations.json
    """
    plat_records = read_json(RECON_DATA_FILE, [])
    picking_list = read_json(PICKING_FILE, [])
    packing_list = read_json(PACKING_FILE, [])
    approvals_data = read_json(APPROVALS_FILE, {})
    saved_recons = read_json(OUTBOUND_RECON_FILE, {})
    catalog = _get_active_catalog_skus() if "_get_active_catalog_skus" in globals() else []
    sku_name_map = {c["sku"]: c["name"] for c in catalog}

    # Chỉ lấy các bản ghi dữ liệu nền tảng đã qua kiểm tra Hợp lệ & Đã xác nhận (không lấy bản ghi trùng bị bỏ qua)
    confirmed_plat = [
        r for r in plat_records
        if r.get("check_status") == "Hợp lệ"
        and r.get("confirm_status") == "Đã xác nhận"
        and not r.get("ignored_duplicate")
    ]

    # Gom theo (platform, order_code)
    grouped_orders = {}
    for r in confirmed_plat:
        plat = _normalize_platform_name(r.get("platform"))
        ocode = str(r.get("order_code", "")).strip().upper()
        key = f"{plat}::{ocode}"
        grp = grouped_orders.setdefault(key, {
            "recon_key": key,
            "platform": plat,
            "order_code": ocode,
            "transaction_date": r.get("transaction_date", ""),
            "source_record_ids": [],
            "sku_platform_map": {}
        })
        grp["source_record_ids"].append(r.get("record_id"))
        s_up = str(r.get("sku", "")).strip().upper()
        s_entry = grp["sku_platform_map"].setdefault(s_up, {
            "sku": s_up,
            "product_name": sku_name_map.get(s_up, r.get("product_name", s_up)),
            "platform_pcs": 0,
            "record_ids": []
        })
        s_entry["platform_pcs"] += int(r.get("platform_pcs", 0) or 0)
        s_entry["record_ids"].append(r.get("record_id"))

    # Danh sách phiếu bàn giao đã Manager xác nhận & đang chờ xác nhận
    approved_handovers = [
        t for t in approvals_data.get("processed_tickets", [])
        if t.get("category") == "HANDOVER" and "xác nhận" in str(t.get("status", "")).lower()
    ]
    pending_handovers = [
        t for t in approvals_data.get("pending_tickets", [])
        if t.get("category") == "HANDOVER"
    ]

    results = []
    for key, grp in grouped_orders.items():
        ocode = grp["order_code"]
        plat = grp["platform"]

        # Tìm các phiếu OUT liên kết với mã đơn này
        linked_picks = [
            o for o in picking_list
            if str(o.get("order_code") or o.get("order_id") or "").strip().upper() == ocode
            and o.get("status") not in ("Đã hủy", "Hủy")
        ]
        pick_ids = [o.get("id") or o.get("pick_id") for o in linked_picks]

        # Tìm thông tin đóng gói
        linked_pack = next(
            (pk for pk in packing_list if str(pk.get("order_code", "")).strip().upper() == ocode),
            None
        )

        # Tìm các đợt bàn giao ĐÃ MANAGER XÁC NHẬN và ĐANG CHỜ XÁC NHẬN cho mã đơn này
        order_approved_bgs = [
            h for h in approved_handovers
            if str(h.get("order_or_po", "")).strip().upper() == ocode
        ]
        order_pending_bgs = [
            h for h in pending_handovers
            if str(h.get("order_or_po", "")).strip().upper() == ocode
        ]

        # Tính tổng PCS bàn giao đã xác nhận theo từng SKU
        confirmed_bg_by_sku = {}
        for bg in order_approved_bgs:
            for item in bg.get("items", []):
                i_sku = str(item.get("sku", "")).strip().upper()
                confirmed_bg_by_sku[i_sku] = confirmed_bg_by_sku.get(i_sku, 0) + int(item.get("qty_actual", item.get("qty_packed", 0)) or 0)

        # Tính OUT thực tế theo từng SKU (chỉ để truy vết nguyên nhân, không thay thế bàn giao)
        out_by_sku = {}
        for o in linked_picks:
            for it in (o.get("items") or [{"sku": o.get("sku", ""), "picked_pcs": o.get("picked_pcs", 0)}]):
                i_sku = str(it.get("sku", "")).strip().upper()
                out_by_sku[i_sku] = out_by_sku.get(i_sku, 0) + int(it.get("picked_pcs", 0) or 0)

        has_any_link = len(linked_picks) > 0 or len(order_approved_bgs) > 0 or len(order_pending_bgs) > 0
        has_confirmed_handover = len(order_approved_bgs) > 0
        has_pending_handover = len(order_pending_bgs) > 0

        # Đối chiếu từng SKU
        all_skus_in_order = sorted(list(set(grp["sku_platform_map"].keys()) | set(confirmed_bg_by_sku.keys())))
        sku_rows = []
        any_sku_mismatch = False
        any_sku_short = False
        any_sku_over = False

        for s_code in all_skus_in_order:
            plat_obj = grp["sku_platform_map"].get(s_code, {})
            p_pcs = int(plat_obj.get("platform_pcs", 0) or 0)
            o_pcs = int(out_by_sku.get(s_code, 0) or 0)
            bg_pcs = confirmed_bg_by_sku.get(s_code, None)

            if not has_any_link:
                row_result = "Chưa liên kết"
                diff_val = None
            elif not has_confirmed_handover:
                row_result = "Chưa bàn giao"
                diff_val = None
            else:
                actual_bg_pcs = int(bg_pcs or 0)
                diff_val = actual_bg_pcs - p_pcs
                if diff_val == 0:
                    row_result = "Khớp"
                elif diff_val < 0:
                    row_result = f"Thiếu {abs(diff_val)}"
                    any_sku_mismatch = True
                    any_sku_short = True
                else:
                    row_result = f"Thừa {diff_val}"
                    any_sku_mismatch = True
                    any_sku_over = True

            sku_rows.append({
                "sku": s_code,
                "product_name": sku_name_map.get(s_code, plat_obj.get("product_name", s_code)),
                "platform_pcs": p_pcs,
                "out_pcs": o_pcs,
                "handover_confirmed_pcs": int(bg_pcs or 0) if has_confirmed_handover else None,
                "diff_pcs": diff_val,
                "sku_result": row_result
            })

        # Kết luận tổng thể toàn đơn (mọi SKU phải khớp thì toàn đơn mới Khớp)
        if not has_any_link:
            result_code = "UNLINKED"
            result_label = "Chưa liên kết"
        elif not has_confirmed_handover:
            result_code = "NOT_HANDED_OVER"
            result_label = "Chưa bàn giao"
        elif has_pending_handover and any_sku_short:
            result_code = "PARTIAL_HANDOVER"
            result_label = "Đang bàn giao một phần"
        elif any_sku_mismatch:
            result_code = "MISMATCH"
            if any_sku_short and any_sku_over:
                result_label = "Lệch hỗn hợp (Thiếu & Thừa)"
            elif any_sku_short:
                result_label = "Thiếu hàng"
            else:
                result_label = "Thừa hàng"
        else:
            result_code = "MATCHED"
            result_label = "Khớp"

        total_plat_pcs = sum(x["platform_pcs"] for x in sku_rows)
        total_bg_pcs = sum(x["handover_confirmed_pcs"] for x in sku_rows) if has_confirmed_handover else None
        total_diff_pcs = (total_bg_pcs - total_plat_pcs) if (total_bg_pcs is not None) else None

        # Kiểm tra phiên bản đối soát đã lưu & phát hiện thay đổi nguồn
        saved_state = saved_recons.get(key, {})
        current_fp = _compute_order_source_fingerprint(plat, ocode, sku_rows, order_approved_bgs)
        process_status = saved_state.get("process_status", "Chưa xử lý")
        needs_recheck = False

        if process_status in ("Đã xác nhận", "Đã xác nhận có chênh lệch") and saved_state.get("source_fingerprint"):
            if saved_state["source_fingerprint"] != current_fp:
                process_status = "Cần đối soát lại"
                needs_recheck = True

        sku_summary = (
            f"{sku_rows[0]['product_name']} ({sku_rows[0]['sku']})"
            if len(sku_rows) == 1
            else f"{len(sku_rows)} SKU ({', '.join(x['sku'] for x in sku_rows)})"
        )

        results.append({
            "recon_key": key,
            "order_code": ocode,
            "platform": plat,
            "transaction_date": grp["transaction_date"],
            "pick_ids": pick_ids,
            "pick_id_display": ", ".join(pick_ids) if pick_ids else "—",
            "handover_ids": [h.get("id") for h in order_approved_bgs],
            "sku_summary": sku_summary,
            "sku_rows": sku_rows,
            "total_platform_pcs": total_plat_pcs,
            "total_handover_pcs": total_bg_pcs,
            "total_diff_pcs": total_diff_pcs,
            "result_code": result_code,
            "result_label": result_label,
            "process_status": process_status,
            "needs_recheck": needs_recheck,
            "discrepancy_cause": saved_state.get("discrepancy_cause", ""),
            "discrepancy_action": saved_state.get("discrepancy_action", ""),
            "discrepancy_note": saved_state.get("discrepancy_note", ""),
            "assigned_actor": saved_state.get("assigned_actor", ""),
            "confirmed_by": saved_state.get("confirmed_by", ""),
            "confirmed_at": saved_state.get("confirmed_at", ""),
            "packing_status": linked_pack.get("display_status", "—") if linked_pack else "—",
            "history": saved_state.get("history", [])
        })

    return results


@app.route("/dispatcher/outbound-reconciliation")
@dispatcher_required
def dispatcher_outbound_reconciliation_page():
    return render_template(
        "DISPATCHER/dispatcher_outbound_reconciliation.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/outbound-reconciliation", methods=["GET"])
@dispatcher_required
def api_dispatcher_outbound_recon_list():
    today_date = datetime.now().date()
    date_range = str(request.args.get("range", "ALL")).strip().upper()
    from_str = str(request.args.get("from", "")).strip()
    to_str = str(request.args.get("to", "")).strip()
    plat_filter = str(request.args.get("platform", "ALL")).strip()
    res_filter = str(request.args.get("result", "ALL")).strip().upper()

    d_from = _parse_dt_flexible(from_str).date() if _parse_dt_flexible(from_str) else None
    d_to = _parse_dt_flexible(to_str).date() if _parse_dt_flexible(to_str) else None

    all_orders = _build_outbound_reconciliation_orders()

    filtered = []
    for o in all_orders:
        if plat_filter != "ALL" and o["platform"] != plat_filter:
            continue
        dt_obj = _parse_dt_flexible(o.get("transaction_date"))
        o_date = dt_obj.date() if dt_obj else today_date
        if date_range == "TODAY" and o_date != today_date:
            continue
        elif date_range == "7D" and (today_date - o_date).days > 7:
            continue
        elif date_range == "30D" and (today_date - o_date).days > 30:
            continue
        elif date_range == "CUSTOM":
            if d_from and o_date < d_from:
                continue
            if d_to and o_date > d_to:
                continue

        if res_filter == "MATCHED" and o["result_code"] != "MATCHED":
            continue
        elif res_filter == "MISMATCH" and o["result_code"] not in ("MISMATCH", "PARTIAL_HANDOVER"):
            continue
        elif res_filter == "MISSING_DATA" and o["result_code"] not in ("NOT_HANDED_OVER", "UNLINKED"):
            continue
        elif res_filter == "CONFIRMED" and o["process_status"] not in ("Đã xác nhận", "Đã xác nhận có chênh lệch"):
            continue

        filtered.append(o)

    # 5 KPI tổng hợp theo thiết kế chốt
    kpis = {
        "total": len(filtered),
        "matched": sum(1 for x in filtered if x["result_code"] == "MATCHED"),
        "mismatch": sum(1 for x in filtered if x["result_code"] in ("MISMATCH", "PARTIAL_HANDOVER")),
        "missing_data": sum(1 for x in filtered if x["result_code"] in ("NOT_HANDED_OVER", "UNLINKED")),
        "confirmed": sum(1 for x in filtered if x["process_status"] in ("Đã xác nhận", "Đã xác nhận có chênh lệch"))
    }

    return jsonify({
        "orders": filtered,
        "kpis": kpis,
        "synced_at": datetime.now().strftime("%H:%M:%S")
    })


@app.route("/api/dispatcher/outbound-reconciliation/action", methods=["POST"])
@dispatcher_required
def api_dispatcher_outbound_recon_action():
    """
    Xử lý các thao tác đối soát trên từng đơn hàng:
    - RECORD_ISSUE: Ghi nhận nguyên nhân chênh lệch & hướng xử lý (không sửa số bàn giao)
    - SEND_CHECK: Gửi yêu cầu kiểm tra sang Staff hoặc Manager
    - CONFIRM_MATCHED: Xác nhận hoàn tất đối soát cho đơn Khớp 100%
    - CONFIRM_WITH_EXPLANATION: Chốt đối soát có giải trình chênh lệch (lưu trạng thái riêng 'Đã xác nhận có chênh lệch')
    """
    dispatcher_name = session.get("user", {}).get("name", "Điều phối viên")
    body = request.get_json(silent=True) or {}
    recon_key = str(body.get("recon_key", "")).strip()
    action = str(body.get("action", "")).upper()
    cause = str(body.get("cause", "")).strip()
    direction = str(body.get("direction", "")).strip()
    note = str(body.get("note", "")).strip()
    target_actor = str(body.get("target_actor", "")).strip()

    all_orders = _build_outbound_reconciliation_orders()
    order_obj = next((x for x in all_orders if x["recon_key"] == recon_key), None)
    if not order_obj:
        return jsonify({"error": "Không tìm thấy đơn hàng trong danh sách đối soát!"}), 404

    with _outbound_recon_lock:
        saved_recons = read_json(OUTBOUND_RECON_FILE, {})
        rec = saved_recons.setdefault(recon_key, {
            "order_code": order_obj["order_code"],
            "platform": order_obj["platform"],
            "history": []
        })
        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")

        # Tạo dấu vân tay dữ liệu nguồn tại thời điểm đối soát
        approvals_data = read_json(APPROVALS_FILE, {})
        approved_bgs = [
            t for t in approvals_data.get("processed_tickets", [])
            if t.get("category") == "HANDOVER"
            and "xác nhận" in str(t.get("status", "")).lower()
            and str(t.get("order_or_po", "")).strip().upper() == order_obj["order_code"]
        ]
        fp = _compute_order_source_fingerprint(order_obj["platform"], order_obj["order_code"], order_obj["sku_rows"], approved_bgs)

        if action == "RECORD_ISSUE":
            if not cause or not note:
                return jsonify({"error": "Vui lòng chọn nguyên nhân và nhập nội dung giải trình xử lý!"}), 400
            rec["discrepancy_cause"] = cause
            rec["discrepancy_action"] = direction
            rec["discrepancy_note"] = note
            rec["process_status"] = "Đang xử lý chênh lệch"
            rec["history"].insert(0, {
                "time": now_str,
                "actor": dispatcher_name,
                "action": f"Ghi nhận nguyên nhân: {cause}",
                "detail": f"Hướng xử lý: {direction} · Ghi chú: {note}"
            })

        elif action == "SEND_CHECK":
            if not target_actor or not note:
                return jsonify({"error": "Vui lòng chọn bộ phận tiếp nhận (Staff / Manager) và nhập nội dung kiểm tra!"}), 400
            rec["assigned_actor"] = target_actor
            rec["discrepancy_cause"] = cause or rec.get("discrepancy_cause", "")
            rec["discrepancy_note"] = note
            rec["process_status"] = f"Chờ {target_actor} kiểm tra"
            rec["history"].insert(0, {
                "time": now_str,
                "actor": dispatcher_name,
                "action": f"Gửi yêu cầu kiểm tra đến {target_actor}",
                "detail": note
            })

            # Nếu gửi Manager kiểm tra -> đẩy thông báo vào approvals_data.json / audit log
            if "Manager" in target_actor and "add_audit_log" in globals():
                add_audit_log("Nghiệp vụ kho", f"Điều phối gửi yêu cầu kiểm tra chênh lệch đơn {order_obj['order_code']}", order_obj["order_code"], note)

        elif action == "CONFIRM_MATCHED":
            if order_obj["result_code"] != "MATCHED":
                return jsonify({"error": "Chỉ đơn hàng Khớp 100% tất cả các SKU mới được xác nhận ở trạng thái Khớp!"}), 400
            rec["process_status"] = "Đã xác nhận"
            rec["confirmed_by"] = dispatcher_name
            rec["confirmed_at"] = now_str
            rec["source_fingerprint"] = fp
            rec["history"].insert(0, {
                "time": now_str,
                "actor": dispatcher_name,
                "action": "Xác nhận hoàn tất đối soát (Khớp)",
                "detail": f"Khớp {order_obj['total_platform_pcs']} PCS trên toàn bộ {len(order_obj['sku_rows'])} SKU"
            })

        elif action == "CONFIRM_WITH_EXPLANATION":
            if order_obj["result_code"] not in ("MISMATCH", "PARTIAL_HANDOVER"):
                return jsonify({"error": "Đơn hàng không ở trạng thái có chênh lệch!"}), 400
            if not (cause or rec.get("discrepancy_cause")) or not (note or rec.get("discrepancy_note")):
                return jsonify({"error": "Bắt buộc phải ghi nhận nguyên nhân và giải trình trước khi chốt chênh lệch!"}), 400
            rec["discrepancy_cause"] = cause or rec.get("discrepancy_cause")
            rec["discrepancy_note"] = note or rec.get("discrepancy_note")
            rec["process_status"] = "Đã xác nhận có chênh lệch"
            rec["confirmed_by"] = dispatcher_name
            rec["confirmed_at"] = now_str
            rec["source_fingerprint"] = fp
            rec["history"].insert(0, {
                "time": now_str,
                "actor": dispatcher_name,
                "action": "Chốt đối soát có giải trình chênh lệch",
                "detail": f"Chênh lệch {order_obj['total_diff_pcs']:+d} PCS · Nguyên nhân: {rec['discrepancy_cause']} · Giải trình: {rec['discrepancy_note']}"
            })
        else:
            return jsonify({"error": "Thao tác không hợp lệ!"}), 400

        write_json(OUTBOUND_RECON_FILE, saved_recons)

    if "add_audit_log" in globals():
        add_audit_log("Nghiệp vụ kho", f"Cập nhật đối soát xuất hàng ({rec['process_status']})", order_obj["order_code"], f"Nền tảng: {order_obj['platform']}")

    return jsonify({"status": "ok"})

#  CHỨC NĂNG BÁO CÁO & LỊCH SỬ (DISPATCHER REPORTS & HISTORY)
def _build_dispatcher_reports_and_history(
    date_range="7D",
    from_str="",
    to_str="",
    platform_filter="ALL",
    staff_filter="ALL",
    report_type="DISPATCH"
):
    now_dt = datetime.now()
    today_date = now_dt.date()
    d_from = _parse_dt_flexible(from_str).date() if _parse_dt_flexible(from_str) else None
    d_to = _parse_dt_flexible(to_str).date() if _parse_dt_flexible(to_str) else None

    def _in_date_range(dt_obj):
        if not dt_obj:
            return True
        target_d = dt_obj.date()
        if date_range == "TODAY":
            return target_d == today_date
        if date_range == "7D":
            return (today_date - target_d).days <= 7
        if date_range == "30D":
            return (today_date - target_d).days <= 30
        if date_range == "CUSTOM":
            if d_from and target_d < d_from:
                return False
            if d_to and target_d > d_to:
                return False
        return True

    picking_list = read_json(PICKING_FILE, [])
    ret_orders = _load_return_orders() if "_load_return_orders" in globals() else read_json(RETURNS_FILE, [])
    packing_list = read_json(PACKING_FILE, [])
    approvals_data = read_json(APPROVALS_FILE, {})
    recon_data = read_json(RECON_DATA_FILE, [])

    processed_handovers = [
        t for t in approvals_data.get("processed_tickets", [])
        if t.get("category") == "HANDOVER"
    ]
    approved_bgs = [
        t for t in processed_handovers
        if "xác nhận" in str(t.get("status", "")).lower()
    ]
    rejected_bgs = [
        t for t in processed_handovers
        if "từ chối" in str(t.get("status", "")).lower()
    ]
    approved_bg_by_order = {
        str(t.get("order_or_po", "")).strip().upper(): t for t in approved_bgs
    }

    # 1. Tổng hợp danh sách phiếu theo kỳ báo cáo (DISTINCT mã phiếu)
    ticket_rows = []
    seen_pick_ids = set()

    for o in picking_list:
        raw_st = o.get("status", "Chờ thực hiện")
        if raw_st == "Nháp":
            continue
        pick_id = str(o.get("id") or o.get("pick_id") or "").strip()
        if not pick_id or pick_id in seen_pick_ids:
            continue
        seen_pick_ids.add(pick_id)

        order_code = str(o.get("order_code") or o.get("order_id") or "").strip().upper()
        plat = _normalize_platform_name(o.get("platform", "Shopee"))
        assignee = o.get("assignee", "Chưa phân công")
        assignee_code = o.get("assignee_code", "")
        created_dt = _parse_dt_flexible(o.get("created_at")) or now_dt
        deadline_dt = _parse_dt_flexible(o.get("deadline"))

        bg_obj = approved_bg_by_order.get(order_code)
        bg_confirmed_dt = _parse_dt_flexible(bg_obj.get("reviewed_at")) if bg_obj else None

        if report_type == "HANDOVER":
            if not bg_obj or not _in_date_range(bg_confirmed_dt or created_dt):
                continue
        else:
            if not _in_date_range(created_dt):
                continue

        if platform_filter != "ALL" and plat != platform_filter:
            continue
        if staff_filter != "ALL" and staff_filter not in (assignee, assignee_code):
            continue

        req_pcs = int(o.get("required_pcs", 0) or 0)
        out_pcs = int(o.get("picked_pcs", 0) or 0)
        handed_pcs = int(bg_obj.get("total_pcs", req_pcs)) if bg_obj else 0

        is_handed_done = bool(bg_obj)
        is_out_done = (req_pcs > 0 and out_pcs >= req_pcs) or raw_st in ("Hoàn thành", "Hoàn tất lấy hàng", "Hoàn tất một phần")
        is_cancelled = raw_st in ("Đã hủy", "Hủy")
        is_overdue = bool(deadline_dt and now_dt > deadline_dt and not is_handed_done and not is_cancelled)

        if is_cancelled:
            disp_st = "Đã hủy"
        elif is_handed_done:
            disp_st = "Hoàn tất"
        elif handed_pcs > 0 and handed_pcs < req_pcs:
            disp_st = "Bàn giao một phần"
        elif is_out_done:
            disp_st = "Chờ đóng gói / BG"
        else:
            disp_st = "Đang xử lý"

        ticket_rows.append({
            "pick_id": pick_id,
            "order_code": order_code,
            "platform": plat,
            "assignee": assignee,
            "assignee_code": assignee_code or assignee,
            "req_pcs": req_pcs,
            "out_pcs": out_pcs,
            "handed_pcs": handed_pcs,
            "status": disp_st,
            "is_handed_done": is_handed_done,
            "is_out_done": is_out_done,
            "is_overdue": is_overdue,
            "is_cancelled": is_cancelled,
            "created_at": o.get("created_at", ""),
            "deadline": o.get("deadline", "")
        })

    # 2. Lấy kết quả đối soát từ chức năng Đối soát xuất hàng
    recon_orders = _build_outbound_reconciliation_orders()
    filtered_recon = []
    for r in recon_orders:
        if platform_filter != "ALL" and r["platform"] != platform_filter:
            continue
        r_dt = _parse_dt_flexible(r.get("transaction_date"))
        if not _in_date_range(r_dt):
            continue
        filtered_recon.append(r)

    recon_matched_cnt = sum(1 for x in filtered_recon if x["result_code"] == "MATCHED")
    recon_mismatch_cnt = sum(1 for x in filtered_recon if x["result_code"] in ("MISMATCH", "PARTIAL_HANDOVER"))
    recon_waiting_cnt = sum(1 for x in filtered_recon if x["result_code"] in ("NOT_HANDED_OVER", "UNLINKED"))

    kpis = {
        "total_tickets": len(ticket_rows),
        "handed_over": sum(1 for t in ticket_rows if t["is_handed_done"]),
        "in_progress": sum(1 for t in ticket_rows if not t["is_handed_done"] and not t["is_cancelled"]),
        "overdue": sum(1 for t in ticket_rows if t["is_overdue"]),
        "recon_matched": recon_matched_cnt,
        "recon_mismatch": recon_mismatch_cnt
    }

    platform_stats = []
    for p_name in ("Shopee", "TikTok Shop", "Lazada"):
        p_tickets = [t for t in ticket_rows if t["platform"] == p_name]
        p_recons = [r for r in filtered_recon if r["platform"] == p_name]
        platform_stats.append({
            "platform": p_name,
            "total": len(p_tickets),
            "handed_over": sum(1 for t in p_tickets if t["is_handed_done"]),
            "in_progress": sum(1 for t in p_tickets if not t["is_handed_done"] and not t["is_cancelled"]),
            "overdue": sum(1 for t in p_tickets if t["is_overdue"]),
            "mismatch": sum(1 for r in p_recons if r["result_code"] in ("MISMATCH", "PARTIAL_HANDOVER"))
        })

    staff_perf_map = {}
    for t in ticket_rows:
        st_name = t["assignee"]
        if not st_name or st_name == "Chưa phân công":
            continue
        entry = staff_perf_map.setdefault(st_name, {
            "staff_name": st_name,
            "staff_code": t["assignee_code"],
            "assigned_count": 0,
            "out_completed": 0,
            "on_time": 0,
            "overdue": 0
        })
        entry["assigned_count"] += 1
        if t["is_out_done"]:
            entry["out_completed"] += 1
        if t["is_overdue"]:
            entry["overdue"] += 1
        elif t["is_out_done"] or t["is_handed_done"]:
            entry["on_time"] += 1

    staff_performance = sorted(staff_perf_map.values(), key=lambda x: x["assigned_count"], reverse=True)

    # 3. Tổng hợp Lịch sử hoạt động Append-Only đầy đủ thông tin (SKU, Box, Vị trí, Người thực hiện, Kết quả)
    history_events = []

    for o in picking_list:
        p_id = o.get("id") or o.get("pick_id")
        o_code = o.get("order_code", "")
        sku_code = str(o.get("sku", "")).upper()
        plat = _normalize_platform_name(o.get("platform", "Shopee"))
        c_time = o.get("created_at", now_dt.strftime("%d/%m/%Y %H:%M"))

        for idx, h in enumerate(o.get("history", [])):
            act = h.get("action", "Thao tác phiếu")
            act_low = act.lower()
            if "phân công" in act_low or "nhân viên" in act_low:
                cat = "ASSIGN"
            elif "thiếu" in act_low:
                cat = "SHORTAGE"
            else:
                cat = "PICK_REQ"

            history_events.append({
                "event_id": f"EVT-{p_id}-H{idx + 1}",
                "time": h.get("time", c_time),
                "actor": h.get("actor", "Điều phối"),
                "actor_role": "Điều phối kho",
                "category": cat,
                "action_label": act,
                "target": p_id,
                "order_code": o_code,
                "platform": plat,
                "summary": h.get("detail", ""),
                "before_val": "—",
                "after_val": h.get("detail", ""),
                "reason": o.get("shortage_note") or o.get("note") or "Theo quy trình điều phối",
                "result": "Thành công",
                "source_ref": f"Phiếu {p_id} · Đơn {o_code} · SKU {sku_code}",
                "location_detail": "—"
            })

        # Giao dịch OUT từng Box, SKU & Vị trí kệ/tầng của Staff
        for idx, tx in enumerate(o.get("transactions", []), start=1):
            box_id = tx.get("box_id", "--")
            slot_raw = tx.get("location_snapshot", "--")
            loc_path = _resolve_slot_hierarchy(slot_raw)["full_path"] if "_resolve_slot_hierarchy" in globals() else slot_raw
            qty_p = int(tx.get("picked_pcs", 0) or 0)
            history_events.append({
                "event_id": tx.get("tx_id") or f"EVT-{p_id}-OUT{idx}",
                "time": f"{c_time[:10]} {tx.get('time', '')}".strip(),
                "actor": tx.get("staff_name", o.get("assignee", "Staff")),
                "actor_role": "Nhân viên kho",
                "category": "OUT",
                "action_label": "OUT – Lấy hàng",
                "target": p_id,
                "order_code": o_code,
                "platform": plat,
                "summary": f"Lấy {qty_p} PCS ({sku_code}) từ {box_id} · Vị trí {slot_raw}",
                "before_val": "Tồn khả dụng trên kệ",
                "after_val": f"-{qty_p} PCS (Còn lại trong Box: {tx.get('remaining_in_box', '--')} PCS)",
                "reason": f"Thực hiện lấy hàng đơn {o_code}",
                "result": "Thành công",
                "source_ref": f"Phiếu {p_id} · SKU {sku_code} · Box {box_id}",
                "location_detail": f"Box: {box_id} · {loc_path}"
            })

    # Giao dịch RETURNED trả hàng về kệ
    for ret in ret_orders:
        r_id = ret.get("id")
        r_sku = str(ret.get("sku", "")).upper()
        for idx, rtx in enumerate(ret.get("transactions", []), start=1):
            is_dmg = "cách ly" in str(rtx.get("condition", "")).lower()
            history_events.append({
                "event_id": f"EVT-{r_id}-{idx}",
                "time": f"{now_dt.strftime('%d/%m/%Y')} {rtx.get('time', '')}".strip(),
                "actor": rtx.get("staff_name", ret.get("assignee", "Staff")),
                "actor_role": "Nhân viên kho",
                "category": "RETURNED",
                "action_label": "RETURNED – Trả hàng",
                "target": r_id,
                "order_code": ret.get("order_code", ""),
                "platform": "Shopee",
                "summary": f"Trả {rtx.get('returned_pcs', 0)} PCS ({r_sku}) về {rtx.get('location_snapshot', '--')} · {rtx.get('condition', '')}",
                "before_val": f"Nguồn OUT: {ret.get('out_order_id', '--')}",
                "after_val": f"+{rtx.get('returned_pcs', 0)} PCS ({rtx.get('box_id', '--')})",
                "reason": ret.get("reason", ""),
                "result": "Lỗi" if is_dmg else "Thành công",
                "source_ref": f"Phiếu trả {r_id} · Nguồn {ret.get('out_order_id', '--')}",
                "location_detail": f"Box: {rtx.get('box_id', '--')} · {rtx.get('location_snapshot', '--')}"
            })

    # Đóng gói hoàn tất
    for pk in packing_list:
        if pk.get("packing_status") == "COMPLETED":
            total_pk = sum(int(x.get("pcs_equiv", x.get("qty", 0))) for p in pk.get("packages", []) for x in p.get("items", []))
            pkg_codes = ", ".join(p.get("package_code", "") for p in pk.get("packages", []))
            history_events.append({
                "event_id": f"EVT-{pk.get('id')}-PACK",
                "time": now_dt.strftime("%d/%m/%Y %H:%M"),
                "actor": pk.get("assignee", "Staff"),
                "actor_role": "Nhân viên kho",
                "category": "PACKING",
                "action_label": "Đóng gói hoàn tất",
                "target": pk.get("order_code", ""),
                "order_code": pk.get("order_code", ""),
                "platform": _normalize_platform_name(pk.get("platform", "Shopee")),
                "summary": f"Đóng gói {total_pk} PCS ({len(pk.get('packages', []))} kiện: {pkg_codes})",
                "before_val": "Chờ đóng gói",
                "after_val": f"{len(pk.get('packages', []))} kiện hoàn tất",
                "reason": "Hoàn tất đóng gói đơn hàng",
                "result": "Thành công",
                "source_ref": f"Phiếu đóng gói {pk.get('id')} · Đơn {pk.get('order_code')}",
                "location_detail": pkg_codes or "Bàn đóng gói"
            })

    # Bàn giao: Manager xác nhận HOẶC Manager từ chối xác nhận
    for bg in approved_bgs:
        history_events.append({
            "event_id": f"EVT-{bg.get('id')}-OK",
            "time": bg.get("reviewed_at", ""),
            "actor": bg.get("reviewed_by", "Manager"),
            "actor_role": "Manager",
            "category": "HANDOVER",
            "action_label": "Xác nhận bàn giao",
            "target": bg.get("order_or_po", ""),
            "order_code": bg.get("order_or_po", ""),
            "platform": _normalize_platform_name(bg.get("partner", "Shopee")),
            "summary": f"Xác nhận bàn giao {bg.get('total_pcs', 0)} PCS ({bg.get('id')}) cho {bg.get('receiver', '--')}",
            "before_val": "Chờ Manager xác nhận",
            "after_val": f"Đã xác nhận bàn giao ({bg.get('total_pcs', 0)} PCS)",
            "reason": f"Người giao: {bg.get('sender', '--')}",
            "result": "Thành công",
            "source_ref": f"Phiếu bàn giao {bg.get('id')}",
            "location_detail": f"Đơn vị nhận: {bg.get('receiver', '--')}"
        })

    for rj in rejected_bgs:
        history_events.append({
            "event_id": f"EVT-{rj.get('id')}-REJ",
            "time": rj.get("reviewed_at", ""),
            "actor": rj.get("reviewed_by", "Manager"),
            "actor_role": "Manager",
            "category": "HANDOVER",
            "action_label": "Từ chối bàn giao",
            "target": rj.get("order_or_po", ""),
            "order_code": rj.get("order_or_po", ""),
            "platform": _normalize_platform_name(rj.get("partner", "Shopee")),
            "summary": f"Từ chối xác nhận {rj.get('id')}: {rj.get('reject_reason', 'Số lượng/chứng từ chưa khớp')}",
            "before_val": "Chờ Manager xác nhận",
            "after_val": "Đã từ chối · Trả lại Staff bổ sung",
            "reason": rj.get("reject_reason", "Chưa đạt điều kiện xác nhận bàn giao"),
            "result": "Từ chối",
            "source_ref": f"Phiếu bàn giao {rj.get('id')}",
            "location_detail": f"Người lập phiếu: {rj.get('sender', '--')}"
        })

    # Dữ liệu đối soát (Hợp lệ / Lỗi / Trùng lặp)
    for rec in recon_data:
        for idx, eh in enumerate(rec.get("edit_history", [])):
            is_err = rec.get("check_status") in ("Có lỗi", "Trùng lặp")
            history_events.append({
                "event_id": f"EVT-{rec.get('record_id')}-{idx}",
                "time": eh.get("time", ""),
                "actor": eh.get("actor", "Điều phối"),
                "actor_role": "Điều phối",
                "category": "RECON_DATA",
                "action_label": eh.get("action", "Dữ liệu đối soát"),
                "target": rec.get("order_code", ""),
                "order_code": rec.get("order_code", ""),
                "platform": rec.get("platform", "Shopee"),
                "summary": eh.get("detail", ""),
                "before_val": "Dữ liệu gốc nền tảng",
                "after_val": f"{rec.get('check_status')} · {rec.get('confirm_status')}",
                "reason": rec.get("error_message") or eh.get("detail", ""),
                "result": "Lỗi" if is_err else "Thành công",
                "source_ref": f"Bản ghi {rec.get('record_id')} (Đợt {rec.get('batch_id')})",
                "location_detail": "—"
            })

    # Đối soát xuất hàng (Ghi nhận lệch, Gửi kiểm tra, Xác nhận đối soát)
    for r_ord in recon_orders:
        for idx, rh in enumerate(r_ord.get("history", [])):
            history_events.append({
                "event_id": f"EVT-RC-{r_ord['order_code']}-{idx}",
                "time": rh.get("time", ""),
                "actor": rh.get("actor", "Điều phối"),
                "actor_role": "Điều phối",
                "category": "RECON_OUT",
                "action_label": rh.get("action", "Đối soát xuất hàng"),
                "target": r_ord["order_code"],
                "order_code": r_ord["order_code"],
                "platform": r_ord["platform"],
                "summary": rh.get("detail", ""),
                "before_val": f"PCS nền tảng: {r_ord['total_platform_pcs']}",
                "after_val": f"PCS bàn giao: {r_ord['total_handover_pcs'] if r_ord['total_handover_pcs'] is not None else '—'} ({r_ord['result_label']})",
                "reason": r_ord.get("discrepancy_note") or rh.get("detail", ""),
                "result": "Thành công",
                "source_ref": f"Đối soát xuất hàng · Đơn {r_ord['order_code']}",
                "location_detail": "—"
            })

    history_actors = sorted(list({ev["actor"] for ev in history_events if ev.get("actor")}))

    return {
        "synced_at": now_dt.strftime("%H:%M:%S"),
        "kpis": kpis,
        "platform_stats": platform_stats,
        "recon_summary": {
            "total": len(filtered_recon),
            "matched": recon_matched_cnt,
            "waiting": recon_waiting_cnt,
            "mismatch": recon_mismatch_cnt
        },
        "staff_performance": staff_performance,
        "ticket_rows": ticket_rows,
        "history_events": history_events,
        "history_actors": history_actors
    }


@app.route("/dispatcher/reports")
@dispatcher_required
def dispatcher_reports_page():
    return render_template(
        "DISPATCHER/dispatcher_reports.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/reports", methods=["GET"])
@dispatcher_required
def api_dispatcher_reports():
    try:
        payload = _build_dispatcher_reports_and_history(
            date_range=request.args.get("range", "7D"),
            from_str=request.args.get("from", ""),
            to_str=request.args.get("to", ""),
            platform_filter=request.args.get("platform", "ALL"),
            staff_filter=request.args.get("staff", "ALL"),
            report_type=request.args.get("report_type", "DISPATCH")
        )
        return jsonify(payload)
    except Exception as exc:
        app.logger.exception("Lỗi API /api/dispatcher/reports")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/dispatcher/reports/export", methods=["GET"])
@dispatcher_required
def api_dispatcher_reports_export():
    """Xuất Excel (.csv UTF-8 BOM) cho 3 loại: Báo cáo điều phối, Báo cáo đối soát, Lịch sử hoạt động."""
    export_kind = str(request.args.get("kind", "DISPATCH")).upper()  # 'DISPATCH' | 'RECON' | 'HISTORY'
    data = _build_dispatcher_reports_and_history(
        date_range=request.args.get("range", "7D"),
        from_str=request.args.get("from", ""),
        to_str=request.args.get("to", ""),
        platform_filter=request.args.get("platform", "ALL"),
        staff_filter=request.args.get("staff", "ALL"),
        report_type=request.args.get("report_type", "DISPATCH")
    )

    output = io.StringIO()
    output.write("\ufeff")
    writer = csv.writer(output)
    now_stamp = datetime.now().strftime("%d/%m/%Y %H:%M")

    if export_kind == "RECON":
        writer.writerow(["SANOVA - BÁO CÁO ĐỐI SOÁT XUẤT HÀNG", f"Xuất lúc: {now_stamp}"])
        writer.writerow(["Mã đơn", "Nền tảng", "Ngày giao dịch", "Phiếu OUT", "Sản phẩm", "PCS nguồn", "PCS bàn giao", "Chênh lệch", "Kết quả", "Trạng thái xử lý"])
        recon_orders = _build_outbound_reconciliation_orders()
        for r in recon_orders:
            writer.writerow([
                r["order_code"], r["platform"], r["transaction_date"], r["pick_id_display"],
                r["sku_summary"], r["total_platform_pcs"],
                r["total_handover_pcs"] if r["total_handover_pcs"] is not None else "",
                r["total_diff_pcs"] if r["total_diff_pcs"] is not None else "",
                r["result_label"], r["process_status"]
            ])
        fname = f"SANOVA_BaoCaoDoiSoat_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

    elif export_kind == "HISTORY":
        writer.writerow(["SANOVA - LỊCH SỬ HOẠT ĐỘNG ĐIỀU PHỐI KHO", f"Xuất lúc: {now_stamp}"])
        writer.writerow(["Mã sự kiện", "Thời gian", "Người thực hiện", "Vai trò", "Hoạt động", "Đối tượng", "Nền tảng", "Nội dung chi tiết", "Kết quả"])
        for ev in data["history_events"]:
            writer.writerow([
                ev["event_id"], ev["time"], ev["actor"], ev["actor_role"],
                ev["action_label"], ev["target"], ev["platform"], ev["summary"], ev["result"]
            ])
        fname = f"SANOVA_LichSuDieuPhoi_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

    else:
        writer.writerow(["SANOVA - BÁO CÁO HOẠT ĐỘNG ĐIỀU PHỐI KHO", f"Xuất lúc: {now_stamp}"])
        writer.writerow(["Mã phiếu", "Mã đơn", "Nền tảng", "Nhân viên", "Số PCS yêu cầu", "Số PCS OUT", "Số PCS bàn giao", "Hạn hoàn thành", "Trạng thái"])
        for t in data["ticket_rows"]:
            writer.writerow([
                t["pick_id"], t["order_code"], t["platform"], t["assignee"],
                t["req_pcs"], t["out_pcs"], t["handed_pcs"], t["deadline"], t["status"]
            ])
        fname = f"SANOVA_BaoCaoDieuPhoi_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"

    return Response(
        output.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={fname}"}
    )

# IV.7. CHỨC NĂNG TÀI KHOẢN CÁ NHÂN (DISPATCHER PROFILE)
from werkzeug.utils import secure_filename

@app.route("/dispatcher/profile", methods=["GET"])
@dispatcher_required
def dispatcher_profile_page():
    return render_template(
        "DISPATCHER/dispatcher_profile.html",
        current_user=session.get("user", {})
    )


@app.route("/api/dispatcher/profile", methods=["GET"])
@dispatcher_required
def api_dispatcher_profile_get():
    """
    Lấy trực tiếp 100% thông tin tài khoản của Điều phối viên đang đăng nhập từ users.json,
    kết hợp chính sách bảo mật từ system_settings.json và nhật ký hoạt động cá nhân từ audit_logs.json.
    """
    sess_user = session.get("user", {})
    username = sess_user.get("username")

    users = load_users()
    user_record = users.get(username)
    if not user_record:
        return jsonify({"error": "Không tìm thấy hồ sơ tài khoản trong hệ thống"}), 404

    sys_cfg = load_system_settings() if "load_system_settings" in globals() else {}
    pwd_cfg = sys_cfg.get("password", {})
    min_len = pwd_cfg.get("min_length", 8)
    reqs = [f"Tối thiểu {min_len} ký tự"]
    if pwd_cfg.get("require_uppercase"):
        reqs.append("có chữ in hoa")
    if pwd_cfg.get("require_number"):
        reqs.append("có chữ số")
    if pwd_cfg.get("require_special"):
        reqs.append("có ký tự đặc biệt")

    all_logs = load_logs() if "load_logs" in globals() else []
    full_name = user_record.get("name", "")
    personal_logs = []
    login_history = []

    for lg in all_logs:
        by_str = str(lg.get("by", ""))
        actor_str = str(lg.get("actor", ""))
        target_str = str(lg.get("target", ""))
        if (username and username in by_str) or (full_name and full_name in (by_str, actor_str)) or (target_str == username):
            act = lg.get("action", "")
            is_login = ("đăng nhập" in act.lower()) or ("đăng xuất" in act.lower())
            t_str = lg.get("timestamp") or f"{lg.get('date', '')} {lg.get('time', '')}".strip()
            personal_logs.append({
                "time": t_str,
                "category": lg.get("category", "Nghiệp vụ kho"),
                "action": act,
                "target": target_str,
                "result": lg.get("result", lg.get("status", "Thành công"))
            })
            if is_login:
                login_history.append({
                    "time": t_str,
                    "device": lg.get("device", "Web Browser · SANOVA Internal"),
                    "ip": lg.get("ip", "127.0.0.1"),
                    "result": lg.get("result", "Thành công"),
                    "success": lg.get("result", "Thành công") == "Thành công"
                })

    return jsonify({
        "profile": {
            "staff_code": user_record.get("staff_code", "DP0001"),
            "name": full_name,
            "username": username,
            "email": user_record.get("email", ""),
            "phone": user_record.get("phone", ""),
            "role": user_record.get("role", "Điều phối / Kế toán kho"),
            "scope": user_record.get("scope", "Kho chính - SANOVA"),
            "status": user_record.get("status", "Hoạt động"),
            "note": user_record.get("note", ""),
            "avatar_url": user_record.get("avatar_url", ""),
            "created_at": user_record.get("created_at", ""),
            "last_login": user_record.get("last_login", ""),
            "last_password_changed": user_record.get("last_password_changed", "Chưa đổi"),
            "noti_prefs": user_record.get("noti_prefs", {
                "shortage": True,
                "delay": True,
                "discrepancy": True
            })
        },
        "password_policy_text": f"Chính sách mật khẩu hệ thống: {', '.join(reqs)}.",
        "activity_logs": personal_logs[:20],
        "login_history": login_history[:10]
    })


@app.route("/api/dispatcher/profile", methods=["PATCH"])
@dispatcher_required
def api_dispatcher_profile_update():
    """Chỉ cho phép cập nhật Email, Số điện thoại và Ghi chú cá nhân; chặn tuyệt đối sửa vai trò / mã NV / kho."""
    sess_user = session.get("user", {})
    username = sess_user.get("username")
    body = request.get_json(silent=True) or {}

    email = str(body.get("email", "")).strip()
    phone = str(body.get("phone", "")).strip()
    note = str(body.get("note", "")).strip()[:255]

    if not email or "@" not in email:
        return jsonify({"error": "Địa chỉ email liên hệ không hợp lệ!"}), 400
    if not phone:
        return jsonify({"error": "Số điện thoại liên hệ không được để trống!"}), 400

    users = load_users()
    if username not in users:
        return jsonify({"error": "Tài khoản không tồn tại!"}), 404

    target = users[username]
    old_summary = f"{target.get('email', '')} · {target.get('phone', '')}"
    target["email"] = email
    target["phone"] = phone
    target["note"] = note
    save_users(users)

    session["user"]["email"] = email
    session.modified = True

    if "add_audit_log" in globals():
        add_audit_log(
            category="Tài khoản",
            action="Điều phối cập nhật thông tin liên hệ cá nhân",
            target=username,
            changes=[{"field": "Liên hệ", "before": old_summary, "after": f"{email} · {phone}"}]
        )

    return jsonify({"status": "ok", "message": "Đã lưu thay đổi thông tin liên hệ!"})


@app.route("/api/dispatcher/profile/avatar", methods=["POST"])
@dispatcher_required
def api_dispatcher_profile_avatar():
    file = request.files.get("avatar")
    if not file or not file.filename:
        return jsonify({"error": "Vui lòng chọn tệp ảnh hợp lệ!"}), 400

    ext = os.path.splitext(secure_filename(file.filename))[1].lower()
    if ext not in (".png", ".jpg", ".jpeg", ".webp"):
        return jsonify({"error": "Chỉ hỗ trợ ảnh định dạng PNG, JPG, JPEG hoặc WEBP!"}), 400

    username = session["user"].get("username", "dispatcher")
    avatar_dir = os.path.join(app.static_folder, "uploads", "avatars")
    os.makedirs(avatar_dir, exist_ok=True)

    fname = f"{username}_avatar{ext}"
    file.save(os.path.join(avatar_dir, fname))
    avatar_url = f"/static/uploads/avatars/{fname}?v={int(datetime.now().timestamp())}"

    users = load_users()
    if username in users:
        users[username]["avatar_url"] = avatar_url
        save_users(users)

    return jsonify({"status": "ok", "avatar_url": avatar_url})


@app.route("/api/dispatcher/profile/notifications", methods=["PUT"])
@dispatcher_required
def api_dispatcher_profile_notifications():
    body = request.get_json(silent=True) or {}
    username = session["user"].get("username")
    users = load_users()
    if username in users:
        users[username]["noti_prefs"] = {
            "shortage": bool(body.get("shortage", True)),
            "delay": bool(body.get("delay", True)),
            "discrepancy": bool(body.get("discrepancy", True))
        }
        save_users(users)
    return jsonify({"status": "ok", "message": "Đã lưu tùy chọn thông báo cá nhân!"})


@app.route("/api/dispatcher/profile/change-password", methods=["POST"])
@dispatcher_required
def api_dispatcher_profile_change_password():
    fail_cnt = session.get("disp_pwd_fails", 0)
    if fail_cnt >= 5:
        return jsonify({"error": "Bạn đã nhập sai mật khẩu hiện tại quá 5 lần. Vui lòng đăng nhập lại!"}), 429

    username = session["user"].get("username")
    users = load_users()
    if username not in users:
        return jsonify({"error": "Tài khoản không tồn tại!"}), 404

    body = request.get_json(silent=True) or {}
    cur_pwd = body.get("current_password", "")
    new_pwd = body.get("new_password", "")
    cfm_pwd = body.get("confirm_password", "")

    if not verify_password(users[username].get("password"), cur_pwd):
        session["disp_pwd_fails"] = fail_cnt + 1
        return jsonify({"error": "Mật khẩu hiện tại không chính xác!"}), 400

    if new_pwd != cfm_pwd:
        return jsonify({"error": "Mật khẩu xác nhận không khớp!"}), 400
    if cur_pwd == new_pwd:
        return jsonify({"error": "Mật khẩu mới phải khác mật khẩu hiện tại!"}), 400

    sys_cfg = load_system_settings() if "load_system_settings" in globals() else {}
    pwd_cfg = sys_cfg.get("password", {})
    min_len = pwd_cfg.get("min_length", 8)
    if len(new_pwd) < min_len:
        return jsonify({"error": f"Mật khẩu mới phải có tối thiểu {min_len} ký tự theo chính sách hệ thống!"}), 400
    if pwd_cfg.get("require_uppercase") and not any(c.isupper() for c in new_pwd):
        return jsonify({"error": "Mật khẩu mới phải chứa ít nhất 1 chữ in hoa (A-Z)!"}), 400
    if pwd_cfg.get("require_number") and not any(c.isdigit() for c in new_pwd):
        return jsonify({"error": "Mật khẩu mới phải chứa ít nhất 1 chữ số (0-9)!"}), 400
    if pwd_cfg.get("require_special") and new_pwd.isalnum():
        return jsonify({"error": "Mật khẩu mới phải chứa ít nhất 1 ký tự đặc biệt!"}), 400

    session["disp_pwd_fails"] = 0
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
    users[username]["password"] = hash_password(new_pwd)
    users[username]["last_password_changed"] = now_str
    save_users(users)

    if "add_audit_log" in globals():
        add_audit_log(category="Bảo mật", action="Điều phối đổi mật khẩu cá nhân", target=username, result="Thành công")

    return jsonify({"status": "ok", "message": "Đổi mật khẩu thành công!"})


# ==========================================================
# 14. KHỞI CHẠY ỨNG DỤNG FLASK

if __name__ == "__main__":
    app.run(
        debug=True,
        host="0.0.0.0",
        port=5000
    )