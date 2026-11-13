document.addEventListener("DOMContentLoaded", function () {
    // 1. Tiêm CSS chuẩn theo mẫu chuông & Modal chi tiết
    if (!document.getElementById("sanova-noti-styles")) {
        const styleEl = document.createElement("style");
        styleEl.id = "sanova-noti-styles";
        styleEl.textContent = `
            .noti-bell-wrapper { position: relative; display: inline-flex; align-items: center; }
            .bell-btn {
                width: 38px; height: 38px; border-radius: 50%; background: #ffffff;
                border: 1px solid #e2e8f0; display: flex; align-items: center; justify-content: center;
                color: #334155; position: relative; cursor: pointer; transition: 0.2s; padding: 0;
            }
            .bell-btn:hover { background: #f8fafc; border-color: #cbd5e1; }
            .bell-count-badge {
                position: absolute; top: -4px; right: -4px; min-width: 18px; height: 18px;
                padding: 0 4px; border-radius: 999px; background: #ef4444; color: #ffffff;
                font-size: 10.5px; font-weight: 800; display: none; align-items: center;
                justify-content: center; border: 2px solid #ffffff; line-height: 1;
            }
            .noti-dropdown {
                position: absolute; top: 48px; right: 0; width: 410px; background: #ffffff;
                border: 1px solid #e2e8f0; border-radius: 18px;
                box-shadow: 0 20px 42px rgba(15, 23, 42, 0.16); z-index: 9999;
                display: none; flex-direction: column; overflow: hidden; text-align: left;
            }
            .noti-dropdown.show { display: flex !important; }
            .noti-head {
                display: flex; justify-content: space-between; align-items: center;
                padding: 16px 18px 12px;
            }
            .noti-head-left { display: flex; align-items: center; gap: 10px; }
            .noti-head-title { font-size: 17px; font-weight: 800; color: #0f172a; }
            .noti-unread-pill {
                background: #fee2e2; color: #dc2626; font-size: 11.5px; font-weight: 700;
                padding: 3px 10px; border-radius: 999px;
            }
            .noti-mark-all {
                background: none; border: none; font-size: 12.5px; font-weight: 600;
                color: #334155; cursor: pointer; display: inline-flex; align-items: center; gap: 4px;
            }
            .noti-mark-all:hover { color: #057a55; text-decoration: underline; }
            .noti-tabs {
                display: grid; grid-template-columns: 1fr 1fr; background: #f1f5f9;
                margin: 0 16px 10px; padding: 3px; border-radius: 999px;
            }
            .noti-tab-btn {
                border: 1.5px solid transparent; background: transparent; padding: 6px 12px;
                border-radius: 999px; font-size: 13px; font-weight: 700; color: #64748b;
                cursor: pointer; transition: 0.15s;
            }
            .noti-tab-btn.active {
                background: #ffffff; color: #057a55; border-color: #10b981;
                box-shadow: 0 1px 3px rgba(0,0,0,0.06);
            }
            .noti-list { max-height: 360px; overflow-y: auto; padding: 0 12px; }
            .noti-item {
                display: flex; align-items: flex-start; gap: 12px; padding: 13px 8px;
                border-bottom: 1px solid #f1f5f9; cursor: pointer; transition: 0.15s;
            }
            .noti-item:last-child { border-bottom: none; }
            .noti-item:hover { background: #f8fafc; border-radius: 10px; }
            .noti-icon-sq {
                width: 38px; height: 38px; border-radius: 11px; display: flex;
                align-items: center; justify-content: center; flex-shrink: 0; margin-top: 2px;
            }
            .noti-sq-red { background: #fee2e2; color: #dc2626; }
            .noti-sq-amber { background: #fef3c7; color: #d97706; }
            .noti-sq-blue { background: #e0f2fe; color: #0284c7; }
            .noti-sq-green { background: #dcfce7; color: #16a34a; }
            .noti-item-body { flex: 1; min-width: 0; }
            .noti-item-title { font-size: 14px; font-weight: 700; color: #0f172a; }
            .noti-item-msg { font-size: 12.5px; color: #475569; margin-top: 2px; line-height: 1.4; }
            .noti-item-time { font-size: 11.5px; color: #94a3b8; margin-top: 4px; }
            .noti-blue-dot {
                width: 8px; height: 8px; border-radius: 50%; background: #0284c7;
                flex-shrink: 0; margin-top: 10px;
            }
            .noti-empty-state {
                text-align: center; padding: 32px 16px; font-size: 13px; color: #64748b;
            }
            .noti-footer {
                padding: 12px 16px; border-top: 1px solid #f1f5f9; background: #ffffff;
            }
            .btn-view-all-noti {
                display: flex; align-items: center; justify-content: center; gap: 6px;
                width: 100%; padding: 9px 14px; border: 1.5px solid #86efac; border-radius: 12px;
                font-size: 13.5px; font-weight: 700; color: #057a55; text-decoration: none;
                background: #ffffff; transition: 0.15s;
            }
            .btn-view-all-noti:hover { background: #ecfdf5; }

            /* MODAL CHI TIẾT THÔNG BÁO */
            .noti-detail-backdrop {
                position: fixed; inset: 0; background: rgba(15, 23, 42, 0.55);
                backdrop-filter: blur(2px); z-index: 100000; display: none;
                align-items: center; justify-content: center; padding: 16px;
            }
            .noti-detail-backdrop.show { display: flex; }
            .noti-detail-modal {
                background: #ffffff; width: 100%; max-width: 500px; border-radius: 18px;
                padding: 24px 26px; box-shadow: 0 24px 48px rgba(15, 23, 42, 0.22);
                animation: notiPopIn 0.18s ease-out;
            }
            @keyframes notiPopIn {
                from { opacity: 0; transform: scale(0.96); }
                to { opacity: 1; transform: scale(1); }
            }
            .nd-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 16px; }
            .nd-badge {
                display: inline-block; padding: 3px 10px; border-radius: 999px;
                font-size: 11.5px; font-weight: 700; margin-bottom: 6px;
            }
            .nd-badge-critical { background: #fee2e2; color: #dc2626; }
            .nd-badge-action { background: #fef3c7; color: #b45309; }
            .nd-badge-info { background: #e0f2fe; color: #0369a1; }
            .nd-title { font-size: 18px; font-weight: 800; color: #0f172a; }
            .nd-close { background: none; border: none; font-size: 18px; color: #64748b; cursor: pointer; }
            .nd-grid {
                background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px;
                padding: 14px 16px; display: flex; flex-direction: column; gap: 10px; font-size: 13px;
            }
            .nd-row { display: grid; grid-template-columns: 135px 1fr; gap: 8px; }
            .nd-lbl { color: #64748b; font-weight: 600; }
            .nd-val { color: #0f172a; font-weight: 700; line-height: 1.45; }
            .nd-note {
                margin-top: 14px; padding: 10px 12px; border-radius: 9px; background: #fffbeb;
                border: 1px solid #fde68a; font-size: 12px; color: #92400e; line-height: 1.45;
            }
            .nd-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }
            .nd-btn-close {
                padding: 9px 18px; border-radius: 10px; border: 1px solid #cbd5e1;
                background: #ffffff; font-size: 13px; font-weight: 700; color: #334155; cursor: pointer;
            }
            .nd-btn-action {
                padding: 9px 20px; border-radius: 10px; border: none; background: #057a55;
                font-size: 13px; font-weight: 700; color: #ffffff; text-decoration: none;
                display: inline-flex; align-items: center; gap: 6px;
            }
            .nd-btn-action:hover { background: #046c4e; }
        `;
        document.head.appendChild(styleEl);
    }

    // 2. Tạo sẵn Modal Chi tiết thông báo vào cuối body
    if (!document.getElementById("notiDetailBackdrop")) {
        const modalHtml = `
            <div class="noti-detail-backdrop" id="notiDetailBackdrop">
                <div class="noti-detail-modal">
                    <div class="nd-header">
                        <div>
                            <span class="nd-badge nd-badge-action" id="ndSeverityBadge">Cần xử lý</span>
                            <h3 class="nd-title" id="ndTitle">Chi tiết thông báo</h3>
                        </div>
                        <button type="button" class="nd-close" id="ndCloseBtn">✕</button>
                    </div>
                    <div class="nd-grid">
                        <div class="nd-row">
                            <span class="nd-lbl">Sự việc:</span>
                            <span class="nd-val" id="ndMessage">---</span>
                        </div>
                        <div class="nd-row" id="ndAccountRow">
                            <span class="nd-lbl">Tài khoản liên quan:</span>
                            <span class="nd-val" id="ndAccount" style="color:#057a55;">---</span>
                        </div>
                        <div class="nd-row">
                            <span class="nd-lbl">Thời gian:</span>
                            <span class="nd-val" id="ndTime">---</span>
                        </div>
                        <div class="nd-row" id="ndReasonRow">
                            <span class="nd-lbl">Nguyên nhân:</span>
                            <span class="nd-val" id="ndReason">---</span>
                        </div>
                        <div class="nd-row" id="ndImpactRow">
                            <span class="nd-lbl">Mức độ ảnh hưởng:</span>
                            <span class="nd-val" id="ndImpact">---</span>
                        </div>
                    </div>
                    <div class="nd-note">
                        ℹ️ Thông báo này đã được chuyển sang trạng thái <strong>Đã đọc</strong>. Nếu sự việc vẫn cần xử lý nghiệp vụ, hãy nhấn nút bên dưới để đi tới chức năng tương ứng.
                    </div>
                    <div class="nd-footer">
                        <button type="button" class="nd-btn-close" id="ndFooterCloseBtn">Đóng</button>
                        <a href="/admin" class="nd-btn-action" id="ndGoTargetBtn">Đi tới chức năng xử lý →</a>
                    </div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML("beforeend", modalHtml);
    }

    const bellContainer = document.getElementById("adminNotiBellWrap");
    const bellBtn = document.getElementById("adminNotiBellBtn");
    const dropdown = document.getElementById("adminNotiDropdown");
    const unreadBadge = document.getElementById("adminNotiBellCount");
    const headerUnreadPill = document.getElementById("notiHeaderUnreadPill");
    const notiListContainer = document.getElementById("adminNotiList");
    const btnMarkAll = document.getElementById("btnMarkAllNotiRead");
    const tabAll = document.getElementById("notiTabAll");
    const tabUnread = document.getElementById("notiTabUnread");

    const detailBackdrop = document.getElementById("notiDetailBackdrop");
    const closeDetail = () => detailBackdrop && detailBackdrop.classList.remove("show");
    document.getElementById("ndCloseBtn")?.addEventListener("click", closeDetail);
    document.getElementById("ndFooterCloseBtn")?.addEventListener("click", closeDetail);
    detailBackdrop?.addEventListener("click", (e) => { if (e.target === detailBackdrop) closeDetail(); });

    if (!bellContainer || !bellBtn || !dropdown) return;

    if (btnMarkAll) btnMarkAll.innerHTML = "✓ Đánh dấu đã đọc tất cả";
    const viewAllLink = dropdown.querySelector(".btn-view-all-noti");
    if (viewAllLink) {
        viewAllLink.setAttribute("href", "/admin/notifications");
        viewAllLink.innerHTML = "Xem tất cả thông báo →";
    }

    let currentTab = "all";
    let cachedNotifications = [];

    bellBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        const isOpen = dropdown.classList.contains("show");
        if (isOpen) {
            dropdown.classList.remove("show");
        } else {
            dropdown.classList.add("show");
            fetchNotifications();
        }
    });

    document.addEventListener("click", function (e) {
        if (!bellContainer.contains(e.target)) {
            dropdown.classList.remove("show");
        }
    });

    if (tabAll && tabUnread) {
        tabAll.addEventListener("click", function (e) {
            e.stopPropagation();
            currentTab = "all";
            tabAll.classList.add("active");
            tabUnread.classList.remove("active");
            renderNotificationList();
        });

        tabUnread.addEventListener("click", function (e) {
            e.stopPropagation();
            currentTab = "unread";
            tabUnread.classList.add("active");
            tabAll.classList.remove("active");
            renderNotificationList();
        });
    }

    if (btnMarkAll) {
        btnMarkAll.addEventListener("click", async function (e) {
            e.stopPropagation();
            try {
                const res = await fetch("/admin/api/notifications/read-all", { method: "POST" });
                const data = await res.json();
                if (data.success) {
                    cachedNotifications.forEach(n => n.is_read = true);
                    updateCounters();
                    renderNotificationList();
                }
            } catch (err) {}
        });
    }

    function getGroupIconHtml(group, severity) {
        if (group === "security" || severity === "critical") {
            return `<div class="noti-icon-sq noti-sq-red">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
            </div>`;
        }
        if (group === "account") {
            return `<div class="noti-icon-sq noti-sq-amber">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="20" y1="8" x2="20" y2="14"></line><line x1="23" y1="11" x2="17" y2="11"></line></svg>
            </div>`;
        }
        if (group === "role" || group === "config") {
            return `<div class="noti-icon-sq noti-sq-blue">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg>
            </div>`;
        }
        return `<div class="noti-icon-sq noti-sq-green">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"></ellipse><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path></svg>
        </div>`;
    }

    function updateCounters() {
        const totalCount = cachedNotifications.length;
        const unreadCount = cachedNotifications.filter(n => !n.is_read).length;

        if (unreadBadge) {
            if (unreadCount > 0) {
                unreadBadge.style.display = "flex";
                unreadBadge.textContent = unreadCount > 9 ? "9+" : unreadCount;
            } else {
                unreadBadge.style.display = "none";
            }
        }
        if (headerUnreadPill) {
            headerUnreadPill.textContent = `${unreadCount} chưa đọc`;
            headerUnreadPill.style.display = unreadCount > 0 ? "inline-flex" : "none";
        }
        if (tabAll) tabAll.textContent = `Tất cả (${totalCount})`;
        if (tabUnread) tabUnread.textContent = `Chưa đọc (${unreadCount})`;
    }

    function openNotificationDetailModal(item) {
        document.getElementById("ndTitle").textContent = item.title;
        document.getElementById("ndMessage").textContent = item.message;
        document.getElementById("ndTime").textContent = `${item.time_ago} (${item.created_at})`;
        document.getElementById("ndGoTargetBtn").setAttribute("href", item.target_url || "/admin");

        const badgeEl = document.getElementById("ndSeverityBadge");
        badgeEl.textContent = item.severity_label || "Thông tin";
        badgeEl.className = "nd-badge " + (
            item.severity === "critical" ? "nd-badge-critical" :
            (item.severity === "action_required" || item.severity === "important" ? "nd-badge-action" : "nd-badge-info")
        );

        // Ẩn/hiện các trường tùy chọn nếu có dữ liệu
        const accRow = document.getElementById("ndAccountRow");
        if (item.account) {
            accRow.style.display = "grid";
            document.getElementById("ndAccount").textContent = item.account;
        } else {
            accRow.style.display = "none";
        }

        const reasonRow = document.getElementById("ndReasonRow");
        if (item.reason) {
            reasonRow.style.display = "grid";
            document.getElementById("ndReason").textContent = item.reason;
        } else {
            reasonRow.style.display = "none";
        }

        const impactRow = document.getElementById("ndImpactRow");
        if (item.impact) {
            impactRow.style.display = "grid";
            document.getElementById("ndImpact").textContent = item.impact;
        } else {
            impactRow.style.display = "none";
        }

        dropdown.classList.remove("show");
        detailBackdrop.classList.add("show");
    }

    function renderNotificationList() {
        if (!notiListContainer) return;
        const list = currentTab === "unread"
            ? cachedNotifications.filter(n => !n.is_read)
            : cachedNotifications;

        if (list.length === 0) {
            notiListContainer.innerHTML = `<div class="noti-empty-state">
                ${currentTab === "unread" ? "Bạn đã đọc tất cả thông báo." : "Chưa có thông báo hệ thống nào."}
            </div>`;
            return;
        }

        notiListContainer.innerHTML = list.map(item => `
            <div class="noti-item" data-id="${item.id}">
                ${getGroupIconHtml(item.group, item.severity)}
                <div class="noti-item-body">
                    <div class="noti-item-title">${item.title}</div>
                    <div class="noti-item-msg">${item.message}</div>
                    <div class="noti-item-time">${item.time_ago}</div>
                </div>
                ${!item.is_read ? '<span class="noti-blue-dot" title="Chưa đọc"></span>' : ""}
            </div>
        `).join("");

        notiListContainer.querySelectorAll(".noti-item").forEach(el => {
            el.addEventListener("click", async function (e) {
                e.stopPropagation();
                const id = this.getAttribute("data-id");
                const item = cachedNotifications.find(n => n.id === id);
                if (!item) return;

                // Đánh dấu đã đọc -> loại khỏi tab Chưa đọc nhưng giữ trong tab Tất cả
                if (!item.is_read) {
                    item.is_read = true;
                    updateCounters();
                    renderNotificationList();
                    fetch(`/admin/api/notifications/read/${id}`, { method: "POST" }).catch(() => {});
                }

                // Mở popup nội dung chi tiết & nút điều hướng xử lý
                openNotificationDetailModal(item);
            });
        });
    }

    async function fetchNotifications() {
        try {
            const res = await fetch("/admin/api/notifications", {
                method: "GET",
                credentials: "same-origin",
                headers: { "Accept": "application/json" }
            });
            if (res.status === 403 || res.status === 401) {
                if (notiListContainer) {
                    notiListContainer.innerHTML = `<div class="noti-empty-state">Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại.</div>`;
                }
                return;
            }
            const data = await res.json();
            if (data.success) {
                cachedNotifications = data.notifications || [];
                updateCounters();
                renderNotificationList();
            }
        } catch (err) {}
    }
    fetchNotifications();
    setInterval(fetchNotifications, 8000);
});