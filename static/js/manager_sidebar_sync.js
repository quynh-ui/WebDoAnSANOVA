(function () {
    // 1. Tự động tiêm CSS cho Dropdown Chuông thông báo Manager
    const style = document.createElement('style');
    style.textContent = `
        .mgr-bell-wrap { position: relative; display: inline-flex; }
        .mgr-bell-badge {
            position: absolute; top: -4px; right: -4px;
            background: #ef4444; color: #ffffff;
            font-size: 10.5px; font-weight: 800;
            min-width: 19px; height: 19px; padding: 0 5px;
            border-radius: 999px; border: 2px solid #ffffff;
            display: none; align-items: center; justify-content: center;
        }
        .mgr-noti-dropdown {
            display: none; position: absolute; right: 0; top: 46px;
            width: 375px; max-width: 92vw;
            background: #ffffff; border: 1px solid #e2e8f0;
            border-radius: 16px; box-shadow: 0 18px 38px rgba(15, 23, 42, 0.16);
            z-index: 999; overflow: hidden;
        }
        .mgr-noti-dropdown.show { display: block; }
        .mgr-noti-head {
            padding: 14px 16px; border-bottom: 1px solid #f1f5f9;
            display: flex; justify-content: space-between; align-items: center;
        }
        .mgr-noti-title { font-size: 14.5px; font-weight: 800; color: #0f172a; display: flex; align-items: center; gap: 8px; }
        .mgr-noti-pill { background: #fee2e2; color: #dc2626; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; }
        .mgr-noti-tabs {
            display: flex; gap: 6px; padding: 8px 14px;
            background: #f8fafc; border-bottom: 1px solid #f1f5f9;
        }
        .mgr-ntab {
            border: 1px solid #e2e8f0; background: #ffffff; color: #475569;
            padding: 4px 10px; border-radius: 999px; font-size: 11.5px; font-weight: 700; cursor: pointer;
        }
        .mgr-ntab.active { background: #033928; color: #ffffff; border-color: #033928; }
        .mgr-noti-list { max-height: 330px; overflow-y: auto; }
        .mgr-noti-item {
            padding: 12px 16px; border-bottom: 1px solid #f1f5f9;
            display: flex; flex-direction: column; gap: 4px;
            cursor: pointer; transition: background 0.14s; text-decoration: none;
        }
        .mgr-noti-item:hover { background: #f0fdf4; }
        .mgr-noti-top { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
        .mgr-ntag { font-size: 10.5px; font-weight: 800; padding: 2px 7px; border-radius: 5px; }
        .ntag-app { background: #dbeafe; color: #1d4ed8; }
        .ntag-stk { background: #fef3c7; color: #b45309; }
        .mgr-ntime { font-size: 11px; color: #94a3b8; }
        .mgr-ntitle { font-size: 13px; font-weight: 700; color: #0f172a; }
        .mgr-nmsg { font-size: 12px; color: #475569; line-height: 1.35; }
        .mgr-noti-foot {
            padding: 10px 14px; background: #f8fafc; border-top: 1px solid #f1f5f9;
            display: grid; grid-template-columns: 1fr 1fr; gap: 8px; text-align: center;
        }
        .mgr-nfoot-link {
            font-size: 12px; font-weight: 700; color: #059669; text-decoration: none;
            padding: 6px; border-radius: 8px; background: #ffffff; border: 1px solid #e2e8f0;
        }
        .mgr-nfoot-link:hover { background: #ecfdf5; }
    `;
    document.head.appendChild(style);

    let cachedNotis = [];
    let currentFilter = 'ALL';

    function initManagerBellUI() {
        const bellBtn = document.querySelector('.bell-btn');
        if (!bellBtn || bellBtn.dataset.mgrBound) return;
        bellBtn.dataset.mgrBound = 'true';

        // Ẩn chấm tròn nhỏ cũ để thay bằng badge đếm số rõ ràng
        const oldDot = bellBtn.querySelector('.bell-dot');
        if (oldDot) oldDot.style.display = 'none';

        const wrap = document.createElement('div');
        wrap.className = 'mgr-bell-wrap';
        bellBtn.parentNode.insertBefore(wrap, bellBtn);
        wrap.appendChild(bellBtn);

        const badge = document.createElement('span');
        badge.className = 'mgr-bell-badge';
        badge.id = 'mgrGlobalBellBadge';
        bellBtn.appendChild(badge);

        const dropdown = document.createElement('div');
        dropdown.className = 'mgr-noti-dropdown';
        dropdown.id = 'mgrGlobalBellDropdown';
        dropdown.innerHTML = `
            <div class="mgr-noti-head">
                <div class="mgr-noti-title">
                    <span>Thông báo điều hành</span>
                    <span class="mgr-noti-pill" id="mgrNotiPillCount">0 cần xử lý</span>
                </div>
            </div>
           <div class="mgr-noti-tabs" style="flex-wrap:wrap;">
                <button type="button" class="mgr-ntab active" data-grp="ALL">Tất cả (<span id="mTabAll">0</span>)</button>
                <button type="button" class="mgr-ntab" data-grp="APPROVAL">Duyệt phiếu (<span id="mTabApp">0</span>)</button>
                <button type="button" class="mgr-ntab" data-grp="STOCKTAKE">Kiểm kê (<span id="mTabStk">0</span>)</button>
                <button type="button" class="mgr-ntab" data-grp="INVENTORY">Tồn &amp; Kệ (<span id="mTabInv">0</span>)</button>
                <button type="button" class="mgr-ntab" data-grp="CLOSING">Chốt tồn (<span id="mTabCls">0</span>)</button>
            </div>
            <div class="mgr-noti-list" id="mgrGlobalNotiList">
                <div style="padding:20px; text-align:center; font-size:12.5px; color:#64748b;">Đang đồng bộ thông báo...</div>
            </div>
            <div class="mgr-noti-foot">
                <a href="/manager/approvals" class="mgr-nfoot-link">Duyệt nhập / bàn giao &rarr;</a>
                <a href="/manager/stocktake?id=DC-0018" class="mgr-nfoot-link">Duyệt điều chỉnh &rarr;</a>
            </div>
        `;
        wrap.appendChild(dropdown);

        bellBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            dropdown.classList.toggle('show');
            if (dropdown.classList.contains('show')) syncManagerSidebarAndBell();
        });

        dropdown.querySelectorAll('.mgr-ntab').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                currentFilter = btn.dataset.grp;
                dropdown.querySelectorAll('.mgr-ntab').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                renderBellDropdownList();
            });
        });

        document.addEventListener('click', (e) => {
            if (!wrap.contains(e.target)) dropdown.classList.remove('show');
        });
    }

    function renderBellDropdownList() {
        const listEl = document.getElementById('mgrGlobalNotiList');
        if (!listEl) return;

        const items = currentFilter === 'ALL'
            ? cachedNotis
            : cachedNotis.filter(n => n.group === currentFilter);

        if (items.length === 0) {
            listEl.innerHTML = '<div style="padding:22px; text-align:center; font-size:12.5px; color:#64748b;">Không có yêu cầu nào đang chờ xử lý.</div>';
            return;
        }

        listEl.innerHTML = items.map(n => `
            <a href="${n.url}" class="mgr-noti-item">
                <div class="mgr-noti-top">
                    <span class="mgr-ntag ${n.group === 'APPROVAL' ? 'ntag-app' : 'ntag-stk'}">${n.tag}</span>
                    <span class="mgr-ntime">${n.time}</span>
                </div>
                <div class="mgr-ntitle">${n.title}</div>
                <div class="mgr-nmsg">${n.message}</div>
            </a>
        `).join('');
    }

    window.syncManagerSidebar = async function () {
        try {
            const res = await fetch('/manager/api/notifications');
            if (!res.ok) return;
            const data = await res.json();

            // 1. Đồng bộ 2 badge đỏ trên Sidebar
            const badgeApp = document.getElementById('sbBadgeApprovals');
            const badgeStk = document.getElementById('sbBadgeStocktake');
            if (badgeApp) {
                badgeApp.textContent = data.approvals_count;
                badgeApp.style.display = data.approvals_count > 0 ? 'inline-flex' : 'none';
            }
            if (badgeStk) {
                badgeStk.textContent = data.stocktake_count;
                badgeStk.style.display = data.stocktake_count > 0 ? 'inline-flex' : 'none';
            }

            // 2. Đồng bộ Chuông thông báo tổng hợp ở góc trên bên phải
            cachedNotis = data.notifications || [];
            const bellBadge = document.getElementById('mgrGlobalBellBadge');
            const pillCount = document.getElementById('mgrNotiPillCount');
            if (bellBadge) {
                bellBadge.textContent = data.total_unread;
                bellBadge.style.display = data.total_unread > 0 ? 'inline-flex' : 'none';
            }
            if (pillCount) pillCount.textContent = `${data.total_unread} cần xử lý`;

            const tAll = document.getElementById('mTabAll');
            const tApp = document.getElementById('mTabApp');
            const tStk = document.getElementById('mTabStk');
            if (tAll) tAll.textContent = data.total_unread;
            if (tApp) tApp.textContent = data.approvals_count;
            if (tStk) tStk.textContent = data.stocktake_count;

            renderBellDropdownList();
        } catch (e) {
            const tagClass = n.group === 'APPROVAL' ? 'ntag-app' : (n.group === 'STOCKTAKE' ? 'ntag-stk' : 'ntag-inv');
        }
    };  

    const syncManagerSidebarAndBell = window.syncManagerSidebar;
    const tInv = document.getElementById('mTabInv');
        if (tInv) tInv.textContent = data.inventory_alert_count || 0;
    document.addEventListener('DOMContentLoaded', () => {
        initManagerBellUI();
        syncManagerSidebarAndBell();
        setInterval(syncManagerSidebarAndBell, 5000);
    });
    // Tự động đồng bộ lại Chuông thông báo & Sidebar NGAY LẬP TỨC sau mọi thao tác POST/PUT/PATCH
    const origFetch = window.fetch;
    window.fetch = async function (...args) {
        const response = await origFetch.apply(this, args);
        const method = (args[1] && args[1].method ? args[1].method : 'GET').toUpperCase();
        if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && response.ok) {
            setTimeout(() => {
                if (typeof window.syncManagerSidebar === 'function') {
                    window.syncManagerSidebar();
                }
            }, 150);
        }
        return response;
    };
})();