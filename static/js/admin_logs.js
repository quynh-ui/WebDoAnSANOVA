let currentLogs = [];
let currentPage = 1;
let currentLimit = 10;
let pollingTimer = null;

document.addEventListener("DOMContentLoaded", function () {
    // Để trống mặc định hai ô ngày để hiển thị toàn bộ lịch sử nếu chưa chọn khoảng
    document.getElementById("dateFrom").value = "";
    document.getElementById("dateTo").value = "";

    // Tải dữ liệu ban đầu
    fetchLogs(1);

    // Tự động kiểm tra nhật ký mới mỗi 5 giây mà không cần F5
    pollingTimer = setInterval(() => {
        fetchLogs(currentPage, true);
    }, 5000);
});

function fetchLogs(page = 1, isSilentPolling = false) {
    currentPage = page;
    const q = document.getElementById("searchInput").value.trim();
    const dateFrom = document.getElementById("dateFrom").value;
    const dateTo = document.getElementById("dateTo").value;
    const category = document.getElementById("categoryFilter").value;
    const actor = document.getElementById("actorFilter").value;
    const result = document.getElementById("resultFilter").value;

    const url = `/admin/api/logs?page=${page}&limit=${currentLimit}&q=${encodeURIComponent(q)}&from=${dateFrom}&to=${dateTo}&category=${encodeURIComponent(category)}&actor=${encodeURIComponent(actor)}&result=${encodeURIComponent(result)}`;

    fetch(url)
        .then(res => res.json())
        .then(data => {
            if (!data.success) return;

            // 1. Cập nhật thẻ thống kê
            document.getElementById("kpiTotal").textContent = Number(data.kpi.total).toLocaleString("vi-VN");
            document.getElementById("kpiToday").textContent = Number(data.kpi.today).toLocaleString("vi-VN");
            document.getElementById("kpiSuccess").textContent = Number(data.kpi.success).toLocaleString("vi-VN");
            document.getElementById("kpiFailedWarn").textContent = Number(data.kpi.failed_warn).toLocaleString("vi-VN");

            // 2. Cập nhật dropdown người thực hiện
            populateActorDropdown(data.actors);

            // 3. Số bản ghi
            document.getElementById("filteredCount").textContent = data.total_filtered;

            // 4. Render danh sách bảng
            currentLogs = data.items;
            renderTable(data.items);

            // 5. Phân trang
            renderPagination(data.page, data.total_pages);
        })
        .catch(err => {
            if (!isSilentPolling) console.error("Lỗi khi tải nhật ký:", err);
        });
}

function renderTable(items) {
    const tbody = document.getElementById("logsTableBody");
    if (!items || items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: #94a3b8; padding: 24px;">Không tìm thấy bản ghi nhật ký phù hợp.</td></tr>`;
        return;
    }

    tbody.innerHTML = items.map(log => {
        const catClass = "cat-" + (log.category || "").replace(/\s+/g, "-");
        const isSuccess = log.result === "Thành công";
        const statusClass = isSuccess ? "status-success" : (log.result === "Thất bại" ? "status-danger" : "status-warning");

        return `
            <tr>
                <td class="time-cell">
                    <strong>${log.time || ""}</strong>
                    <span class="date-sub">${log.date ? formatDate(log.date) : ""}</span>
                </td>
                <td>
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
                        <span>${log.actor || log.by || "Hệ thống"}</span>
                    </div>
                </td>
                <td>
                    <span class="cat-badge ${catClass}">${log.category}</span>
                </td>
                <td style="max-width: 280px; font-weight: 500;">
                    ${log.action}
                </td>
                <td>
                    <span style="color: #334155; font-weight: 600;">${log.target || "—"}</span>
                </td>
                <td>
                    <span class="status-badge ${statusClass}">
                        ${isSuccess ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>' : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>'}
                        ${log.result}
                    </span>
                </td>
                <td style="text-align: center;">
                    <button type="button" class="btn-view-log" onclick="openDetailPanel('${log.id}')">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        Xem
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

function openDetailPanel(logId) {
    const log = currentLogs.find(l => l.id === logId);
    if (!log) return;

    const banner = document.getElementById("panelResultBanner");
    const bannerText = document.getElementById("panelStatusText");
    bannerText.textContent = log.result;
    banner.className = "status-banner " + (log.result === "Thành công" ? "success" : "danger");

    document.getElementById("dId").textContent = log.id;
    document.getElementById("dTime").textContent = log.timestamp || `${log.date} ${log.time}`;
    document.getElementById("dActor").textContent = log.by || log.actor;
    
    const catClass = "cat-" + (log.category || "").replace(/\s+/g, "-");
    document.getElementById("dCategory").innerHTML = `<span class="cat-badge ${catClass}">${log.category}</span>`;
    
    document.getElementById("dAction").textContent = log.action;
    document.getElementById("dTarget").textContent = log.target || "—";
    document.getElementById("dIp").textContent = log.ip || "127.0.0.1";
    document.getElementById("dDevice").textContent = log.device || "Trình duyệt nội bộ";
    document.getElementById("dReason").textContent = log.reason || "—";

    const diffContainer = document.getElementById("diffContent");
    if (log.changes && log.changes.length > 0) {
        diffContainer.innerHTML = `
            <table class="diff-table">
                <thead>
                    <tr>
                        <th>Trường</th>
                        <th>Trước</th>
                        <th>Sau</th>
                    </tr>
                </thead>
                <tbody>
                    ${log.changes.map(c => `
                        <tr>
                            <td><strong>${c.field}</strong></td>
                            <td style="color: #64748b;">${c.before || '—'}</td>
                            <td style="color: #057a55; font-weight: 700;">${c.after || '—'}</td>
                        </tr>
                    `).join("")}
                </tbody>
            </table>
        `;
    } else {
        diffContainer.innerHTML = `
            <div class="diff-empty-box">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                <span>Không có thay đổi dữ liệu.</span>
            </div>
        `;
    }

    document.getElementById("detailPanel").classList.add("open");
    document.getElementById("panelBackdrop").classList.add("open");
}

function closeDetailPanel() {
    document.getElementById("detailPanel").classList.remove("open");
    document.getElementById("panelBackdrop").classList.remove("open");
}

function renderPagination(page, totalPages) {
    const container = document.getElementById("paginationControls");
    let html = `<button type="button" class="page-btn" ${page <= 1 ? 'disabled' : ''} onclick="fetchLogs(${page - 1})">‹</button>`;

    for (let p = 1; p <= totalPages; p++) {
        if (p === 1 || p === totalPages || (p >= page - 1 && p <= page + 1)) {
            html += `<button type="button" class="page-btn ${p === page ? 'active' : ''}" onclick="fetchLogs(${p})">${p}</button>`;
        } else if (p === page - 2 || p === page + 2) {
            html += `<span style="padding: 0 4px; color: #94a3b8;">...</span>`;
        }
    }

    html += `<button type="button" class="page-btn" ${page >= totalPages ? 'disabled' : ''} onclick="fetchLogs(${page + 1})">›</button>`;
    container.innerHTML = html;
}

function changeLimit(newLimit) {
    currentLimit = parseInt(newLimit);
    fetchLogs(1);
}

function resetFilters() {
    document.getElementById("searchInput").value = "";
    document.getElementById("dateFrom").value = "";
    document.getElementById("dateTo").value = "";
    document.getElementById("categoryFilter").value = "ALL";
    document.getElementById("actorFilter").value = "ALL";
    document.getElementById("resultFilter").value = "ALL";
    fetchLogs(1);
}

function populateActorDropdown(actors) {
    const select = document.getElementById("actorFilter");
    if (!select || !actors) return;
    const currentVal = select.value;
    select.innerHTML = '<option value="ALL">Tất cả</option>' + 
        actors.map(a => `<option value="${a}" ${a === currentVal ? 'selected' : ''}>${a}</option>`).join("");
}

function handleExportExcel() {
    const q = document.getElementById("searchInput").value.trim();
    const dateFrom = document.getElementById("dateFrom").value;
    const dateTo = document.getElementById("dateTo").value;
    const category = document.getElementById("categoryFilter").value;
    const actor = document.getElementById("actorFilter").value;
    const result = document.getElementById("resultFilter").value;

    const url = `/admin/logs/export?q=${encodeURIComponent(q)}&from=${dateFrom}&to=${dateTo}&category=${encodeURIComponent(category)}&actor=${encodeURIComponent(actor)}&result=${encodeURIComponent(result)}`;
    window.location.href = url;
}

function formatDate(isoStr) {
    if (!isoStr) return "";
    const [y, m, d] = isoStr.split("-");
    return `${d}/${m}/${y}`;
}