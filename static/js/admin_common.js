(function (global) {
    const nativeFetch = global.fetch.bind(global);

    function getToken() {
        return localStorage.getItem("sanova_token") || "";
    }

    // Tự động đính kèm Authorization Bearer cho mọi request API Admin/Auth trên Cloudflare Worker
    global.fetch = function (input, init) {
        const url = typeof input === "string" ? input : (input && input.url) || "";
        const isApi = url.startsWith("/admin/") || url.startsWith("/api/");
        if (isApi) {
            const token = getToken();
            const opts = Object.assign({}, init || {});
            const headers = new Headers(opts.headers || (typeof input !== "string" && input ? input.headers : undefined));
            if (token && !headers.has("Authorization")) {
                headers.set("Authorization", "Bearer " + token);
            }
            opts.headers = headers;
            return nativeFetch(input, opts);
        }
        return nativeFetch(input, init);
    };

    function escapeHtml(s) {
        return String(s ?? "").replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
        });
    }

    async function ensureAdminAuth() {
        try {
            const res = await global.fetch("/api/auth/me");
            if (!res.ok) {
                localStorage.removeItem("sanova_token");
                localStorage.removeItem("sanova_user");
                global.location.href = "/login";
                return null;
            }
            const data = await res.json();
            const user = data.user || {};
            if (!(user.role || "").includes("Quản trị viên")) {
                global.location.href = data.redirect_to || "/login";
                return null;
            }
            localStorage.setItem("sanova_user", JSON.stringify(user));

            // Điền tên Admin đang đăng nhập vào thanh trên cùng
            document.querySelectorAll(".admin-profile-pill span").forEach(function (el) {
                el.textContent = user.name || user.username || "Admin";
            });
            const headerName = document.getElementById("headerNameLabel");
            if (headerName) headerName.textContent = user.name || user.username || "Admin";

            return user;
        } catch (err) {
            global.location.href = "/login";
            return null;
        }
    }

    async function handleLogout(e) {
        if (e) e.preventDefault();
        try {
            await global.fetch("/api/auth/logout", { method: "POST" });
        } catch (_) {}
        localStorage.removeItem("sanova_token");
        localStorage.removeItem("sanova_user");
        global.location.href = "/login";
    }

    document.addEventListener("DOMContentLoaded", function () {
        document.querySelectorAll('a[href="/logout"]').forEach(function (a) {
            a.addEventListener("click", handleLogout);
        });
        ensureAdminAuth();
    });

    global.SanovaAdmin = {
        ensureAdminAuth,
        handleLogout,
        escapeHtml,
        getToken,
    };
})(window);
