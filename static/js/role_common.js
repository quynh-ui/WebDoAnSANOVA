(function (global) {
    const nativeFetch = global.fetch.bind(global);

    function getToken() {
        return localStorage.getItem("sanova_token") || "";
    }

    // Tự động gắn Authorization: Bearer cho mọi request API khi chạy trên Cloudflare Workers
    global.fetch = function (input, init) {
        const url = typeof input === "string" ? input : (input && input.url) || "";
        const isApi =
            url.startsWith("/api/") ||
            url.startsWith("/manager/api/") ||
            url.startsWith("/warehouse/api/") ||
            url.startsWith("/admin/api/");
        if (isApi) {
            const token = getToken();
            const opts = Object.assign({}, init || {});
            const headers = new Headers(
                opts.headers || (typeof input !== "string" && input ? input.headers : undefined)
            );
            if (token && !headers.has("Authorization")) {
                headers.set("Authorization", "Bearer " + token);
            }
            opts.headers = headers;
            return nativeFetch(input, opts);
        }
        return nativeFetch(input, init);
    };

    async function ensureRoleAuth() {
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
            localStorage.setItem("sanova_user", JSON.stringify(user));

            // Đồng bộ tên hiển thị người dùng đang đăng nhập trên thanh header / profile pill
            document.querySelectorAll("[data-sanova-user-name]").forEach(function (el) {
                el.textContent = user.name || user.username || el.textContent;
            });
            return user;
        } catch (_) {
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
        ensureRoleAuth();
    });

    global.SanovaRoleCommon = {
        ensureRoleAuth,
        handleLogout,
        getToken,
    };
})(window);
