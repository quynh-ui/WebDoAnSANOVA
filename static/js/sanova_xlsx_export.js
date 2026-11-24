(function (global) {
    const SHEETJS_URLS = [
        "https://cdn.sheetjs.com/xlsx-0.20.3/package/dist/xlsx.full.min.js",
        "https://cdn.jsdelivr.net/npm/xlsx@0.18.5/dist/xlsx.full.min.js"
    ];

    let loadPromise = null;

    function loadScript(src) {
        return new Promise((resolve, reject) => {
            const s = document.createElement("script");
            s.src = src;
            s.async = true;
            s.onload = () => resolve();
            s.onerror = () => reject(new Error("Không tải được thư viện SheetJS: " + src));
            document.head.appendChild(s);
        });
    }

    async function ensureXlsx() {
        if (global.XLSX) return global.XLSX;
        if (!loadPromise) {
            loadPromise = (async () => {
                let lastErr = null;
                for (const url of SHEETJS_URLS) {
                    try {
                        await loadScript(url);
                        if (global.XLSX) return global.XLSX;
                    } catch (e) {
                        lastErr = e;
                    }
                }
                loadPromise = null;
                throw lastErr || new Error("Không thể khởi tạo SheetJS.");
            })();
        }
        return loadPromise;
    }

    function sanitizeSheetName(name, fallback) {
        const cleaned = String(name || fallback || "Sheet")
            .replace(/[\\/*?:[\]]/g, " ")
            .replace(/\s+/g, " ")
            .trim();
        return (cleaned || "Sheet").slice(0, 31);
    }

    function formatStamp(d = new Date()) {
        const pad = (n) => String(n).padStart(2, "0");
        return (
            d.getFullYear() +
            pad(d.getMonth() + 1) +
            pad(d.getDate()) +
            "_" +
            pad(d.getHours()) +
            pad(d.getMinutes())
        );
    }

    function computeColWidths(rows, customWidths) {
        if (Array.isArray(customWidths) && customWidths.length) {
            return customWidths.map((w) => ({ wch: w }));
        }
        if (!rows || !rows.length) return [];
        const isAoA = Array.isArray(rows[0]);
        const keys = isAoA ? rows[0].map((_, idx) => idx) : Object.keys(rows[0]);
        return keys.map((k, colIdx) => {
            let maxLen = isAoA ? 10 : String(k).length;
            const limit = Math.min(rows.length, 300);
            for (let i = 0; i < limit; i++) {
                const val = isAoA ? rows[i]?.[colIdx] : rows[i]?.[k];
                const len = String(val ?? "").length;
                if (len > maxLen) maxLen = len;
            }
            return { wch: Math.max(10, Math.min(48, maxLen + 3)) };
        });
    }

    function applyNumberFormats(ws, numFmt) {
        if (!ws || !ws["!ref"]) return;
        const XLSX = global.XLSX;
        const range = XLSX.utils.decode_range(ws["!ref"]);
        const fmt = numFmt || "#,##0";
        for (let r = range.s.r + 1; r <= range.e.r; r++) {
            for (let c = range.s.c; c <= range.e.c; c++) {
                const addr = XLSX.utils.encode_cell({ r, c });
                const cell = ws[addr];
                if (cell && cell.t === "n" && !cell.z) {
                    cell.z = fmt;
                }
            }
        }
    }

    async function exportWorkbook({ filename, sheets }) {
        const XLSX = await ensureXlsx();
        const wb = XLSX.utils.book_new();
        const usedNames = new Set();

        (sheets || []).forEach((sheet, idx) => {
            let sheetName = sanitizeSheetName(sheet.name, "Sheet" + (idx + 1));
            if (usedNames.has(sheetName)) {
                sheetName = (sheetName.slice(0, 28) + "_" + (idx + 1)).slice(0, 31);
            }
            usedNames.add(sheetName);

            const rows = Array.isArray(sheet.rows) && sheet.rows.length
                ? sheet.rows
                : [{ "Thông báo": "Không có dữ liệu" }];

            const ws = Array.isArray(rows[0])
                ? XLSX.utils.aoa_to_sheet(rows)
                : XLSX.utils.json_to_sheet(rows);

            ws["!cols"] = computeColWidths(rows, sheet.colWidths);
            applyNumberFormats(ws, sheet.numFmt);
            XLSX.utils.book_append_sheet(wb, ws, sheetName);
        });

        let finalName = String(filename || `SANOVA_Export_${formatStamp()}.xlsx`).trim();
        if (!finalName.toLowerCase().endsWith(".xlsx")) {
            finalName += ".xlsx";
        }
        XLSX.writeFile(wb, finalName);
        return finalName;
    }

    global.SanovaXlsxExport = {
        ensureXlsx,
        formatStamp,
        exportWorkbook,
    };
})(window);
