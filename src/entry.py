import json
from urllib.parse import urlparse
from js import Response
from pyodide.ffi import to_js


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


async def db_set_json(env, store_key, data):
    raw = json.dumps(data, ensure_ascii=False)
    await (
        env.DATABASE.prepare(
            """
            INSERT INTO json_store (store_key, payload, updated_at)
            VALUES (?, ?, datetime('now'))
            ON CONFLICT(store_key) DO UPDATE SET
                payload = excluded.payload,
                updated_at = datetime('now')
            """
        )
        .bind(store_key, raw)
        .run()
    )


def json_response(data, status=200):
    headers = to_js({"Content-Type": "application/json; charset=utf-8"})
    return Response.new(
        json.dumps(data, ensure_ascii=False),
        to_js({"status": status, "headers": headers}),
    )


def text_response(text, status=200):
    headers = to_js({"Content-Type": "text/plain; charset=utf-8"})
    return Response.new(
        text,
        to_js({"status": status, "headers": headers}),
    )


async def fetch(request, env, ctx=None):
    path = urlparse(request.url).path
    method = str(request.method).upper()

    if path == "/api/dispatcher/notifications" and method == "GET":
        notis = await db_get_json(env, "dispatcher_notifications", [])
        unread = len([n for n in notis if not n.get("is_read")])
        return json_response(
            {
                "success": True,
                "unread_count": unread,
                "notifications": notis,
            }
        )

    if path == "/api/health" and method == "GET":
        res = await env.DATABASE.prepare(
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

    return text_response("SANOVA Worker is running on Cloudflare D1.")