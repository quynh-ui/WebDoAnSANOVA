import json
from urllib.parse import urlparse
from workers import Response, WorkerEntrypoint


async def db_get_json(env, store_key, default):
    row = (
        await env.DATABASE.prepare(
            "SELECT payload FROM json_store WHERE store_key = ? LIMIT 1"
        )
        .bind(store_key)
        .first()
    )
    if not row or not getattr(row, "payload", None):
        return default
    try:
        return json.loads(row.payload)
    except Exception:
        return default


async def db_set_json(env, store_key, data):
    raw = json.dumps(data, ensure_ascii=False)
    await env.DATABASE.prepare(
        """
        INSERT INTO json_store (store_key, payload, updated_at)
        VALUES (?, ?, datetime('now'))
        ON CONFLICT(store_key) DO UPDATE SET
            payload = excluded.payload,
            updated_at = datetime('now')
        """
    ).bind(store_key, raw).run()


def json_response(data, status=200):
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=status,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        path = urlparse(request.url).path
        method = request.method.upper()

        if path == "/api/dispatcher/notifications" and method == "GET":
            notis = await db_get_json(self.env, "dispatcher_notifications", [])
            return json_response(
                {
                    "success": True,
                    "unread_count": len([n for n in notis if not n.get("is_read")]),
                    "notifications": notis,
                }
            )

        if path == "/api/health" and method == "GET":
            tables = await self.env.DATABASE.prepare(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).all()
            table_names = [r.name for r in (tables.results or [])]
            return json_response(
                {
                    "success": True,
                    "service": "webdoansanova",
                    "d1_tables": table_names,
                }
            )

        return Response(
            "SANOVA Worker is running on Cloudflare D1.",
            status=200,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )