"""ASGI body cap for the two upload surfaces (the ingress container and the host orchestrator).

Starlette's multipart parser spools a file part IN FULL before the endpoint runs (to /tmp — in the
ingress container a tmpfs, i.e. host RAM), so the endpoint's own byte count bounded what was KEPT,
never what a client could make the process buffer: concurrent multi-GB POSTs were each spooled whole
before their 413. Refused here, before the parser: by Content-Length when declared, else by counting
the chunks as they stream through (never assembled — uploads run to a GiB). The post-body receive is
handed to the server untouched: a wrapper that answers it itself cancels every streaming response.
"""
from __future__ import annotations


class BodyCap:
    def __init__(self, inner, cap: int) -> None:
        self.inner, self.cap = inner, cap

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)
        for k, v in scope.get("headers") or []:
            if k == b"content-length" and v.isdigit() and int(v) > self.cap:
                return await self._reject(send)
        state = {"seen": 0, "over": False, "started": False, "answered": False}

        async def counting_receive():
            if state["over"]:   # the parser sees the client gone and stops reading: nothing past the cap is spooled
                return {"type": "http.disconnect"}
            msg = await receive()
            if msg["type"] == "http.request":
                state["seen"] += len(msg.get("body", b""))
                if state["seen"] > self.cap:
                    state["over"] = True
                    return {"type": "http.disconnect"}
            return msg

        async def guarded_send(msg):
            if state["over"] and not state["started"]:   # the app's own answer to the aborted read (a 400, nothing) is replaced by the 413
                if not state["answered"]:
                    state["answered"] = True
                    await self._reject(send)
                return
            if msg["type"] == "http.response.start":
                state["started"] = True
            await send(msg)
        try:
            await self.inner(scope, counting_receive, guarded_send)
        except Exception:
            if not (state["over"] and not state["started"]):
                raise
        if state["over"]:
            # the multipart parser's spool for the part in flight (a SpooledTemporaryFile, rolled over to /tmp at 1 MiB) is
            # dropped by the unwind, not closed: the traceback's frame cycle kept it open until a collection happened to run,
            # and a tmpfs sized for two uploads filled with refused ones. One collection per refusal is cheap; refusals are rare
            import gc
            gc.collect()
        if state["over"] and not state["started"] and not state["answered"]:
            state["answered"] = True
            await self._reject(send)

    async def _reject(self, send):
        body = b'{"detail":"upload exceeds the size bound (AUTHENTICODE_MAX_UPLOAD_MB)"}'
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})


FRAMING_SLACK = 64 * 1024   # multipart boundaries and part headers around the file bytes the endpoint counts exactly
