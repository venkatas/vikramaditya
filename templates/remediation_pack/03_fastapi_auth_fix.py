"""
Auth + rate-limit + size-cap fix template for a FastAPI app that exposes
unauth admin/data routes.

Pattern this fixes:
    /data/<file>.csv          — unauth large-record dump
    /api/.../upload           — unauth file processor with no size cap
    /api/.../runs[/...]       — unauth read of historical run results
    No DELETE endpoint        — test artifacts persist forever

Three changes, all non-breaking for any caller that already supplies
the existing admin token used by other secured routes:

  1. Add a `require_admin_token` dependency.
  2. Apply it to the leaked routes.
  3. Add per-IP rate limiting + size cap on uploads.

Required deps (add to requirements.txt if not present):
    slowapi>=0.1.9
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address


# ---------------------------------------------------------------------------
# Auth dependency — re-uses the same token as other already-secured routes.
# Replace `<APP>_ADMIN_TOKEN` with whatever env var the existing /admin/*
# handlers read.
# ---------------------------------------------------------------------------
ADMIN_TOKEN = os.environ.get("<APP>_ADMIN_TOKEN", "")

def require_admin_token(
    x_admin_token: Optional[str] = Header(default=None, alias="x-admin-token"),
) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Admin token not configured")
    if not x_admin_token or x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid admin token")


# ---------------------------------------------------------------------------
# Rate limiter — 5 uploads per IP per minute, 30 reads per IP per minute
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

# Wire into the existing FastAPI app:
#   app.state.limiter = limiter
#   app.add_exception_handler(429, lambda r, e:
#       JSONResponse({"detail": "Rate limit exceeded"}, status_code=429))


# ---- Public-data endpoint that should require auth ----------------------
@app.get(
    "/data/<DATAFILE>.csv",
    dependencies=[Depends(require_admin_token)],
)
def get_data_csv():
    return FileResponse("path/to/<DATAFILE>.csv", media_type="text/csv")


# ---- Upload endpoint: auth + rate-limit + size-cap ----------------------
MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB

@app.post(
    "/api/<NAMESPACE>/upload",
    dependencies=[Depends(require_admin_token)],
)
@limiter.limit("5/minute")
async def upload_handler(request: Request, file: UploadFile = File(...)):
    total = 0
    chunks: list[bytes] = []
    while True:
        chunk = await file.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large")
        chunks.append(chunk)
    body = b"".join(chunks)
    # ... existing parsing logic (pandas.read_excel etc.) ...
    return {"id": "...", "name": file.filename}


# ---- Read endpoints: auth ------------------------------------------------
@app.get("/api/<NAMESPACE>/runs", dependencies=[Depends(require_admin_token)])
@limiter.limit("30/minute")
def list_runs(request: Request):
    return []


@app.get(
    "/api/<NAMESPACE>/runs/{run_id}/meta",
    dependencies=[Depends(require_admin_token)],
)
def get_run_meta(run_id: str):
    pass


@app.get(
    "/api/<NAMESPACE>/runs/{run_id}/results",
    dependencies=[Depends(require_admin_token)],
)
def get_run_results(run_id: str):
    pass


# ---- IMPORTANT: add a DELETE so VAPT / dev artifacts can be removed ------
@app.delete(
    "/api/<NAMESPACE>/runs/{run_id}",
    dependencies=[Depends(require_admin_token)],
)
def delete_run(run_id: str):
    return {"deleted": run_id}


# Verification (after deploy):
#   curl -sk https://<API_HOST>/data/<DATAFILE>.csv -i | head -3
#   → HTTP/2 401  {"detail":"Invalid admin token"}
#   curl -sk -H "x-admin-token: $TOKEN" https://<API_HOST>/data/<DATAFILE>.csv | head -1
#   → first row of the CSV
#   curl -sk -X POST https://<API_HOST>/api/<NAMESPACE>/upload -F file=@x.xlsx -i | head -3
#   → HTTP/2 401
