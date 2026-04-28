"""
Production config for FastAPI: disable interactive docs (/docs, /redoc,
/openapi.json) unless an explicit dev/staging env-var is set.

Apply where the FastAPI() instance is constructed.
"""
import os
from fastapi import FastAPI

# Default behavior: docs OFF unless <APP>_ENV is "dev" or "staging".
_env = os.environ.get("<APP>_ENV", "production").lower()
_docs_enabled = _env in {"dev", "development", "staging"}

app = FastAPI(
    title="<APP_TITLE>",
    version="<APP_VERSION>",
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

# Verification (after deploy with <APP>_ENV=production):
#   curl -sk https://<API_HOST>/openapi.json -i | head -1
#   → HTTP/2 404
#   curl -sk https://<API_HOST>/docs -i | head -1
#   → HTTP/2 404
