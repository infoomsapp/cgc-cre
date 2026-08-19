# PATH: api/index.py
#
# Vercel entrypoint. Vercel's Python runtime detects the ASGI `app` object
# exported from this file and wraps it as a serverless function -- every
# real route still lives in app/main.py, this file only re-exports the
# existing FastAPI instance so the same codebase runs on both Railway
# (uvicorn, long-running process) and Vercel (serverless) without
# duplicating a single route.

from app.main import app
