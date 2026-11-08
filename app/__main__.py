"""Start the loopback-only SECRA agent console: python -m app."""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("SECRA_UI_PORT", "8765"))
    if not 1024 <= port <= 65535:
        raise SystemExit("SECRA_UI_PORT must be between 1024 and 65535")
    uvicorn.run("app.ui.server:app", host="127.0.0.1", port=port, workers=1)
