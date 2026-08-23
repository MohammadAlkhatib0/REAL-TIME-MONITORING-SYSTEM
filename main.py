"""
Real-Time Network Monitoring System - FastAPI Main Application
Exposes application instance 'app' and imports routes/WebSocket handlers.
"""
from backend.main import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
