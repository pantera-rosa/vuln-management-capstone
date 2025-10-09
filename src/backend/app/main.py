from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.v1.routes import api_router

app = FastAPI(title="VulnGuard", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")
