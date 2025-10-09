from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .api.v1.routes import api_router

app = FastAPI(title="VulnGuard", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict to only accepted origins as neede
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")
