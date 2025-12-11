from src.backend.utils.http import get_json
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_PERSONAL_ACCESS_TOKEN = os.environ.get("GITHUB_PERSONAL_ACCESS_TOKEN", "")

def fetch_ghsa_details(ghsa_id: str) -> dict:
    ghsa_url = f"https://api.github.com/advisories/{ghsa_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    if GITHUB_PERSONAL_ACCESS_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_PERSONAL_ACCESS_TOKEN}"
        print("Using GitHub Personal Access Token for authentication.")

    ghsa_json = asyncio.run(get_json(ghsa_url, headers=headers))
    return ghsa_json