import os, httpx
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

DEFAULT_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "20"))

@retry(
    reraise=True,
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.5, max=8),
    retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
)
async def get_json(url: str, params: dict | None = None, headers: dict | None = None):
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as client:
        resp = await client.get(url, params=params, headers=headers)
        resp.raise_for_status()
        return resp.json()
