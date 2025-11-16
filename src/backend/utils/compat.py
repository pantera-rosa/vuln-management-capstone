from typing import Any, Mapping

def model_to_dict(obj: Any) -> dict:
    """
    Return a plain dict from a Pydantic model (v1 or v2) or a mapping-like object.
    """
    if hasattr(obj, "model_dump"):      # Pydantic v2
        return obj.model_dump()
    if hasattr(obj, "dict"):            # Pydantic v1
        return obj.dict()
    if isinstance(obj, Mapping):
        return dict(obj)
    # very last resort (avoid if possible)
    return {k: getattr(obj, k) for k in dir(obj) if not k.startswith("_")}