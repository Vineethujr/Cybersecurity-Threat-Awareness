"""Input sanitization. Output is ALSO escaped in the frontend (defence in depth against XSS)."""
import re

_TAGS = re.compile(r"<[^>]*>")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(value, max_len=1000) -> str:
    text = _CTRL.sub("", str(value or ""))
    text = _TAGS.sub("", text)
    return re.sub(r"[ \t]+", " ", text).strip()[:max_len]
