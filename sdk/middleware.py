import httpx
import functools
from typing import Callable

FIREWALL_API_URL = "http://localhost:8000/scan"


class FirewallBlockException(Exception):
    """raised when the firewall blocks a request"""
    pass


def scan_with_firewall(content: str, context_type: str = "user_prompt") -> dict:
    try:
        resp = httpx.post(
            FIREWALL_API_URL,
            json={"content": content, "context_type": context_type},
            timeout=5.0
        )
        resp.raise_for_status()
        return resp.json()
    except httpx.RequestError as e:
        # failsafe: if firewall is down, allow the request through
        print(f"[firewall] warning: could not reach API: {e}")
        return {"action": "ALLOW", "risk_score": 0.0, "reasons": ["firewall unreachable"]}


def firewall_protected(func: Callable) -> Callable:
    """decorator that intercepts the first string arg and scans it via the firewall"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if args and isinstance(args[0], str):
            original_prompt = args[0]
        elif len(args) > 1 and isinstance(args[1], str):
            # handles self.method(prompt) calls
            original_prompt = args[1]
        else:
            return func(*args, **kwargs)

        result = scan_with_firewall(original_prompt)
        action = result.get("action")

        if action == "BLOCK":
            raise FirewallBlockException(f"blocked — {result.get('reasons', [])}")

        elif action == "SANITIZE":
            sanitized = result.get("sanitized_content")
            if sanitized:
                if isinstance(args[0], str):
                    args = (sanitized,) + args[1:]
                else:
                    args = (args[0], sanitized) + args[2:]

        return func(*args, **kwargs)

    return wrapper
