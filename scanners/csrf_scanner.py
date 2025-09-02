# \
# import requests
# from bs4 import BeautifulSoup

# TOKEN_NAMES = {"csrf", "csrf_token", "xsrf", "token", "authenticity_token"}

# def scan_csrf_tokens(url: str, timeout: int = 10) -> dict:
#     """
#     Looks for HTML forms and checks whether POST forms include a CSRF token-like input.
#     Heuristic only.
#     """
#     session = requests.Session()
#     session.headers.update({"User-Agent": "EduScanner/1.0"})
#     out = {"forms_checked": 0, "post_forms_without_token": 0, "issues": []}
#     try:
#         r = session.get(url, timeout=timeout, allow_redirects=True)
#         soup = BeautifulSoup(r.text, "html.parser")
#         forms = soup.find_all("form")
#         out["forms_checked"] = len(forms)
#         for f in forms:
#             method = (f.get("method") or "get").lower()
#             if method != "post":
#                 continue
#             inputs = f.find_all("input")
#             has_token = False
#             for inp in inputs:
#                 name = (inp.get("name") or "").lower()
#                 typ = (inp.get("type") or "").lower()
#                 if name in TOKEN_NAMES or typ == "hidden" and any(t in name for t in TOKEN_NAMES):
#                     has_token = True
#                     break
#             if not has_token:
#                 out["post_forms_without_token"] += 1
#                 action = f.get("action") or "(no action)"
#                 out["issues"].append(f"POST form missing CSRF-like token. Action: {action}")
#     except Exception as e:
#         out["issues"].append(f"Fetch error: {type(e).__name__}: {e}")
#     return out


import requests
from bs4 import BeautifulSoup

TOKEN_NAMES = {"csrf", "csrf_token", "xsrf", "token", "authenticity_token"}
COOKIE_NAMES = ["samesite", "csrf_token", "auth_token"]

def scan_csrf_tokens(url: str, timeout: int = 10) -> dict:
    session = requests.Session()
    session.headers.update({"User-Agent": "EduScanner/1.0"})
    out = {"forms_checked": 0, "post_forms_without_token": 0, "issues": []}
    
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")
        out["forms_checked"] = len(forms)
        
        for f in forms:
            method = (f.get("method") or "get").lower()
            if method != "post":
                continue
            inputs = f.find_all("input")
            has_token = False
            for inp in inputs:
                name = (inp.get("name") or "").lower()
                typ = (inp.get("type") or "").lower()
                if name in TOKEN_NAMES or typ == "hidden" and any(t in name for t in TOKEN_NAMES):
                    has_token = True
                    break
            if not has_token:
                out["post_forms_without_token"] += 1
                action = f.get("action") or "(no action)"
                out["issues"].append(f"POST form missing CSRF-like token. Action: {action}")
        
        # Check for SameSite cookies
        cookies = r.cookies
        samesite_cookie = any(cookie for cookie in cookies if 'samesite' in cookie.lower())
        if not samesite_cookie:
            out["issues"].append("No SameSite cookie attribute found, which could make your site vulnerable to CSRF.")
        
    except Exception as e:
        out["issues"].append(f"Fetch error: {type(e).__name__}: {e}")
    
    return out
