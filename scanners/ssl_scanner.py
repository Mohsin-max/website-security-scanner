# \
# import socket, ssl
# from urllib.parse import urlparse
# from datetime import datetime

# def check_ssl_issues(url: str) -> dict:
#     """
#     Checks basic SSL/TLS issues:
#       - whether host supports TLS
#       - certificate expiry
#     """
#     out = {
#         "supports_tls": "Unknown",
#         "certificate_expiry": "Unknown",
#         "days_to_expiry": "Unknown",
#         "notes": []
#     }
#     parsed = urlparse(url)
#     hostname = parsed.hostname
#     port = 443

#     try:
#         ctx = ssl.create_default_context()
#         with socket.create_connection((hostname, port), timeout=8) as sock:
#             with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
#                 cert = ssock.getpeercert()
#                 out["supports_tls"] = "Yes"
#                 not_after = cert.get('notAfter')
#                 if not_after:
#                     # Format like 'Jun  1 12:00:00 2025 GMT'
#                     exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
#                     days = (exp - datetime.utcnow()).days
#                     out["certificate_expiry"] = exp.strftime('%Y-%m-%d %H:%M:%S UTC')
#                     out["days_to_expiry"] = days
#                     if days < 0:
#                         out["notes"].append("Certificate appears expired.")
#                     elif days < 30:
#                         out["notes"].append("Certificate expires in less than 30 days.")
#                 else:
#                     out["notes"].append("Could not read certificate expiry.")
#     except Exception as e:
#         out["supports_tls"] = "No / Error"
#         out["notes"].append(f"TLS handshake failed: {type(e).__name__}: {e}")

#     return out




import socket, ssl
from urllib.parse import urlparse
from datetime import datetime

def check_ssl_issues(url: str) -> dict:
    out = {
        "supports_tls": "Unknown",
        "certificate_expiry": "Unknown",
        "days_to_expiry": "Unknown",
        "ssl_protocols": [],
        "cipher_suites": [],
        "notes": []
    }
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                out["supports_tls"] = "Yes"
                
                not_after = cert.get('notAfter')
                if not_after:
                    exp = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    days = (exp - datetime.utcnow()).days
                    out["certificate_expiry"] = exp.strftime('%Y-%m-%d %H:%M:%S UTC')
                    out["days_to_expiry"] = days
                    if days < 0:
                        out["notes"].append("Certificate appears expired.")
                    elif days < 30:
                        out["notes"].append("Certificate expires in less than 30 days.")
                else:
                    out["notes"].append("Could not read certificate expiry.")
                
                # SSL Protocols and Ciphers
                out["ssl_protocols"] = ssock.version()  # Example: TLSv1.3
                out["cipher_suites"] = ssock.cipher()  # Example: ('TLS_AES_128_GCM_SHA256', 'TLSv1.3')

    except Exception as e:
        out["supports_tls"] = "No / Error"
        out["notes"].append(f"TLS handshake failed: {type(e).__name__}: {e}")

    return out
