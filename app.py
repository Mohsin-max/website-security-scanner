# \
# from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
# from scanners.ssl_scanner import check_ssl_issues
# from scanners.sql_scanner import scan_sql_injection
# from scanners.xss_scanner import scan_xss_reflection
# from scanners.csrf_scanner import scan_csrf_tokens
# from report_generator import generate_pdf_report
# from urllib.parse import urlparse, urlencode
# import re
# import os
# import time

# app = Flask(__name__)

# def normalize_url(raw_url: str) -> str:
#     raw_url = raw_url.strip()
#     if not re.match(r'^https?://', raw_url, re.I):
#         raw_url = 'http://' + raw_url
#     return raw_url

# @app.route('/', methods=['GET'])
# def index():
#     return render_template('index.html')

# @app.route('/scan', methods=['POST'])
# def scan():
#     target = request.form.get('target', '').strip()
#     if not target:
#         return render_template('index.html', error="Please enter a URL.")
#     url = normalize_url(target)

#     start = time.time()
#     ssl_result = check_ssl_issues(url)
#     sql_result = scan_sql_injection(url)
#     xss_result = scan_xss_reflection(url)
#     csrf_result = scan_csrf_tokens(url)
#     duration = round(time.time() - start, 2)

#     results = {
#         'target': url,
#         'duration': duration,
#         'ssl': ssl_result,
#         'sql_injection': sql_result,
#         'xss': xss_result,
#         'csrf': csrf_result
#     }
#     return render_template('results.html', results=results)

# @app.route('/report', methods=['POST'])
# def report():
#     # Expect JSON payload with `results`
#     results = request.json.get('results')
#     if not results:
#         return jsonify({'error': 'No results provided'}), 400

#     filepath = generate_pdf_report(results)
#     return jsonify({'path': filepath})

# if __name__ == '__main__':
#     app.run(debug=True)




from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from scanners.ssl_scanner import check_ssl_issues
from scanners.sql_scanner import scan_sql_injection
from scanners.xss_scanner import scan_xss_reflection
from scanners.csrf_scanner import scan_csrf_tokens
from report_generator import generate_pdf_report
from urllib.parse import urlparse, urlencode
import re
import os
import time

app = Flask(__name__)

def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not re.match(r'^https?://', raw_url, re.I):
        raw_url = 'http://' + raw_url
    return raw_url

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target = request.form.get('target', '').strip()
    if not target:
        return render_template('index.html', error="Please enter a URL.")
    url = normalize_url(target)

    start = time.time()
    ssl_result = check_ssl_issues(url)
    sql_result = scan_sql_injection(url)
    xss_result = scan_xss_reflection(url)
    csrf_result = scan_csrf_tokens(url)
    duration = round(time.time() - start, 2)

    results = {
        'target': url,
        'duration': duration,
        'ssl': ssl_result,
        'sql_injection': sql_result,
        'xss': xss_result,
        'csrf': csrf_result
    }

    # Adding Recommendations for each scan
    results['ssl']['recommendations'] = [
        "Recommendation: Use a valid SSL certificate and ensure the site is using HTTPS.",
        "Recommendation: Regularly update your SSL certificates to avoid expiration."
    ] if results['ssl']['supports_tls'] == 'No' else [
        "Recommendation: Keep your SSL certificate up to date to prevent security risks."
    ]
    
    results['sql_injection']['recommendations'] = [
        "Recommendation: Use prepared statements and parameterized queries to prevent SQL Injection attacks.",
        "Recommendation: Validate all user inputs and sanitize database queries."
    ] if results['sql_injection']['possible'] else [
        "No SQL Injection risk detected. Well done!"
    ]
    
    results['xss']['recommendations'] = [
        "Recommendation: Sanitize all user inputs to prevent XSS attacks.",
        "Recommendation: Use a Content Security Policy (CSP) header to mitigate XSS risks."
    ] if results['xss']['possible'] else [
        "No XSS risk detected. Good job!"
    ]
    
    results['csrf']['recommendations'] = [
        "Recommendation: Ensure all POST forms have a CSRF token to prevent attacks.",
        "Recommendation: Implement SameSite cookies to prevent CSRF attacks."
    ] if results['csrf']['post_forms_without_token'] > 0 else [
        "No CSRF issues detected. Good security practices!"
    ]

    return render_template('results.html', results=results)

@app.route('/report', methods=['POST'])
def report():
    # Expect JSON payload with `results`
    results = request.json.get('results')
    if not results:
        return jsonify({'error': 'No results provided'}), 400

    filepath = generate_pdf_report(results)
    return jsonify({'path': filepath})

if __name__ == '__main__':
    app.run(debug=True)
