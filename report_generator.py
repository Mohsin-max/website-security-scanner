\
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib import colors
from datetime import datetime
import os
import textwrap
import tempfile

def draw_wrapped_text(c, text, x, y, max_width):
    # simple wrapper on reportlab to wrap text
    lines = []
    wrapper = textwrap.TextWrapper(width=int(max_width/6))  # heuristic characters per line
    for para in text.split('\n'):
        lines.extend(wrapper.wrap(para) if para else [''])
    for line in lines:
        c.drawString(x, y, line)
        y -= 14
    return y

def section(c, title, x, y):
    c.setFont("Helvetica-Bold", 13)
    c.setFillColor(colors.HexColor("#0141a0"))
    c.drawString(x, y, title)
    c.setFillColor(colors.black)
    c.setFont("Helvetica", 11)
    return y - 18

def generate_pdf_report(results: dict) -> str:
    # results contains ssl/sql_injection/xss/csrf keys with dict payloads
    tmpdir = tempfile.gettempdir()
    filename = f"scan-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pdf"
    filepath = os.path.join(tmpdir, filename)

    c = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4
    x_margin = 2*cm
    y = height - 2*cm

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(x_margin, y, "Website Security Scan Report")
    y -= 20
    c.setFont("Helvetica", 10)
    c.drawString(x_margin, y, f"Target: {results.get('target', '')}")
    y -= 14
    c.drawString(x_margin, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 14
    c.drawString(x_margin, y, f"Scan Duration: {results.get('duration', '?')}s")
    y -= 24

    # SSL
    y = section(c, "SSL/TLS", x_margin, y)
    ssl_res = results.get('ssl', {})
    for k, v in ssl_res.items():
        y = draw_wrapped_text(c, f"- {k}: {v}", x_margin, y, width-2*x_margin)
    y -= 10

    # SQLi
    y = section(c, "SQL Injection", x_margin, y)
    sqli = results.get('sql_injection', {})
    for k, v in sqli.items():
        if isinstance(v, list):
            y = draw_wrapped_text(c, f"- {k}: {', '.join(v) if v else 'None'}", x_margin, y, width-2*x_margin)
        else:
            y = draw_wrapped_text(c, f"- {k}: {v}", x_margin, y, width-2*x_margin)
    y -= 10

    # XSS
    y = section(c, "Cross-Site Scripting (XSS)", x_margin, y)
    xss = results.get('xss', {})
    for k, v in xss.items():
        if isinstance(v, list):
            y = draw_wrapped_text(c, f"- {k}: {', '.join(v) if v else 'None'}", x_margin, y, width-2*x_margin)
        else:
            y = draw_wrapped_text(c, f"- {k}: {v}", x_margin, y, width-2*x_margin)
    y -= 10

    # CSRF
    y = section(c, "Cross-Site Request Forgery (CSRF)", x_margin, y)
    csrf = results.get('csrf', {})
    for k, v in csrf.items():
        if isinstance(v, list):
            y = draw_wrapped_text(c, f"- {k}: {', '.join(v) if v else 'None'}", x_margin, y, width-2*x_margin)
        else:
            y = draw_wrapped_text(c, f"- {k}: {v}", x_margin, y, width-2*x_margin)
    y -= 10

    # Footer
    if y < 2*cm:
        c.showPage()
        y = height - 2*cm
    c.setFont("Helvetica-Oblique", 9)
    c.setFillColor(colors.grey)
    c.drawString(x_margin, 1.5*cm, "Educational tool – run scans only where you have permission.")
    c.save()
    return filepath
