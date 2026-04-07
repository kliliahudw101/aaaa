import datetime
import os
import json
import html

def generate_report(target_url, results):
    """Generate professional HTML report with all findings."""
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # HTML-safe target URL
    safe_target = html.escape(target_url)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Deep Recon v5.0 - Report - {html.escape(os.path.basename(target_url))}</title>
    <style>
        body {{ font-family: sans-serif; background: #121212; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1000px; margin: auto; }}
        .section {{ background: #1e1e1e; padding: 20px; border-radius: 8px; margin-bottom: 20px; border-left: 5px solid #00d4ff; }}
        h1, h2 {{ color: #00d4ff; }}
        pre {{ background: #000; padding: 15px; border-radius: 5px; overflow-x: auto; color: #00ff00; font-size: 13px; }}
        .meta {{ color: #888; font-size: 12px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ DEEP RECON v5.0</h1>
        <div class="meta">Target: {safe_target} | Date: {now}</div>
"""
    for key, value in results.items():
        # JSON formatting and HTML escaping
        formatted_value = json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value)
        safe_value = html.escape(formatted_value)

        html_content += f"""
        <div class="section">
            <h2>{html.escape(key.upper())}</h2>
            <pre>{safe_value}</pre>
        </div>
"""

    html_content += """
    </div>
</body>
</html>"""

    filename = f"reports/report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    os.makedirs("reports", exist_ok=True)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filename
