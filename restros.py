#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         DEEP RECON v4.0 - Advanced Security Reconnaissance Tool  ║
║              Authorized Penetration Testing Only                 ║
║         فحص عميق - أداة استطلاع أمنية متقدمة                    ║
╚══════════════════════════════════════════════════════════════════╝

A comprehensive multi-phase security reconnaissance script with AI-powered analysis.
Supports bilingual interface (English/Arabic), multiple AI models via Ollama and
OpenRouter.ai, and generates detailed reports (TXT + HTML) with CVE matching.

v4.0 New Features:
    - WHOIS Lookup (Phase 00)
    - HTTP Methods Testing (PUT/DELETE/OPTIONS/TRACE)
    - CORS Misconfiguration Detection
    - Cookie Security Analysis
    - Email Harvesting
    - Wayback Machine URL Discovery
    - Social Media & External Link Extraction
    - Subdomain Takeover Detection
    - Favicon Hash (Shodan Integration)
    - HTML Report Generation
    - Proxy Support (HTTP/SOCKS5)
    - Rate Limiting
    - Proper Thread Safety
    - Logging to File

Requirements:
    pip3 install requests colorama

Usage:
    python3 deep_recon_v4.py
"""

import os
import sys
import re
import json
import socket
import ssl
import subprocess
import shutil
import logging
import datetime
import time
import urllib.parse
import hashlib
import base64
import struct
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from threading import Lock
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] 'requests' module is required. Install with: pip3 install requests")
    sys.exit(1)

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    print("[!] 'colorama' module is required. Install with: pip3 install colorama")
    sys.exit(1)

# Disable InsecureRequestWarning globally
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ═══════════════════════════════════════════════════════════════════
# BILINGUAL STRINGS
# ═══════════════════════════════════════════════════════════════════

STRINGS = {
    "en": {
        "banner": """{cyan}
    ╔══════════════════════════════════════════════════════════════╗
    ║            ██████╗ ███████╗████████╗██████╗  ██████╗ ███████╗ ║
    ║            ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝ ║
    ║            ██████╔╝█████╗     ██║   ██████╔╝██║   ██║███████╗ ║
    ║            ██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║ ║
    ║            ██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝███████║ ║
    ║            ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ║
    ║       Advanced Security Reconnaissance Scanner v4.0          ║
    ║              Authorized Penetration Testing Only              ║
    ╚══════════════════════════════════════════════════════════════╝{reset}""",
        "select_lang": "{yellow}[?] Select Language / اختر اللغة:{reset}",
        "lang_en": "[1] English",
        "lang_ar": "[2] العربية",
        "enter_target": "{yellow}[?] Enter target URL (e.g., https://example.com):{reset} ",
        "invalid_target": "{red}[!] Invalid target URL. Please enter a valid URL.{reset}",
        "select_level": "{yellow}[?] Select scan level:{reset}",
        "quick": "[1] Quick  (whois + headers + fingerprint + dirs) - ~5 min",
        "standard": "[2] Standard  (all except full port + AI) - ~20 min",
        "deep": "[3] Deep  (everything + full port + AI) - ~40 min",
        "custom": "[4] Custom  (user selects phases)",
        "model_type": "{yellow}[?] Select AI model source:{reset}",
        "ollama": "[1] Ollama (Local)",
        "openrouter": "[2] OpenRouter.ai (Cloud API)",
        "both": "[3] Both (Multi-model merge)",
        "skip_ai": "[4] Skip AI Analysis",
        "api_key": "{yellow}[?] Enter OpenRouter API Key (empty for default free model):{reset} ",
        "api_key_invalid": "{red}[!] Invalid API key format.{reset}",
        "detecting_models": "{cyan}[*] Detecting installed Ollama models...{reset}",
        "no_ollama": "{yellow}[!] Ollama not found or not running. Install/start Ollama to use local AI.{reset}",
        "installed_models": "{green}[+] Installed Ollama models:{reset}",
        "select_model": "{yellow}[?] Select model (enter number, or 'q' to finish):{reset} ",
        "model_not_found": "{red}[!] Model '{model}' not found locally!{reset}",
        "model_found": "{green}[+] Model '{model}' found! Use it? (Y/n):{reset} ",
        "pull_model": "{yellow}[?] Model '{model}' not installed. Pull it? (Y/n):{reset} ",
        "pulling_model": "{cyan}[*] Pulling model '{model}'...{reset}",
        "pull_complete": "{green}[+] Model '{model}' pulled successfully!{reset}",
        "pull_failed": "{red}[!] Failed to pull model '{model}'.{reset}",
        "selected_models": "{green}[+] Selected models: {models}{reset}",
        "custom_api_model": "{yellow}[?] Enter OpenRouter model name (e.g., arcee-ai/trinity-large-preview:free):{reset} ",
        "phase": "Phase",
        "starting": "{cyan}[*]{reset} Starting...",
        "completed": "{green}[+] {phase} Completed!{reset}",
        "scanning": "{cyan}[*] {phase}: Scanning...{reset}",
        "error": "{red}[!] Error in {phase}: {err}{reset}",
        "no_results": "{yellow}[!] No results found.{reset}",
        "consolidating": "{cyan}[*] Consolidating all results...{reset}",
        "ai_analyzing": "{cyan}[*] AI analyzing all results...{reset}",
        "multi_model_merge": "{cyan}[*] Multi-model merge in progress...{reset}",
        "round": "Round",
        "model_response": "{green}[+] {model}: Response received ({len} chars){reset}",
        "model_timeout": "{yellow}[!] {model}: Timed out{reset}",
        "model_error": "{red}[!] {model}: {err}{reset}",
        "generating_report": "{cyan}[*] Generating final report...{reset}",
        "generating_html": "{cyan}[*] Generating HTML report...{reset}",
        "done": "{green}╔══════════════════════════════════════════════════╗\n║              SCAN COMPLETED SUCCESSFULLY!                    ║\n╚══════════════════════════════════════════════════════════════╝{reset}",
        "results_dir": "{green}[+] Results saved to: {path}{reset}",
        "consolidated_file": "{green}[+] Consolidated results: {path}{reset}",
        "ai_explanation_file": "{green}[+] AI explanation: {path}{reset}",
        "html_report_file": "{green}[+] HTML report: {path}{reset}",
        "saving_config": "{cyan}[*] Saving scan configuration...{reset}",
        "select_custom_phases": "{yellow}[?] Select phases (comma-separated, e.g., 0,1,3,5 or 'all'):{reset} ",
        "phase_list": """
Available phases:
  [00] WHOIS Lookup (domain registration info)
  [01] Reconnaissance (headers, robots, sitemap, cert, WAF, emails, wayback, social)
  [02] Port Scanning (nmap top 1000 / Python fallback)
  [03] Web Fingerprint (tech detect, security headers, JS files, cookies)
  [04] Directory Discovery (brute force)
  [05] Vulnerability Scanning (XSS, traversal, info disclosure, HTTP methods, CORS)
  [06] API Endpoint Hunting
  [07] SSL/TLS Analysis
  [08] DNS Enumeration + Subdomain Takeover Detection
  [09] CVE Matching (NVD API)
  [10] AI Analysis (Strategic + Exploit Recommendations)
  [11] Final Report (TXT + HTML)
""",
        "warning_auth": """{yellow}
╔══════════════════════════════════════════════════════════════╗
║  WARNING: Authorized Use Only!                              ║
║  This tool is for authorized security testing ONLY.         ║
║  Unauthorized scanning is illegal. Always obtain proper      ║
║  authorization before scanning any target.                   ║
╚══════════════════════════════════════════════════════════════╝{reset}""",
        "continue_prompt": "{yellow}[?] Do you have authorization to test this target? (Y/n):{reset} ",
        "abort": "{red}[!] Scan aborted by user.{reset}",
        "tool_not_found": "{yellow}[!] {tool} not found, using Python fallback{reset}",
        "nmap_found": "{green}[+] nmap found at: {path}{reset}",
        "openssl_found": "{green}[+] openssl found at: {path}{reset}",
        "writing_file": "{dim}[*] Writing: {path}{reset}",
        "progress": "{cyan}[{bar}] {percent}% - {phase}{reset}",
        "total_progress": "\n{green}[■■■■■■■■■■] 100% - All Phases Complete{reset}",
        "no_ai_models": "{yellow}[!] No AI models selected. AI analysis will be skipped.{reset}",
        "api_model_select": """
Available OpenRouter free models:
  [1] arcee-ai/trinity-large-preview:free (Default)
  [2] meta-llama/llama-4-maverick:free
  [3] google/gemma-3-27b-it:free
  [4] mistralai/mistral-small-3.1-24b-instruct:free
  [5] Custom model name
""",
        "select_api_model": "{yellow}[?] Select OpenRouter model (or enter custom name):{reset} ",
        "dns_error": "{red}[!] DNS resolution failed for: {host}{reset}",
        "proxy_config": "{yellow}[?] Use proxy? (enter proxy URL or 'n' to skip):{reset} ",
        "proxy_set": "{green}[+] Proxy configured: {proxy}{reset}",
        "rate_limit": "{yellow}[?] Request delay in seconds (0-5, default 0.1):{reset} ",
        "rate_limit_set": "{green}[+] Rate limit set: {delay}s between requests{reset}",
    },
    "ar": {
        "banner": """{cyan}
    ╔══════════════════════════════════════════════════════════════╗
    ║            ██████╗ ███████╗████████╗██████╗  ██████╗ ███████╗ ║
    ║            ██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝ ║
    ║            ██████╔╝█████╗     ██║   ██████╔╝██║   ██║███████╗ ║
    ║            ██╔══██╗██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║ ║
    ║            ██║  ██║███████╗   ██║   ██║  ██║╚██████╔╝███████║ ║
    ║            ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ║
    ║       ماسح استطلاع أمني متقدم v4.0                            ║
    ║              للاختبار المصرح به فقط                           ║
    ╚══════════════════════════════════════════════════════════════╝{reset}""",
        "select_lang": "{yellow}[?] اختر اللغة / Select Language:{reset}",
        "lang_en": "[1] English",
        "lang_ar": "[2] العربية",
        "enter_target": "{yellow}[?] أدخل رابط الهدف (مثال: https://example.com):{reset} ",
        "invalid_target": "{red}[!] رابط الهدف غير صالح.{reset}",
        "select_level": "{yellow}[?] اختر مستوى الفحص:{reset}",
        "quick": "[1] سريع (whois + رؤوس + بصمة + أدلة) - ~5 دقائق",
        "standard": "[2] قياسي (الكل ما عدا فحص المنافذ الكامل + AI) - ~20 دقيقة",
        "deep": "[3] عميق (الكل + منافذ كاملة + ذكاء اصطناعي) - ~40 دقيقة",
        "custom": "[4] مخصص (اختيار المستخدم للمراحل)",
        "model_type": "{yellow}[?] اختر مصدر نموذج الذكاء الاصطناعي:{reset}",
        "ollama": "[1] Ollama (محلي)",
        "openrouter": "[2] OpenRouter.ai (سحابي)",
        "both": "[3] كلاهما (دمج متعدد النماذج)",
        "skip_ai": "[4] تخطي تحليل الذكاء الاصطناعي",
        "api_key": "{yellow}[?] أدخل مفتاح OpenRouter API (فارغ للنموذج المجاني الافتراضي):{reset} ",
        "api_key_invalid": "{red}[!] صيغة مفتاح API غير صالحة.{reset}",
        "detecting_models": "{cyan}[*] جاري الكشف عن نماذج Ollama المثبتة...{reset}",
        "no_ollama": "{yellow}[!] Ollama غير موجود أو لا يعمل.{reset}",
        "installed_models": "{green}[+] النماذج المثبتة:{reset}",
        "select_model": "{yellow}[?] اختر النموذج (أدخل الرقم، أو 'q' للانتهاء):{reset} ",
        "model_not_found": "{red}[!] النموذج '{model}' غير موجود محلياً!{reset}",
        "model_found": "{green}[+] النموذج '{model}' موجود! هل تريد استخدامه؟ (Y/n):{reset} ",
        "pull_model": "{yellow}[?] النموذج '{model}' غير مثبت. هل تريد تحميله؟ (Y/n):{reset} ",
        "pulling_model": "{cyan}[*] جاري تحميل النموذج '{model}'...{reset}",
        "pull_complete": "{green}[+] تم تحميل النموذج '{model}' بنجاح!{reset}",
        "pull_failed": "{red}[!] فشل تحميل النموذج '{model}'.{reset}",
        "selected_models": "{green}[+] النماذج المختارة: {models}{reset}",
        "custom_api_model": "{yellow}[?] أدخل اسم نموذج OpenRouter:{reset} ",
        "phase": "المرحلة",
        "starting": "{cyan}[*]{reset} جاري البدء...",
        "completed": "{green}[+] {phase} اكتمل!{reset}",
        "scanning": "{cyan}[*] {phase}: جاري الفحص...{reset}",
        "error": "{red}[!] خطأ في {phase}: {err}{reset}",
        "no_results": "{yellow}[!] لم يتم العثور على نتائج.{reset}",
        "consolidating": "{cyan}[*] جاري تجميع جميع النتائج...{reset}",
        "ai_analyzing": "{cyan}[*] الذكاء الاصطناعي يحلل جميع النتائج...{reset}",
        "multi_model_merge": "{cyan}[*] جاري دمج النماذج المتعددة...{reset}",
        "round": "الجولة",
        "model_response": "{green}[+] {model}: تم استلام الرد ({len} حرف){reset}",
        "model_timeout": "{yellow}[!] {model}: انتهت المهلة{reset}",
        "model_error": "{red}[!] {model}: {err}{reset}",
        "generating_report": "{cyan}[*] جاري إنشاء التقرير النهائي...{reset}",
        "generating_html": "{cyan}[*] جاري إنشاء تقرير HTML...{reset}",
        "done": """{green}╔══════════════════════════════════════════════════╗
║              اكتمل الفحص بنجاح!                              ║
╚══════════════════════════════════════════════════════════════╝{reset}""",
        "results_dir": "{green}[+] تم حفظ النتائج في: {path}{reset}",
        "consolidated_file": "{green}[+] النتائج المجمعة: {path}{reset}",
        "ai_explanation_file": "{green}[+] شرح الذكاء الاصطناعي: {path}{reset}",
        "html_report_file": "{green}[+] تقرير HTML: {path}{reset}",
        "saving_config": "{cyan}[*] جاري حفظ إعدادات الفحص...{reset}",
        "select_custom_phases": "{yellow}[?] اختر المراحل (مفصولة بفواصل، مثال: 0,1,3,5 أو 'all'): ",
        "phase_list": """
المراحل المتاحة:
  [00] بحث WHOIS (معلومات تسجيل النطاق)
  [01] الاستطلاع (رؤوس، روابط، خريطة الموقع، شهادات، WAF، بريد، أرشيف، روابط اجتماعية)
  [02] فحص المنافذ (أعلى 1000 منفذ)
  [03] بصمة الويب (اكتشاف التقنيات، رؤوس الأمان، ملفات JS، ملفات تعريف الارتباط)
  [04] اكتشاف الأدلة (قوة brute)
  [05] فحص الثغرات (XSS، اجتياز، إفشاء معلومات، طرق HTTP، CORS)
  [06] اصطياد نقاط API
  [07] تحليل SSL/TLS
  [08] تعداد DNS + كشف استيلاء النطاقات الفرعية
  [09] مطابقة CVE (NVD API)
  [10] تحليل الذكاء الاصطناعي
  [11] التقرير النهائي (TXT + HTML)
""",
        "warning_auth": """{yellow}
╔══════════════════════════════════════════════════════════════╗
║  تحذير: للاستخدام المصرح به فقط!                        ║
║  هذه الأداة للاختبار الأمني المصرح به فقط.                 ║
║  الفحص غير المصرح به غير قانوني.                            ║
╚══════════════════════════════════════════════════════════════╝{reset}""",
        "continue_prompt": "{yellow}[?] هل لديك تصريح لاختبار هذا الهدف؟ (Y/n):{reset} ",
        "abort": "{red}[!] تم إلغاء الفحص من قبل المستخدم.{reset}",
        "tool_not_found": "{yellow}[!] {tool} غير موجود، استخدام البديل Python{reset}",
        "nmap_found": "{green}[+] تم العثور على nmap في: {path}{reset}",
        "openssl_found": "{green}[+] تم العثور على openssl في: {path}{reset}",
        "writing_file": "{dim}[*] جاري الكتابة: {path}{reset}",
        "progress": "{cyan}[{bar}] {percent}% - {phase}{reset}",
        "total_progress": "\n{green}[■■■■■■■■■■] 100% - جميع المراحل مكتملة{reset}",
        "no_ai_models": "{yellow}[!] لم يتم اختيار نماذج ذكاء اصطناعي. سيتم تخطي التحليل.{reset}",
        "api_model_select": """
نماذج OpenRouter المجانية المتاحة:
  [1] arcee-ai/trinity-large-preview:free (افتراضي)
  [2] meta-llama/llama-4-maverick:free
  [3] google/gemma-3-27b-it:free
  [4] mistralai/mistral-small-3.1-24b-instruct:free
  [5] اسم نموذج مخصص
""",
        "select_api_model": "{yellow}[?] اختر نموذج OpenRouter (أو أدخل اسم مخصص):{reset} ",
        "dns_error": "{red}[!] فشل حل DNS لـ: {host}{reset}",
        "proxy_config": "{yellow}[?] استخدام بروكسي؟ (أدخل رابط البروكسي أو 'n' للتخطي): ",
        "proxy_set": "{green}[+] تم تكوين البروكسي: {proxy}{reset}",
        "rate_limit": "{yellow}[?] تأخير الطلبات بالثواني (0-5، الافتراضي 0.1): ",
        "rate_limit_set": "{green}[+] تم تعيين معدل الطلبات: {delay} ثانية بين كل طلب{reset}",
    }
}


# ═══════════════════════════════════════════════════════════════════
# WORDLISTS & CONSTANTS
# ═══════════════════════════════════════════════════════════════════

COMMON_DIRS = [
    "/admin", "/login", "/api", "/backup", "/config", "/db", "/test", "/dev",
    "/staging", "/old", "/tmp", "/uploads", "/files", "/private", "/internal",
    "/debug", "/console", "/manager", "/phpmyadmin", "/wp-admin", "/.git",
    "/.env", "/.htaccess", "/crossdomain.xml", "/server-status", "/server-info",
    "/cgi-bin/", "/wp-content", "/xmlrpc.php", "/soap/", "/rest/", "/graphql",
    "/swagger", "/api-docs", "/v1/", "/v2/", "/adminer.php", "/info.php",
    "/phpinfo.php", "/shell.php", "/cmd.php", "/config.php.bak", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/wp-config.php.bak", "/.svn/", "/.hg/",
    "/.bzr/", "/.git/HEAD", "/.git/config", "/.DS_Store", "/web.config",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
    "/.well-known/security.txt", "/security.txt", "/humans.txt",
    "/robots.txt", "/sitemap.xml", "/favicon.ico",
]

MOODLE_DIRS = [
    "/moodle/", "/lms/", "/course/", "/mod/", "/pluginfile.php", "/webservice/",
    "/admin/", "/user/", "/login/", "/enrol/", "/auth/", "/theme/", "/blocks/",
    "/filter/", "/repository/", "/tag/", "/grade/", "/group/", "/cohort/",
    "/badges/", "/calendar/", "/message/", "/blog/", "/notes/", "/draftfile/",
    "/backup/", "/cache/", "/local/", "/customfield/", "/contentbank/", "/media/",
    "/h5p/", "/question/", "/lti/", "/mod/quiz/", "/mod/assign/", "/mod/forum/",
    "/mod/workshop/", "/mod/chat/", "/mod/choice/", "/mod/data/", "/mod/glossary/",
    "/mod/lesson/", "/mod/scorm/", "/mod/survey/", "/mod/wiki/", "/mod/url/",
    "/mod/page/", "/mod/folder/", "/mod/imscp/", "/mod/label/", "/mod/book/",
    "/mod/resource/", "/mod/lti/", "/mod/hsuforum/", "/mod/ouwiki/",
    "/mod/certificate/", "/mod/customcert/", "/mod/attendance/", "/mod/checklist/",
    "/mod/external-tool/", "/mod/bigbluebuttonbn/", "/mod/booking/",
    "/mod/facetoface/", "/blocks/html/", "/blocks/settings/", "/blocks/navigation/",
    "/admin/tool/", "/admin/settings.php", "/admin/search.php", "/admin/user.php",
    "/admin/uploaduser.php", "/admin/roles/", "/course/category.php", "/enrol/manual/",
    "/auth/ldap/", "/theme/image.php", "/lib/javascript.php", "/pix/", "/help.php",
    "/ajax.php", "/service.php", "/token.php", "/login/signup.php",
    "/login/forgot_password.php", "/login/index.php", "/moodle/file.php",
    "/moodle/draftfile.php", "/filter/tex/mimetex.cgi", "/backup/restore.php",
    "/webservice/rest/server.php", "/webservice/xmlrpc/server.php",
    "/webservice/soap/server.php", "/h5p/embed.php", "/question/bank.php",
    "/mod/quiz/attempt.php", "/mod/quiz/report.php", "/grade/report/grader/",
    "/cohort/assign.php", "/blocks/rss_client/", "/blocks/completion_status/",
    "/blocks/quiz_results/", "/blocks/activity_modules/", "/blocks/login/",
    "/admin/tool/lp/", "/admin/tool/dataprivacy/", "/admin/tool/analytics/",
    "/admin/tool/monitor/", "/admin/tool/task/", "/admin/tool/log/",
    "/course/management.php", "/user/editadvanced.php", "/user/preferences.php",
    "/message/index.php", "/calendar/view.php", "/badges/mybadges.php",
    "/blog/index.php", "/notes/index.php", "/tag/search.php", "/group/index.php",
    "/cohort/index.php",
]

ALL_DIRS = list(dict.fromkeys(COMMON_DIRS + MOODLE_DIRS))

SUBDOMAIN_PREFIXES = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "api", "dev", "staging",
    "test", "admin", "portal", "vpn", "remote", "blog", "forum", "shop",
    "store", "cdn", "static", "media", "images", "img", "assets", "css",
    "js", "app", "m", "mobile", "web", "cloud", "s3", "db", "database",
    "mysql", "postgres", "redis", "elastic", "git", "github", "gitlab",
    "ci", "jenkins", "build", "deploy", "monitor", "grafana", "prometheus",
    "log", "logs", "syslog", "metrics", "status", "health", "ping",
    "backup", "old", "new", "beta", "alpha", "demo", "sandbox", "stage",
    "prod", "production", "internal", "intranet", "wiki", "docs", "doc",
    "help", "support", "crm", "erp", "hr", "auth", "sso", "oauth",
    "login", "signin", "signup", "register", "accounts", "billing",
    "payment", "pay", "checkout", "cart", "order", "tracking", "notify",
    "notification", "email", "newsletter", "news", "feed", "rss", "api2",
    "v2", "v3", "rest", "graphql", "soap", "ws", "wss", "tcp", "udp",
]

# Services known for subdomain takeover vulnerabilities
TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "shopify.com": "Shopify",
    "fastly.net": "Fastly",
    "pantheon.io": "Pantheon",
    "azurewebsites.net": "Azure Web Apps",
    "azurestaticapps.net": "Azure Static Apps",
    "firebaseapp.com": "Firebase",
    "netlify.com": "Netlify",
    "vercel.app": "Vercel",
    "zeit.co": "Vercel (legacy)",
    "wpengine.com": "WP Engine",
    "kinsta.com": "Kinsta",
    "myshopify.com": "Shopify",
    "cloudwaysapps.com": "Cloudways",
    "elasticbeanstalk.com": "AWS Elastic Beanstalk",
    "readthedocs.io": "Read the Docs",
    "surge.sh": "Surge",
    "heroku-dns.com": "Heroku",
    "githubusercontent.com": "GitHub Raw",
    "wp.com": "WordPress.com",
    "fields.azurewebsites.net": "Azure",
    "1.azurestaticapps.net": "Azure Static Apps",
    "us-east-1.elasticbeanstalk.com": "AWS EB",
}

SOCIAL_MEDIA_PATTERNS = {
    "Facebook": [r'facebook\.com', r'fb\.com', r'fb\.me'],
    "Twitter/X": [r'twitter\.com', r'x\.com', r't\.co'],
    "LinkedIn": [r'linkedin\.com'],
    "Instagram": [r'instagram\.com'],
    "YouTube": [r'youtube\.com', r'youtu\.be'],
    "GitHub": [r'github\.com'],
    "GitLab": [r'gitlab\.com'],
    "TikTok": [r'tiktok\.com'],
    "Reddit": [r'reddit\.com'],
    "Discord": [r'discord\.com', r'discord\.gg'],
    "Telegram": [r't\.me', r'telegram\.org'],
    "WhatsApp": [r'wa\.me', r'web\.whatsapp\.com'],
    "Pinterest": [r'pinterest\.com'],
    "Snapchat": [r'snapchat\.com'],
    "Twitch": [r'twitch\.tv'],
    "Medium": [r'medium\.com'],
}

OPENROUTER_FREE_MODELS = {
    "1": "arcee-ai/trinity-large-preview:free",
    "2": "meta-llama/llama-4-maverick:free",
    "3": "google/gemma-3-27b-it:free",
    "4": "mistralai/mistral-small-3.1-24b-instruct:free",
}

OLLAMA_QWEN_MODELS = [
    {"tag": "qwen2.5-coder:0.5b", "size": "397 MB"},
    {"tag": "qwen2.5-coder:1.5b", "size": "986 MB"},
    {"tag": "qwen2.5-coder:latest", "size": "4.7 GB"},
]


# ═══════════════════════════════════════════════════════════════════
# GLOBAL STATE (Thread-Safe)
# ═══════════════════════════════════════════════════════════════════

class GlobalState:
    """Thread-safe global state for the scanner."""
    def __init__(self):
        self.lang = "en"
        self.target_url = ""
        self.target_host = ""
        self.target_scheme = "https"
        self.base_path = ""
        self.scan_level = "standard"
        self.models_config = []
        self.openrouter_api_key = ""
        self.output_dir = ""
        self.output_base = ""
        self.scan_start_time = None
        self.results = {}
        self.nmap_available = False
        self.nmap_path = ""
        self.openssl_available = False
        self.openssl_path = ""
        self.selected_phases = set()
        self.print_lock = Lock()
        self.results_lock = Lock()
        self.proxy = None
        self.proxies = {}
        self.rate_delay = 0.1
        self.logger = None

    def get_results(self):
        """Thread-safe read of results."""
        with self.results_lock:
            return dict(self.results)

    def set_result(self, phase_num, content):
        """Thread-safe write to results."""
        with self.results_lock:
            self.results[phase_num] = self.results.get(phase_num, "") + content

G = GlobalState()

# ═══════════════════════════════════════════════════════════════════
# PHASE NAMES MAP
# ═══════════════════════════════════════════════════════════════════

PHASE_NAMES = {
    0: "whois_lookup",
    1: "reconnaissance",
    2: "port_scanning",
    3: "web_fingerprint",
    4: "directory_discovery",
    5: "vulnerability_scanning",
    6: "api_endpoint_hunting",
    7: "ssl_tls_analysis",
    8: "dns_enumeration",
    9: "cve_matching",
    10: "ai_analysis",
    11: "final_report",
}

PHASE_LABELS_EN = {
    0: "Phase 00: WHOIS Lookup",
    1: "Phase 01: Reconnaissance",
    2: "Phase 02: Port Scanning",
    3: "Phase 03: Web Fingerprint",
    4: "Phase 04: Directory Discovery",
    5: "Phase 05: Vulnerability Scanning",
    6: "Phase 06: API Endpoint Hunting",
    7: "Phase 07: SSL/TLS Analysis",
    8: "Phase 08: DNS Enumeration",
    9: "Phase 09: CVE Matching",
    10: "Phase 10: AI Analysis",
    11: "Phase 11: Final Report",
}

PHASE_LABELS_AR = {
    0: "المرحلة 00: بحث WHOIS",
    1: "المرحلة 01: الاستطلاع",
    2: "المرحلة 02: فحص المنافذ",
    3: "المرحلة 03: بصمة الويب",
    4: "المرحلة 04: اكتشاف الأدلة",
    5: "المرحلة 05: فحص الثغرات",
    6: "المرحلة 06: اصطياد نقاط API",
    7: "المرحلة 07: تحليل SSL/TLS",
    8: "المرحلة 08: تعداد DNS",
    9: "المرحلة 09: مطابقة CVE",
    10: "المرحلة 10: تحليل الذكاء الاصطناعي",
    11: "المرحلة 11: التقرير النهائي",
}


# ═══════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def t(key, **kwargs):
    """Get translated string with formatting."""
    lang = getattr(G, 'lang', 'en')
    s = STRINGS.get(lang, STRINGS["en"]).get(key, STRINGS["en"].get(key, key))
    try:
        return s.format(cyan=Fore.CYAN, green=Fore.GREEN, yellow=Fore.YELLOW,
                        red=Fore.RED, blue=Fore.BLUE, magenta=Fore.MAGENTA,
                        dim=Style.DIM, bold=Style.BRIGHT, reset=Style.RESET_ALL,
                        **kwargs)
    except (KeyError, IndexError):
        return s


def safe_print(msg, **kwargs):
    """Thread-safe print."""
    with G.print_lock:
        print(msg, **kwargs)


def log_debug(msg):
    """Log debug message."""
    if G.logger:
        G.logger.debug(msg)

def log_info(msg):
    """Log info message."""
    if G.logger:
        G.logger.info(msg)

def log_warning(msg):
    """Log warning message."""
    if G.logger:
        G.logger.warning(msg)

def log_error(msg):
    """Log error message."""
    if G.logger:
        G.logger.error(msg)


def rate_sleep():
    """Apply rate limiting delay."""
    if G.rate_delay > 0:
        time.sleep(G.rate_delay)


def progress_bar(percent, phase_name="", width=30):
    """Display a progress bar."""
    filled = int(width * percent / 100)
    bar = "■" * filled + "□" * (width - filled)
    pbar = t("progress", bar=bar, percent=percent, phase=phase_name)
    safe_print(f"\r{pbar}", end="")
    if percent >= 100:
        safe_print("")


def get_timestamp():
    """Get current timestamp in multiple formats."""
    now = datetime.datetime.now()
    return {
        "iso": now.isoformat(),
        "file": now.strftime("%Y%m%d_%H%M%S"),
        "readable": now.strftime("%Y-%m-%d %H:%M:%S"),
    }


def phase_label(num):
    """Get localized phase label."""
    if G.lang == "ar":
        return PHASE_LABELS_AR.get(num, f"المرحلة {num:02d}")
    return PHASE_LABELS_EN.get(num, f"Phase {num:02d}")


def make_tool_header(tool_name, command=""):
    """Create standardized file header."""
    ts = get_timestamp()["readable"]
    lines = [
        "=" * 63,
        f"Tool: {tool_name}",
        f"Timestamp: {ts}",
        f"Target: {G.target_url}",
    ]
    if command:
        lines.append(f"Command: {command}")
    lines.append("=" * 63)
    return "\n".join(lines)


def write_result(phase_num, filename, content, tool_name, command=""):
    """Write scan result to the appropriate file (thread-safe)."""
    header = make_tool_header(tool_name, command)
    full_content = f"{header}\n{content}\n"
    ts = get_timestamp()["file"]
    phase_dir = os.path.join(G.output_dir, f"{phase_num:02d}_{PHASE_NAMES[phase_num]}")
    os.makedirs(phase_dir, exist_ok=True)
    filepath = os.path.join(phase_dir, f"{ts}_{filename}")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(full_content)
    except OSError as e:
        log_error(f"Failed to write {filepath}: {e}")
    G.set_result(phase_num, full_content + "\n")
    safe_print(t("writing_file", path=filepath))
    log_info(f"Wrote {filename} for phase {phase_num}")
    return filepath


def write_raw(filename, content):
    """Write raw data to raw_data folder."""
    raw_dir = os.path.join(G.output_dir, "raw_data")
    os.makedirs(raw_dir, exist_ok=True)
    filepath = os.path.join(raw_dir, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as e:
        log_error(f"Failed to write raw file {filepath}: {e}")
    return filepath


def resolve_host():
    """Resolve target hostname to IP."""
    try:
        ip = socket.gethostbyname(G.target_host)
        return ip
    except socket.gaierror:
        safe_print(t("dns_error", host=G.target_host))
        return "0.0.0.0"


def http_request(method, url, timeout=15, allow_redirects=True, headers=None, data=None):
    """Make HTTP request with error handling, proxy, and rate limiting.
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE, OPTIONS, TRACE, PATCH, HEAD)
        url: Target URL
        timeout: Request timeout in seconds
        allow_redirects: Follow redirects
        headers: Additional headers dict
        data: Request body (for POST/PUT/PATCH)
    
    Returns:
        requests.Response or None
    """
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    if headers:
        default_headers.update(headers)
    
    rate_sleep()
    
    try:
        resp = requests.request(
            method=method,
            url=url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            headers=default_headers,
            verify=False,
            proxies=G.proxies,
            data=data,
        )
        return resp
    except requests.exceptions.ConnectionError as e:
        log_warning(f"Connection error for {url}: {e}")
        return None
    except requests.exceptions.Timeout:
        log_warning(f"Timeout for {url}")
        return None
    except requests.exceptions.TooManyRedirects:
        log_warning(f"Too many redirects for {url}")
        return None
    except Exception as e:
        log_error(f"Request error for {url}: {e}")
        return None


def http_get(url, timeout=15, allow_redirects=True, headers=None):
    """Make HTTP GET request."""
    return http_request("GET", url, timeout, allow_redirects, headers)


def http_head(url, timeout=10, allow_redirects=False, headers=None):
    """Make HTTP HEAD request."""
    return http_request("HEAD", url, timeout, allow_redirects, headers)


def http_options(url, timeout=10, headers=None):
    """Make HTTP OPTIONS request."""
    return http_request("OPTIONS", url, timeout, False, headers)


def http_trace(url, timeout=10, headers=None):
    """Make HTTP TRACE request."""
    return http_request("TRACE", url, timeout, False, headers)


def compute_murmurhash(data):
    """Compute Favicon MurmurHash for Shodan lookups."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    # Use mmh3-like hash via FNV then format as signed int32
    # This is a simplified version; for exact mmh3, use pymmh3 library
    import hashlib
    md5_hash = hashlib.md5(data).hexdigest()
    # Convert to a Shodan-compatible hash format
    h = int(md5_hash[:8], 16)
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def setup_logging(output_dir):
    """Configure logging to file."""
    log_file = os.path.join(output_dir, "scan.log")
    logger = logging.getLogger("deep_recon")
    logger.setLevel(logging.DEBUG)
    
    # File handler
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    
    # Console handler (warnings only)
    ch = logging.StreamHandler()
    ch.setLevel(logging.WARNING)
    ch.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    G.logger = logger
    return logger


# ═══════════════════════════════════════════════════════════════════
# AI MODEL FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def call_ollama(model_name, prompt, timeout=30):
    """Call local Ollama model via subprocess."""
    try:
        result = subprocess.run(
            ["ollama", "run", model_name],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout.strip()
        if output:
            return output
        if result.stderr:
            err = result.stderr.strip()
            if "error" in err.lower():
                return f"ERROR: {err}"
        return "ERROR: No output from model"
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: Model timed out after {timeout}s"
    except FileNotFoundError:
        return "ERROR: Ollama not found. Is it installed and running?"
    except Exception as e:
        return f"ERROR: {str(e)}"


def call_openrouter(api_key, model, prompt, timeout=30):
    """Call OpenRouter.ai API model."""
    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}" if api_key else "",
                "Content-Type": "application/json",
                "HTTP-Referer": "https://deep-recon.security.local",
                "X-Title": "Deep Recon Scanner v4.0",
            },
            json={
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a senior cybersecurity penetration testing expert. "
                                  "Provide detailed, actionable security analysis. "
                                  "Always include specific CVE numbers when applicable. "
                                  "Structure your response with clear headings and bullet points."
                    },
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 4096,
                "temperature": 0.3,
            },
            timeout=timeout + 10,
            verify=False,
            proxies=G.proxies,
        )
        data = response.json()
        if "choices" in data and data["choices"]:
            return data["choices"][0]["message"]["content"]
        elif "error" in data:
            return f"ERROR: {data['error']}"
        return f"ERROR: Unexpected response: {json.dumps(data)[:500]}"
    except requests.exceptions.Timeout:
        return f"TIMEOUT: API request timed out after {timeout + 10}s"
    except Exception as e:
        return f"ERROR: {str(e)}"


def call_model(model_cfg, prompt, timeout=30):
    """Call a model based on its configuration."""
    if model_cfg["type"] == "ollama":
        return call_ollama(model_cfg["model"], prompt, timeout)
    elif model_cfg["type"] == "openrouter":
        return call_openrouter(G.openrouter_api_key, model_cfg["model"], prompt, timeout)
    return "ERROR: Unknown model type"


def multi_model_merge(prompt, rounds=2, timeout_per_model=30):
    """Multi-model merge chat system with consensus rounds."""
    if not G.models_config:
        return {"error": "No models configured"}

    safe_print(t("multi_model_merge"))
    log_info("Starting multi-model merge analysis")

    # Round 1: Get initial responses from all models simultaneously
    responses = {}
    safe_print(f"  {Fore.CYAN}[*] {t('round')} 1/{rounds}: Gathering initial responses...{Style.RESET_ALL}")

    with ThreadPoolExecutor(max_workers=len(G.models_config)) as executor:
        future_to_model = {}
        for model_cfg in G.models_config:
            future = executor.submit(call_model, model_cfg, prompt, timeout_per_model)
            future_to_model[future] = model_cfg

        for future in as_completed(future_to_model, timeout=timeout_per_model + 5):
            model_cfg = future_to_model[future]
            name = model_cfg["name"]
            try:
                result = future.result(timeout=timeout_per_model + 5)
                if result.startswith("TIMEOUT"):
                    safe_print(t("model_timeout", model=name))
                elif result.startswith("ERROR"):
                    safe_print(t("model_error", model=name, err=result.split(":", 1)[1].strip() if ":" in result else result))
                else:
                    safe_print(t("model_response", model=name, len=len(result)))
                responses[name] = result
            except FuturesTimeoutError:
                safe_print(t("model_timeout", model=name))
                responses[name] = f"TIMEOUT: Model did not respond within {timeout_per_model}s"
            except Exception as e:
                safe_print(t("model_error", model=name, err=str(e)))
                responses[name] = f"ERROR: {str(e)}"

    # Consensus rounds
    for round_num in range(2, rounds + 1):
        safe_print(f"  {Fore.CYAN}[*] {t('round')} {round_num}/{rounds}: Seeking consensus...{Style.RESET_ALL}")
        log_info(f"Consensus round {round_num}/{rounds}")

        combined = "\n\n".join(
            [f"[{name}]:\n{resp}" for name, resp in responses.items()]
        )
        consensus_prompt = (
            f"Previous analysis from {len(responses)} security expert models:\n\n"
            f"{combined}\n\n"
            f"As a senior security analyst, review all the above analyses and provide "
            f"your refined, consolidated assessment. Resolve any disagreements between models. "
            f"Provide the definitive consensus analysis with:\n"
            f"1. Confirmed findings (all models agree)\n"
            f"2. Probable findings (most models agree)\n"
            f"3. Possible findings (some models suggest)\n"
            f"4. Risk rating for each finding\n"
            f"5. Recommended actions"
        )

        new_responses = {}
        with ThreadPoolExecutor(max_workers=len(G.models_config)) as executor:
            future_to_model = {}
            for model_cfg in G.models_config:
                future = executor.submit(call_model, model_cfg, consensus_prompt, timeout_per_model)
                future_to_model[future] = model_cfg

            for future in as_completed(future_to_model, timeout=timeout_per_model + 5):
                model_cfg = future_to_model[future]
                name = model_cfg["name"]
                try:
                    result = future.result(timeout=timeout_per_model + 5)
                    if result.startswith("TIMEOUT"):
                        safe_print(t("model_timeout", model=name))
                    else:
                        safe_print(t("model_response", model=name, len=len(result)))
                    new_responses[name] = result
                except FuturesTimeoutError:
                    safe_print(t("model_timeout", model=name))
                    new_responses[name] = f"TIMEOUT: Consensus round timed out"
                except Exception as e:
                    safe_print(t("model_error", model=name, err=str(e)))
                    new_responses[name] = f"ERROR: {str(e)}"

        responses = new_responses

    return responses


# ═══════════════════════════════════════════════════════════════════
# PHASE 00: WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════════

def phase_00_whois():
    """Phase 00: WHOIS Lookup - Domain registration information."""
    plabel = phase_label(0)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)
    whois_output = f"WHOIS Lookup for {G.target_host}\n"
    whois_output += "=" * 63 + "\n\n"

    # Try whois command
    whois_path = shutil.which("whois")
    if whois_path:
        safe_print(f"  {Fore.CYAN}[*] Running WHOIS lookup via command...{Style.RESET_ALL}")
        try:
            result = subprocess.run(
                ["whois", G.target_host],
                capture_output=True, text=True, timeout=30
            )
            whois_data = result.stdout
            if result.stderr:
                whois_data += "\n\nSTDERR:\n" + result.stderr
            
            # Extract key info
            whois_output += "--- Raw WHOIS Data ---\n"
            whois_output += whois_data[:5000] + ("\n[... TRUNCATED ...]\n" if len(whois_data) > 5000 else "")
            
            # Extract structured info
            whois_output += "\n\n--- Extracted Information ---\n"
            extract_fields = [
                ("Registrar", r'Registrar\s*:\s*(.+)'),
                ("Creation Date", r'Creation Date\s*:\s*(.+)'),
                ("Registry Expiry Date", r'Registry Expiry Date\s*:\s*(.+)'),
                ("Updated Date", r'Updated Date\s*:\s*(.+)'),
                ("Name Server", r'Name Server\s*:\s*(.+)'),
                ("Domain Status", r'Domain Status\s*:\s*(.+)'),
                ("Registrant Organization", r'Registrant Organization\s*:\s*(.+)'),
                ("Registrant Country", r'Registrant Country\s*:\s*(.+)'),
                ("Registrant Email", r'Registrant Email\s*:\s*(.+)'),
                ("DNSSEC", r'DNSSEC\s*:\s*(.+)'),
            ]
            
            for field_name, pattern in extract_fields:
                matches = re.findall(pattern, whois_data, re.IGNORECASE)
                if matches:
                    whois_output += f"  {field_name}: {', '.join(set(m.strip() for m in matches))}\n"
            
            # Check domain age
            creation_match = re.search(r'Creation Date\s*:\s*(.+)', whois_data, re.IGNORECASE)
            if creation_match:
                try:
                    # Try common date formats
                    date_str = creation_match.group(1).strip()
                    for fmt in ["%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%d-%b-%Y", "%Y-%m-%d"]:
                        try:
                            creation_date = datetime.datetime.strptime(date_str[:25], fmt)
                            age_days = (datetime.datetime.now() - creation_date).days
                            whois_output += f"\n  Domain Age: ~{age_days} days ({age_days // 365} years)\n"
                            break
                        except ValueError:
                            continue
                except Exception:
                    pass

            write_result(0, "whois_lookup.txt", whois_output, "WHOIS",
                         f"whois {G.target_host}")
            log_info("WHOIS lookup completed via command")
            
        except subprocess.TimeoutExpired:
            whois_output += "\nWHOIS command timed out after 30 seconds.\n"
            write_result(0, "whois_lookup.txt", whois_output, "WHOIS", "Timed out")
        except Exception as e:
            whois_output += f"\nWHOIS error: {str(e)}\n"
            write_result(0, "whois_lookup.txt", whois_output, "WHOIS", f"Error: {e}")
    else:
        # Python fallback - use online WHOIS API
        safe_print(f"  {Fore.YELLOW}[!] whois command not found, using online API...{Style.RESET_ALL}")
        try:
            api_url = f"https://whoisjson.com/api/v1/whois?domain={G.target_host}"
            resp = requests.get(api_url, timeout=15, verify=False, proxies=G.proxies)
            if resp and resp.status_code == 200:
                data = resp.json()
                whois_output += json.dumps(data, indent=2, ensure_ascii=False)
            else:
                # Try another API
                api_url2 = f"https://whois-api.whoisxmlapi.com/api/v1?domainName={G.target_host}&outputFormat=JSON"
                resp2 = requests.get(api_url2, timeout=15, verify=False, proxies=G.proxies)
                if resp2 and resp2.status_code == 200:
                    data = resp2.json()
                    whois_output += json.dumps(data, indent=2, ensure_ascii=False)
                else:
                    whois_output += "Could not retrieve WHOIS data from online APIs.\n"
        except Exception as e:
            whois_output += f"Online WHOIS API error: {str(e)}\n"
        
        write_result(0, "whois_lookup.txt", whois_output, "WHOIS API", "Online lookup")

    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return whois_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 01: RECONNAISSANCE (Enhanced)
# ═══════════════════════════════════════════════════════════════════

def phase_01_reconnaissance():
    """Phase 01: Enhanced Reconnaissance - HTTP headers, robots, sitemap, cert, WAF,
    email harvesting, wayback machine, social media links, favicon hash."""
    plabel = phase_label(1)
    safe_print(t("scanning", phase=plabel))
    progress_bar(5, plabel)
    output_lines = []

    # 1. HTTP Headers
    safe_print(f"  {Fore.CYAN}[*] Fetching HTTP headers...{Style.RESET_ALL}")
    resp = http_get(G.target_url, timeout=15)
    if resp:
        headers_output = f"HTTP Status: {resp.status_code}\n\n"
        for k, v in resp.headers.items():
            headers_output += f"{k}: {v}\n"
        write_result(1, "http_headers.txt", headers_output, "Python requests",
                     f"GET {G.target_url}")
        output_lines.append(headers_output)
    else:
        safe_print(f"  {Fore.YELLOW}[!] Could not fetch HTTP headers{Style.RESET_ALL}")
        output_lines.append("HTTP headers: Could not fetch\n")
    progress_bar(15, plabel)

    # 2. robots.txt
    safe_print(f"  {Fore.CYAN}[*] Checking robots.txt...{Style.RESET_ALL}")
    robots_url = f"{G.target_url.rstrip('/')}/robots.txt"
    robots_resp = http_get(robots_url, timeout=10)
    if robots_resp and robots_resp.status_code == 200:
        robots_content = robots_resp.text
    else:
        robots_content = "robots.txt not found or not accessible."
    write_result(1, "robots_txt.txt", robots_content, "Python requests", f"GET {robots_url}")
    output_lines.append(f"\n--- robots.txt ---\n{robots_content}")
    progress_bar(25, plabel)

    # 3. sitemap.xml
    safe_print(f"  {Fore.CYAN}[*] Checking sitemap.xml...{Style.RESET_ALL}")
    sitemap_url = f"{G.target_url.rstrip('/')}/sitemap.xml"
    sitemap_resp = http_get(sitemap_url, timeout=10)
    if sitemap_resp and sitemap_resp.status_code == 200:
        sitemap_content = sitemap_resp.text[:10000]
    else:
        sitemap_content = "sitemap.xml not found or not accessible."
    write_result(1, "sitemap_xml.txt", sitemap_content, "Python requests", f"GET {sitemap_url}")
    output_lines.append(f"\n--- sitemap.xml ---\n{sitemap_content}")
    progress_bar(35, plabel)

    # 4. Certificate Transparency (crt.sh)
    safe_print(f"  {Fore.CYAN}[*] Querying certificate transparency (crt.sh)...{Style.RESET_ALL}")
    try:
        cert_url = f"https://crt.sh/?q=%.{G.target_host}&output=json"
        cert_resp = requests.get(cert_url, timeout=20, verify=False, proxies=G.proxies)
        if cert_resp and cert_resp.status_code == 200:
            cert_data = cert_resp.json()
            cert_output = f"Found {len(cert_data)} certificates\n\n"
            seen = set()
            for cert in cert_data:
                name = cert.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip()
                    if n and n not in seen:
                        seen.add(n)
                        cert_output += f"  - {n}\n"
        else:
            cert_output = "Could not query crt.sh API."
    except Exception as e:
        cert_output = f"Error querying crt.sh: {str(e)}"
    write_result(1, "cert_transparency.txt", cert_output, "crt.sh API",
                 f"GET {cert_url}")
    output_lines.append(f"\n--- Certificate Transparency ---\n{cert_output}")
    progress_bar(50, plabel)

    # 5. WAF Detection
    safe_print(f"  {Fore.CYAN}[*] Detecting WAF...{Style.RESET_ALL}")
    waf_output = "WAF Detection Results:\n\n"
    if resp:
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body_lower = resp.text.lower() if resp.text else ""

        waf_signatures = {
            "Cloudflare": ["cf-ray", "__cfduid", "cloudflare", "_cf_bm"],
            "AWS WAF": ["awselb", "awswaf", "x-amzn-requestid"],
            "Akamai": ["akamai", "x-akamai", "x-cache-remote"],
            "Imperva/Incapsula": ["x-iinfo", "incap_ses", "visid_incap"],
            "Sucuri": ["x-sucuri-id", "sucuri"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "F5 BIG-IP": ["bigip", "f5", "bip"],
            "Citrix": ["ns_af", "citrix_ns_id", "via: ns"],
            "Barracuda": ["bnmsg", "barracuda"],
            "Fortinet": ["fortigate", "fortiweb"],
            "Azure WAF": ["x-azure-ref", "x-ms-request-id"],
            "Google Cloud": ["gws", "s-frontrun-prod"],
        }

        waf_detected = []
        for waf_name, sigs in waf_signatures.items():
            for sig in sigs:
                if sig.lower() in headers_lower or sig.lower() in body_lower:
                    waf_detected.append(waf_name)
                    break

        if waf_detected:
            waf_output += f"DETECTED WAF(s): {', '.join(waf_detected)}\n\n"
            for waf in waf_detected:
                waf_output += f"  [+] {waf}\n"
                for sig in waf_signatures[waf]:
                    if sig.lower() in headers_lower:
                        waf_output += f"      Header match: {sig}\n"
                    if sig.lower() in body_lower:
                        waf_output += f"      Body match: {sig}\n"
        else:
            waf_output += "No WAF detected.\n"
    else:
        waf_output += "Could not determine WAF status.\n"

    write_result(1, "waf_detection.txt", waf_output, "WAF Signature Analysis", "Header/body analysis")
    output_lines.append(f"\n--- WAF Detection ---\n{waf_output}")
    progress_bar(65, plabel)

    # 6. Email Harvesting (NEW)
    safe_print(f"  {Fore.CYAN}[*] Harvesting emails from page...{Style.RESET_ALL}")
    email_output = "Email Harvesting Results:\n\n"
    emails_found = set()
    
    if resp and resp.text:
        # Extract from main page
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        emails_found.update(re.findall(email_pattern, resp.text))
    
    # Extract from robots.txt
    if robots_content:
        emails_found.update(re.findall(email_pattern, robots_content))
    
    # Extract from sitemap
    if sitemap_content:
        emails_found.update(re.findall(email_pattern, sitemap_content))
    
    if emails_found:
        email_output += f"Found {len(emails_found)} unique email(s):\n\n"
        for email in sorted(emails_found):
            email_output += f"  - {email}\n"
        
        # Categorize
        admin_emails = [e for e in emails_found if any(w in e.lower() for w in ['admin', 'info', 'support', 'help', 'contact', 'security'])]
        generic_emails = [e for e in emails_found if any(w in e.split('@')[0].lower() for w in ['noreply', 'no-reply', 'mailer', 'notification'])]
        personal_emails = list(set(emails_found) - set(admin_emails) - set(generic_emails))
        
        email_output += f"\nCategories:\n"
        if admin_emails:
            email_output += f"  Admin/Support ({len(admin_emails)}): {', '.join(sorted(admin_emails))}\n"
        if generic_emails:
            email_output += f"  Generic/System ({len(generic_emails)}): {', '.join(sorted(generic_emails))}\n"
        if personal_emails:
            email_output += f"  Personal ({len(personal_emails)}): {', '.join(sorted(personal_emails))}\n"
    else:
        email_output += "No email addresses found.\n"
    
    write_result(1, "emails_harvested.txt", email_output, "Email Harvester", "Regex extraction")
    output_lines.append(f"\n--- Emails ---\n{email_output}")
    progress_bar(75, plabel)

    # 7. Wayback Machine URLs (NEW)
    safe_print(f"  {Fore.CYAN}[*] Querying Wayback Machine...{Style.RESET_ALL}")
    wayback_output = "Wayback Machine URL Discovery:\n\n"
    try:
        wayback_api = f"http://web.archive.org/cdx/search/cdx?url={G.target_host}/*&output=json&limit=100&fl=original"
        wb_resp = requests.get(wayback_api, timeout=20, verify=False, proxies=G.proxies)
        if wb_resp and wb_resp.status_code == 200:
            wb_data = wb_resp.json()
            if len(wb_data) > 1:
                urls = [row[0] for row in wb_data[1:]]  # Skip header
                unique_urls = sorted(set(urls))
                wayback_output += f"Found {len(unique_urls)} unique archived URLs:\n\n"
                for u in unique_urls[:50]:
                    wayback_output += f"  - {u}\n"
                if len(unique_urls) > 50:
                    wayback_output += f"\n  ... and {len(unique_urls) - 50} more URLs\n"
            else:
                wayback_output += "No archived URLs found.\n"
        else:
            wayback_output += "Could not query Wayback Machine API.\n"
    except Exception as e:
        wayback_output += f"Wayback Machine error: {str(e)}\n"
    write_result(1, "wayback_urls.txt", wayback_output, "Wayback Machine", "CDX API query")
    output_lines.append(f"\n--- Wayback Machine ---\n{wayback_output}")
    progress_bar(85, plabel)

    # 8. Social Media & External Links (NEW)
    safe_print(f"  {Fore.CYAN}[*] Extracting social media links...{Style.RESET_ALL}")
    social_output = "Social Media & External Links:\n\n"
    
    if resp and resp.text:
        html = resp.text
        
        # Extract social media links
        social_found = {}
        for platform, patterns in SOCIAL_MEDIA_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(rf'(https?://[^\s"\'<>]*{pattern}[^\s"\'<>]*)', html, re.IGNORECASE)
                if matches:
                    social_found[platform] = sorted(set(matches))
        
        if social_found:
            social_output += f"Social Media Found ({len(social_found)} platforms):\n\n"
            for platform, urls in sorted(social_found.items()):
                social_output += f"  {platform}:\n"
                for url in urls[:3]:
                    social_output += f"    - {url}\n"
                if len(urls) > 3:
                    social_output += f"    ... and {len(urls) - 3} more\n"
        else:
            social_output += "No social media links found.\n"
        
        # External links
        external_links = set()
        ext_pattern = r'href=["\'](https?://(?!' + re.escape(G.target_host) + r')[^\s"\'<>]+)["\']'
        external_links.update(re.findall(ext_pattern, html))
        
        if external_links:
            social_output += f"\nExternal Links ({len(external_links)}):\n\n"
            for link in sorted(external_links)[:30]:
                social_output += f"  - {link}\n"
            if len(external_links) > 30:
                social_output += f"\n  ... and {len(external_links) - 30} more\n"
    
    write_result(1, "social_links.txt", social_output, "Link Extractor", "Regex from HTML")
    output_lines.append(f"\n--- Social/External Links ---\n{social_output}")
    progress_bar(92, plabel)

    # 9. Favicon Hash (NEW - Shodan)
    safe_print(f"  {Fore.CYAN}[*] Computing Favicon hash...{Style.RESET_ALL}")
    favicon_output = "Favicon Hash Analysis:\n\n"
    favicon_url = f"{G.target_url.rstrip('/')}/favicon.ico"
    favicon_resp = http_get(favicon_url, timeout=10)
    if favicon_resp and favicon_resp.status_code == 200 and len(favicon_resp.content) > 0:
        favicon_hash = compute_murmurhash(favicon_resp.content)
        favicon_output += f"Favicon URL: {favicon_url}\n"
        favicon_output += f"Favicon Size: {len(favicon_resp.content)} bytes\n"
        favicon_output += f"Favicon Hash: {favicon_hash}\n"
        favicon_output += f"\nShodan Search Query:\n"
        favicon_output += f"  http.favicon.hash:{abs(favicon_hash)}\n"
        # Also compute base64 encoded for Shodan
        b64 = base64.b64encode(favicon_resp.content).decode()
        favicon_output += f"\nFavicon Base64 (first 100 chars): {b64[:100]}...\n"
    else:
        favicon_output += "Could not retrieve favicon.ico\n"
    write_result(1, "favicon_hash.txt", favicon_output, "Favicon Hash", "MurmurHash computation")
    output_lines.append(f"\n--- Favicon Hash ---\n{favicon_output}")

    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return "\n".join(output_lines)


# ═══════════════════════════════════════════════════════════════════
# PHASE 02: PORT SCANNING
# ═══════════════════════════════════════════════════════════════════

def python_port_scan(common_only=False, max_threads=100):
    """Python-based port scanner fallback."""
    output_lines = [f"Python Port Scan Results for {G.target_host}\n"]
    output_lines.append(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<15}\n")
    output_lines.append("-" * 35)

    if common_only:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888,
                 9090, 27017, 6379, 9200, 9300, 11211, 15672, 2181, 5000,
                 3000, 4000, 4443, 5431, 5984, 6443, 7474, 7687, 8000, 8081,
                 8181, 8484, 8880, 9000, 9091, 9200, 9500, 10000, 11300,
                 50000, 50070]
    else:
        ports = list(range(1, 1025))

    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 6379: "Redis",
        9200: "Elasticsearch", 27017: "MongoDB", 11211: "Memcached",
        5000: "Flask/Dev", 3000: "Node.js/Dev", 4000: "Dev",
        8000: "Django/Dev", 8888: "HTTP-Alt", 9090: "Prometheus/Proxy",
        15672: "RabbitMQ-Mgmt", 2181: "Zookeeper", 6443: "Kubernetes API",
        7474: "Neo4j", 7687: "Neo4j Bolt", 9300: "Elasticsearch Transport",
    }

    open_ports = []
    lock = Lock()

    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)  # Increased from 2 to 3
            result = sock.connect_ex((G.target_host, port))
            sock.close()
            if result == 0:
                with lock:
                    open_ports.append(port)
        except Exception:
            pass

    safe_print(f"  {Fore.CYAN}[*] Scanning {len(ports)} ports with {max_threads} threads...{Style.RESET_ALL}")
    log_info(f"Port scan started: {len(ports)} ports")

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        list(executor.map(scan_port, ports))

    open_ports.sort()
    for port in open_ports:
        svc = services.get(port, "Unknown")
        output_lines.append(f"{port:<10}{'open':<10}{svc:<15}")

    output_lines.append(f"\nTotal open ports found: {len(open_ports)}")
    log_info(f"Port scan complete: {len(open_ports)} open ports found")
    return "\n".join(output_lines)


def phase_02_port_scanning(full=False):
    """Phase 02: Port Scanning."""
    plabel = phase_label(2)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)

    nmap_path = shutil.which("nmap")
    G.nmap_available = nmap_path is not None
    G.nmap_path = nmap_path or ""

    if G.nmap_available:
        safe_print(t("nmap_found", path=nmap_path))
    else:
        safe_print(t("tool_not_found", tool="nmap"))

    # Top 1000 ports scan
    safe_print(f"  {Fore.CYAN}[*] Scanning top 1000 ports...{Style.RESET_ALL}")
    top1000_output = ""

    if G.nmap_available:
        try:
            cmd = ["nmap", "-sV", "-sC", "--top-ports", "1000", "-T4", G.target_host]
            safe_print(f"  {Fore.DIM}[*] Running: {' '.join(cmd)}{Style.RESET_ALL}")
            log_info(f"Running nmap: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            top1000_output = result.stdout
            if result.stderr:
                top1000_output += f"\n\nSTDERR:\n{result.stderr}"
        except subprocess.TimeoutExpired:
            top1000_output = "Nmap scan timed out after 300 seconds."
        except Exception as e:
            top1000_output = f"Nmap error: {str(e)}"
    else:
        top1000_output = python_port_scan(common_only=True)

    write_result(2, "port_scan.txt", top1000_output,
                 "nmap" if G.nmap_available else "Python socket",
                 "nmap -sV -sC --top-ports 1000" if G.nmap_available else "Python socket scan")
    progress_bar(50, plabel)

    # Full port scan (only in Deep mode)
    if full and G.nmap_available:
        safe_print(f"  {Fore.CYAN}[*] Running full 65535 port scan...{Style.RESET_ALL}")
        try:
            cmd = ["nmap", "-sV", "-p-", "-T4", "--min-rate", "1000", G.target_host]
            safe_print(f"  {Fore.DIM}[*] Running: {' '.join(cmd)}{Style.RESET_ALL}")
            log_info(f"Running full nmap scan")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            full_output = result.stdout
            if result.stderr:
                full_output += f"\n\nSTDERR:\n{result.stderr}"
        except subprocess.TimeoutExpired:
            full_output = "Full port scan timed out after 600 seconds."
        except Exception as e:
            full_output = f"Full port scan error: {str(e)}"
        write_result(2, "full_port_scan.txt", full_output, "nmap", "nmap -sV -p- -T4")
    elif full and not G.nmap_available:
        safe_print(f"  {Fore.YELLOW}[!] Full port scan requires nmap. Skipping.{Style.RESET_ALL}")

    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return top1000_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 03: WEB FINGERPRINT (Enhanced with Cookie Analysis)
# ═══════════════════════════════════════════════════════════════════

def phase_03_web_fingerprint():
    """Phase 03: Web Fingerprint - Technology detection, security headers, JS files, Cookie analysis."""
    plabel = phase_label(3)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)
    output_lines = []

    resp = http_get(G.target_url, timeout=15)
    if not resp:
        safe_print(f"  {Fore.RED}[!] Cannot fetch target for fingerprinting{Style.RESET_ALL}")
        progress_bar(100, plabel)
        return "ERROR: Cannot connect to target"

    html = resp.text
    headers = resp.headers
    headers_lower = {k.lower(): v for k, v in headers.items()}

    # 1. Technology Detection
    safe_print(f"  {Fore.CYAN}[*] Detecting technologies...{Style.RESET_ALL}")
    tech_output = "Technology Detection Results:\n\n"
    tech_found = []

    tech_signatures = {
        "WordPress": ["/wp-content/", "/wp-includes/", "wp-json", "wordpress"],
        "Joomla": ["/media/jui/", "/components/com_", "joomla"],
        "Drupal": ["drupal", "sites/all/themes", "Drupal.settings"],
        "Moodle": ["moodle", "moodle/form", "core/login", "atto", "tiny_mce"],
        "Laravel": ["laravel_session", "laravel_token", "XSRF-TOKEN"],
        "Django": ["csrfmiddlewaretoken", "django"],
        "Ruby on Rails": ["_rails", "rails", "turbolinks"],
        "Express.js": ["x-powered-by: express", "express"],
        "React": ["react", "__NEXT_DATA__", "next.js", "_next"],
        "Vue.js": ["vue", "v-cloak", "v-bind", "vuejs"],
        "Angular": ["ng-app", "ng-version", "angular", "ng-content"],
        "jQuery": ["jquery", "jQuery"],
        "Bootstrap": ["bootstrap", "bootstrap.min.css"],
        "Nginx": ["server: nginx", "nginx"],
        "Apache": ["server: apache", "apache", "mod_"],
        "IIS": ["server: microsoft-iis", "x-aspnet", "x-powered-by: asp.net"],
        "PHP": ["x-powered-by: php", ".php"],
        "ASP.NET": ["x-aspnet-version", "asp.net", "viewstate"],
        "Cloudflare": ["cf-ray", "cloudflare"],
        "Amazon S3": ["x-amz-request-id", "s3", "amazonaws"],
        "CloudFront": ["x-amz-cf-id", "cloudfront"],
        "cPanel": ["cpanel", "x-cpanel"],
        "phpMyAdmin": ["phpmyadmin", "pma"],
        "Font Awesome": ["font-awesome", "fontawesome"],
        "Google Analytics": ["google-analytics", "ga(", "gtag("],
        "OpenGraph": ["og:title", "og:description", "property=\"og:"],
        "Let's Encrypt": ["Let's Encrypt"],
        "OpenSSL": ["OpenSSL"],
        "Next.js": ["__NEXT_DATA__", "_next/static", "_next/image"],
        "Nuxt.js": ["__NUXT__", "_nuxt/"],
        "Svelte": ["svelte", "__svelte"],
        "Tailwind CSS": ["tailwind", "tailwindcss"],
    }

    for tech, sigs in tech_signatures.items():
        for sig in sigs:
            sig_lower = sig.lower()
            if sig_lower in headers_lower:
                tech_found.append(f"{tech} (header: {sig})")
                break
            if sig_lower in html.lower():
                tech_found.append(f"{tech} (body: {sig})")
                break

    if tech_found:
        tech_output += "Detected Technologies:\n"
        for tech_item in sorted(set(tech_found)):
            tech_output += f"  [+] {tech_item}\n"
    else:
        tech_output += "No specific technologies detected.\n"

    write_result(3, "technology_detection.txt", tech_output, "Technology Fingerprint", "Header/body analysis")
    output_lines.append(tech_output)
    progress_bar(35, plabel)

    # 2. Security Headers Analysis
    safe_print(f"  {Fore.CYAN}[*] Analyzing security headers...{Style.RESET_ALL}")
    sec_headers_output = "Security Headers Analysis:\n\n"

    security_headers = {
        "Strict-Transport-Security": {"present": False, "desc": "HSTS - Forces HTTPS"},
        "Content-Security-Policy": {"present": False, "desc": "CSP - Prevents XSS"},
        "X-Content-Type-Options": {"present": False, "desc": "Prevents MIME sniffing"},
        "X-Frame-Options": {"present": False, "desc": "Prevents clickjacking"},
        "X-XSS-Protection": {"present": False, "desc": "XSS filter (deprecated)"},
        "Referrer-Policy": {"present": False, "desc": "Controls referrer info"},
        "Permissions-Policy": {"present": False, "desc": "Controls browser features"},
        "Cross-Origin-Opener-Policy": {"present": False, "desc": "COOP protection"},
        "Cross-Origin-Resource-Policy": {"present": False, "desc": "CORP protection"},
        "Cross-Origin-Embedder-Policy": {"present": False, "desc": "COEP protection"},
    }

    for header_name, info in security_headers.items():
        value = headers_lower.get(header_name.lower(), None)
        if value:
            info["present"] = True
            sec_headers_output += f"  {Fore.GREEN}[OK]{Style.RESET_ALL} {header_name}: {value}\n"
            sec_headers_output += f"      {info['desc']}\n"
        else:
            sec_headers_output += f"  {Fore.RED}[MISSING]{Style.RESET_ALL} {header_name}\n"
            sec_headers_output += f"      {info['desc']}\n"

    present_count = sum(1 for h in security_headers.values() if h["present"])
    total_count = len(security_headers)
    score_pct = int((present_count / total_count) * 100)
    sec_headers_output += f"\nScore: {present_count}/{total_count} headers present ({score_pct}%)\n"
    
    if score_pct < 40:
        sec_headers_output += f"Rating: {Fore.RED}POOR{Style.RESET_ALL} - Critical security headers are missing\n"
    elif score_pct < 70:
        sec_headers_output += f"Rating: {Fore.YELLOW}FAIR{Style.RESET_ALL} - Some important headers missing\n"
    else:
        sec_headers_output += f"Rating: {Fore.GREEN}GOOD{Style.RESET_ALL} - Most security headers present\n"

    write_result(3, "security_headers.txt", sec_headers_output, "Security Headers Check", "HTTP header analysis")
    output_lines.append(sec_headers_output)
    progress_bar(55, plabel)

    # 3. Cookie Security Analysis (NEW)
    safe_print(f"  {Fore.CYAN}[*] Analyzing cookie security...{Style.RESET_ALL}")
    cookie_output = "Cookie Security Analysis:\n\n"
    
    cookies = resp.cookies
    set_cookie_headers = headers_lower.get("set-cookie", "")
    
    all_cookies = {}
    # Parse from requests cookie jar
    for cookie in cookies:
        all_cookies[cookie.name] = {
            "value": cookie.value[:20] + "..." if len(cookie.value) > 20 else cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr('HttpOnly') or cookie.httponly if hasattr(cookie, 'httponly') else False,
        }
    
    # Parse from Set-Cookie headers
    for sc in set_cookie_headers.split(","):
        sc = sc.strip()
        if "=" in sc.split(";")[0]:
            name_val = sc.split(";")[0].strip()
            name = name_val.split("=")[0].strip()
            if name not in all_cookies:
                all_cookies[name] = {"value": "...", "domain": "unknown", "path": "unknown", "secure": False, "httponly": False}
            all_cookies[name]["secure"] = "secure" in sc.lower()
            all_cookies[name]["httponly"] = "httponly" in sc.lower()
            if "samesite" in sc.lower():
                samesite_match = re.search(r'samesite\s*=\s*(\w+)', sc, re.IGNORECASE)
                all_cookies[name]["samesite"] = samesite_match.group(1) if samesite_match else "none"
            else:
                all_cookies[name]["samesite"] = "missing"

    if all_cookies:
        cookie_output += f"Found {len(all_cookies)} cookie(s):\n\n"
        insecure_cookies = []
        for name, info in all_cookies.items():
            flags = []
            issues = []
            
            if info.get("secure"):
                flags.append(f"{Fore.GREEN}Secure{Style.RESET_ALL}")
            else:
                flags.append(f"{Fore.RED}Secure:MISSING{Style.RESET_ALL}")
                issues.append("Missing Secure flag")
            
            if info.get("httponly"):
                flags.append(f"{Fore.GREEN}HttpOnly{Style.RESET_ALL}")
            else:
                flags.append(f"{Fore.RED}HttpOnly:MISSING{Style.RESET_ALL}")
                issues.append("Missing HttpOnly flag")
            
            samesite = info.get("samesite", "missing")
            if samesite and samesite.lower() not in ["missing", "none"]:
                flags.append(f"{Fore.GREEN}SameSite={samesite}{Style.RESET_ALL}")
            else:
                flags.append(f"{Fore.RED}SameSite:MISSING{Style.RESET_ALL}")
                issues.append("Missing SameSite flag")
            
            cookie_output += f"  Cookie: {name}\n"
            cookie_output += f"    Domain: {info.get('domain', 'N/A')}\n"
            cookie_output += f"    Path: {info.get('path', 'N/A')}\n"
            cookie_output += f"    Flags: {' | '.join(flags)}\n"
            if issues:
                cookie_output += f"    {Fore.YELLOW}Issues: {', '.join(issues)}{Style.RESET_ALL}\n"
                insecure_cookies.append((name, issues))
            cookie_output += "\n"
        
        if insecure_cookies:
            cookie_output += f"\n{Fore.RED}[!] {len(insecure_cookies)} cookie(s) with missing security flags!{Style.RESET_ALL}\n"
        else:
            cookie_output += f"\n{Fore.GREEN}[OK] All cookies have proper security flags.{Style.RESET_ALL}\n"
    else:
        cookie_output += "No cookies found in response.\n"

    write_result(3, "cookie_analysis.txt", cookie_output, "Cookie Security Analyzer", "Cookie flag check")
    output_lines.append(cookie_output)
    progress_bar(75, plabel)

    # 4. JavaScript Files Listing
    safe_print(f"  {Fore.CYAN}[*] Extracting JavaScript files...{Style.RESET_ALL}")
    js_patterns = [
        r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
        r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\']',
    ]
    js_files = []
    for pattern in js_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        js_files.extend(matches)

    js_files = sorted(set(js_files))
    js_output = f"JavaScript Files Found ({len(js_files)}):\n\n"
    for js in js_files:
        full_url = js if js.startswith("http") else f"{G.target_url.rstrip('/')}/{js.lstrip('/')}"
        js_output += f"  - {full_url}\n"

    if not js_files:
        js_output += "No JavaScript files found.\n"

    write_result(3, "js_files_list.txt", js_output, "JS File Extraction", "Regex HTML parsing")
    output_lines.append(js_output)
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return "\n".join(output_lines)


# ═══════════════════════════════════════════════════════════════════
# PHASE 04: DIRECTORY DISCOVERY
# ═══════════════════════════════════════════════════════════════════

def phase_04_directory_discovery():
    """Phase 04: Directory Discovery - Python-based brute force."""
    plabel = phase_label(4)
    safe_print(t("scanning", phase=plabel))
    progress_bar(5, plabel)
    safe_print(f"  {Fore.CYAN}[*] Scanning {len(ALL_DIRS)} directories...{Style.RESET_ALL}")
    log_info(f"Directory discovery: {len(ALL_DIRS)} paths to scan")

    found_dirs = []
    lock = Lock()

    def check_dir(path):
        url = f"{G.target_url.rstrip('/')}{path}"
        try:
            resp = requests.head(url, timeout=5, allow_redirects=False, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
                                proxies=G.proxies)
            if resp.status_code in [200, 301, 302, 401, 403]:
                with lock:
                    found_dirs.append((path, resp.status_code))
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=30) as executor:
        list(executor.map(check_dir, ALL_DIRS))

    found_dirs.sort(key=lambda x: x[0])

    dir_output = f"Directory Discovery Results ({len(found_dirs)} found):\n\n"
    dir_output += f"{'STATUS':<10}{'PATH':<50}{'URL'}\n"
    dir_output += "-" * 120
    for path, status in found_dirs:
        url = f"{G.target_url.rstrip('/')}{path}"
        dir_output += f"\n{status:<10}{path:<50}{url}"

    if not found_dirs:
        dir_output += "\nNo directories found.\n"

    write_result(4, "dir_scan.txt", dir_output, "Python Directory Brute Force",
                 f"Scanned {len(ALL_DIRS)} paths")
    log_info(f"Directory discovery: {len(found_dirs)} directories found")
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return dir_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 05: VULNERABILITY SCANNING (Enhanced with HTTP Methods + CORS)
# ═══════════════════════════════════════════════════════════════════

def phase_05_vulnerability_scanning():
    """Phase 05: Enhanced Vulnerability Scanning - XSS, traversal, info disclosure,
    HTTP methods testing, CORS misconfiguration."""
    plabel = phase_label(5)
    safe_print(t("scanning", phase=plabel))
    progress_bar(5, plabel)
    output_lines = []
    vuln_output = "Enhanced Vulnerability Scan Results\n"
    vuln_output += "=" * 63 + "\n\n"

    resp = http_get(G.target_url, timeout=15)
    base_url = G.target_url.rstrip("/")

    # 1. Open Redirect Test
    safe_print(f"  {Fore.CYAN}[*] Testing open redirect...{Style.RESET_ALL}")
    vuln_output += "[1] Open Redirect Test\n"
    redirect_payloads = [
        "/redirect?url=https://evil.com",
        "/login?redirect=https://evil.com",
        "/logout?next=https://evil.com",
        "/?url=https://evil.com",
        "/redirect?target=https://evil.com",
        "/goto=https://evil.com",
        "/return=https://evil.com",
        "/continue=https://evil.com",
    ]
    redirect_found = []
    for payload in redirect_payloads:
        test_url = f"{base_url}{payload}"
        try:
            test_resp = http_get(test_url, timeout=5, allow_redirects=False)
            if test_resp:
                location = test_resp.headers.get("Location", "")
                if "evil.com" in location:
                    redirect_found.append((test_url, location))
        except Exception:
            pass

    if redirect_found:
        vuln_output += f"  {Fore.RED}[!] POTENTIAL OPEN REDIRECT:{Style.RESET_ALL}\n"
        for url, loc in redirect_found:
            vuln_output += f"    URL: {url}\n    Redirects to: {loc}\n"
    else:
        vuln_output += "  [OK] No open redirect found in basic tests.\n"
    vuln_output += "\n"
    progress_bar(15, plabel)

    # 2. Reflected XSS Check
    safe_print(f"  {Fore.CYAN}[*] Testing reflected XSS...{Style.RESET_ALL}")
    vuln_output += "[2] Reflected XSS Check\n"
    xss_payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
    ]
    xss_found = []
    for payload in xss_payloads:
        test_url = f"{base_url}/?q={urllib.parse.quote(payload)}"
        try:
            test_resp = http_get(test_url, timeout=5)
            if test_resp and payload in test_resp.text:
                xss_found.append((test_url, payload))
        except Exception:
            pass

    if xss_found:
        vuln_output += f"  {Fore.RED}[!] POTENTIAL XSS VULNERABILITY FOUND:{Style.RESET_ALL}\n"
        for url, payload in xss_found:
            vuln_output += f"    URL: {url}\n    Payload: {payload[:80]}\n"
    else:
        vuln_output += "  [OK] No obvious reflected XSS found in basic tests.\n"
    vuln_output += "\n"
    progress_bar(30, plabel)

    # 3. Directory Traversal Check
    safe_print(f"  {Fore.CYAN}[*] Testing directory traversal...{Style.RESET_ALL}")
    vuln_output += "[3] Directory Traversal Check\n"
    traversal_paths = [
        "/../../../etc/passwd",
        "/..%2f..%2f..%2fetc%2fpasswd",
        "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/....//....//....//etc/passwd",
        "/static/../../../etc/passwd",
    ]
    traversal_found = []
    for path in traversal_paths:
        test_url = f"{base_url}{path}"
        try:
            test_resp = http_get(test_url, timeout=5)
            if test_resp and "root:" in test_resp.text:
                traversal_found.append((test_url, test_resp.status_code))
        except Exception:
            pass

    if traversal_found:
        vuln_output += f"  {Fore.RED}[!] POTENTIAL DIRECTORY TRAVERSAL:{Style.RESET_ALL}\n"
        for url, code in traversal_found:
            vuln_output += f"    URL: {url} (Status: {code})\n"
    else:
        vuln_output += "  [OK] No directory traversal found in basic tests.\n"
    vuln_output += "\n"
    progress_bar(45, plabel)

    # 4. Information Disclosure
    safe_print(f"  {Fore.CYAN}[*] Checking information disclosure...{Style.RESET_ALL}")
    vuln_output += "[4] Information Disclosure\n"
    info_endpoints = [
        "/.env", "/.git/config", "/.git/HEAD", "/server-status", "/phpinfo.php",
        "/info.php", "/.htaccess", "/web.config", "/debug", "/trace",
        "/actuator", "/actuator/env", "/actuator/health", "/.well-known/security.txt",
    ]
    info_found = []
    for path in info_endpoints:
        test_url = f"{base_url}{path}"
        try:
            test_resp = http_get(test_url, timeout=5)
            if test_resp and test_resp.status_code == 200:
                content_len = len(test_resp.text)
                if content_len > 10:
                    info_found.append((path, test_resp.status_code, content_len))
        except Exception:
            pass

    if info_found:
        vuln_output += f"  {Fore.RED}[!] POTENTIAL INFO DISCLOSURE:{Style.RESET_ALL}\n"
        for path, code, size in info_found:
            vuln_output += f"    {path} (Status: {code}, Size: {size} bytes)\n"
    else:
        vuln_output += "  [OK] No information disclosure found.\n"
    vuln_output += "\n"
    progress_bar(55, plabel)

    # 5. Common Misconfigurations
    safe_print(f"  {Fore.CYAN}[*] Checking misconfigurations...{Style.RESET_ALL}")
    vuln_output += "[5] Common Misconfigurations\n"
    if resp:
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            ("Server version disclosure", "server" in headers_lower,
             headers_lower.get("server", "")),
            ("X-Powered-By header", "x-powered-by" in headers_lower,
             headers_lower.get("x-powered-by", "")),
            ("Missing X-Content-Type-Options", "x-content-type-options" not in headers_lower, ""),
            ("Missing X-Frame-Options", "x-frame-options" not in headers_lower, ""),
            ("Missing CSP", "content-security-policy" not in headers_lower, ""),
            ("Missing HSTS", "strict-transport-security" not in headers_lower, ""),
        ]

        for name, found, value in checks:
            if found and value:
                vuln_output += f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {name}: {value}\n"
            elif found:
                vuln_output += f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {name}\n"
    progress_bar(65, plabel)

    # 6. HTTP Methods Testing (NEW)
    safe_print(f"  {Fore.CYAN}[*] Testing HTTP methods...{Style.RESET_ALL}")
    vuln_output += "\n[6] HTTP Methods Testing\n"
    
    dangerous_methods = ["PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"]
    allowed_methods = set()
    
    # Test OPTIONS first
    options_resp = http_options(base_url)
    if options_resp:
        allow_header = options_resp.headers.get("Allow", "")
        if allow_header:
            for method in allow_header.split(","):
                method = method.strip().upper()
                if method in dangerous_methods:
                    allowed_methods.add(method)
        vuln_output += f"  OPTIONS Allow header: {allow_header}\n"
    
    # Also test each method individually
    for method in ["PUT", "DELETE", "TRACE", "PATCH"]:
        test_resp = http_request(method, base_url, timeout=5, data="test" if method in ["PUT", "PATCH"] else None)
        if test_resp:
            if test_resp.status_code not in [405, 501, 403]:
                if method == "TRACE" and test_resp.status_code == 200:
                    allowed_methods.add("TRACE (XST VULNERABLE!)")
                elif method in ["PUT", "DELETE", "PATCH"] and test_resp.status_code in [200, 201, 204]:
                    allowed_methods.add(method)
    
    if allowed_methods:
        vuln_output += f"  {Fore.RED}[!] Dangerous methods allowed: {', '.join(sorted(allowed_methods))}{Style.RESET_ALL}\n"
        for m in allowed_methods:
            if "TRACE" in m:
                vuln_output += f"    {Fore.RED}CRITICAL: TRACE method enabled - Cross-Site Tracing (XST) possible!{Style.RESET_ALL}\n"
    else:
        vuln_output += "  [OK] No dangerous HTTP methods detected.\n"
    vuln_output += "\n"
    progress_bar(80, plabel)

    # 7. CORS Misconfiguration (NEW)
    safe_print(f"  {Fore.CYAN}[*] Testing CORS configuration...{Style.RESET_ALL}")
    vuln_output += "[7] CORS Misconfiguration Check\n"
    
    cors_origins = [
        ("null", "null"),
        ("https://evil.com", "https://evil.com"),
        (G.target_url, G.target_url),
        ("https://evil." + G.target_host, f"https://evil.{G.target_host}"),
    ]
    
    cors_issues = []
    for origin_name, origin_value in cors_origins:
        test_resp = http_get(base_url, timeout=5, headers={"Origin": origin_value})
        if test_resp:
            acao = test_resp.headers.get("Access-Control-Allow-Origin", "")
            acac = test_resp.headers.get("Access-Control-Allow-Credentials", "")
            
            if acao == "*":
                cors_issues.append((origin_name, acao, acac))
                vuln_output += f"  {Fore.RED}[!] Origin '{origin_name}' -> ACAO: {acao}{Style.RESET_ALL}\n"
            elif acao == origin_value and origin_name in ["null", "https://evil.com", f"https://evil.{G.target_host}"]:
                cors_issues.append((origin_name, acao, acac))
                vuln_output += f"  {Fore.RED}[!] Origin '{origin_name}' REFLECTED -> ACAO: {acao}{Style.RESET_ALL}\n"
                if acac.lower() == "true":
                    vuln_output += f"    {Fore.RED}CRITICAL: Credentials allowed with reflected origin!{Style.RESET_ALL}\n"
            elif acao:
                vuln_output += f"  [i] Origin '{origin_name}' -> ACAO: {acao}\n"
    
    if not cors_issues:
        vuln_output += "  [OK] No CORS misconfiguration detected.\n"
    vuln_output += "\n"

    write_result(5, "vuln_scan.txt", vuln_output, "Enhanced Vulnerability Scanner",
                 "XSS, traversal, info disclosure, HTTP methods, CORS")
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return vuln_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 06: API ENDPOINT HUNTING
# ═══════════════════════════════════════════════════════════════════

def phase_06_api_endpoint_hunting():
    """Phase 06: API Endpoint Hunting."""
    plabel = phase_label(6)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)

    api_output = "API Endpoint Discovery Results\n"
    api_output += "=" * 63 + "\n\n"
    base_url = G.target_url.rstrip("/")

    safe_print(f"  {Fore.CYAN}[*] Parsing page source for API endpoints...{Style.RESET_ALL}")
    resp = http_get(G.target_url, timeout=15)
    api_endpoints = set()

    if resp:
        html = resp.text
        api_patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/v[0-9]+/[^"\']+)["\']',
            r'["\'](/graphql)["\']',
            r'["\'](/soap/[^"\']+)["\']',
            r'["\'](/webservice/[^"\']+)["\']',
            r'["\'](/service\.php[^"\']*)["\']',
            r'["\'](/ajax\.php[^"\']*)["\']',
            r'["\'](/token\.php[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'XMLHttpRequest\.open\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
            r'url:\s*["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
            r'baseUrl:\s*["\']([^"\']+)["\']',
            r'apiUrl:\s*["\']([^"\']+)["\']',
        ]

        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for m in matches:
                if len(m) > 1:
                    api_endpoints.add(m)

    safe_print(f"  {Fore.CYAN}[*] Checking common API paths...{Style.RESET_ALL}")
    common_api_paths = [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/rest/", "/graphql", "/soap/",
        "/api/users", "/api/admin", "/api/config", "/api/settings",
        "/api/health", "/api/status", "/api/info", "/api/version",
        "/swagger", "/swagger-ui", "/api-docs", "/api/docs",
        "/openapi.json", "/swagger.json",
        "/webservice/rest/server.php", "/webservice/xmlrpc/server.php",
        "/json/", "/jsonapi/", "/rpc/",
        "/api/keys", "/api/tokens", "/api/auth", "/api/login",
        "/api/search", "/api/export", "/api/import", "/api/upload",
    ]

    found_apis = []
    for path in common_api_paths:
        url = f"{base_url}{path}"
        try:
            resp_api = requests.head(url, timeout=5, verify=False,
                                    headers={"User-Agent": "Mozilla/5.0"},
                                    proxies=G.proxies)
            if resp_api.status_code in [200, 401, 403, 405]:
                found_apis.append((path, resp_api.status_code))
        except Exception:
            pass

    api_output += f"[1] Endpoints found in page source: {len(api_endpoints)}\n"
    for ep in sorted(api_endpoints):
        api_output += f"  - {ep}\n"

    api_output += f"\n[2] Common API paths found: {len(found_apis)}\n"
    for path, code in found_apis:
        api_output += f"  - {path} (Status: {code})\n"

    api_output += "\n[3] Unauthenticated access test:\n"
    for path, code in found_apis:
        if code == 200:
            url = f"{base_url}{path}"
            try:
                test_resp = http_get(url, timeout=5)
                if test_resp:
                    size = len(test_resp.text)
                    if size > 0:
                        api_output += f"  {Fore.YELLOW}[!] {path} - Accessible without auth ({size} bytes){Style.RESET_ALL}\n"
            except Exception:
                pass

    write_result(6, "api_discovery.txt", api_output, "API Endpoint Hunter",
                 "Source parsing + path enumeration")
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return api_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 07: SSL/TLS ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def phase_07_ssl_tls_analysis():
    """Phase 07: SSL/TLS Analysis."""
    plabel = phase_label(7)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)
    output_lines = []

    openssl_path = shutil.which("openssl")
    G.openssl_available = openssl_path is not None
    G.openssl_path = openssl_path or ""

    if G.openssl_available:
        safe_print(t("openssl_found", path=openssl_path))

    if G.openssl_available:
        safe_print(f"  {Fore.CYAN}[*] Running OpenSSL s_client...{Style.RESET_ALL}")
        try:
            cmd = ["openssl", "s_client", "-connect", f"{G.target_host}:443",
                   "-servername", G.target_host, "-showcerts"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                   input="QUIT\n")
            openssl_output = result.stdout
            if result.stderr:
                openssl_output += "\n\nSTDERR:\n" + result.stderr
        except Exception as e:
            openssl_output = f"OpenSSL error: {str(e)}"
        write_result(7, "openssl_client.txt", openssl_output, "OpenSSL s_client",
                     f"openssl s_client -connect {G.target_host}:443")
        output_lines.append(openssl_output)
    progress_bar(50, plabel)

    safe_print(f"  {Fore.CYAN}[*] Running Python SSL check...{Style.RESET_ALL}")
    ssl_output = "Python SSL/TLS Analysis\n"
    ssl_output += "=" * 63 + "\n\n"

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((G.target_host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=G.target_host) as ssock:
                ssl_output += f"SSL Version: {ssock.version()}\n"
                ssl_output += f"Cipher: {ssock.cipher()}\n"
                ssl_output += f"Shared Ciphers: {len(ssock.shared_ciphers())}\n\n"

                cert = ssock.getpeercert()
                if cert:
                    ssl_output += "Certificate Details:\n"
                    for key in ["subject", "issuer", "version", "serialNumber",
                                "notBefore", "notAfter"]:
                        if key in cert:
                            ssl_output += f"  {key}: {cert[key]}\n"

                    if "subjectAltName" in cert:
                        ssl_output += "  Subject Alternative Names:\n"
                        for san_type, san_value in cert["subjectAltName"]:
                            ssl_output += f"    {san_type}: {san_value}\n"

                    not_before = cert.get("notBefore", "")
                    not_after = cert.get("notAfter", "")
                    if not_before and not_after:
                        ssl_output += f"\n  Certificate Validity: {not_before} - {not_after}\n"
    except ssl.SSLError as e:
        ssl_output += f"SSL Error: {str(e)}\n"
    except Exception as e:
        ssl_output += f"Error: {str(e)}\n"

    write_result(7, "python_ssl_check.txt", ssl_output, "Python SSL Module", "ssl.create_default_context()")
    output_lines.append(ssl_output)
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return "\n".join(output_lines)


# ═══════════════════════════════════════════════════════════════════
# PHASE 08: DNS ENUMERATION + SUBDOMAIN TAKEOVER (Enhanced)
# ═══════════════════════════════════════════════════════════════════

def phase_08_dns_enumeration():
    """Phase 08: DNS Enumeration with Subdomain Takeover Detection."""
    plabel = phase_label(8)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)
    output_lines = []

    # 1. A Record
    safe_print(f"  {Fore.CYAN}[*] Querying A records...{Style.RESET_ALL}")
    try:
        a_records = socket.gethostbyname_ex(G.target_host)
        a_output = f"A Record Lookup for {G.target_host}:\n\n"
        a_output += f"  Primary: {a_records[0]}\n"
        if a_records[2]:
            a_output += f"  Aliases: {', '.join(a_records[1])}\n"
            a_output += f"  Addresses: {', '.join(a_records[2])}\n"
    except socket.gaierror:
        a_output = f"A Record Lookup for {G.target_host}:\n  DNS resolution failed.\n"
    write_result(8, "a_record.txt", a_output, "socket.gethostbyname_ex", f"Lookup {G.target_host}")
    output_lines.append(a_output)
    progress_bar(25, plabel)

    # 2. NS Record
    safe_print(f"  {Fore.CYAN}[*] Querying NS records...{Style.RESET_ALL}")
    ns_output = f"NS Record Lookup for {G.target_host}:\n\n"
    try:
        dig_path = shutil.which("dig")
        host_path = shutil.which("host")
        if dig_path:
            result = subprocess.run(["dig", "NS", G.target_host, "+short"],
                                   capture_output=True, text=True, timeout=10)
            ns_output += result.stdout if result.stdout.strip() else "  No NS records found.\n"
        elif host_path:
            result = subprocess.run(["host", "-t", "NS", G.target_host],
                                   capture_output=True, text=True, timeout=10)
            ns_output += result.stdout if result.stdout.strip() else "  No NS records found.\n"
        else:
            ns_output += "  dig/host not available. Install dnsutils for NS lookup.\n"
    except Exception as e:
        ns_output += f"  Error: {str(e)}\n"
    write_result(8, "ns_record.txt", ns_output, "DNS NS Lookup", "dig/host")
    output_lines.append(ns_output)
    progress_bar(40, plabel)

    # 3. TXT Record
    safe_print(f"  {Fore.CYAN}[*] Querying TXT records...{Style.RESET_ALL}")
    txt_output = f"TXT Record Lookup for {G.target_host}:\n\n"
    try:
        dig_path = shutil.which("dig")
        if dig_path:
            result = subprocess.run(["dig", "TXT", G.target_host, "+short"],
                                   capture_output=True, text=True, timeout=10)
            txt_output += result.stdout if result.stdout.strip() else "  No TXT records found.\n"
        else:
            txt_output += "  dig not available.\n"
    except Exception as e:
        txt_output += f"  Error: {str(e)}\n"
    write_result(8, "txt_record.txt", txt_output, "DNS TXT Lookup", "dig TXT")
    output_lines.append(txt_output)
    progress_bar(55, plabel)

    # 4. Subdomain Enumeration
    safe_print(f"  {Fore.CYAN}[*] Enumerating subdomains ({len(SUBDOMAIN_PREFIXES)} prefixes)...{Style.RESET_ALL}")
    found_subdomains = []
    lock = Lock()

    def check_subdomain(prefix):
        fqdn = f"{prefix}.{G.target_host}"
        try:
            ip = socket.gethostbyname(fqdn)
            with lock:
                found_subdomains.append((fqdn, ip))
        except socket.gaierror:
            pass

    with ThreadPoolExecutor(max_workers=50) as executor:
        list(executor.map(check_subdomain, SUBDOMAIN_PREFIXES))

    found_subdomains.sort(key=lambda x: x[0])
    subdomain_output = f"Subdomain Enumeration for {G.target_host}:\n\n"
    subdomain_output += f"{'SUBDOMAIN':<45}{'IP ADDRESS'}\n"
    subdomain_output += "-" * 70
    for sub, ip in found_subdomains:
        subdomain_output += f"\n{sub:<45}{ip}"
    subdomain_output += f"\n\nTotal subdomains found: {len(found_subdomains)}"

    write_result(8, "subdomain_enum.txt", subdomain_output, "Python Subdomain Enum",
                 f"Brute force {len(SUBDOMAIN_PREFIXES)} prefixes")
    output_lines.append(subdomain_output)
    progress_bar(80, plabel)

    # 5. Subdomain Takeover Detection (NEW)
    safe_print(f"  {Fore.CYAN}[*] Checking for subdomain takeover vulnerabilities...{Style.RESET_ALL}")
    takeover_output = "Subdomain Takeover Detection:\n\n"
    
    dig_path = shutil.which("dig")
    potential_takeovers = []
    
    for subdomain, ip in found_subdomains:
        if dig_path:
            try:
                result = subprocess.run(
                    ["dig", "CNAME", subdomain, "+short"],
                    capture_output=True, text=True, timeout=5
                )
                cname = result.stdout.strip()
                
                if cname:
                    cname = cname.rstrip(".")
                    # Check if CNAME points to a known takeover service
                    for service_domain, service_name in TAKEOVER_SERVICES.items():
                        if service_domain in cname.lower():
                            # Verify if the service is actually responding
                            try:
                                check_resp = http_get(f"https://{subdomain}", timeout=5)
                                if check_resp and check_resp.status_code in [404, 502, 503]:
                                    potential_takeovers.append({
                                        "subdomain": subdomain,
                                        "cname": cname,
                                        "service": service_name,
                                        "status": check_resp.status_code,
                                        "severity": "HIGH"
                                    })
                                elif check_resp is None:
                                    potential_takeovers.append({
                                        "subdomain": subdomain,
                                        "cname": cname,
                                        "service": service_name,
                                        "status": "timeout",
                                        "severity": "MEDIUM"
                                    })
                            except Exception:
                                potential_takeovers.append({
                                    "subdomain": subdomain,
                                    "cname": cname,
                                    "service": service_name,
                                    "status": "error",
                                    "severity": "LOW"
                                })
            except Exception:
                pass

    if potential_takeovers:
        takeover_output += f"{Fore.RED}[!] {len(potential_takeovers)} potential subdomain takeover(s) detected!{Style.RESET_ALL}\n\n"
        for to in potential_takeovers:
            sev_color = Fore.RED if to["severity"] == "HIGH" else Fore.YELLOW
            takeover_output += f"  {sev_color}[{to['severity']}] {to['subdomain']}{Style.RESET_ALL}\n"
            takeover_output += f"    CNAME: {to['cname']}\n"
            takeover_output += f"    Service: {to['service']}\n"
            takeover_output += f"    HTTP Status: {to['status']}\n\n"
    else:
        takeover_output += "  [OK] No obvious subdomain takeover vulnerabilities detected.\n"

    write_result(8, "takeover_detection.txt", takeover_output, "Subdomain Takeover Detector",
                 f"Checked {len(found_subdomains)} subdomains")
    output_lines.append(takeover_output)
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return "\n".join(output_lines)


# ═══════════════════════════════════════════════════════════════════
# PHASE 09: CVE MATCHING
# ═══════════════════════════════════════════════════════════════════

def phase_09_cve_matching():
    """Phase 09: CVE Matching based on detected technologies."""
    plabel = phase_label(9)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)

    tech_results = G.get_results().get(3, "")
    resp = http_get(G.target_url, timeout=15)
    headers = resp.headers if resp else {}

    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")
    x_aspnet = headers.get("X-AspNet-Version", "")

    search_terms = []
    if "apache" in server.lower():
        ver = re.search(r'apache/([\d.]+)', server, re.IGNORECASE)
        search_terms.append(f"Apache HTTP Server {ver.group(1)}" if ver else "Apache HTTP Server")
    if "nginx" in server.lower():
        ver = re.search(r'nginx/([\d.]+)', server, re.IGNORECASE)
        search_terms.append(f"Nginx {ver.group(1)}" if ver else "Nginx")
    if "php" in powered_by.lower() or "php" in str(headers).lower():
        ver = re.search(r'php/([\d.]+)', powered_by, re.IGNORECASE)
        search_terms.append(f"PHP {ver.group(1)}" if ver else "PHP")
    for tech in ["WordPress", "Moodle", "Drupal", "Joomla"]:
        if tech.lower() in tech_results.lower():
            search_terms.append(tech)
    if "openssl" in tech_results.lower():
        ver = re.search(r'openssl\s*([\d.]+)', tech_results, re.IGNORECASE)
        search_terms.append(f"OpenSSL {ver.group(1)}" if ver else "OpenSSL")
    if "iis" in server.lower():
        ver = re.search(r'(\d+\.\d+)', server)
        search_terms.append(f"IIS {ver.group(1)}" if ver else "IIS")

    search_terms = list(dict.fromkeys(search_terms))

    safe_print(f"  {Fore.CYAN}[*] Searching NVD for CVEs ({len(search_terms)} technologies)...{Style.RESET_ALL}")
    nvd_output = f"CVE Matching Results for {G.target_url}\n"
    nvd_output += "=" * 63 + "\n\n"
    nvd_output += f"Detected Technologies: {', '.join(search_terms) if search_terms else 'None identified'}\n\n"

    all_cves = []

    for i, tech in enumerate(search_terms):
        nvd_output += f"\n--- Searching: {tech} ---\n"
        try:
            nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {"keywordSearch": tech, "resultsPerPage": 10}
            resp_nvd = requests.get(nvd_url, params=params, timeout=20,
                                   headers={"User-Agent": "DeepRecon-Scanner/4.0",
                                           "Accept": "application/json"},
                                   verify=False, proxies=G.proxies)
            if resp_nvd.status_code == 200:
                data = resp_nvd.json()
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "N/A")
                    desc_text = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc_text = d.get("value", "")[:200]
                            break
                    metrics = cve.get("metrics", {})
                    severity = "N/A"
                    score = "N/A"
                    if "cvssMetricV31" in metrics:
                        cvss = metrics["cvssMetricV31"][0].get("cvssData", {})
                        severity = cvss.get("baseSeverity", "N/A")
                        score = cvss.get("baseScore", "N/A")
                    elif "cvssMetricV30" in metrics:
                        cvss = metrics["cvssMetricV30"][0].get("cvssData", {})
                        severity = cvss.get("baseSeverity", "N/A")
                        score = cvss.get("baseScore", "N/A")

                    cve_entry = {"cve_id": cve_id, "description": desc_text,
                                 "severity": severity, "score": str(score), "technology": tech}
                    all_cves.append(cve_entry)
                    nvd_output += f"  [{severity}] {cve_id} (Score: {score})\n"
                    nvd_output += f"    {desc_text}\n\n"
            else:
                nvd_output += f"  NVD API returned status {resp_nvd.status_code}\n"
        except requests.exceptions.Timeout:
            nvd_output += f"  NVD API request timed out for: {tech}\n"
        except Exception as e:
            nvd_output += f"  Error searching NVD for {tech}: {str(e)}\n"

        progress_bar(10 + int(80 * (i + 1) / max(len(search_terms), 1)), plabel)

    write_result(9, "nvd_search.txt", nvd_output, "NVD API Search",
                 f"Terms: {', '.join(search_terms)}")
    cve_json = json.dumps(all_cves, indent=2, ensure_ascii=False)
    write_result(9, "matched_cves.json", cve_json, "CVE Match Results", "JSON export")
    write_raw("matched_cves.json", cve_json)

    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return nvd_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 10: AI ANALYSIS
# ═══════════════════════════════════════════════════════════════════

def phase_10_ai_analysis():
    """Phase 10: AI Analysis using selected models."""
    plabel = phase_label(10)
    safe_print(t("scanning", phase=plabel))
    progress_bar(10, plabel)

    if not G.models_config:
        safe_print(t("no_ai_models"))
        no_ai_output = "AI Analysis: Skipped (no models selected)\n"
        write_result(10, "strategic_analysis.txt", no_ai_output, "AI Analysis", "No models configured")
        write_result(10, "exploit_recommendations.txt", no_ai_output, "AI Analysis", "No models configured")
        progress_bar(100, plabel)
        safe_print(t("completed", phase=plabel))
        return no_ai_output

    safe_print(t("consolidating"))
    all_results = ""
    for phase_num in sorted(G.get_results().keys()):
        all_results += G.get_results()[phase_num]

    max_len = 30000
    if len(all_results) > max_len:
        all_results = all_results[:max_len] + "\n\n[... TRUNCATED ...]"

    lang_instruction = "Respond in English." if G.lang == "en" else "أجب باللغة العربية."

    # 1. Strategic Analysis
    safe_print(t("ai_analyzing"))
    strategic_prompt = f"""You are a senior cybersecurity expert performing a penetration test assessment.

Target: {G.target_url}
Scan Level: {G.scan_level}

Here are the complete scan results:

{all_results}

{lang_instruction}

Based on these results, provide a comprehensive strategic analysis including:
1. Executive Summary
2. Attack Surface Analysis
3. Critical Findings (with severity ratings)
4. Risk Assessment Matrix
5. Entry Points Identified
6. Potential Attack Chains
7. Prioritized Recommendations
8. Overall Security Score (1-10)

Be specific and actionable. Reference exact findings from the scan data."""

    if len(G.models_config) == 1:
        analysis_result = call_model(G.models_config[0], strategic_prompt, timeout=60)
        responses = {G.models_config[0]["name"]: analysis_result}
    else:
        responses = multi_model_merge(strategic_prompt, rounds=2, timeout_per_model=60)

    progress_bar(50, plabel)

    analysis_output = "Strategic Security Analysis\n" + "=" * 63 + "\n\n"
    if len(responses) > 1:
        analysis_output += f"Multi-Model Analysis ({len(responses)} models)\n\n"
        for name, response in responses.items():
            analysis_output += f"{'─' * 63}\nModel: {name}\n{'─' * 63}\n{response}\n\n"
    else:
        for name, response in responses.items():
            analysis_output += f"Model: {name}\n\n{response}\n"

    write_result(10, "strategic_analysis.txt", analysis_output, "AI Strategic Analysis",
                 f"Models: {', '.join(m['name'] for m in G.models_config)}")

    # 2. Exploit Recommendations
    safe_print(f"  {Fore.CYAN}[*] Generating exploit recommendations...{Style.RESET_ALL}")
    exploit_prompt = f"""You are a penetration testing expert providing exploit recommendations.

Target: {G.target_url}
Key findings from the scan:
{all_results[:15000]}

{lang_instruction}

Based on the findings, provide:
1. Specific Exploit Recommendations
2. Proof of Concept (PoC) outlines (for authorized testing)
3. Specific CVE exploit references
4. Metasploit module suggestions (if applicable)
5. Manual exploitation steps
6. Remediation and Patching guidance
7. Hardening recommendations

IMPORTANT: This is for authorized penetration testing only."""

    if len(G.models_config) == 1:
        exploit_result = call_model(G.models_config[0], exploit_prompt, timeout=60)
        exploit_responses = {G.models_config[0]["name"]: exploit_result}
    else:
        exploit_responses = multi_model_merge(exploit_prompt, rounds=1, timeout_per_model=60)

    exploit_output = "Exploit Recommendations\n" + "=" * 63 + "\n\n"
    if len(exploit_responses) > 1:
        exploit_output += f"Multi-Model Analysis ({len(exploit_responses)} models)\n\n"
        for name, response in exploit_responses.items():
            exploit_output += f"{'─' * 63}\nModel: {name}\n{'─' * 63}\n{response}\n\n"
    else:
        for name, response in exploit_responses.items():
            exploit_output += f"Model: {name}\n\n{response}\n"

    write_result(10, "exploit_recommendations.txt", exploit_output, "AI Exploit Recommendations",
                 f"Models: {', '.join(m['name'] for m in G.models_config)}")
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return analysis_output


# ═══════════════════════════════════════════════════════════════════
# PHASE 11: FINAL REPORT (TXT + HTML)
# ═══════════════════════════════════════════════════════════════════

def generate_html_report():
    """Generate a professional HTML report."""
    safe_print(t("generating_html"))
    
    all_results = G.get_results()
    now = datetime.datetime.now()
    scan_end = now.isoformat()
    scan_start = G.scan_start_time.isoformat() if G.scan_start_time else scan_end
    duration = (now - G.scan_start_time).total_seconds() if G.scan_start_time else 0
    ip = resolve_host()

    html = f"""<!DOCTYPE html>
<html lang="{G.lang}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Deep Recon v4.0 - Security Report - {G.target_host}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); padding: 40px; border-radius: 12px; text-align: center; margin-bottom: 30px; border: 1px solid #1a3a5c; }}
        .header h1 {{ color: #00d4ff; font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ color: #888; font-size: 1.1em; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }}
        .meta-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; border: 1px solid #2a2a3e; }}
        .meta-card h3 {{ color: #00d4ff; margin-bottom: 10px; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }}
        .meta-card p {{ color: #ccc; font-size: 1.1em; }}
        .phase-section {{ background: #1a1a2e; border-radius: 12px; margin-bottom: 20px; border: 1px solid #2a2a3e; overflow: hidden; }}
        .phase-header {{ background: linear-gradient(90deg, #16213e, #1a2a4e); padding: 15px 25px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
        .phase-header h2 {{ color: #00d4ff; font-size: 1.2em; }}
        .phase-header .toggle {{ color: #888; font-size: 1.5em; transition: transform 0.3s; }}
        .phase-header:hover .toggle {{ color: #00d4ff; transform: rotate(90deg); }}
        .phase-content {{ padding: 20px 25px; display: none; }}
        .phase-content.active {{ display: block; }}
        .phase-content pre {{ background: #0d0d0d; padding: 15px; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; font-size: 0.85em; color: #aaa; border: 1px solid #2a2a3e; max-height: 500px; overflow-y: auto; }}
        .severity-critical {{ color: #ff4444; }}
        .severity-high {{ color: #ff8800; }}
        .severity-medium {{ color: #ffcc00; }}
        .severity-low {{ color: #44ff44; }}
        .footer {{ text-align: center; padding: 30px; color: #555; margin-top: 30px; border-top: 1px solid #1a1a2e; }}
        .badge {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
        .badge-critical {{ background: #ff444433; color: #ff4444; border: 1px solid #ff4444; }}
        .badge-high {{ background: #ff880033; color: #ff8800; border: 1px solid #ff8800; }}
        .badge-info {{ background: #00d4ff22; color: #00d4ff; border: 1px solid #00d4ff33; }}
        .summary-stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin: 20px 0; }}
        .stat {{ background: #0d0d1a; padding: 15px; border-radius: 8px; text-align: center; border: 1px solid #2a2a3e; }}
        .stat .number {{ font-size: 2em; color: #00d4ff; font-weight: bold; }}
        .stat .label {{ font-size: 0.8em; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
        .model-tag {{ background: #16213e; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; display: inline-block; margin: 2px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ DEEP RECON v4.0</h1>
            <p class="subtitle">Advanced Security Reconnaissance Report</p>
            <p class="subtitle" style="margin-top:5px; font-size:0.9em;">{G.target_url}</p>
        </div>

        <div class="meta-grid">
            <div class="meta-card">
                <h3>Target</h3>
                <p>{G.target_url}</p>
            </div>
            <div class="meta-card">
                <h3>IP Address</h3>
                <p>{ip}</p>
            </div>
            <div class="meta-card">
                <h3>Scan Level</h3>
                <p>{G.scan_level.upper()}</p>
            </div>
            <div class="meta-card">
                <h3>Duration</h3>
                <p>{duration:.1f}s ({duration/60:.1f} min)</p>
            </div>
            <div class="meta-card">
                <h3>Start Time</h3>
                <p>{scan_start}</p>
            </div>
            <div class="meta-card">
                <h3>End Time</h3>
                <p>{scan_end}</p>
            </div>
        </div>
        
        <div class="meta-card" style="margin-bottom:20px;">
            <h3>AI Models Used</h3>
            <p>{' '.join(f'<span class="model-tag">{m["name"]} ({m["type"]})</span>' for m in G.models_config) if G.models_config else '<span style="color:#888;">None (AI skipped)</span>'}</p>
        </div>

        <div class="summary-stats">
            <div class="stat">
                <div class="number">{len(all_results)}</div>
                <div class="label">Phases Run</div>
            </div>
            <div class="stat">
                <div class="number">{sum(len(v) for v in all_results.values()):,}</div>
                <div class="label">Total Data (bytes)</div>
            </div>
            <div class="stat">
                <div class="number">{duration:.0f}</div>
                <div class="label">Seconds</div>
            </div>
        </div>
"""

    for phase_num in sorted(all_results.keys()):
        label = phase_label(phase_num)
        content = all_results[phase_num]
        # Escape HTML
        safe_content = content.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        truncated = safe_content[:10000] + ("\n[... TRUNCATED ...]" if len(safe_content) > 10000 else "")

        html += f"""
        <div class="phase-section">
            <div class="phase-header" onclick="togglePhase('phase_{phase_num}')">
                <h2>{label}</h2>
                <span class="toggle">▶</span>
            </div>
            <div class="phase-content" id="phase_{phase_num}">
                <pre>{truncated}</pre>
            </div>
        </div>
"""

    html += f"""
        <div class="footer">
            <p>Generated by Deep Recon v4.0 | {scan_end}</p>
            <p style="margin-top:5px;">Authorized Penetration Testing Only</p>
        </div>
    </div>
    <script>
        function togglePhase(id) {{
            const el = document.getElementById(id);
            el.classList.toggle('active');
        }}
    </script>
</body>
</html>"""

    filepath = os.path.join(G.output_dir, "report.html")
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        safe_print(t("html_report_file", path=filepath))
        log_info(f"HTML report written: {filepath}")
    except OSError as e:
        log_error(f"Failed to write HTML report: {e}")
    return filepath


def phase_11_final_report():
    """Phase 11: Compile Final Report (TXT + HTML)."""
    plabel = phase_label(11)
    safe_print(t("generating_report"))
    progress_bar(10, plabel)

    now = datetime.datetime.now()
    scan_end = now.isoformat()
    scan_start = G.scan_start_time.isoformat() if G.scan_start_time else scan_end
    duration = (now - G.scan_start_time).total_seconds() if G.scan_start_time else 0

    report = f"""
{'═' * 70}
                    DEEP RECON v4.0 - FINAL REPORT
{'═' * 70}

{'═' * 70}
                         EXECUTIVE SUMMARY
{'═' * 70}

Target: {G.target_url}
Hostname: {G.target_host}
IP Address: {resolve_host()}
Scan Level: {G.scan_level}
Language: {G.lang.upper()}
Start Time: {scan_start}
End Time: {scan_end}
Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)

AI Models Used:
"""
    for m in G.models_config:
        report += f"  - {m['name']} ({m['type']}: {m['model']})\n"
    if not G.models_config:
        report += "  - None (AI analysis skipped)\n"

    all_results = G.get_results()
    report += f"\n{'═' * 70}\n                       PHASE SUMMARY\n{'═' * 70}\n"

    for phase_num in sorted(all_results.keys()):
        label = phase_label(phase_num)
        content = all_results[phase_num]
        report += f"\n  {label} - Output size: {len(content):,} bytes\n"

    report += f"\n{'═' * 70}\n                      DETAILED RESULTS\n{'═' * 70}\n"

    for phase_num in sorted(all_results.keys()):
        label = phase_label(phase_num)
        content = all_results[phase_num]
        report += f"\n{'█' * 70}\n  {label} - DETAILED OUTPUT\n{'█' * 70}\n\n"
        if len(content) > 20000:
            report += content[:20000] + "\n\n[... TRUNCATED ...]\n"
        else:
            report += content

    report += f"\n{'═' * 70}\n                          END OF REPORT\n{'═' * 70}\n"
    report += f"Generated by: Deep Recon v4.0\nTimestamp: {scan_end}\n{'═' * 70}\n"

    write_result(11, "deep_recon_report.txt", report, "Deep Recon v4.0 Report Generator",
                 f"Compiled from {len(all_results)} phases")
    progress_bar(70, plabel)

    # Generate HTML report
    generate_html_report()
    progress_bar(100, plabel)
    safe_print(t("completed", phase=plabel))
    return report


# ═══════════════════════════════════════════════════════════════════
# CONSOLIDATED & AI EXPLANATION
# ═══════════════════════════════════════════════════════════════════

def create_consolidated_file():
    """Create consolidated results file."""
    safe_print(t("consolidating"))
    filepath = os.path.join(G.output_base, "consolidated_all_results.txt")
    all_results = G.get_results()
    now = datetime.datetime.now()

    content = f"""
{'═' * 70}
          CONSOLIDATED SCAN RESULTS - DEEP RECON v4.0
{'═' * 70}

Target: {G.target_url}
Scan Level: {G.scan_level}
Date: {now.strftime('%Y-%m-%d %H:%M:%S')}
Duration: {(now - G.scan_start_time).total_seconds():.1f} seconds
Total Phases: {len(all_results)}
{'═' * 70}

"""
    for phase_num in sorted(all_results.keys()):
        label = phase_label(phase_num)
        content += f"\n{'█' * 70}\n  {label}\n{'█' * 70}\n\n"
        content += all_results[phase_num] + "\n"

    content += f"\n{'═' * 70}\n  END OF CONSOLIDATED RESULTS\n{'═' * 70}\n"

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
    except OSError as e:
        log_error(f"Failed to write consolidated file: {e}")
    safe_print(t("consolidated_file", path=filepath))


def create_ai_explanation_file():
    """Create AI explanation file."""
    if not G.models_config:
        filepath = os.path.join(G.output_base, "ai_full_explanation.txt")
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("AI Explanation: Skipped (no AI models configured)\n")
        except OSError:
            pass
        safe_print(t("ai_explanation_file", path=filepath))
        return

    safe_print(t("ai_analyzing"))
    filepath = os.path.join(G.output_base, "ai_full_explanation.txt")
    all_results = G.get_results()

    all_data = ""
    for phase_num in sorted(all_results.keys()):
        all_data += all_results[phase_num]
    if len(all_data) > 25000:
        all_data = all_data[:25000] + "\n\n[... TRUNCATED ...]"

    lang_instruction = "Respond in English." if G.lang == "en" else "أجب باللغة العربية."
    explanation_prompt = f"""You are a senior cybersecurity instructor explaining penetration test results to a client.

Target: {G.target_url}
Scan Level: {G.scan_level}

Here are ALL the scan results:
{all_data}

{lang_instruction}

Provide a COMPLETE explanation of ALL findings:
1. OVERVIEW: What was scanned and what was found
2. RECONNAISSANCE FINDINGS
3. PORT FINDINGS
4. TECHNOLOGY FINDINGS
5. DIRECTORY FINDINGS
6. VULNERABILITY FINDINGS
7. API FINDINGS
8. SSL/TLS FINDINGS
9. DNS FINDINGS
10. CVE FINDINGS
11. OVERALL RISK ASSESSMENT
12. PRIORITY REMEDIATION: Top 10 actions

For each finding explain: What it is, Why it matters, How risky, What to do."""

    model_cfg = G.models_config[0]
    explanation = call_model(model_cfg, explanation_prompt, timeout=90)
    formatted = f"AI Explanation - {model_cfg['name']}\n{'═' * 70}\n\n{explanation}\n"

    for other_model in G.models_config[1:]:
        summary_prompt = f"Summarize this security scan in a concise executive summary (max 500 words).\n\n{explanation[:8000]}"
        try:
            summary = call_model(other_model, summary_prompt, timeout=45)
            formatted += f"\nAdditional Analysis ({other_model['name']}):\n{'─' * 70}\n{summary}\n\n"
        except Exception:
            formatted += f"\nAdditional Analysis ({other_model['name']}): Unavailable\n\n"

    formatted += f"\n{'═' * 70}\n  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    formatted += f"  Models: {', '.join(m['name'] for m in G.models_config)}\n{'═' * 70}\n"

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(formatted)
    except OSError as e:
        log_error(f"Failed to write AI explanation: {e}")
    safe_print(t("ai_explanation_file", path=filepath))


# ═══════════════════════════════════════════════════════════════════
# MODEL SELECTION
# ═══════════════════════════════════════════════════════════════════

def detect_ollama_models():
    """Detect installed Ollama models."""
    try:
        result = subprocess.run(["ollama", "ls"], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            models = []
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if parts:
                    models.append(parts[0])
            return models
        return []
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    except Exception:
        return []


def select_ollama_models():
    """Let user select from detected/available Ollama models."""
    safe_print(t("detecting_models"))
    installed = detect_ollama_models()

    if not installed:
        safe_print(t("no_ollama"))
        return []

    safe_print(t("installed_models"))
    for i, model in enumerate(installed, 1):
        size_info = ""
        for qm in OLLAMA_QWEN_MODELS:
            if qm["tag"] in model:
                size_info = f" ({qm['size']})"
                break
        safe_print(f"    {Fore.GREEN}[{i}]{Style.RESET_ALL} {model}{size_info}")

    # Show recommended missing models
    available_qwen = [qm["tag"] for qm in OLLAMA_QWEN_MODELS]
    missing_qwen = [qm for qm in OLLAMA_QWEN_MODELS if qm["tag"] not in installed]
    if missing_qwen:
        safe_print(f"\n    {Fore.YELLOW}[!] Recommended models not installed:{Style.RESET_ALL}")
        offset = len(installed)
        for i, qm in enumerate(missing_qwen, offset + 1):
            safe_print(f"    {Fore.YELLOW}[{i}]{Style.RESET_ALL} {qm['tag']} ({qm['size']}) - NOT INSTALLED")
            installed.append(qm["tag"])

    safe_print("")
    selected = []
    while True:
        choice = input(t("select_model")).strip()
        if choice.lower() == 'q' or choice == '':
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(installed):
                model_name = installed[idx]
                local_installed = detect_ollama_models()
                if model_name in local_installed:
                    confirm = input(t("model_found", model=model_name)).strip().lower()
                    if confirm != 'n':
                        name = model_name
                        for qm in OLLAMA_QWEN_MODELS:
                            if qm["tag"] == model_name:
                                name = f"Qwen {qm['size']} (Local)"
                                break
                        selected.append({"type": "ollama", "model": model_name, "name": name})
                else:
                    safe_print(t("model_not_found", model=model_name))
                    confirm = input(t("pull_model", model=model_name)).strip().lower()
                    if confirm != 'n':
                        safe_print(t("pulling_model", model=model_name))
                        try:
                            subprocess.run(["ollama", "pull", model_name], timeout=300)
                            safe_print(t("pull_complete", model=model_name))
                            name = model_name
                            for qm in OLLAMA_QWEN_MODELS:
                                if qm["tag"] == model_name:
                                    name = f"Qwen {qm['size']} (Local)"
                                    break
                            selected.append({"type": "ollama", "model": model_name, "name": name})
                        except Exception:
                            safe_print(t("pull_failed", model=model_name))
        except (ValueError, IndexError):
            pass

    return selected


def select_openrouter_model():
    """Select OpenRouter model."""
    safe_print(t("api_model_select"))
    choice = input(t("select_api_model")).strip()
    if choice in OPENROUTER_FREE_MODELS:
        model = OPENROUTER_FREE_MODELS[choice]
    elif choice == "5":
        model = input(t("custom_api_model")).strip()
    else:
        model = choice.strip()

    if model:
        name = model.split("/")[-1].replace(":free", "").replace(":latest", "")
        return {"type": "openrouter", "model": model, "name": f"{name} (Cloud)"}
    return None


def get_api_key():
    """Get OpenRouter API key from user."""
    key = input(t("api_key")).strip()
    if not key:
        safe_print(f"  {Fore.DIM}[+] Using default free model (no API key needed){Style.RESET_ALL}")
        return ""
    return key


# ═══════════════════════════════════════════════════════════════════
# CONFIG & SETUP
# ═══════════════════════════════════════════════════════════════════

def save_config():
    """Save scan configuration to JSON."""
    config = {
        "target": G.target_url,
        "scan_level": G.scan_level,
        "language": G.lang,
        "models": [{"type": m["type"], "model": m["model"]} for m in G.models_config],
        "timestamp_start": G.scan_start_time.isoformat() if G.scan_start_time else "",
        "hostname": G.target_host,
        "ip_address": resolve_host(),
        "proxy": G.proxy,
        "rate_delay": G.rate_delay,
    }
    config_dir = os.path.join(G.output_dir, "00_config")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "scan_config.json")
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log_error(f"Failed to save config: {e}")
    safe_print(t("saving_config"))


def setup_output_directory():
    """Create output directory structure."""
    ts = get_timestamp()["file"]
    safe_host = re.sub(r'[^\w\.-]', '_', G.target_host)
    G.output_dir = f"deep_recon_{safe_host}_{ts}"
    G.output_base = "."
    os.makedirs(G.output_dir, exist_ok=True)

    for phase_num in PHASE_NAMES:
        phase_dir = os.path.join(G.output_dir, f"{phase_num:02d}_{PHASE_NAMES[phase_num]}")
        os.makedirs(phase_dir, exist_ok=True)

    raw_dir = os.path.join(G.output_dir, "raw_data")
    os.makedirs(raw_dir, exist_ok=True)

    safe_print(t("results_dir", path=os.path.abspath(G.output_dir)))


def get_phases_for_level(level):
    """Return set of phase numbers for a scan level."""
    if level == "quick":
        return {0, 1, 3, 4, 11}
    elif level == "standard":
        return {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11}
    elif level == "deep":
        return {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
    elif level == "custom":
        return G.selected_phases
    return {0, 1, 3, 4, 11}


# ═══════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ═══════════════════════════════════════════════════════════════════

def run_scan():
    """Execute the scan based on selected phases."""
    phases = get_phases_for_level(G.scan_level)
    log_info(f"Starting scan: {G.target_url}, level={G.scan_level}, phases={sorted(phases)}")

    if 0 in phases:
        phase_00_whois()
    if 1 in phases:
        phase_01_reconnaissance()
    if 2 in phases:
        full_port = G.scan_level == "deep"
        phase_02_port_scanning(full=full_port)
    if 3 in phases:
        phase_03_web_fingerprint()
    if 4 in phases:
        phase_04_directory_discovery()
    if 5 in phases:
        phase_05_vulnerability_scanning()
    if 6 in phases:
        phase_06_api_endpoint_hunting()
    if 7 in phases:
        phase_07_ssl_tls_analysis()
    if 8 in phases:
        phase_08_dns_enumeration()
    if 9 in phases:
        phase_09_cve_matching()
    if 10 in phases:
        phase_10_ai_analysis()
    if 11 in phases:
        phase_11_final_report()

    create_consolidated_file()
    create_ai_explanation_file()
    log_info("Scan completed successfully")


def main():
    """Main entry point."""
    # Clear screen
    os.system('clear' if os.name != 'nt' else 'cls')

    # Show banner
    print(t("banner"))

    # 1. Language Selection
    print(t("select_lang"))
    print(t("lang_en"))
    print(t("lang_ar"))
    lang_choice = input("> ").strip()
    if lang_choice == "2":
        G.lang = "ar"
    else:
        G.lang = "en"

    print()
    print(t("banner"))

    # Authorization warning
    print(t("warning_auth"))
    auth = input(t("continue_prompt")).strip().lower()
    if auth == 'n':
        print(t("abort"))
        sys.exit(0)

    # 2. Target URL
    print()
    while True:
        target = input(t("enter_target")).strip()
        if not target:
            print(t("invalid_target"))
            continue
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
        try:
            parsed = urllib.parse.urlparse(target)
            if parsed.hostname:
                G.target_url = target.rstrip("/")
                G.target_host = parsed.hostname
                G.target_scheme = parsed.scheme or "https"
                G.base_path = parsed.path or "/"
                break
        except Exception:
            pass
        print(t("invalid_target"))

    # 3. Scan Level
    print()
    print(t("select_level"))
    print(t("quick"))
    print(t("standard"))
    print(t("deep"))
    print(t("custom"))

    while True:
        level_choice = input("> ").strip()
        if level_choice == "1":
            G.scan_level = "quick"
            break
        elif level_choice == "2":
            G.scan_level = "standard"
            break
        elif level_choice == "3":
            G.scan_level = "deep"
            break
        elif level_choice == "4":
            G.scan_level = "custom"
            print(t("select_custom_phases"))
            print(t("phase_list"))
            phases_input = input("> ").strip().lower()
            if phases_input == "all":
                G.selected_phases = set(range(0, 12))
            else:
                try:
                    G.selected_phases = set(int(p.strip()) for p in phases_input.split(",") if p.strip().isdigit())
                    G.selected_phases = {p for p in G.selected_phases if 0 <= p <= 11}
                    G.selected_phases.add(11)
                except ValueError:
                    G.selected_phases = {0, 1, 3, 4, 11}
            safe_print(f"  {Fore.GREEN}[+] Selected phases: {sorted(G.selected_phases)}{Style.RESET_ALL}")
            break
        else:
            print(f"  {Fore.RED}[!] Invalid choice{Style.RESET_ALL}")

    # 4. Proxy Configuration (NEW)
    print()
    proxy_input = input(t("proxy_config")).strip().lower()
    if proxy_input and proxy_input not in ['n', 'no', 'none', 'skip']:
        G.proxy = proxy_input
        if proxy_input.startswith("socks"):
            G.proxies = {"http": proxy_input, "https": proxy_input}
        else:
            G.proxies = {"http": proxy_input, "https": proxy_input}
        safe_print(t("proxy_set", proxy=proxy_input))
    
    # 5. Rate Limiting (NEW)
    rate_input = input(t("rate_limit")).strip()
    try:
        delay = float(rate_input)
        G.rate_delay = max(0, min(delay, 10))  # Clamp 0-10
    except ValueError:
        G.rate_delay = 0.1
    safe_print(t("rate_limit_set", delay=str(G.rate_delay)))

    # 6. AI Model Selection
    print()
    print(t("model_type"))
    print(t("ollama"))
    print(t("openrouter"))
    print(t("both"))
    print(t("skip_ai"))

    model_choice = input("> ").strip()

    if model_choice == "4":
        G.models_config = []
    elif model_choice == "1":
        selected = select_ollama_models()
        G.models_config = selected
    elif model_choice == "2":
        G.openrouter_api_key = get_api_key()
        model = select_openrouter_model()
        if model:
            G.models_config = [model]
    elif model_choice == "3":
        safe_print(f"\n  {Fore.CYAN}--- Ollama Models ---{Style.RESET_ALL}")
        ollama_models = select_ollama_models()
        safe_print(f"\n  {Fore.CYAN}--- OpenRouter Models ---{Style.RESET_ALL}")
        G.openrouter_api_key = get_api_key()
        openrouter_model = select_openrouter_model()
        G.models_config = ollama_models
        if openrouter_model:
            G.models_config.append(openrouter_model)

    if G.models_config:
        model_names = ", ".join(m["name"] for m in G.models_config)
        safe_print(t("selected_models", models=model_names))
    else:
        safe_print(t("no_ai_models"))

    # 7. Setup
    print()
    G.scan_start_time = datetime.datetime.now()
    setup_output_directory()
    setup_logging(G.output_dir)
    save_config()

    # 8. Run Scan
    print()
    safe_print(f"  {Fore.GREEN}{'═' * 63}{Style.RESET_ALL}")
    safe_print(f"  {Fore.GREEN}  Scan Starting: {G.target_url}{Style.RESET_ALL}")
    safe_print(f"  {Fore.GREEN}  Level: {G.scan_level.upper()}{Style.RESET_ALL}")
    safe_print(f"  {Fore.GREEN}  Phases: {sorted(get_phases_for_level(G.scan_level))}{Style.RESET_ALL}")
    if G.proxy:
        safe_print(f"  {Fore.GREEN}  Proxy: {G.proxy}{Style.RESET_ALL}")
    safe_print(f"  {Fore.GREEN}{'═' * 63}{Style.RESET_ALL}")
    print()

    try:
        run_scan()
    except KeyboardInterrupt:
        safe_print(f"\n  {Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        if G.get_results():
            create_consolidated_file()
        safe_print(t("results_dir", path=os.path.abspath(G.output_dir)))
        sys.exit(0)

    # 9. Done
    print()
    safe_print(t("total_progress"))
    print()
    safe_print(t("done"))
    print()
    safe_print(t("results_dir", path=os.path.abspath(G.output_dir)))
    safe_print(t("html_report_file", path=os.path.abspath(os.path.join(G.output_dir, "report.html"))))
    consolidated_path = os.path.join(G.output_base, "consolidated_all_results.txt")
    ai_explain_path = os.path.join(G.output_base, "ai_full_explanation.txt")
    if os.path.exists(consolidated_path):
        safe_print(t("consolidated_file", path=os.path.abspath(consolidated_path)))
    if os.path.exists(ai_explain_path):
        safe_print(t("ai_explanation_file", path=os.path.abspath(ai_explain_path)))


if __name__ == "__main__":
    main()

