# cache-decept
🎯 Web Cache Deception Scanner — Automated WCD detection for bug bounty hunters.



📋 Description
CacheDecept is an automated scanner for detecting Web Cache Deception (WCD) vulnerabilities. WCD is a security flaw where an attacker tricks a caching system (CDN, reverse proxy) into storing sensitive user-specific data in a publicly accessible cache.

🚀 Features
✅ 27 Sensitive Paths (account, profile, dashboard, settings, etc.)
✅ 35+ File Extensions (.css, .js, .png, .woff2, etc.)
✅ Path Delimiters (; ~ \ // .. @ ? = # ! etc.)
✅ Encoded Delimiters (%2e, %2f, %00, %0a, etc.)
✅ Unkeyed Headers (X-Forwarded-Host, X-Original-URL, etc.)
✅ Auth Pre-Check (avoid wasting requests on public pages)
✅ Rate Limit Detection (auto-detect 429 responses and pause)
✅ Keyword Detection (verify sensitive data in poisoned responses)
✅ Multi-threaded scanning with configurable rate limits
✅ Multiple Output Formats (HTML, JSON, TXT)
✅ Burp Suite Integration (Raw request support)
📦 Installation
git clone https://github.com/imoinGorGy/cache-decept.gitcd cache-deceptpip install -r requirements.txt
🚀 Usage
Basic Scan
bash

# Single URL
python3 cache_decept.py -u https://target.com/profile -ck "session=YOUR_SESSION"

# Multiple URLs from file
python3 cache_decept.py -f urls.txt -ck "session=YOUR_SESSION"
With Rate Limiting (Recommended!)
bash

# 1 request per second
python3 cache_decept.py -f urls.txt -ck "session=..." -rl 1

# 0.5 requests per second (2s delay)
python3 cache_decept.py -f urls.txt -ck "session=..." -rl 0.5
With Custom Sensitive Path
bash

python3 cache_decept.py -u https://target.com -p my-account -ck "session=..."
With Keyword Detection
bash

# Verify sensitive data is cached!
python3 cache_decept.py -u https://target.com/profile -ck "..." -k "Welcome John"
With Unkeyed Headers (Cache Poisoning)
bash

python3 cache_decept.py -u https://target.com/profile -ck "..." --headers
Full Featured Scan
bash

python3 cache_decept.py -f urls.txt -ck "session=..." \
    -rl 2 -t 10 --headers \
    --html --json -o report \
    -k "Welcome" -v
⚙️ Command Line Options
Flag
Description
Default
-u, --url	Single URL to test	—
-f, --file	File with URLs (one per line)	—
-p, --path	Sensitive path (e.g., my-account)	—
-ck, --cookies	Cookie string	—
--auth	Basic auth (user:pass)	—
--token	Bearer token	—
-rl, --rate-limit	Requests per second	0 (unlimited)
-t, --threads	Concurrent threads	5
--timeout	Request timeout (sec)	10
--rate-limit-pause	Wait time on 429 (sec)	60
-k, --keyword	Keyword to find in cached response	—
-H, --header	Custom HTTP header	—
--headers	Test with Unkeyed Headers	False
--ua	Custom User-Agent	Chrome
--max-variants	Max variants per URL	60
-o, --output	Output file base name	—
--html	Save HTML report	—
--json	Save JSON report	—
--txt	Save TXT report	—
-v, --verbose	Verbose mode	False

📖 How It Works
text

1. Auth Pre-Check     → Is this page sensitive?
2. Baseline Request   → Get original response
3. Variant Testing    → Test 60+ URL variations
4. Cache Detection    → Check Cache-Control, X-Cache, Age headers
5. No-Auth Verify     → Request again WITHOUT cookies!
6. Confirm Finding    → If content accessible without auth = 💥 CONFIRMED!
📸 Example Output
text

💥💥💥 CACHE DECEPTION FOUND! 💥💥💥
  URL:     https://target.com/api/user/profile
  Variant: https://target.com/api/user/profile8f3a1b2c.css
  Type:    extension.css
  Cache:   HIT | Control: public, max-age=3600
  No-Auth: 200 | Len: 4023
────────────────────────────────────────────────
🔍 Understanding the Vulnerability
Web Cache Deception works by:

Attacker sends a crafted URL (e.g., /profile.css) to victim
Victim (authenticated) clicks the link — their browser sends the request with cookies
Server ignores the fake extension and returns the real profile page
Cache sees .css extension and stores the response as "static" content
Attacker later requests the same URL — receives the victim's cached data!
⚠️ Ethical Usage
ONLY use this tool on systems you have explicit permission to test:

✅ Bug bounty programs (within scope)
✅ Your own systems
✅ Authorized penetration tests
❌ Never test without written permission!
🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first.

📝 License
MIT License — See LICENSE file.

🔗 References
Web Cache Deception Attack — Omer Gil
PortSwigger Web Security Academy — WCD Labs
Gotta Cache 'Em All — Filip ***
