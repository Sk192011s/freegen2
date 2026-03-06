// main.ts - Deno Deploy Entry Point (Redesigned UI + Hardened Security)

const kv = await Deno.openKv();

// ============== CONFIGURATION & ADMIN ==============
interface AppConfig {
  keys: string[];
  validFrom: string;
  validUntil: string;
  validityText: string;
  maxPerPeriod: number;
  keyVersion: string;
  tzOffset: number;
  profileIconUrl: string;
}

async function getConfig(): Promise<AppConfig> {
  const kvConfig = await kv.get<Partial<AppConfig>>(["app_config"]);

  const rawKeys = Deno.env.get("VLESS_KEYS") || "";
  const envKeys = rawKeys.split(",").map(k => k.trim()).filter(k => k.length > 0);

  const defaultConf: AppConfig = {
    keys: envKeys,
    validFrom: Deno.env.get("VALID_FROM") || "2026-03-05",
    validUntil: Deno.env.get("VALID_UNTIL") || "2026-03-12",
    validityText: Deno.env.get("VALIDITY_TEXT") || "၅ ရက် မတ်လ ၂၀၂၆ မှ ၁၂ ရက် မတ်လ ၂၀၂၆ ထိ",
    maxPerPeriod: parseInt(Deno.env.get("MAX_GENERATES_PER_PERIOD") || "2"),
    keyVersion: Deno.env.get("KEY_VERSION") || "v2",
    tzOffset: parseInt(Deno.env.get("TZ_OFFSET_MINUTES") || "390"),
    profileIconUrl: Deno.env.get("PROFILE_ICON_URL") || ""
  };

  if (kvConfig.value) {
    return { ...defaultConf, ...kvConfig.value };
  }
  return defaultConf;
}

// ============== SECURITY: HTML ESCAPING ==============

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function isValidUrl(url: string): boolean {
  if (!url) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:";
  } catch {
    return false;
  }
}

// ============== SECURITY: TIMING-SAFE COMPARE ==============

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    // Still do comparison to avoid length-based timing leak
    let result = a.length ^ b.length;
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      result |= (a.charCodeAt(i % a.length) || 0) ^ (b.charCodeAt(i % b.length) || 0);
    }
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// ============== ADMIN AUTH WITH BRUTE-FORCE PROTECTION ==============

async function checkAdminAuth(req: Request): Promise<boolean> {
  const auth = req.headers.get("authorization");
  if (!auth) return false;

  const adminPass = Deno.env.get("ADMIN_PASSWORD") || "admin123";
  const expected = `Basic ${btoa("admin:" + adminPass)}`;

  const ip = getClientIP(req);
  const lockoutKey = ["admin_lockout", ip];
  const lockoutEntry = await kv.get<{ count: number; lastAttempt: number }>(lockoutKey);

  if (lockoutEntry.value) {
    const { count, lastAttempt } = lockoutEntry.value;
    // Lockout for 15 minutes after 5 failed attempts
    if (count >= 5 && Date.now() - lastAttempt < 15 * 60 * 1000) {
      return false;
    }
  }

  const isValid = timingSafeEqual(auth, expected);

  if (!isValid) {
    const currentCount = lockoutEntry.value?.count || 0;
    await kv.set(lockoutKey, { count: currentCount + 1, lastAttempt: Date.now() }, { expireIn: 15 * 60 * 1000 });
  } else {
    // Reset on successful login
    await kv.delete(lockoutKey);
  }

  return isValid;
}

function requireAuth(): Response {
  return new Response("Unauthorized", {
    status: 401,
    headers: { "WWW-Authenticate": 'Basic realm="Admin"' },
  });
}

// ============== SECURITY: CSRF TOKEN ==============

async function generateCSRFToken(ip: string, userAgent: string): Promise<string> {
  const secret = Deno.env.get("CSRF_SECRET") || "pagaduu-csrf-xK9#mP2$vL7@nQ4-2026";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const raw = `${ip}||${userAgent}||${hour}||${secret}`;
  return await hashSHA256(raw);
}

async function validateCSRFToken(token: string, ip: string, userAgent: string): Promise<boolean> {
  const secret = Deno.env.get("CSRF_SECRET") || "pagaduu-csrf-xK9#mP2$vL7@nQ4-2026";
  const hour = Math.floor(Date.now() / (1000 * 60 * 60));
  const current = await hashSHA256(`${ip}||${userAgent}||${hour}||${secret}`);
  const previous = await hashSHA256(`${ip}||${userAgent}||${hour - 1}||${secret}`);
  return timingSafeEqual(token, current) || timingSafeEqual(token, previous);
}

// ============== FINGERPRINT & RATE LIMITING ==============

async function hashSHA256(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
}

async function generateServerFingerprint(ip: string, userAgent: string): Promise<string> {
  const salt = Deno.env.get("FP_SALT") || "pagaduu-fp-salt-2026";
  const raw = `${ip}||${userAgent}||${salt}`;
  return await hashSHA256(raw);
}

function isWithinValidPeriod(config: AppConfig): boolean {
  const now = Date.now();
  const fromLocal = new Date(config.validFrom + "T00:00:00");
  const untilLocal = new Date(config.validUntil + "T23:59:59");

  const fromUTC = fromLocal.getTime() - (config.tzOffset * 60 * 1000);
  const untilUTC = untilLocal.getTime() - (config.tzOffset * 60 * 1000);

  return now >= fromUTC && now <= untilUTC;
}

function getValidUntilUTC(config: AppConfig): number {
  const untilLocal = new Date(config.validUntil + "T23:59:59");
  return untilLocal.getTime() - (config.tzOffset * 60 * 1000);
}

async function checkRateLimit(
  fingerprint: string,
  config: AppConfig
): Promise<{ allowed: boolean; remaining: number; message: string }> {
  if (!isWithinValidPeriod(config)) {
    return {
      allowed: false,
      remaining: 0,
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။"
    };
  }

  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const kvKey = ["rate_limit_period", fingerprint, periodKey];

  const entry = await kv.get<number>(kvKey);
  const count = entry.value || 0;

  if (count >= config.maxPerPeriod) {
    return {
      allowed: false,
      remaining: 0,
      message: `ဤ Key သက်တမ်းအတွင်း Generate လုပ်ခွင့် (${config.maxPerPeriod} ကြိမ်) ကုန်သွားပါပြီ။ Key အသစ်ထွက်လာရင် ပြန်သုံးလို့ ရပါမယ်။`
    };
  }

  return {
    allowed: true,
    remaining: config.maxPerPeriod - count,
    message: ""
  };
}

async function incrementRateLimitAtomic(
  fingerprint: string,
  ipFingerprint: string,
  config: AppConfig
): Promise<boolean> {
  const periodKey = `${config.keyVersion}_${config.validFrom}_${config.validUntil}`;
  const fpKey = ["rate_limit_period", fingerprint, periodKey];
  const ipKey = ["rate_limit_period", ipFingerprint, periodKey];

  const untilUTC = getValidUntilUTC(config);
  const expireIn = Math.max(untilUTC - Date.now() + 86400000, 86400000);

  const maxRetries = 10;
  for (let i = 0; i < maxRetries; i++) {
    const fpEntry = await kv.get<number>(fpKey);
    const ipEntry = await kv.get<number>(ipKey);
    const fpCount = fpEntry.value || 0;
    const ipCount = ipEntry.value || 0;

    const result = await kv.atomic()
      .check(fpEntry)
      .check(ipEntry)
      .set(fpKey, fpCount + 1, { expireIn })
      .set(ipKey, ipCount + 1, { expireIn })
      .commit();

    if (result.ok) return true;
    const jitter = Math.random() * 20;
    await new Promise(resolve => setTimeout(resolve, 30 * (i + 1) + jitter));
  }
  return false;
}

// ============== TOTAL GENERATE COUNTER ==============

async function incrementTotalCount(): Promise<number> {
  const key = ["stats", "total_generates"];
  const maxRetries = 10;
  for (let i = 0; i < maxRetries; i++) {
    const entry = await kv.get<number>(key);
    const count = entry.value || 0;
    const result = await kv.atomic()
      .check(entry)
      .set(key, count + 1)
      .commit();
    if (result.ok) return count + 1;
    const jitter = Math.random() * 10;
    await new Promise(resolve => setTimeout(resolve, 20 * (i + 1) + jitter));
  }
  return -1;
}

async function getTotalCount(): Promise<number> {
  const entry = await kv.get<number>(["stats", "total_generates"]);
  return entry.value || 0;
}

// ============== KEY MANAGEMENT ==============

function getRandomKey(config: AppConfig): { key: string } | null {
  if (!config.keys || config.keys.length === 0) return null;

  const randomBytes = new Uint32Array(1);
  crypto.getRandomValues(randomBytes);
  const randomIndex = randomBytes[0] % config.keys.length;
  const key = config.keys[randomIndex];

  return { key };
}

// ============== SECURE PAYLOAD: Server-side token store ==============
// Instead of sending the AES key to the client (which defeats encryption),
// we store the decrypted data server-side with a one-time retrieval token.

async function storePayloadToken(data: Record<string, unknown>): Promise<string> {
  const tokenBytes = new Uint8Array(32);
  crypto.getRandomValues(tokenBytes);
  const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, "0")).join("");

  await kv.set(["payload_token", token], data, { expireIn: 5 * 60 * 1000 }); // 5 min TTL
  return token;
}

async function retrievePayloadToken(token: string): Promise<Record<string, unknown> | null> {
  if (!token || token.length !== 64 || !/^[0-9a-f]+$/.test(token)) return null;

  const key = ["payload_token", token];
  const entry = await kv.get<Record<string, unknown>>(key);
  if (!entry.value) return null;

  // One-time use: delete after retrieval
  await kv.delete(key);
  return entry.value;
}

// ============== RESPONSE HELPERS ==============

function jsonResponse(data: unknown, status = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      "Pragma": "no-cache",
      "Expires": "0",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "X-XSS-Protection": "1; mode=block",
      "Referrer-Policy": "no-referrer",
      ...extraHeaders,
    }
  });
}

function getClientIP(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || req.headers.get("cf-connecting-ip")
    || req.headers.get("x-real-ip")
    || "unknown";
}

function validateRequest(req: Request): { valid: boolean; error?: string } {
  const ua = req.headers.get("user-agent") || "";
  if (!ua || ua.length < 10) {
    return { valid: false, error: "Invalid request" };
  }
  // Block common bots
  const botPatterns = /curl|wget|python|scrapy|httpclient|bot|spider/i;
  if (botPatterns.test(ua)) {
    return { valid: false, error: "Blocked" };
  }
  return { valid: true };
}

// ============== NONCE GENERATOR ==============

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ============== API HANDLERS ==============

async function handleGenerate(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  const validation = validateRequest(req);
  if (!validation.valid) {
    return jsonResponse({ success: false, error: "invalid_request", message: "ခွင့်မပြုပါ။" }, 403);
  }

  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  // Request timing check (must be at least 800ms after page load)
  let body: Record<string, unknown>;
  try {
    body = await req.json();

    // Honeypot check
    if (body.website && (body.website as string).length > 0) {
      // Silently return fake success to not tip off bots
      return jsonResponse({ success: true, token: "fake-" + generateNonce(), remaining: 0 });
    }

    // Timing check
    const requestTime = body.t as number;
    if (!requestTime || Date.now() - requestTime > 30000 || Date.now() - requestTime < 300) {
      return jsonResponse({ success: false, error: "invalid_request", message: "ခွင့်မပြုပါ။" }, 403);
    }

    if (!body.csrf_token || !(await validateCSRFToken(body.csrf_token as string, ip, userAgent))) {
      return jsonResponse({ success: false, error: "invalid_token", message: "Session သက်တမ်းကုန်ပါပြီ။ Page ကို Refresh လုပ်ပါ။" }, 403);
    }
  } catch {
    return jsonResponse({ success: false, error: "invalid_body", message: "ခွင့်မပြုပါ။" }, 400);
  }

  const config = await getConfig();

  if (!isWithinValidPeriod(config)) {
    return jsonResponse({
      success: false,
      error: "expired",
      message: "လက်ရှိ Key သက်တမ်း ကုန်ဆုံးနေပါသည်။ Key အသစ်ထွက်လာရင် ပြန်လာပါ။"
    }, 403);
  }

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-pagaduu-salt`);

  const fpCheck = await checkRateLimit(fingerprint, config);
  const ipCheck = await checkRateLimit(ipFingerprint, config);

  if (!fpCheck.allowed || !ipCheck.allowed) {
    const message = !fpCheck.allowed ? fpCheck.message : ipCheck.message;
    return jsonResponse({ success: false, error: "limit_reached", message, remaining: 0 }, 429);
  }

  const result = getRandomKey(config);
  if (!result) {
    return jsonResponse({ success: false, error: "no_keys", message: "လက်ရှိ Key မရှိပါ။ နောက်မှ ပြန်လာပါ။" }, 503);
  }

  const incrementSuccess = await incrementRateLimitAtomic(fingerprint, ipFingerprint, config);
  if (!incrementSuccess) {
    return jsonResponse({ success: false, error: "server_busy", message: "Server အလုပ်များနေပါသည်။ ခဏစောင့်၍ ထပ်ကြိုးစားပါ။" }, 503);
  }

  const totalCount = await incrementTotalCount();
  const remaining = Math.min(fpCheck.remaining, ipCheck.remaining) - 1;

  // Store payload server-side, return a one-time token
  const payloadToken = await storePayloadToken({
    key: result.key,
    validityText: config.validityText,
    remaining,
    totalGenerated: totalCount,
    ts: Date.now()
  });

  return jsonResponse({ success: true, token: payloadToken, remaining });
}

async function handleRetrieve(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  const validation = validateRequest(req);
  if (!validation.valid) {
    return jsonResponse({ success: false, error: "invalid_request" }, 403);
  }

  try {
    const body = await req.json();
    const token = body.token as string;

    const data = await retrievePayloadToken(token);
    if (!data) {
      return jsonResponse({ success: false, error: "invalid_token", message: "Token မှားယွင်းနေပါသည် သို့မဟုတ် သက်တမ်းကုန်ပါပြီ။" }, 404);
    }

    return jsonResponse({ success: true, data });
  } catch {
    return jsonResponse({ success: false, error: "invalid_body" }, 400);
  }
}

async function handleCheckRemaining(req: Request): Promise<Response> {
  if (req.method !== "POST") return jsonResponse({ error: "Method not allowed" }, 405);

  const config = await getConfig();
  const ip = getClientIP(req);
  const userAgent = req.headers.get("user-agent") || "unknown";

  const fingerprint = await generateServerFingerprint(ip, userAgent);
  const ipFingerprint = await hashSHA256(`ip-only-${ip}-pagaduu-salt`);

  const withinPeriod = isWithinValidPeriod(config);

  let remaining = 0;
  let allowed = false;

  if (withinPeriod) {
    const fpCheck = await checkRateLimit(fingerprint, config);
    const ipCheck = await checkRateLimit(ipFingerprint, config);
    remaining = Math.min(fpCheck.remaining, ipCheck.remaining);
    allowed = fpCheck.allowed && ipCheck.allowed;
  }

  const csrfToken = await generateCSRFToken(ip, userAgent);
  const totalGenerated = await getTotalCount();

  return jsonResponse({
    remaining,
    allowed,
    maxPerPeriod: config.maxPerPeriod,
    validityText: config.validityText,
    validFrom: config.validFrom,
    validUntil: config.validUntil,
    withinPeriod,
    keyVersion: config.keyVersion,
    totalGenerated,
    csrf_token: csrfToken
  });
}

// ============== DEBUG & ADMIN API ==============

async function handleDebug(req: Request): Promise<Response> {
  const authKey = Deno.env.get("DEBUG_AUTH_KEY") || "";
  if (!authKey) return new Response("Not found", { status: 404 });

  const url = new URL(req.url);
  const providedKey = url.searchParams.get("key") || "";
  if (!timingSafeEqual(providedKey, authKey)) return new Response("Not found", { status: 404 });

  const config = await getConfig();
  const now = new Date();

  return jsonResponse({
    currentTimeUTC: now.toISOString(),
    config: { keysCount: config.keys.length, validFrom: config.validFrom, validUntil: config.validUntil, keyVersion: config.keyVersion, maxPerPeriod: config.maxPerPeriod },
    computed: { isWithinPeriod: isWithinValidPeriod(config) }
  });
}

async function handleAdminAPI(req: Request): Promise<Response> {
  if (!(await checkAdminAuth(req))) return requireAuth();

  if (req.method === "GET") {
    const config = await getConfig();
    return jsonResponse(config);
  }

  if (req.method === "POST") {
    try {
      const body = await req.json();
      const currentConfig = await getConfig();

      // Validate inputs
      const maxPerPeriod = parseInt(body.maxPerPeriod ?? currentConfig.maxPerPeriod);
      if (isNaN(maxPerPeriod) || maxPerPeriod < 1 || maxPerPeriod > 100) {
        return jsonResponse({ success: false, error: "Invalid maxPerPeriod (1-100)" }, 400);
      }

      // Validate dates
      const validFrom = body.validFrom ?? currentConfig.validFrom;
      const validUntil = body.validUntil ?? currentConfig.validUntil;
      if (!/^\d{4}-\d{2}-\d{2}$/.test(validFrom) || !/^\d{4}-\d{2}-\d{2}$/.test(validUntil)) {
        return jsonResponse({ success: false, error: "Invalid date format (YYYY-MM-DD)" }, 400);
      }

      // Validate keys array
      let keys = currentConfig.keys;
      if (body.keys !== undefined) {
        if (!Array.isArray(body.keys)) {
          return jsonResponse({ success: false, error: "Keys must be an array" }, 400);
        }
        keys = body.keys.map((k: unknown) => String(k).trim()).filter((k: string) => k.length > 0);
      }

      // Validate profileIconUrl
      let profileIconUrl = body.profileIconUrl ?? currentConfig.profileIconUrl;
      if (profileIconUrl && !isValidUrl(profileIconUrl)) {
        profileIconUrl = "";
      }

      const newConfig: AppConfig = {
        ...currentConfig,
        keys,
        validFrom,
        validUntil,
        validityText: String(body.validityText ?? currentConfig.validityText).slice(0, 200),
        maxPerPeriod,
        keyVersion: String(body.keyVersion ?? currentConfig.keyVersion).slice(0, 20),
        profileIconUrl
      };

      await kv.set(["app_config"], newConfig);
      return jsonResponse({ success: true, message: "Configuration updated successfully." });
    } catch {
      return jsonResponse({ success: false, error: "Invalid payload" }, 400);
    }
  }
  return jsonResponse({ error: "Method not allowed" }, 405);
}

// ============== ADMIN HTML PAGE ==============

function getAdminHTML(): string {
  const nonce = generateNonce();
  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Pagaduu Admin Panel</title>
  <style nonce="${nonce}">
    *{margin:0;padding:0;box-sizing:border-box}
    body{background:#05050e;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
    .card{max-width:560px;width:100%;background:linear-gradient(145deg,rgba(15,15,45,0.95),rgba(10,10,30,0.98));padding:36px 32px;border-radius:20px;border:1px solid rgba(255,255,255,0.06);box-shadow:0 20px 60px rgba(0,0,0,0.5)}
    h2{text-align:center;font-size:20px;background:linear-gradient(135deg,#818cf8,#c084fc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:28px}
    label{display:block;margin-top:18px;font-size:12px;font-weight:600;color:#94a3b8;letter-spacing:0.5px;text-transform:uppercase}
    input,textarea{width:100%;padding:12px 14px;margin-top:8px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);color:#fff;border-radius:10px;font-family:inherit;font-size:14px;transition:all 0.3s}
    input:focus,textarea:focus{outline:none;border-color:rgba(99,102,241,0.5);box-shadow:0 0 0 3px rgba(99,102,241,0.1);background:rgba(255,255,255,0.06)}
    textarea{resize:vertical}
    button[type="submit"]{margin-top:28px;width:100%;padding:14px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-weight:700;border:none;border-radius:12px;cursor:pointer;font-size:15px;transition:all 0.3s;letter-spacing:0.3px}
    button[type="submit"]:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(99,102,241,0.4)}
    button[type="submit"]:active{transform:translateY(0)}
    #msg{margin-top:18px;text-align:center;font-weight:600;font-size:13px;min-height:20px}
  </style>
</head>
<body>
  <div class="card">
    <h2>Pagaduu Admin Settings</h2>
    <form id="adminForm">
      <label>Profile Icon URL</label>
      <input type="url" id="profileIconUrl" placeholder="https://example.com/photo.jpg">
      <label>VLESS Keys (comma separated)</label>
      <textarea id="keys" rows="5" placeholder="vless://... , vless://..."></textarea>
      <label>Valid From</label>
      <input type="date" id="validFrom">
      <label>Valid Until</label>
      <input type="date" id="validUntil">
      <label>Validity Text</label>
      <input type="text" id="validityText" maxlength="200">
      <label>Max Generates Per User</label>
      <input type="number" id="maxPerPeriod" min="1" max="100">
      <label>Key Version</label>
      <input type="text" id="keyVersion" maxlength="20">
      <button type="submit">Save Changes</button>
    </form>
    <div id="msg"></div>
  </div>
  <script nonce="${nonce}">
    fetch('/api/admin/config').then(function(r){return r.json()}).then(function(d){
      document.getElementById('profileIconUrl').value=d.profileIconUrl||'';
      document.getElementById('keys').value=(d.keys||[]).join(',\\n');
      document.getElementById('validFrom').value=d.validFrom||'';
      document.getElementById('validUntil').value=d.validUntil||'';
      document.getElementById('validityText').value=d.validityText||'';
      document.getElementById('maxPerPeriod').value=d.maxPerPeriod||2;
      document.getElementById('keyVersion').value=d.keyVersion||'';
    });
    document.getElementById('adminForm').onsubmit=function(e){
      e.preventDefault();
      var m=document.getElementById('msg');
      m.style.color='#fbbf24';m.textContent='Saving...';
      var ks=document.getElementById('keys').value.split(',').map(function(k){return k.trim()}).filter(function(k){return k});
      fetch('/api/admin/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
        profileIconUrl:document.getElementById('profileIconUrl').value,
        keys:ks,
        validFrom:document.getElementById('validFrom').value,
        validUntil:document.getElementById('validUntil').value,
        validityText:document.getElementById('validityText').value,
        maxPerPeriod:parseInt(document.getElementById('maxPerPeriod').value),
        keyVersion:document.getElementById('keyVersion').value
      })}).then(function(r){
        if(r.ok){m.style.color='#34d399';m.textContent='Saved successfully!';}
        else{r.json().then(function(d){m.style.color='#f87171';m.textContent=d.error||'Error saving';});}
        setTimeout(function(){m.textContent=''},4000);
      });
    };
  </script>
</body>
</html>`;
}

// ============== MAIN HTML PAGE (REDESIGNED UI) ==============

function getHTML(config: AppConfig, nonce: string): string {

  const safeProfileUrl = config.profileIconUrl && isValidUrl(config.profileIconUrl)
    ? escapeHtml(config.profileIconUrl)
    : "";

  const profileIconHtml = safeProfileUrl
    ? `<img src="${safeProfileUrl}" alt="" style="width:100%;height:100%;border-radius:14px;object-fit:cover;" loading="lazy" referrerpolicy="no-referrer">`
    : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>`;

  return `<!DOCTYPE html>
<html lang="my">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
  <title>Pagaduu - VLESS Key Generator</title>
  <meta name="robots" content="noindex,nofollow">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Padauk:wght@400;700&family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">

  <style nonce="${nonce}">
    :root {
      --primary: #7c3aed;
      --primary-light: #a78bfa;
      --primary-glow: rgba(124,58,237,0.35);
      --accent: #06b6d4;
      --accent-light: #22d3ee;
      --bg: #030014;
      --surface: rgba(255,255,255,0.03);
      --surface-hover: rgba(255,255,255,0.06);
      --surface-active: rgba(255,255,255,0.08);
      --border: rgba(255,255,255,0.06);
      --border-hover: rgba(255,255,255,0.12);
      --text: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #475569;
      --success: #10b981;
      --danger: #ef4444;
      --warning: #f59e0b;
      --radius: 16px;
      --radius-sm: 12px;
      --radius-xs: 8px;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Padauk', 'Inter', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      overflow-x: hidden;
      -webkit-font-smoothing: antialiased;
    }

    /* ===== ANIMATED BACKGROUND ===== */
    .bg-scene {
      position: fixed; inset: 0;
      z-index: 0; pointer-events: none;
      overflow: hidden;
    }

    .bg-scene::before {
      content: '';
      position: absolute;
      width: 150vmax; height: 150vmax;
      top: 50%; left: 50%;
      transform: translate(-50%, -50%);
      background: conic-gradient(
        from 0deg,
        transparent 0%,
        rgba(124,58,237,0.06) 10%,
        transparent 20%,
        rgba(6,182,212,0.04) 30%,
        transparent 40%,
        rgba(236,72,153,0.05) 50%,
        transparent 60%,
        rgba(124,58,237,0.04) 70%,
        transparent 80%,
        rgba(6,182,212,0.06) 90%,
        transparent 100%
      );
      animation: bgRotate 60s linear infinite;
    }

    @keyframes bgRotate { to { transform: translate(-50%, -50%) rotate(360deg); } }

    .bg-mesh {
      position: absolute; inset: 0;
      background-image:
        radial-gradient(ellipse 600px 400px at 20% 20%, rgba(124,58,237,0.08), transparent),
        radial-gradient(ellipse 500px 500px at 80% 80%, rgba(6,182,212,0.06), transparent),
        radial-gradient(ellipse 400px 300px at 60% 30%, rgba(236,72,153,0.04), transparent);
    }

    .bg-grid {
      position: absolute; inset: 0;
      background-image:
        linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
      background-size: 80px 80px;
      mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, black 20%, transparent 70%);
      -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 40%, black 20%, transparent 70%);
    }

    .bg-orbs .orb {
      position: absolute;
      border-radius: 50%;
      filter: blur(80px);
      animation: orbDrift 30s ease-in-out infinite;
    }

    .bg-orbs .orb:nth-child(1) {
      width: 500px; height: 500px;
      background: rgba(124,58,237,0.12);
      top: -15%; left: -10%;
    }

    .bg-orbs .orb:nth-child(2) {
      width: 400px; height: 400px;
      background: rgba(6,182,212,0.08);
      bottom: -10%; right: -8%;
      animation-delay: -10s;
    }

    .bg-orbs .orb:nth-child(3) {
      width: 300px; height: 300px;
      background: rgba(236,72,153,0.06);
      top: 40%; left: 50%;
      animation-delay: -20s;
    }

    @keyframes orbDrift {
      0%, 100% { transform: translate(0, 0) scale(1); }
      33% { transform: translate(50px, -40px) scale(1.1); }
      66% { transform: translate(-30px, 50px) scale(0.9); }
    }

    .stars {
      position: fixed; inset: 0;
      z-index: 0; pointer-events: none;
    }

    .star {
      position: absolute;
      width: 2px; height: 2px;
      background: white;
      border-radius: 50%;
      animation: twinkle 4s ease-in-out infinite;
    }

    @keyframes twinkle {
      0%, 100% { opacity: 0; transform: scale(0.5); }
      50% { opacity: 0.7; transform: scale(1.2); }
    }

    /* ===== LAYOUT ===== */
    .app {
      position: relative;
      z-index: 1;
      max-width: 460px;
      margin: 0 auto;
      padding: 12px;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    /* ===== HEADER ===== */
    .header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 14px 18px;
      background: var(--surface);
      backdrop-filter: blur(40px);
      -webkit-backdrop-filter: blur(40px);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      transition: border-color 0.3s;
    }

    .header:hover { border-color: var(--border-hover); }

    .brand { display: flex; align-items: center; gap: 12px; }

    .brand-logo {
      width: 40px; height: 40px;
      border-radius: 14px;
      background: linear-gradient(135deg, var(--primary), #ec4899);
      display: flex; align-items: center; justify-content: center;
      box-shadow: 0 4px 20px var(--primary-glow);
      position: relative;
      overflow: hidden;
    }

    .brand-logo::after {
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.15));
      border-radius: inherit;
    }

    .brand-logo svg, .brand-logo img { width: 20px; height: 20px; color: white; position: relative; z-index: 1; }

    .brand-text h1 {
      font-size: 16px; font-weight: 800;
      background: linear-gradient(135deg, #e0e7ff, var(--primary-light));
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text;
      font-family: 'Inter', sans-serif;
      letter-spacing: -0.3px;
    }

    .brand-text span {
      font-size: 10px; color: var(--text-muted);
      letter-spacing: 2px; text-transform: uppercase;
      font-family: 'Inter', sans-serif;
    }

    .header-actions { display: flex; align-items: center; gap: 8px; }

    .btn-tg {
      display: flex; align-items: center; gap: 5px;
      padding: 6px 14px;
      background: rgba(6,182,212,0.08);
      border: 1px solid rgba(6,182,212,0.15);
      border-radius: var(--radius-xs);
      color: var(--accent-light);
      font-size: 11px; font-weight: 600;
      text-decoration: none;
      font-family: 'Inter', sans-serif;
      transition: all 0.3s;
    }

    .btn-tg:hover {
      background: rgba(6,182,212,0.15);
      border-color: rgba(6,182,212,0.3);
      transform: translateY(-1px);
    }

    .btn-tg svg { width: 12px; height: 12px; }

    .badge-pro {
      padding: 4px 10px;
      background: linear-gradient(135deg, var(--primary), #ec4899);
      border-radius: 20px;
      font-size: 9px; font-weight: 800;
      color: white;
      letter-spacing: 2px;
      text-transform: uppercase;
      font-family: 'Inter', sans-serif;
    }

    /* ===== VALIDITY BANNER ===== */
    .banner {
      display: flex; align-items: center; gap: 14px;
      padding: 14px 18px;
      background: var(--surface);
      backdrop-filter: blur(30px);
      -webkit-backdrop-filter: blur(30px);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      transition: all 0.3s;
    }

    .banner:hover { border-color: var(--border-hover); }

    .banner-icon {
      width: 42px; height: 42px;
      border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: center;
      flex-shrink: 0;
    }

    .banner.active .banner-icon {
      background: rgba(6,182,212,0.1);
      color: var(--accent-light);
    }

    .banner.expired .banner-icon {
      background: rgba(239,68,68,0.1);
      color: var(--danger);
    }

    .banner-icon svg { width: 20px; height: 20px; }

    .banner-body { flex: 1; min-width: 0; }

    .banner-title {
      font-size: 13px; font-weight: 700;
      margin-bottom: 2px;
    }

    .banner.active .banner-title { color: var(--accent-light); }
    .banner.expired .banner-title { color: #fca5a5; }

    .banner-sub {
      font-size: 11.5px; color: var(--text-muted);
      line-height: 1.5;
    }

    .banner.expired {
      border-color: rgba(239,68,68,0.15);
      background: linear-gradient(135deg, rgba(239,68,68,0.04), var(--surface));
    }

    .banner.active {
      border-color: rgba(6,182,212,0.12);
      background: linear-gradient(135deg, rgba(6,182,212,0.04), var(--surface));
    }

    /* ===== STATS GRID ===== */
    .stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }

    .stat {
      background: var(--surface);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 14px 6px;
      text-align: center;
      transition: all 0.3s;
      position: relative;
      overflow: hidden;
    }

    .stat::after {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      opacity: 0.8;
    }

    .stat:nth-child(1)::after { background: linear-gradient(90deg, var(--primary), #c084fc); }
    .stat:nth-child(2)::after { background: linear-gradient(90deg, var(--accent), #3b82f6); }
    .stat:nth-child(3)::after { background: linear-gradient(90deg, var(--warning), #f97316); }
    .stat:nth-child(4)::after { background: linear-gradient(90deg, var(--success), var(--accent)); }

    .stat:hover {
      border-color: var(--border-hover);
      transform: translateY(-2px);
      background: var(--surface-hover);
    }

    .stat-icon {
      width: 30px; height: 30px;
      margin: 0 auto 6px;
      border-radius: var(--radius-xs);
      display: flex; align-items: center; justify-content: center;
    }

    .stat-icon svg { width: 14px; height: 14px; }

    .stat:nth-child(1) .stat-icon { background: rgba(124,58,237,0.12); color: var(--primary-light); }
    .stat:nth-child(2) .stat-icon { background: rgba(6,182,212,0.12); color: var(--accent-light); }
    .stat:nth-child(3) .stat-icon { background: rgba(245,158,11,0.12); color: var(--warning); }
    .stat:nth-child(4) .stat-icon { background: rgba(16,185,129,0.12); color: var(--success); }

    .stat-val {
      font-size: 16px; font-weight: 800;
      color: white;
      font-family: 'Inter', sans-serif;
      letter-spacing: -0.5px;
    }

    .stat-lbl {
      font-size: 9px; color: var(--text-muted);
      margin-top: 2px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-family: 'Inter', sans-serif;
    }

    /* ===== MAIN CARD ===== */
    .main {
      flex: 1;
      background: var(--surface);
      backdrop-filter: blur(40px);
      -webkit-backdrop-filter: blur(40px);
      border: 1px solid var(--border);
      border-radius: 20px;
      padding: 28px 20px 24px;
      position: relative;
      overflow: hidden;
    }

    .main::before {
      content: '';
      position: absolute;
      top: -1px; left: 20%; right: 20%;
      height: 1px;
      background: linear-gradient(90deg, transparent, var(--primary-light), transparent);
      opacity: 0.3;
    }

    .hero { text-align: center; margin-bottom: 28px; }

    .hero-icon {
      width: 72px; height: 72px;
      margin: 0 auto 16px;
      border-radius: 22px;
      background: linear-gradient(135deg, var(--primary), #ec4899);
      display: flex; align-items: center; justify-content: center;
      position: relative;
      animation: heroFloat 4s ease-in-out infinite;
    }

    .hero-icon::before {
      content: '';
      position: absolute; inset: -6px;
      border-radius: 28px;
      background: linear-gradient(135deg, var(--primary), #ec4899);
      opacity: 0.2;
      filter: blur(16px);
      animation: heroPulse 4s ease-in-out infinite;
    }

    .hero-icon::after {
      content: '';
      position: absolute; inset: 0;
      border-radius: inherit;
      background: linear-gradient(135deg, transparent 40%, rgba(255,255,255,0.12));
    }

    .hero-icon svg { color: white; width: 32px; height: 32px; position: relative; z-index: 1; }

    @keyframes heroFloat {
      0%, 100% { transform: translateY(0); }
      50% { transform: translateY(-8px); }
    }

    @keyframes heroPulse {
      0%, 100% { opacity: 0.2; transform: scale(1); }
      50% { opacity: 0.35; transform: scale(1.05); }
    }

    .hero h2 {
      font-size: 22px; font-weight: 800;
      color: white;
      margin-bottom: 4px;
      letter-spacing: -0.3px;
    }

    .hero p { font-size: 13px; color: var(--text-secondary); }

    /* ===== COMPAT SECTION ===== */
    .compat {
      margin-bottom: 22px;
      padding: 16px;
      background: rgba(255,255,255,0.02);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
    }

    .compat-title {
      font-size: 11px; font-weight: 700;
      color: var(--primary-light);
      margin-bottom: 10px;
      display: flex; align-items: center; gap: 6px;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      font-family: 'Inter', sans-serif;
    }

    .compat-title svg { width: 13px; height: 13px; }

    .compat-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }

    .compat-tag {
      padding: 4px 12px;
      background: rgba(16,185,129,0.06);
      border: 1px solid rgba(16,185,129,0.15);
      border-radius: 6px;
      font-size: 11px; color: #34d399;
      font-weight: 600;
      font-family: 'Inter', sans-serif;
    }

    .compat-warn {
      display: flex; align-items: center; gap: 8px;
      padding: 10px 14px;
      background: rgba(239,68,68,0.04);
      border: 1px solid rgba(239,68,68,0.1);
      border-radius: var(--radius-xs);
      font-size: 11px; color: #fca5a5;
    }

    .compat-warn svg { width: 14px; height: 14px; flex-shrink: 0; color: var(--danger); }
    .compat-warn strong { color: #fca5a5; }

    /* ===== GENERATE BUTTON ===== */
    .hp-trap { position:absolute;left:-9999px;top:-9999px;opacity:0;height:0;width:0;overflow:hidden;pointer-events:none; }

    .gen-btn {
      width: 100%;
      padding: 16px 20px;
      border: none;
      border-radius: var(--radius-sm);
      background: linear-gradient(135deg, var(--primary), #c026d3);
      color: white;
      font-family: 'Padauk', sans-serif;
      font-size: 16px; font-weight: 700;
      cursor: pointer;
      display: flex; align-items: center; justify-content: center; gap: 10px;
      position: relative;
      overflow: hidden;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      letter-spacing: 0.3px;
    }

    .gen-btn::before {
      content: '';
      position: absolute; inset: 0;
      background: linear-gradient(135deg, transparent, rgba(255,255,255,0.1), transparent);
      transform: translateX(-100%);
      transition: transform 0.6s;
    }

    .gen-btn:hover::before { transform: translateX(100%); }

    .gen-btn:hover:not(:disabled) {
      transform: translateY(-3px);
      box-shadow: 0 12px 40px var(--primary-glow);
    }

    .gen-btn:active:not(:disabled) { transform: translateY(-1px); }

    .gen-btn:disabled {
      opacity: 0.35;
      cursor: not-allowed;
      transform: none !important;
      box-shadow: none !important;
    }

    .gen-btn:disabled::before { display: none; }
    .gen-btn svg { width: 20px; height: 20px; }

    .spinner {
      width: 20px; height: 20px;
      border: 2.5px solid rgba(255,255,255,0.25);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      display: none;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    /* ===== ERROR MSG ===== */
    .error {
      margin-top: 14px;
      padding: 14px 16px;
      background: rgba(239,68,68,0.05);
      border: 1px solid rgba(239,68,68,0.15);
      border-radius: var(--radius-sm);
      color: #fca5a5;
      font-size: 13px;
      display: none;
      align-items: center; gap: 10px;
      animation: shakeIn 0.5s ease;
    }

    .error.show { display: flex; }
    .error svg { width: 18px; height: 18px; flex-shrink: 0; color: var(--danger); }

    @keyframes shakeIn {
      0%, 100% { transform: translateX(0); }
      20% { transform: translateX(-6px); }
      40% { transform: translateX(6px); }
      60% { transform: translateX(-3px); }
      80% { transform: translateX(3px); }
    }

    /* ===== RESULT ===== */
    .result { margin-top: 20px; display: none; }
    .result.show { display: block; }

    .result-box {
      background: rgba(0,0,0,0.25);
      border: 1px solid rgba(16,185,129,0.12);
      border-radius: var(--radius);
      padding: 20px;
      position: relative;
      overflow: hidden;
      animation: resultReveal 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }

    .result-box::before {
      content: '';
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
      background: linear-gradient(90deg, var(--success), var(--accent));
    }

    @keyframes resultReveal {
      from { opacity: 0; transform: translateY(16px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }

    .result-label {
      display: flex; align-items: center; gap: 8px;
      margin-bottom: 14px;
      font-size: 12px; color: #34d399;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      font-family: 'Inter', sans-serif;
    }

    .result-label svg { width: 16px; height: 16px; }

    .result-key {
      background: rgba(0,0,0,0.35);
      border: 1px solid var(--border);
      border-radius: var(--radius-xs);
      padding: 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10.5px;
      color: var(--primary-light);
      word-break: break-all;
      line-height: 1.7;
      max-height: 120px;
      overflow-y: auto;
      user-select: all;
    }

    .result-footer {
      display: flex; align-items: center; justify-content: space-between;
      margin-top: 16px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      flex-wrap: wrap; gap: 10px;
    }

    .result-expire {
      display: flex; align-items: center; gap: 6px;
      font-size: 11.5px; color: var(--accent-light);
      font-family: 'Inter', sans-serif;
    }

    .result-expire svg { width: 14px; height: 14px; }

    .result-actions { display: flex; gap: 8px; }

    .btn-action {
      display: flex; align-items: center; gap: 6px;
      padding: 8px 16px;
      border: 1px solid rgba(124,58,237,0.2);
      border-radius: var(--radius-xs);
      background: rgba(124,58,237,0.06);
      color: var(--primary-light);
      font-family: 'Inter', sans-serif;
      font-size: 12px; font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }

    .btn-action:hover {
      background: var(--primary);
      color: white;
      border-color: var(--primary);
      transform: translateY(-1px);
    }

    .btn-action svg { width: 14px; height: 14px; }

    /* ===== INFO ROWS ===== */
    .info-row {
      margin-top: 12px;
      padding: 14px 16px;
      background: rgba(0,0,0,0.12);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: space-between;
      transition: border-color 0.3s;
    }

    .info-row:hover { border-color: var(--border-hover); }

    .info-row .ir-label {
      font-size: 12px; color: var(--text-secondary);
      display: flex; align-items: center; gap: 8px;
    }

    .info-row .ir-label svg { width: 15px; height: 15px; opacity: 0.6; }

    .info-row .ir-value {
      font-size: 15px; font-weight: 800;
      font-family: 'Inter', sans-serif;
      letter-spacing: -0.3px;
    }

    .info-row.remaining .ir-value { color: #fbbf24; }

    .info-row.total .ir-value {
      background: linear-gradient(135deg, #34d399, var(--accent-light));
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text;
    }

    .info-row.version .ir-value {
      color: var(--primary-light);
      font-size: 13px;
      text-transform: uppercase;
    }

    /* ===== HOW TO ===== */
    .howto {
      margin-top: 12px;
      background: rgba(0,0,0,0.12);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      overflow: hidden;
    }

    .howto-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 14px 16px;
      cursor: pointer;
      user-select: none;
      transition: background 0.3s;
    }

    .howto-header:hover { background: var(--surface-hover); }

    .howto-header .ht-label {
      font-size: 12.5px; color: var(--text-secondary);
      display: flex; align-items: center; gap: 8px;
      font-weight: 600;
    }

    .howto-header .ht-label svg { width: 15px; height: 15px; opacity: 0.6; }
    .howto-header .ht-arrow { color: var(--text-muted); transition: transform 0.3s; }
    .howto-header .ht-arrow svg { width: 15px; height: 15px; }
    .howto-header.open .ht-arrow { transform: rotate(180deg); }

    .howto-body { max-height: 0; overflow: hidden; transition: max-height 0.4s ease; }
    .howto-body.open { max-height: 500px; }

    .howto-steps {
      padding: 4px 16px 16px;
      font-size: 12.5px; color: var(--text-secondary);
      line-height: 1.8;
    }

    .step { display: flex; gap: 12px; margin-bottom: 10px; }

    .step-n {
      width: 24px; height: 24px;
      background: rgba(124,58,237,0.1);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px; font-weight: 800;
      color: var(--primary-light);
      flex-shrink: 0;
      margin-top: 2px;
      font-family: 'Inter', sans-serif;
    }

    .step .app-hl { color: var(--primary-light); font-weight: 700; }

    /* ===== TG FOOTER BAR ===== */
    .tg-bar {
      margin-top: 12px;
      padding: 14px 16px;
      background: rgba(6,182,212,0.03);
      border: 1px solid rgba(6,182,212,0.08);
      border-radius: var(--radius-sm);
      display: flex; align-items: center; justify-content: space-between;
    }

    .tg-bar-info { display: flex; align-items: center; gap: 12px; }

    .tg-bar-icon {
      width: 36px; height: 36px;
      background: rgba(6,182,212,0.08);
      border-radius: var(--radius-xs);
      display: flex; align-items: center; justify-content: center;
      color: var(--accent-light);
    }

    .tg-bar-icon svg { width: 17px; height: 17px; }

    .tg-bar-text { font-size: 10.5px; color: var(--text-muted); }
    .tg-bar-text strong { display: block; color: var(--accent-light); font-size: 12px; }

    .tg-bar-link {
      padding: 8px 16px;
      background: rgba(6,182,212,0.06);
      border: 1px solid rgba(6,182,212,0.15);
      border-radius: var(--radius-xs);
      color: var(--accent-light);
      font-family: 'Inter', sans-serif;
      font-size: 12px; font-weight: 600;
      text-decoration: none;
      transition: all 0.3s;
    }

    .tg-bar-link:hover {
      background: rgba(6,182,212,0.15);
      transform: translateY(-1px);
    }

    /* ===== FOOTER ===== */
    .footer {
      text-align: center;
      padding: 16px 0 8px;
      font-size: 11px; color: var(--text-muted);
    }

    .footer a { color: var(--primary-light); text-decoration: none; }

    /* ===== OVERLAYS / MODALS ===== */
    .overlay {
      position: fixed; inset: 0;
      z-index: 100;
      display: none;
      align-items: center; justify-content: center;
      background: rgba(0,0,0,0.65);
      backdrop-filter: blur(8px);
      -webkit-backdrop-filter: blur(8px);
    }

    .overlay.show { display: flex; animation: overlayIn 0.3s ease; }

    @keyframes overlayIn { from { opacity: 0; } to { opacity: 1; } }

    .modal {
      background: linear-gradient(145deg, rgba(15,15,45,0.98), rgba(5,5,20,0.99));
      border: 1px solid var(--border-hover);
      border-radius: 24px;
      padding: 32px;
      text-align: center;
      animation: modalPop 0.5s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      max-width: 300px; width: 90%;
    }

    @keyframes modalPop {
      from { transform: scale(0.6); opacity: 0; }
      to { transform: scale(1); opacity: 1; }
    }

    .modal-icon {
      width: 60px; height: 60px;
      border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin: 0 auto 16px;
    }

    .modal-icon.success { background: rgba(16,185,129,0.12); }
    .modal-icon.success svg { color: var(--success); width: 28px; height: 28px; }

    .modal h3 { color: white; margin-bottom: 4px; font-size: 17px; }
    .modal p { color: var(--text-secondary); font-size: 12px; }

    .qr-container {
      background: white;
      border-radius: var(--radius-sm);
      padding: 16px;
      display: inline-block;
      margin: 16px 0;
    }

    .qr-container canvas, .qr-container img { display: block; }

    .btn-modal-close {
      margin-top: 8px;
      padding: 10px 32px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius-xs);
      color: var(--text);
      font-family: 'Padauk', sans-serif;
      font-size: 14px;
      cursor: pointer;
      transition: all 0.3s;
    }

    .btn-modal-close:hover { background: var(--surface-hover); }

    /* ===== TOAST ===== */
    .toast {
      position: fixed;
      bottom: 32px; left: 50%;
      transform: translateX(-50%) translateY(80px);
      background: linear-gradient(135deg, var(--success), #059669);
      color: white;
      padding: 12px 24px;
      border-radius: var(--radius-xs);
      font-size: 13px; font-weight: 700;
      z-index: 200;
      transition: transform 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
      display: flex; align-items: center; gap: 8px;
      box-shadow: 0 8px 30px rgba(16,185,129,0.4);
      font-family: 'Padauk', sans-serif;
    }

    .toast.show { transform: translateX(-50%) translateY(0); }
    .toast svg { width: 15px; height: 15px; }

    /* ===== SCROLLBAR ===== */
    ::-webkit-scrollbar { width: 3px; }
    ::-webkit-scrollbar-track { background: transparent; }
    ::-webkit-scrollbar-thumb { background: var(--primary); border-radius: 3px; }

    /* ===== RESPONSIVE ===== */
    @media (max-width: 420px) {
      .app { padding: 8px; }
      .main { padding: 22px 16px 20px; border-radius: var(--radius); }
      .stats { grid-template-columns: repeat(2, 1fr); }
      .result-actions { flex-direction: column; width: 100%; }
      .btn-action { width: 100%; justify-content: center; }
      .result-footer { flex-direction: column; align-items: flex-start; }
      .header { padding: 12px 14px; }
      .brand-text h1 { font-size: 14px; }
    }
  </style>
</head>
<body>

  <!-- Background -->
  <div class="bg-scene">
    <div class="bg-mesh"></div>
    <div class="bg-grid"></div>
    <div class="bg-orbs">
      <div class="orb"></div>
      <div class="orb"></div>
      <div class="orb"></div>
    </div>
  </div>
  <div class="stars" id="stars"></div>

  <!-- App -->
  <div class="app">

    <!-- Header -->
    <div class="header">
      <div class="brand">
        <div class="brand-logo">
          ${profileIconHtml}
        </div>
        <div class="brand-text">
          <h1>Pagaduu VPN</h1>
          <span>Key Generator</span>
        </div>
      </div>
      <div class="header-actions">
        <a href="https://t.me/iqowoq" target="_blank" rel="noopener noreferrer" class="btn-tg">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          TG
        </a>
        <div class="badge-pro">PRO</div>
      </div>
    </div>

    <!-- Validity Banner -->
    <div class="banner active" id="banner">
      <div class="banner-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/><path d="m9 16 2 2 4-4"/></svg>
      </div>
      <div class="banner-body">
        <div class="banner-title" id="validityText">Loading...</div>
        <div class="banner-sub" id="validityStatus">Key သက်တမ်း စစ်ဆေးနေပါသည်...</div>
      </div>
    </div>

    <!-- Stats -->
    <div class="stats">
      <div class="stat">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
        </div>
        <div class="stat-val" id="statRemaining">-</div>
        <div class="stat-lbl">ကျန်ရှိ</div>
      </div>
      <div class="stat">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>
        </div>
        <div class="stat-val" id="statMax">-</div>
        <div class="stat-lbl">ခွင့်ပြု</div>
      </div>
      <div class="stat">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        </div>
        <div class="stat-val" id="statTotal">-</div>
        <div class="stat-lbl">စုစုပေါင်း</div>
      </div>
      <div class="stat">
        <div class="stat-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="stat-val" id="statStatus">-</div>
        <div class="stat-lbl">Status</div>
      </div>
    </div>

    <!-- Main Card -->
    <div class="main">

      <div class="hero">
        <div class="hero-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m15.5 7.5 2.3 2.3a1 1 0 0 0 1.4 0l2.1-2.1a1 1 0 0 0 0-1.4L19 4"/><path d="m21 2-9.6 9.6"/><circle cx="7.5" cy="15.5" r="5.5"/></svg>
        </div>
        <h2>VLESS Key ရယူမည်</h2>
        <p>Generate ကိုနှိပ်၍ Key အသစ် ရယူပါ</p>
      </div>

      <!-- Compatibility -->
      <div class="compat">
        <div class="compat-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>
          Compatible Apps
        </div>
        <div class="compat-tags">
          <span class="compat-tag">V2rayNG</span>
          <span class="compat-tag">V2Box</span>
          <span class="compat-tag">Nekoray</span>
          <span class="compat-tag">V2rayN</span>
          <span class="compat-tag">Streisand</span>
          <span class="compat-tag">Shadowrocket</span>
        </div>
        <div class="compat-warn">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          <span><strong>Hiddify App</strong> တွင် သုံး၍ မရနိုင်ပါ။ V2rayNG / V2Box ကို အသုံးပြုပါ။</span>
        </div>
      </div>

      <!-- Honeypot -->
      <div class="hp-trap" aria-hidden="true">
        <input type="text" id="hpWebsite" name="website" tabindex="-1" autocomplete="off">
      </div>

      <!-- Generate Button -->
      <button class="gen-btn" id="genBtn">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z"/><path d="M5 3v4"/><path d="M19 17v4"/><path d="M3 5h4"/><path d="M17 19h4"/></svg>
        <span id="btnText">Generate Key</span>
        <div class="spinner" id="spinner"></div>
      </button>

      <!-- Error -->
      <div class="error" id="errorMsg">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <span id="errorText"></span>
      </div>

      <!-- Result -->
      <div class="result" id="resultArea">
        <div class="result-box">
          <div class="result-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            Key Generated Successfully
          </div>
          <div class="result-key" id="resultKey"></div>
          <div class="result-footer">
            <div class="result-expire">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
              <span id="expireText"></span>
            </div>
            <div class="result-actions">
              <button class="btn-action" id="copyBtn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                Copy
              </button>
              <button class="btn-action" id="qrBtn">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="8" height="8" rx="1"/><rect x="14" y="2" width="8" height="8" rx="1"/><rect x="2" y="14" width="8" height="8" rx="1"/><path d="M14 14h2v2h-2z"/><path d="M20 14h2v2h-2z"/><path d="M14 20h2v2h-2z"/><path d="M20 20h2v2h-2z"/></svg>
                QR Code
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- How To -->
      <div class="howto">
        <div class="howto-header" id="howtoHeader">
          <div class="ht-label">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            Key အသုံးပြုနည်း
          </div>
          <div class="ht-arrow">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
          </div>
        </div>
        <div class="howto-body" id="howtoBody">
          <div class="howto-steps">
            <div class="step">
              <div class="step-n">1</div>
              <div>Generate Key ခလုတ်နှိပ်ပြီး Key ကို <strong>Copy</strong> ယူပါ (သို့) <strong>QR Code</strong> Scan ဖတ်ပါ။</div>
            </div>
            <div class="step">
              <div class="step-n">2</div>
              <div><span class="app-hl">V2rayNG</span> — ညာဘက်အပေါ် <strong>+</strong> &rarr; "Import config from clipboard"</div>
            </div>
            <div class="step">
              <div class="step-n">3</div>
              <div><span class="app-hl">V2Box</span> — ညာဘက်အပေါ် <strong>+</strong> &rarr; "Import from clipboard" (QR scan လည်းရပါသည်)</div>
            </div>
            <div class="step">
              <div class="step-n">4</div>
              <div>ချိတ်ဆက်ပြီး ပြထားသော <strong>သက်တမ်းကုန်ဆုံးရက်</strong>ထိ အသုံးပြုနိုင်ပါသည်။</div>
            </div>
            <div class="step">
              <div class="step-n" style="background:rgba(239,68,68,0.1);color:var(--danger);">!</div>
              <div style="color:#fca5a5;"><strong>Hiddify App</strong> တွင် ဤ Key ကို သုံး၍ <strong>မရနိုင်ပါ</strong>။</div>
            </div>
          </div>
        </div>
      </div>

      <!-- Info Rows -->
      <div class="info-row remaining">
        <div class="ir-label">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></svg>
          ဤသက်တမ်းအတွင်း ကျန်ရှိအကြိမ်
        </div>
        <div class="ir-value" id="remainingCount">-</div>
      </div>

      <div class="info-row total">
        <div class="ir-label">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>
          စုစုပေါင်း Generate ပြုလုပ်ပြီး
        </div>
        <div class="ir-value" id="totalCount">-</div>
      </div>

      <div class="info-row version">
        <div class="ir-label">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>
          Key Version
        </div>
        <div class="ir-value" id="keyVersionText">-</div>
      </div>

      <!-- Telegram Bar -->
      <div class="tg-bar">
        <div class="tg-bar-info">
          <div class="tg-bar-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
          </div>
          <div class="tg-bar-text">
            အကူအညီ / ဆက်သွယ်ရန်
            <strong>@iqowoq</strong>
          </div>
        </div>
        <a href="https://t.me/iqowoq" target="_blank" rel="noopener noreferrer" class="tg-bar-link">Message</a>
      </div>

    </div>

    <div class="footer">
      Powered by <a href="https://t.me/iqowoq" target="_blank" rel="noopener noreferrer">Pagaduu</a> &copy; 2026
    </div>

  </div>

  <!-- Success Overlay -->
  <div class="overlay" id="successOverlay">
    <div class="modal">
      <div class="modal-icon success">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
      </div>
      <h3>အောင်မြင်ပါသည်!</h3>
      <p>Key ကို Copy ယူ၍ V2rayNG / V2Box တွင် အသုံးပြုပါ</p>
    </div>
  </div>

  <!-- QR Modal -->
  <div class="overlay" id="qrModal">
    <div class="modal">
      <h3>QR Code</h3>
      <p>V2rayNG / V2Box App ဖြင့် Scan ဖတ်ပါ</p>
      <div class="qr-container" id="qrContainer"></div>
      <br>
      <button class="btn-modal-close" id="qrCloseBtn">ပိတ်မည်</button>
    </div>
  </div>

  <!-- Toast -->
  <div class="toast" id="toast">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
    <span>Copy ကူးယူပြီးပါပြီ!</span>
  </div>

  <script nonce="${nonce}">
    // QR Library
    (function(){
      var s=document.createElement('script');
      s.src='https://unpkg.com/qrcode-generator@1.4.4/qrcode.js';
      s.onerror=function(){console.warn('QR lib failed')};
      document.head.appendChild(s);
    })();

    var csrfToken='';
    var currentKey='';
    var isGenerating=false;
    var pageLoadTime=Date.now();

    // Stars
    (function(){
      var c=document.getElementById('stars');
      for(var i=0;i<40;i++){
        var s=document.createElement('div');
        s.className='star';
        s.style.left=Math.random()*100+'%';
        s.style.top=Math.random()*100+'%';
        s.style.animationDelay=Math.random()*4+'s';
        s.style.animationDuration=(3+Math.random()*4)+'s';
        c.appendChild(s);
      }
    })();

    // Event listeners (no inline handlers)
    document.getElementById('genBtn').addEventListener('click', handleGenerate);
    document.getElementById('copyBtn').addEventListener('click', copyKey);
    document.getElementById('qrBtn').addEventListener('click', showQR);
    document.getElementById('qrCloseBtn').addEventListener('click', closeQR);
    document.getElementById('howtoHeader').addEventListener('click', toggleHowto);
    document.getElementById('qrModal').addEventListener('click', function(e){
      if(e.target===this) closeQR();
    });

    // Init
    checkRemaining();

    function checkRemaining(){
      fetch('/api/check',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:'{}'
      })
      .then(function(r){return r.json()})
      .then(function(d){
        csrfToken=d.csrf_token||'';

        var banner=document.getElementById('banner');
        var vText=document.getElementById('validityText');
        var vStatus=document.getElementById('validityStatus');

        vText.textContent=d.validityText||'N/A';

        if(d.withinPeriod){
          vStatus.textContent='အသုံးပြုနိုင်ပါသည်';
          banner.className='banner active';
        } else {
          vStatus.textContent='Key သက်တမ်း ကုန်ဆုံးနေပါသည်';
          banner.className='banner expired';
        }

        document.getElementById('statRemaining').textContent=d.remaining+'/'+d.maxPerPeriod;
        document.getElementById('statMax').textContent=d.maxPerPeriod+' ကြိမ်';
        document.getElementById('statTotal').textContent=d.totalGenerated||0;

        var sEl=document.getElementById('statStatus');
        if(d.withinPeriod){
          sEl.textContent='Active';
          sEl.style.color='#34d399';
        } else {
          sEl.textContent='Expired';
          sEl.style.color='#fca5a5';
        }

        document.getElementById('remainingCount').textContent=d.remaining+' ကြိမ်';
        document.getElementById('totalCount').textContent=(d.totalGenerated||0)+' ကြိမ်';
        document.getElementById('keyVersionText').textContent=d.keyVersion||'-';

        var btn=document.getElementById('genBtn');
        var txt=document.getElementById('btnText');

        if(!d.allowed){
          btn.disabled=true;
          txt.textContent=!d.withinPeriod
            ?'Key သက်တမ်း ကုန်ဆုံးနေပါသည်'
            :'Generate ခွင့် ကုန်သွားပါပြီ';
        } else {
          btn.disabled=false;
          txt.textContent='Generate Key';
        }
      })
      .catch(function(){});
    }

    function handleGenerate(){
      if(isGenerating) return;

      // Minimum delay check to block automated requests
      if(Date.now()-pageLoadTime<1000){return;}

      isGenerating=true;

      var btn=document.getElementById('genBtn');
      var spinner=document.getElementById('spinner');
      var txt=document.getElementById('btnText');
      var errBox=document.getElementById('errorMsg');
      var resArea=document.getElementById('resultArea');

      errBox.classList.remove('show');
      resArea.classList.remove('show');

      btn.disabled=true;
      spinner.style.display='block';
      txt.textContent='Generating...';

      var hp=document.getElementById('hpWebsite');
      var hpVal=hp?hp.value:'';

      fetch('/api/generate',{
        method:'POST',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({
          csrf_token:csrfToken,
          website:hpVal,
          t:Date.now()
        })
      })
      .then(function(r){return r.json()})
      .then(function(d){
        if(!d.success){
          showError(d.message);
          if(d.error==='limit_reached'||d.error==='expired'){
            btn.disabled=true;
            txt.textContent=d.error==='expired'
              ?'Key သက်တမ်း ကုန်ဆုံးနေပါသည်'
              :'Generate ခွင့် ကုန်သွားပါပြီ';
            spinner.style.display='none';
            isGenerating=false;
            return;
          }
          if(d.error==='invalid_token') checkRemaining();
          resetBtn();
          return;
        }

        // Retrieve actual key via one-time token
        fetch('/api/retrieve',{
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({token:d.token})
        })
        .then(function(r2){return r2.json()})
        .then(function(d2){
          if(!d2.success){
            showError(d2.message||'တစ်ခုခု မှားယွင်းနေပါသည်။');
            resetBtn();
            return;
          }

          var data=d2.data;
          currentKey=data.key;

          document.getElementById('resultKey').textContent=currentKey;
          document.getElementById('expireText').textContent='သက်တမ်း: '+data.validityText;
          resArea.classList.add('show');

          var rem=data.remaining;
          document.getElementById('remainingCount').textContent=rem+' ကြိမ်';

          if(data.totalGenerated){
            document.getElementById('statTotal').textContent=data.totalGenerated;
            document.getElementById('totalCount').textContent=data.totalGenerated+' ကြိမ်';
          }

          showSuccess();
          checkRemaining();

          if(rem<=0){
            btn.disabled=true;
            txt.textContent='Generate ခွင့် ကုန်သွားပါပြီ';
            spinner.style.display='none';
            isGenerating=false;
            return;
          }

          resetBtn();
        })
        .catch(function(){
          showError('ချိတ်ဆက်မှု မအောင်မြင်ပါ။ ထပ်ကြိုးစားပါ။');
          resetBtn();
        });
      })
      .catch(function(){
        showError('ချိတ်ဆက်မှု မအောင်မြင်ပါ။ ထပ်ကြိုးစားပါ။');
        resetBtn();
      });
    }

    function showError(msg){
      document.getElementById('errorText').textContent=msg;
      document.getElementById('errorMsg').classList.add('show');
    }

    function resetBtn(){
      document.getElementById('spinner').style.display='none';
      document.getElementById('btnText').textContent='Generate Key';
      document.getElementById('genBtn').disabled=false;
      isGenerating=false;
    }

    function showSuccess(){
      var o=document.getElementById('successOverlay');
      o.classList.add('show');
      setTimeout(function(){o.classList.remove('show')},2200);
    }

    function copyKey(){
      if(!currentKey)return;
      if(navigator.clipboard&&navigator.clipboard.writeText){
        navigator.clipboard.writeText(currentKey).then(showToast).catch(fallbackCopy);
      } else { fallbackCopy(); }
    }

    function fallbackCopy(){
      var ta=document.createElement('textarea');
      ta.value=currentKey;
      ta.style.cssText='position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try{document.execCommand('copy')}catch(e){}
      document.body.removeChild(ta);
      showToast();
    }

    function showToast(){
      var t=document.getElementById('toast');
      t.classList.add('show');
      setTimeout(function(){t.classList.remove('show')},2500);
    }

    function showQR(){
      if(!currentKey)return;
      var modal=document.getElementById('qrModal');
      var c=document.getElementById('qrContainer');
      c.innerHTML='';

      if(typeof qrcode==='undefined'){
        c.innerHTML='<p style="color:#666;font-size:12px;padding:20px;">QR Library load မရပါ။ Copy ယူ၍ အသုံးပြုပါ။</p>';
        modal.classList.add('show');
        return;
      }

      try{
        var qr=qrcode(0,'L');
        qr.addData(currentKey);
        qr.make();
        var sz=Math.floor(200/qr.getModuleCount());
        c.innerHTML=qr.createImgTag(sz,0);
      }catch(e){
        c.innerHTML='<p style="color:#666;font-size:12px;padding:20px;">Key ရှည်လွန်းသဖြင့် QR ဖန်တီးမရပါ။</p>';
      }
      modal.classList.add('show');
    }

    function closeQR(){document.getElementById('qrModal').classList.remove('show')}

    function toggleHowto(){
      document.getElementById('howtoHeader').classList.toggle('open');
      document.getElementById('howtoBody').classList.toggle('open');
    }
  </script>

</body>
</html>`;
}

// ============== ROUTER ==============

Deno.serve(async (req) => {
  const url = new URL(req.url);
  const nonce = generateNonce();

  const securityHeaders: Record<string, string> = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  };

  // Block common attack paths
  const blockedPaths = ["/wp-admin", "/wp-login", "/.env", "/config", "/.git", "/phpinfo", "/wp-content", "/xmlrpc"];
  if (blockedPaths.some(p => url.pathname.toLowerCase().startsWith(p))) {
    return new Response("Not found", { status: 404 });
  }

  // API Routes
  if (url.pathname === "/api/generate") return await handleGenerate(req);
  if (url.pathname === "/api/retrieve") return await handleRetrieve(req);
  if (url.pathname === "/api/check") return await handleCheckRemaining(req);
  if (url.pathname === "/api/debug") return await handleDebug(req);

  // Admin Routes
  if (url.pathname === "/api/admin/config") return await handleAdminAPI(req);
  if (url.pathname === "/admin") {
    if (!(await checkAdminAuth(req))) return requireAuth();
    return new Response(getAdminHTML(), {
      headers: { "Content-Type": "text/html; charset=utf-8", ...securityHeaders }
    });
  }

  // Main Page
  const config = await getConfig();

  return new Response(getHTML(config, nonce), {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Content-Security-Policy": [
        "default-src 'self'",
        `script-src 'nonce-${nonce}' https://unpkg.com`,
        `style-src 'nonce-${nonce}' https://fonts.googleapis.com`,
        "font-src https://fonts.gstatic.com",
        "img-src 'self' data: blob: https:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
      ].join("; "),
      ...securityHeaders,
    }
  });
});
