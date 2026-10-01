// ==========================================================================
// web_server.cpp — login, CSRF, configuration / status page, /save, export
// --------------------------------------------------------------------------
// Called from NetTask only (serviceHttp() in ethernet_tcp.cpp hands over one
// complete request). Zero heap: one static page buffer.
// ==========================================================================
#include "web_server.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "esp_random.h"
#include "esp_system.h"
#include "mbedtls/base64.h"
#include "config_nvs.h"
#include "ethernet_tcp.h"
#include "rs485_rtu.h"
#include "utils.h"

// A ring of tokens: opening a second configuration tab must not invalidate the
// first one's form, while every token still expires and is single-use (FIX-02).
struct CsrfToken { char value[17]; uint32_t issuedMs; bool used; };
static CsrfToken g_csrf[CSRF_TOKEN_SLOTS] = {};

// Per-source-IP brute-force lockout (audit FIX-22): one attacker must not be
// able to lock the real administrator out.
struct AuthHost { uint32_t ip; uint8_t fails; uint32_t lockUntil; };
static AuthHost g_authHosts[AUTH_TRACKED_HOSTS] = {};

// A per-IP table alone is bypassed by an attacker who rotates source addresses,
// so a global cap runs alongside it (audit FIX-A06).
#define AUTH_GLOBAL_WINDOW_MS 60000UL
#define AUTH_GLOBAL_MAX_FAILS 20
static uint16_t g_authFailWindow  = 0;
static uint32_t g_authWindowStart = 0;
// The configuration page carries the form plus ~25 diagnostic rows plus the
// per-slave table, so it needs real room (PAGE_BUFFER_SIZE, web_server.h).
// Static, so the request path still allocates nothing; 12 kB of an ESP32's
// ~300 kB is affordable (audit FIX-62).
static char     g_page[PAGE_BUFFER_SIZE];
static size_t   g_pageLen = 0;
static bool     g_pageOverflow = false;
static size_t   g_pageNeeded = 0;          // bytes the last build would have used

// Credentials live inside the configuration record, so a password change is the
// same single atomic write as a settings change (audit FIX-A2).
void authReport() {
  if (!g_pwIsDefault) return;
#if WEB_FORCE_DEFAULT_PASSWORD
  char def[24];
  defaultPassword(def, sizeof(def));
  LOGF("[SEC] web login: %s / %s\n", WEB_AUTH_USER, def);
  LOGF("[SEC] WEB_FORCE_DEFAULT_PASSWORD is 1: this password is re-applied at "
       "every boot and printed here. Set it to 0 before shipping.\n");
#else
  LOGF("[SEC] web login: the built-in default password is active - change it "
       "from the web page\n");
#endif
}

static AuthHost* authSlot(uint32_t ip) {
  for (auto& h : g_authHosts) if (h.ip == ip) return &h;
  AuthHost* oldest = &g_authHosts[0];
  for (auto& h : g_authHosts) {
    if (h.ip == 0) { h.ip = ip; h.fails = 0; h.lockUntil = 0; return &h; }
    if ((int32_t)(h.lockUntil - oldest->lockUntil) < 0) oldest = &h;
  }
  oldest->ip = ip; oldest->fails = 0; oldest->lockUntil = 0;
  return oldest;
}

// Issue a token into the oldest / expired / already used slot.
static const char* newCsrfToken() {
  const uint32_t now = millis();
  int victim = 0;
  for (int i = 0; i < CSRF_TOKEN_SLOTS; i++) {
    CsrfToken& t = g_csrf[i];
    if (t.value[0] == 0 || t.used || now - t.issuedMs > CSRF_TOKEN_TTL_MS) { victim = i; break; }
    if ((int32_t)(t.issuedMs - g_csrf[victim].issuedMs) < 0) victim = i;
  }
  CsrfToken& t = g_csrf[victim];
  snprintf(t.value, sizeof(t.value), "%08lX%08lX",
           (unsigned long)esp_random(), (unsigned long)esp_random());
  t.issuedMs = now;
  t.used = false;
  return t.value;
}

// Accept any unexpired, unused token; consume it so it cannot be replayed.
static bool csrfValid(const char* token) {
  if (!token || strlen(token) != 16) return false;
  const uint32_t now = millis();
  for (auto& t : g_csrf) {
    if (t.value[0] == 0 || t.used) continue;
    if (now - t.issuedMs > CSRF_TOKEN_TTL_MS) { t.value[0] = 0; continue; }
    if (ctEqualBytes((const uint8_t*)token, (const uint8_t*)t.value, 16)) {
      t.used = true;                                  // single use
      return true;
    }
  }
  return false;
}

static void pageReset() {
  g_pageLen = 0; g_pageOverflow = false; g_pageNeeded = 0; g_page[0] = '\0';
}

static void pageRaw(const char* s) {                 // literal text (may contain '%')
  size_t n = strlen(s);
  g_pageNeeded += n;
  if (g_pageLen + n >= sizeof(g_page)) { g_pageOverflow = true; return; }
  memcpy(g_page + g_pageLen, s, n + 1);
  g_pageLen += n;
}

static void pageFmt(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
static void pageFmt(const char* fmt, ...) {
  if (g_pageLen >= sizeof(g_page) - 1) { g_pageOverflow = true; return; }
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(g_page + g_pageLen, sizeof(g_page) - g_pageLen, fmt, ap);
  va_end(ap);
  if (n >= 0) g_pageNeeded += (size_t)n;
  if (n < 0 || (size_t)n >= sizeof(g_page) - g_pageLen) {
    g_pageOverflow = true;
    g_pageLen = sizeof(g_page) - 1;
  } else {
    g_pageLen += (size_t)n;
  }
}

// A HEAD request gets exactly the headers a GET would produce, and no body.
static bool g_httpHeadOnly = false;

static void httpSend(EthernetClient& c, int code, const char* reason, const char* ctype,
                     const char* body, size_t bodyLen, const char* extraHeaders = "") {
  char hdr[320];
  int n = snprintf(hdr, sizeof(hdr),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Type: %s\r\n"
                   "Content-Length: %u\r\n"
                   "Connection: close\r\n"
                   "Cache-Control: no-store\r\n"
                   "X-Frame-Options: DENY\r\n"
                   "%s\r\n",
                   code, reason, ctype, (unsigned)bodyLen, extraHeaders);
  if (n <= 0 || (size_t)n >= sizeof(hdr)) return;
  // The config page is ~6 KB; a Modbus response is <= 260 B. One deadline does
  // not fit both (audit FIX-A04), and a browser that stops reading must not be
  // able to delay the Modbus path (audit FIX-08).
  if (!writeAll(c, (const uint8_t*)hdr, (size_t)n, HTTP_WRITE_TIMEOUT_MS)) {
    g_stat.httpWriteFail++;
    return;
  }
  if (bodyLen && !g_httpHeadOnly &&
      !writeAll(c, (const uint8_t*)body, bodyLen, HTTP_WRITE_TIMEOUT_MS))
    g_stat.httpWriteFail++;
}

// (The default for extraHeaders is declared in web_server.h.)
void httpSendSimple(EthernetClient& c, int code, const char* reason, const char* msg,
                    const char* extraHeaders) {
  pageReset();
  pageRaw("<!DOCTYPE html><html><body style='font-family:Arial;text-align:center;padding:50px;'>");
  pageFmt("<h2>%d %s</h2><p>%s</p><p><a href='/'>Back</a></p></body></html>", code, reason, msg);
  httpSend(c, code, reason, "text/html", g_page, g_pageLen, extraHeaders);
}

// Case-insensitive header lookup within the header block.
bool httpHeader(const char* req, size_t hdrLen, const char* name, char* out, size_t outCap) {
  const char* end = req + hdrLen;
  const char* p = strstr(req, "\r\n");
  if (!p) return false;
  p += 2;
  size_t nlen = strlen(name);
  while (p < end) {
    const char* eol = strstr(p, "\r\n");
    if (!eol || eol == p || eol > end) break;
    if ((size_t)(eol - p) > nlen && strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
      const char* v = p + nlen + 1;
      while (v < eol && (*v == ' ' || *v == '\t')) v++;
      size_t vl = (size_t)(eol - v);
      while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) vl--;
      if (vl >= outCap) return false;
      memcpy(out, v, vl);
      out[vl] = '\0';
      return true;
    }
    p = eol + 2;
  }
  return false;
}

static int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  c = (char)tolower((unsigned char)c);
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

// application/x-www-form-urlencoded field lookup + decode.
static bool formField(const char* body, const char* key, char* out, size_t cap) {
  size_t klen = strlen(key);
  const char* p = body;
  while (*p) {
    const char* amp = strchr(p, '&');
    const char* end = amp ? amp : p + strlen(p);
    const char* eq = (const char*)memchr(p, '=', (size_t)(end - p));
    if (eq && (size_t)(eq - p) == klen && strncmp(p, key, klen) == 0) {
      size_t o = 0;
      for (const char* s = eq + 1; s < end; ) {
        char c = *s++;
        if (c == '+') c = ' ';
        else if (c == '%') {
          if (end - s < 2) return false;
          int h = hexVal(s[0]), l = hexVal(s[1]);
          if (h < 0 || l < 0) return false;
          c = (char)((h << 4) | l);
          s += 2;
        }
        if (o + 1 >= cap) return false;
        out[o++] = c;
      }
      out[o] = '\0';
      return true;
    }
    if (!amp) break;
    p = amp + 1;
  }
  return false;
}

// Decode the Basic credentials, hash them, compare against the stored hash.
static bool httpAuthorized(const char* req, size_t hdrLen, bool& credentialsPresent) {
  credentialsPresent = false;
  char v[200];
  if (!httpHeader(req, hdrLen, "Authorization", v, sizeof(v))) return false;
  if (strncasecmp(v, "Basic ", 6) != 0) return false;
  credentialsPresent = true;

  const char* tok = v + 6;
  while (*tok == ' ') tok++;

  uint8_t plain[WEB_PASS_MAX_LEN + 48];
  size_t plainLen = 0;
  if (mbedtls_base64_decode(plain, sizeof(plain) - 1, &plainLen,
                            (const unsigned char*)tok, strlen(tok)) != 0) return false;
  plain[plainLen] = 0;

  char* colon = strchr((char*)plain, ':');
  if (!colon) { memset(plain, 0, sizeof(plain)); return false; }
  *colon = 0;
  const char* user = (const char*)plain;
  const char* pass = colon + 1;

  bool ok = false;
  if (strcmp(user, WEB_AUTH_USER) == 0) {
    uint8_t h[32];
    hashCredentials(user, pass, h);
    ok = ctEqualBytes(h, g_pwHash, sizeof(h));
  }
  memset(plain, 0, sizeof(plain));
  memset(v, 0, sizeof(v));
  return ok;
}

static void selectOpt(const char* value, const char* label, bool sel) {
  pageFmt("<option value=\"%s\"%s>%s</option>", value, sel ? " selected" : "", label);
}

static void sendConfigPage(EthernetClient& c) {
  pageReset();
  pageRaw(
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\">"
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
    "<title>Modbus Gateway</title><style>"
    "body{font-family:Arial,sans-serif;background:#eef2f3;padding:20px;display:flex;justify-content:center}"
    ".box{background:#fff;padding:25px;border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,.1);width:100%;max-width:450px}"
    "h2{text-align:center;color:#2c3e50;border-bottom:2px solid #3498db;padding-bottom:10px}"
    "label{font-weight:bold;margin-top:15px;display:block;color:#34495e;font-size:14px}"
    "input,select{width:100%;padding:10px;margin-top:5px;border:1px solid #bdc3c7;border-radius:4px;box-sizing:border-box}"
    ".btn{width:100%;padding:12px;background:#3498db;color:#fff;border:none;border-radius:4px;margin-top:25px;cursor:pointer;font-size:16px;font-weight:bold}"
    ".btn:hover{background:#2980b9}"
    ".st{background:#ecf0f1;padding:8px;margin-top:20px;border-radius:4px;text-align:center;color:#2980b9;font-weight:bold}"
    "table{width:100%;font-size:13px;margin-top:8px;border-collapse:collapse}td{padding:3px 4px;border-bottom:1px solid #eee}"
    "</style></head><body><div class=\"box\"><h2>Modbus Gateway Setup</h2>"
    "<form action=\"/save\" method=\"POST\">"
    "<div class=\"st\">Ethernet Network (W5500)</div>");

  char ip[16], sn[16], gw[16];
  snprintf(ip, sizeof(ip), "%u.%u.%u.%u", cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3]);
  snprintf(sn, sizeof(sn), "%u.%u.%u.%u", cfg.sn[0], cfg.sn[1], cfg.sn[2], cfg.sn[3]);
  snprintf(gw, sizeof(gw), "%u.%u.%u.%u", cfg.gw[0], cfg.gw[1], cfg.gw[2], cfg.gw[3]);
  pageFmt("<label>Static IP</label><input name=\"l_ip\" maxlength=\"15\" value=\"%s\">", ip);
  pageFmt("<label>Subnet Mask</label><input name=\"l_sn\" maxlength=\"15\" value=\"%s\">", sn);
  pageFmt("<label>Gateway</label><input name=\"l_gw\" maxlength=\"15\" value=\"%s\">", gw);
  pageFmt("<label>Modbus TCP Port</label><input type=\"number\" name=\"m_port\" min=\"1\" max=\"65535\" value=\"%u\">", cfg.port);

  pageRaw("<div class=\"st\">RS-485 Serial Settings</div><label>Baud Rate</label><select name=\"baud\">");
  for (uint8_t i = 0; i < BAUD_COUNT; i++) {
    char v[8]; snprintf(v, sizeof(v), "%lu", (unsigned long)BAUDS[i]);
    selectOpt(v, v, BAUDS[i] == cfg.baud);
  }
  pageRaw("</select><label>Data / Parity / Stop</label><select name=\"fmt\">");
  for (uint8_t i = 0; i < SERIAL_FMT_COUNT; i++) {
    char v[4]; snprintf(v, sizeof(v), "%u", i);
    selectOpt(v, SERIAL_FMTS[i].name, i == cfg.fmt);
  }
  pageFmt("</select><label>RTU Response Timeout (ms)</label>"
          "<input type=\"number\" name=\"rtu_to\" min=\"20\" max=\"5000\" value=\"%u\">", cfg.rtuTimeoutMs);

  // Suggest a timeout from what the slaves actually did (FIX-A16).
  if (g_turnaroundMaxUs > 0) {
    uint32_t suggest = (g_turnaroundMaxUs / 1000) * 3 + 20;     // 3x worst case + margin
    if (suggest < 50) suggest = 50;
    if (suggest > 5000) suggest = 5000;
    pageFmt("<p style='font-size:12px;color:#7f8c8d;margin:6px 0'>Measured slave turnaround: "
            "min %lu ms, max %lu ms &rarr; suggested timeout <b>%lu ms</b></p>",
            (unsigned long)(g_turnaroundMinUs == 0xFFFFFFFFUL ? 0 : g_turnaroundMinUs / 1000),
            (unsigned long)(g_turnaroundMaxUs / 1000), (unsigned long)suggest);
  }

  pageRaw("<label>Reply with a Modbus exception when the slave fails</label><select name=\"exc\">");
  selectOpt("1", "Yes - return exception (0x0B / 0x04 / 0x0A)", (cfg.flags & CFG_FLAG_TCP_EXCEPTION) != 0);
  selectOpt("0", "No - stay silent, let the master time out", (cfg.flags & CFG_FLAG_TCP_EXCEPTION) == 0);
  pageRaw("</select>");

  pageRaw("<div class=\"st\">Web Password</div>");
  if (g_pwIsDefault)
    pageRaw("<p style='color:#e67e22;font-size:13px;margin:8px 0'><b>This device still uses the "
            "built-in default password.</b> Set a new one below. (If the firmware was built with "
            "WEB_FORCE_DEFAULT_PASSWORD = 1, the default comes back at the next boot.)</p>");
  pageFmt("<label>New Password (%u-%u chars, blank = keep current)</label>"
          "<input type=\"password\" name=\"pw1\" maxlength=\"%u\" autocomplete=\"new-password\">"
          "<label>Repeat New Password</label>"
          "<input type=\"password\" name=\"pw2\" maxlength=\"%u\" autocomplete=\"new-password\">",
          (unsigned)WEB_PASS_MIN_LEN, (unsigned)WEB_PASS_MAX_LEN,
          (unsigned)WEB_PASS_MAX_LEN, (unsigned)WEB_PASS_MAX_LEN);

  pageFmt("<input type=\"hidden\" name=\"csrf\" value=\"%s\">", newCsrfToken());
  pageRaw("<button type=\"submit\" class=\"btn\">Save &amp; Restart</button></form>");

  pageFmt("<div class=\"st\">Status</div><table>"
          "<tr><td>Firmware</td><td>%s</td></tr>"
          "<tr><td>Last reset</td><td>%s</td></tr>"
          "<tr><td>MAC</td><td>%02X:%02X:%02X:%02X:%02X:%02X</td></tr>"
          "<tr><td>Uptime</td><td>%lu s</td></tr>"
          "<tr><td>Link / W5500</td><td>%s / %s</td></tr>"
          "<tr><td>Modbus clients</td><td>%u / %u</td></tr>"
          "<tr><td>Queued requests</td><td>%u (max %u per client)</td></tr>"
          "<tr><td>Requests / OK</td><td>%lu / %lu</td></tr>"
          "<tr><td>RTU timeout</td><td>%lu</td></tr>"
          "<tr><td>RTU CRC / frame error</td><td>%lu / %lu</td></tr>"
          "<tr><td>Wrong unit / wrong function</td><td>%lu / %lu</td></tr>"
          "<tr><td>UART frame / parity / overflow</td><td>%lu / %lu / %lu</td></tr>"
          "<tr><td>Broadcasts / rejected / aged out</td><td>%lu / %lu / %lu</td></tr>"
          "<tr><td>Stale RTU results / abandoned jobs</td><td>%lu / %lu</td></tr>"
          "<tr><td>Queue back-pressure events</td><td>%lu</td></tr>"
          "<tr><td>TCP disconnects</td><td>%lu</td></tr>"
          "<tr><td>Auth failures / lockouts</td><td>%lu / %lu</td></tr>"
          "<tr><td>HTTP write failures</td><td>%lu</td></tr>"
          "<tr><td>Config write / CRC failures</td><td>%lu / %lu</td></tr>"
          "<tr><td>TCP accepted / evicted / dropped</td><td>%lu / %lu / %lu</td></tr>"
          "<tr><td>TCP rejected / internal errors</td><td>%lu / %lu</td></tr>"
          "<tr><td>W5500 recoveries</td><td>%lu</td></tr>"
          "<tr><td>Free heap</td><td>%lu bytes</td></tr>"
          "<tr><td>Stack left Net / Rtu</td><td>%lu / %lu bytes</td></tr>"
          "<tr><td>Slave turnaround last / max</td><td>%lu / %lu ms</td></tr>"
          "</table>",
          FW_VERSION, resetReasonName(),
          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
          (unsigned long)(millis() / 1000), g_linkUp ? "UP" : "DOWN", g_ethOk ? "OK" : "FAULT",
          activeModbusClients(), (unsigned)MAX_CLIENTS,
          queuedRequests(), (unsigned)REQ_QUEUE_DEPTH,
          (unsigned long)g_stat.requests, (unsigned long)g_stat.rtuOk,
          (unsigned long)g_stat.rtuTimeout,
          (unsigned long)g_stat.rtuCrc, (unsigned long)g_stat.rtuFrame,
          (unsigned long)g_stat.rtuUnitMismatch, (unsigned long)g_stat.rtuFcMismatch,
          (unsigned long)g_uartFrameErr, (unsigned long)g_uartParityErr, (unsigned long)g_uartOverflow,
          (unsigned long)g_stat.broadcasts, (unsigned long)g_stat.reqRejected,
          (unsigned long)g_stat.reqAged,
          (unsigned long)g_stat.staleResults, (unsigned long)g_stat.rtuAbandoned,
          (unsigned long)g_stat.queueBackpressure, (unsigned long)g_stat.tcpDisconnects,
          (unsigned long)g_stat.authFailures, (unsigned long)g_stat.authLockouts,
          (unsigned long)g_stat.httpWriteFail,
          (unsigned long)g_stat.cfgSaveFail, (unsigned long)g_stat.cfgCrcFail,
          (unsigned long)g_stat.tcpAccepted, (unsigned long)g_stat.tcpEvicted, (unsigned long)g_stat.tcpDropped,
          (unsigned long)g_stat.tcpRejected, (unsigned long)g_stat.internalErr,
          (unsigned long)g_stat.ethRecoveries,
          (unsigned long)esp_get_free_heap_size(),
          (unsigned long)(g_netTask ? uxTaskGetStackHighWaterMark(g_netTask) : 0),
          (unsigned long)(g_rtuTask ? uxTaskGetStackHighWaterMark(g_rtuTask) : 0),
          (unsigned long)(g_turnaroundLastUs / 1000), (unsigned long)(g_turnaroundMaxUs / 1000));

  bool anyUnit = false;
  for (const auto& u : g_unitStat) if (u.used) { anyUnit = true; break; }
  if (anyUnit) {
    pageRaw("<div class=\"st\">Per Slave (unit id)</div><table>"
            "<tr><td><b>Unit</b></td><td><b>OK</b></td><td><b>Failed</b></td></tr>");
    for (const auto& u : g_unitStat)
      if (u.used)
        pageFmt("<tr><td>%u</td><td>%lu</td><td>%lu</td></tr>",
                u.unit, (unsigned long)u.ok, (unsigned long)u.fail);
    pageRaw("</table>");
  }
  pageFmt("<p style='font-size:11px;color:#7f8c8d'>"
          "Counters live in RAM only and reset on reboot. Capacity: %u TCP masters, "
          "%u pipelined requests each, one RS-485 transaction at a time. "
          "Serial: Modbus RTU only (no ASCII), 1200-115200 baud, 8 data bits, "
          "N/E/O parity, 1-2 stop bits.</p>",
          (unsigned)MAX_CLIENTS, (unsigned)REQ_QUEUE_DEPTH)
          ;
  pageRaw("<p style='font-size:11px;color:#7f8c8d'><a href=\"/config.json\">Export configuration"
          "</a></p></div></body></html>");

  if (g_pageOverflow) {
    LOGF("[HTTP] page needs %u bytes, buffer is %u -> raise PAGE_BUFFER_SIZE\n",
         (unsigned)g_pageNeeded, (unsigned)PAGE_BUFFER_SIZE);
    char msg[120];
    snprintf(msg, sizeof(msg),
             "Page needs %u bytes but the build buffer is %u. Raise PAGE_BUFFER_SIZE.",
             (unsigned)g_pageNeeded, (unsigned)PAGE_BUFFER_SIZE);
    httpSendSimple(c, 500, "Internal Error", msg);
    return;
  }
  LOGF("[HTTP] config page %u bytes (buffer %u)\n",
       (unsigned)g_pageLen, (unsigned)PAGE_BUFFER_SIZE);
  httpSend(c, 200, "OK", "text/html", g_page, g_pageLen);
}

static void handleSave(EthernetClient& c, const char* body) {
  char f_ip[20], f_sn[20], f_gw[20], f_port[8], f_baud[8], f_fmt[4], f_to[8], f_csrf[24], f_exc[4];
  IPAddress ip, sn, gw;
  uint32_t port = 0, baud = 0, fmt = 0, to = 0, exc = 1;

  // Same-origin proof: the token was handed out with the form (audit FIX-15).
  if (!formField(body, "csrf", f_csrf, sizeof(f_csrf)) || !csrfValid(f_csrf)) {
    httpSendSimple(c, 403, "Forbidden", "Stale or missing form token. Reload the page and try again.");
    return;
  }

  bool ok = formField(body, "l_ip", f_ip, sizeof(f_ip)) && parseIPv4(f_ip, ip) &&
            formField(body, "l_sn", f_sn, sizeof(f_sn)) && parseIPv4(f_sn, sn) &&
            formField(body, "l_gw", f_gw, sizeof(f_gw)) && parseIPv4(f_gw, gw) &&
            formField(body, "m_port", f_port, sizeof(f_port)) && parseU32(f_port, 1, 65535, port) &&
            formField(body, "baud", f_baud, sizeof(f_baud)) && parseU32(f_baud, 1, 1000000, baud) &&
            formField(body, "fmt", f_fmt, sizeof(f_fmt)) && parseU32(f_fmt, 0, SERIAL_FMT_COUNT - 1, fmt) &&
            formField(body, "rtu_to", f_to, sizeof(f_to)) && parseU32(f_to, 20, 5000, to) &&
            formField(body, "exc", f_exc, sizeof(f_exc)) && parseU32(f_exc, 0, 1, exc);
  ok = ok && networkValid(ip, sn, gw) && portValid(port) && baudValid(baud);

  if (!ok) {
    httpSendSimple(c, 400, "Bad Request",
                   "Invalid input. Check IP / subnet / gateway (same subnet), port (1-65535, not 80), baud and timeout.");
    return;
  }

  // Optional password change, validated before anything is written.
  char pw1[WEB_PASS_MAX_LEN + 2] = {0}, pw2[WEB_PASS_MAX_LEN + 2] = {0};
  bool havePw1 = formField(body, "pw1", pw1, sizeof(pw1));
  bool havePw2 = formField(body, "pw2", pw2, sizeof(pw2));
  bool changePw = (havePw1 && pw1[0]) || (havePw2 && pw2[0]);
  if (changePw) {
    size_t l1 = strlen(pw1);
    if (strcmp(pw1, pw2) != 0 || l1 < WEB_PASS_MIN_LEN || l1 > WEB_PASS_MAX_LEN) {
      memset(pw1, 0, sizeof(pw1)); memset(pw2, 0, sizeof(pw2));
      char msg[80];
      snprintf(msg, sizeof(msg), "The two passwords must match and be %u-%u characters long.",
               (unsigned)WEB_PASS_MIN_LEN, (unsigned)WEB_PASS_MAX_LEN);
      httpSendSimple(c, 400, "Bad Request", msg);
      return;
    }
  }

  // One atomic blob: a power cut can no longer mix old and new values (FIX-04).
  GatewayConfig next;
  next.ip = ip; next.sn = sn; next.gw = gw;
  next.port = (uint16_t)port; next.baud = baud;
  next.fmt = (uint8_t)fmt; next.rtuTimeoutMs = (uint16_t)to;
  next.flags = exc ? CFG_FLAG_TCP_EXCEPTION : 0;

  // Settings and credentials are ONE record, so this is a single verified write
  // to the inactive slot: power loss here leaves the old slot fully intact and
  // the new one either valid or ignored (audit FIX-A2).
  uint8_t newHash[32];
  bool newIsDefault = g_pwIsDefault;
  memcpy(newHash, g_pwHash, sizeof(newHash));
  if (changePw) {
    hashCredentials(WEB_AUTH_USER, pw1, newHash);
    newIsDefault = false;
  }
  memset(pw1, 0, sizeof(pw1));
  memset(pw2, 0, sizeof(pw2));

  if (!persistConfig(next, newHash, newIsDefault)) {
    g_stat.cfgSaveFail++;
    httpSendSimple(c, 500, "Internal Error",
                   "Nothing was changed: the settings could not be stored.");
    return;
  }
  memcpy(g_pwHash, newHash, sizeof(g_pwHash));
  g_pwIsDefault = newIsDefault;
  // The token was consumed by csrfValid(); other open tabs keep their own.

  char s_ip[16];
  snprintf(s_ip, sizeof(s_ip), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  pageReset();
  pageFmt("<!DOCTYPE html><html><body style='font-family:Arial;text-align:center;padding:50px;'>"
          "<h2 style='color:#2ecc71;'>Settings Saved!</h2><p>Device is restarting...</p>"
          "<p>New address: http://%s/</p>%s</body></html>",
          s_ip, changePw ? "<p>The new password is active after the restart.</p>" : "");
  httpSend(c, 200, "OK", "text/html", g_page, g_pageLen);
  g_restartPending = true;                          // restart from the task loop, not here
  g_restartAtMs = millis() + 800;
}

static void routeHttpRequest(EthernetClient& c, char* req, size_t hdrLen, const char* body) {
  // Request line: METHOD SP PATH SP VERSION
  char method[8] = {0}, path[64] = {0};
  const char* sp1 = strchr(req, ' ');
  const char* sp2 = sp1 ? strchr(sp1 + 1, ' ') : nullptr;
  if (!sp1 || !sp2 || (size_t)(sp1 - req) >= sizeof(method) || (size_t)(sp2 - sp1 - 1) >= sizeof(path)) {
    httpSendSimple(c, 400, "Bad Request", "Malformed request line.");
    return;
  }
  memcpy(method, req, (size_t)(sp1 - req));
  memcpy(path, sp1 + 1, (size_t)(sp2 - sp1 - 1));
  char* q = strchr(path, '?'); if (q) *q = '\0';

  // HEAD is answered like GET but without a body (audit FIX-09).
  const bool isHead = (strcmp(method, "HEAD") == 0);
  g_httpHeadOnly = isHead;

  const uint32_t now = millis();
  AuthHost* host = authSlot(ipToU32(c.remoteIP()));
  if (host->lockUntil && (int32_t)(now - host->lockUntil) < 0) {
    httpSendSimple(c, 429, "Too Many Requests", "Too many failed logins from this host. Try again later.");
    return;
  }

  if (now - g_authWindowStart > AUTH_GLOBAL_WINDOW_MS) {
    g_authWindowStart = now;
    g_authFailWindow = 0;
  }
  if (g_authFailWindow > AUTH_GLOBAL_MAX_FAILS) {   // brake, whatever the source IP
    httpSendSimple(c, 429, "Too Many Requests", "Too many failed logins. Try again later.");
    return;
  }

  bool credentialsPresent = false;
  if (!httpAuthorized(req, hdrLen, credentialsPresent)) {
    if (credentialsPresent) {
      g_authFailWindow++;
      g_stat.authFailures++;
      if (++host->fails >= AUTH_MAX_FAILS) {
        host->fails = 0;
        host->lockUntil = now + AUTH_LOCKOUT_MS;
        g_stat.authLockouts++;
        LOGF("[SEC] login lockout for %u.%u.%u.%u\n",
             c.remoteIP()[0], c.remoteIP()[1], c.remoteIP()[2], c.remoteIP()[3]);
      }
    }
    httpSendSimple(c, 401, "Unauthorized", "Login required.",
                   "WWW-Authenticate: Basic realm=\"Modbus Gateway\"\r\n");
    return;
  }
  host->fails = 0;
  host->lockUntil = 0;

  if ((strcmp(method, "GET") == 0 || isHead) && strcmp(path, "/") == 0) {
    sendConfigPage(c);
    g_httpHeadOnly = false;
    return;
  }

  // Configuration export (authenticated). Import is done through the form; the
  // JSON is for site documentation and for cloning settings by hand (FIX-A15).
  if ((strcmp(method, "GET") == 0 || isHead) && strcmp(path, "/config.json") == 0) {
    pageReset();
    pageFmt("{\"fw\":\"%s\",\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
            "\"ip\":\"%u.%u.%u.%u\",\"mask\":\"%u.%u.%u.%u\",\"gw\":\"%u.%u.%u.%u\","
            "\"modbus_port\":%u,\"baud\":%lu,\"format\":\"%s\",\"rtu_timeout_ms\":%u,"
            "\"tcp_exception\":%s,\"max_clients\":%u,\"queue_depth\":%u}",
            FW_VERSION, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3],
            cfg.sn[0], cfg.sn[1], cfg.sn[2], cfg.sn[3],
            cfg.gw[0], cfg.gw[1], cfg.gw[2], cfg.gw[3],
            cfg.port, (unsigned long)cfg.baud, SERIAL_FMTS[cfg.fmt].name, cfg.rtuTimeoutMs,
            (cfg.flags & CFG_FLAG_TCP_EXCEPTION) ? "true" : "false", (unsigned)MAX_CLIENTS,
            (unsigned)REQ_QUEUE_DEPTH);
    httpSend(c, 200, "OK", "application/json", g_page, g_pageLen);
    g_httpHeadOnly = false;
    return;
  }

  if (strcmp(method, "POST") == 0 && strcmp(path, "/save") == 0) {
    // Be explicit about what this tiny server does and does not accept
    // (audit FIX-15) instead of silently treating it as an empty body.
    char v[48];
    if (httpHeader(req, hdrLen, "Transfer-Encoding", v, sizeof(v))) {
      httpSendSimple(c, 501, "Not Implemented", "Chunked request bodies are not supported.");
      return;
    }
    if (!httpHeader(req, hdrLen, "Content-Length", v, sizeof(v))) {
      httpSendSimple(c, 411, "Length Required", "A Content-Length header is required.");
      return;
    }
    if (!httpHeader(req, hdrLen, "Content-Type", v, sizeof(v)) ||
        strncasecmp(v, "application/x-www-form-urlencoded", 33) != 0) {
      httpSendSimple(c, 415, "Unsupported Media Type", "Expected application/x-www-form-urlencoded.");
      return;
    }
    handleSave(c, body);
    return;
  }

  if (strcmp(method, "GET") == 0 || isHead || strcmp(method, "POST") == 0)
    httpSendSimple(c, 404, "Not Found", "No such page.");
  else
    httpSendSimple(c, 405, "Method Not Allowed", "Only GET, HEAD and POST are supported.");
  g_httpHeadOnly = false;
}

// Entry point for one complete request. The HEAD flag is cleared on the way
// out whatever path the router took, so it can never leak into the next
// response (for example a 413 sent by serviceHttp() before routing).
void handleHttpRequest(EthernetClient& c, char* req, size_t hdrLen, const char* body) {
  routeHttpRequest(c, req, hdrLen, body);
  g_httpHeadOnly = false;
}
