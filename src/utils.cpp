// ==========================================================================
// utils.cpp — shared helpers (no module state)
// ==========================================================================
#include "utils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "esp_system.h"

// --------------------------------------------------------------------------
// External watchdog (DONE pulse)
// --------------------------------------------------------------------------

void pulseExternalWatchdog() {
  digitalWrite(WDT_DONE_PIN, HIGH);
  delayMicroseconds(50);
  digitalWrite(WDT_DONE_PIN, LOW);
}

// --------------------------------------------------------------------------
// IPv4 parsing and validation
// --------------------------------------------------------------------------

uint32_t ipToU32(const IPAddress& a) {
  return ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
}

// Strict dotted-quad parser (IPAddress::fromString on core 3.x also accepts IPv6).
bool parseIPv4(const char* s, IPAddress& out) {
  uint8_t oct[4];
  for (int i = 0; i < 4; i++) {
    if (!isdigit((unsigned char)*s)) return false;
    uint32_t v = 0; int digits = 0;
    while (isdigit((unsigned char)*s)) {
      v = v * 10 + (uint32_t)(*s++ - '0');
      if (++digits > 3 || v > 255) return false;
    }
    oct[i] = (uint8_t)v;
    if (i < 3) { if (*s != '.') return false; s++; }
  }
  if (*s != '\0') return false;
  out = IPAddress(oct[0], oct[1], oct[2], oct[3]);
  return true;
}

bool parseU32(const char* s, uint32_t minV, uint32_t maxV, uint32_t& out) {
  if (!isdigit((unsigned char)*s)) return false;
  char* end = nullptr;
  unsigned long v = strtoul(s, &end, 10);
  if (!end || *end != '\0' || v < minV || v > maxV) return false;
  out = (uint32_t)v;
  return true;
}

bool maskValid(const IPAddress& m) {
  uint32_t v = ipToU32(m);
  uint32_t inv = ~v;
  return v != 0 && (inv & (inv + 1)) == 0 && inv >= 3;   // contiguous, /1 .. /30
}

bool networkValid(const IPAddress& ip, const IPAddress& sn, const IPAddress& gw) {
  if (!maskValid(sn)) return false;
  uint32_t i = ipToU32(ip), m = ipToU32(sn), g = ipToU32(gw);
  if (ip[0] == 0 || ip[0] == 127 || ip[0] >= 224) return false;
  if ((i & ~m) == 0 || (i & ~m) == ~m) return false;             // network / broadcast addr
  if (g != 0 && ((g & m) != (i & m) || g == i || (g & ~m) == ~m)) return false;
  return true;
}

// --------------------------------------------------------------------------
// Minimal SHA-256 (FIPS 180-4). Self-contained on purpose: the mbedTLS SHA
// entry points were renamed between IDF 4.x and 5.x, and the web password hash
// must not depend on which Arduino core the firmware is built with.
// --------------------------------------------------------------------------
typedef struct { uint32_t state[8]; uint64_t bits; uint8_t buf[64]; size_t idx; } Sha256Ctx;

static const uint32_t SHA256_K[64] = {
  0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
  0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
  0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
  0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
  0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
  0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
  0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
  0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL };

static inline uint32_t shaRor(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256Block(Sha256Ctx* c, const uint8_t* p) {
  uint32_t w[64], a, b, cc, d, e, f, g, h;
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) | ((uint32_t)p[i*4+2] << 8) | p[i*4+3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = shaRor(w[i-15],7) ^ shaRor(w[i-15],18) ^ (w[i-15] >> 3);
    uint32_t s1 = shaRor(w[i-2],17) ^ shaRor(w[i-2],19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
  e=c->state[4]; f=c->state[5]; g=c->state[6];  h=c->state[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = shaRor(e,6) ^ shaRor(e,11) ^ shaRor(e,25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + S1 + ch + SHA256_K[i] + w[i];
    uint32_t S0 = shaRor(a,2) ^ shaRor(a,13) ^ shaRor(a,22);
    uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
    uint32_t t2 = S0 + mj;
    h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }
  c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
  c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
  Sha256Ctx c;
  c.state[0]=0x6a09e667UL; c.state[1]=0xbb67ae85UL; c.state[2]=0x3c6ef372UL; c.state[3]=0xa54ff53aUL;
  c.state[4]=0x510e527fUL; c.state[5]=0x9b05688cUL; c.state[6]=0x1f83d9abUL; c.state[7]=0x5be0cd19UL;
  c.bits = (uint64_t)len * 8; c.idx = 0;
  size_t i = 0;
  while (len - i >= 64) { sha256Block(&c, data + i); i += 64; }
  size_t rem = len - i;
  memcpy(c.buf, data + i, rem);
  c.buf[rem++] = 0x80;
  if (rem > 56) { memset(c.buf + rem, 0, 64 - rem); sha256Block(&c, c.buf); rem = 0; }
  memset(c.buf + rem, 0, 56 - rem);
  for (int k = 0; k < 8; k++) c.buf[56 + k] = (uint8_t)(c.bits >> (56 - 8 * k));
  sha256Block(&c, c.buf);
  for (int k = 0; k < 8; k++) {
    out[k*4]   = (uint8_t)(c.state[k] >> 24); out[k*4+1] = (uint8_t)(c.state[k] >> 16);
    out[k*4+2] = (uint8_t)(c.state[k] >> 8);  out[k*4+3] = (uint8_t)(c.state[k]);
  }
}

// Constant-time buffer compare (no early exit on the first differing byte).
bool ctEqualBytes(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
  return d == 0;
}

// "user:password" -> sha256. The plaintext exists only for the microseconds it
// takes to hash a login attempt; only the hash is ever stored.
void hashCredentials(const char* user, const char* pass, uint8_t out[32]) {
  char joined[WEB_PASS_MAX_LEN + 40];
  snprintf(joined, sizeof(joined), "%s:%s", user, pass);
  sha256((const uint8_t*)joined, strlen(joined), out);
  memset(joined, 0, sizeof(joined));
}

// --------------------------------------------------------------------------
// Modbus RTU CRC-16
// --------------------------------------------------------------------------

uint16_t modbusCRC(const uint8_t* buf, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t pos = 0; pos < len; pos++) {
    crc ^= buf[pos];
    for (int i = 0; i < 8; i++) crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0xA001) : (uint16_t)(crc >> 1);
  }
  return crc;
}

// --------------------------------------------------------------------------
// Diagnostics
// --------------------------------------------------------------------------

// Boot/reset reason: the first thing a field engineer wants after an unexpected
// restart (audit FIX-38).
const char* resetReasonName() {
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON:  return "power-on";
    case ESP_RST_EXT:      return "external pin";
    case ESP_RST_SW:       return "software restart";
    case ESP_RST_PANIC:    return "panic / exception";
    case ESP_RST_INT_WDT:  return "interrupt watchdog";
    case ESP_RST_TASK_WDT: return "task watchdog";
    case ESP_RST_WDT:      return "other watchdog";
    case ESP_RST_BROWNOUT: return "brown-out";
    case ESP_RST_SDIO:     return "SDIO";
    default:               return "unknown";
  }
}
