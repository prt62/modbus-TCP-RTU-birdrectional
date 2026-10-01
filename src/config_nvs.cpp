// ==========================================================================
// config_nvs.cpp — configuration record, password hash, counters, MAC
// ==========================================================================
#include "config_nvs.h"
#include <Preferences.h>
#include <string.h>
#include "esp_mac.h"
#include "utils.h"

// --------------------------------------------------------------------------
// Shared state (declared in config_nvs.h)
// --------------------------------------------------------------------------

GatewayConfig cfg;
byte          mac[6];
uint8_t       g_pwHash[32];               // runtime credential state (mirrors the record)
bool          g_pwIsDefault    = false;
Stats         g_stat           = {};
UnitStat      g_unitStat[UNIT_STAT_SLOTS] = {};
bool          g_restartPending = false;   // NetTask restarts once the reply is out
uint32_t      g_restartAtMs    = 0;

// The one handle to the "modbus_cfg" NVS namespace. configInit() opens it;
// until then every get/put fails (that was the modular draft's critical bug).
static Preferences prefs;

// Web login user name. The password itself is never stored in clear text: only
// sha256("user:password") lives in the configuration record.
const char* const WEB_AUTH_USER = "admin";

const SerialFmt SERIAL_FMTS[] = {
  {"8N1", SERIAL_8N1}, {"8E1", SERIAL_8E1}, {"8O1", SERIAL_8O1}, {"8N2", SERIAL_8N2},
};
const uint8_t  SERIAL_FMT_COUNT = sizeof(SERIAL_FMTS) / sizeof(SERIAL_FMTS[0]);
const uint32_t BAUDS[] = {1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200};
const uint8_t  BAUD_COUNT = sizeof(BAUDS) / sizeof(BAUDS[0]);

// Open the NVS namespace. Every other function in this file reads or writes
// through `prefs`, so setup() calls this before factoryResetCheck() and
// loadConfig(). On failure the gateway still runs, on factory defaults.
bool configInit() {
  if (prefs.begin("modbus_cfg", false)) return true;
  LOGF("[CFG] NVS unavailable -> running on defaults\n");
  return false;
}

void unitStatRecord(uint8_t unit, bool ok) {
  UnitStat* victim = nullptr;
  for (auto& u : g_unitStat) {
    if (u.used && u.unit == unit) {
      if (ok) u.ok++; else u.fail++;
      return;
    }
    if (!u.used) { victim = &u; break; }
    if (!victim || (u.ok + u.fail) < (victim->ok + victim->fail)) victim = &u;
  }
  if (!victim) return;
  victim->used = true; victim->unit = unit;
  victim->ok = ok ? 1 : 0;
  victim->fail = ok ? 0 : 1;
}

// Modbus TCP port 80 would collide with the web server, and only the baud
// rates offered on the page are accepted (a corrupt value must never reach
// the UART driver).
bool baudValid(uint32_t b) {
  for (uint8_t i = 0; i < BAUD_COUNT; i++) if (BAUDS[i] == b) return true;
  return false;
}

bool portValid(uint32_t p) { return p >= 1 && p <= 65535 && p != HTTP_PORT; }

// Default password: WEB_DEFAULT_PASSWORD when it is set (commissioning,
// "admin123"), otherwise a per-device value derived from the MAC ("MG-xxxxxx",
// printed on the device label) so that a leaked firmware image does not unlock
// the installed base. Only authReport() may print it, and only while
// WEB_FORCE_DEFAULT_PASSWORD is 1.
void defaultPassword(char* out, size_t cap) {
  if (sizeof(WEB_DEFAULT_PASSWORD) > 1) {            // fixed, known password
    snprintf(out, cap, "%s", WEB_DEFAULT_PASSWORD);
    return;
  }
  // Per-device fallback. Never callable before generateUniqueMac(): an all-zero
  // MAC would produce the same password on every device and would not match the
  // label.
  if ((mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]) == 0)
    LOGF("[SEC] BUG: default password requested before the MAC was generated\n");
  snprintf(out, cap, "MG-%02X%02X%02X", mac[3], mac[4], mac[5]);
}

// --------------------------------------------------------------------------
// Persistent configuration (NVS, A/B slots)
// --------------------------------------------------------------------------

// One write, one CRC, one version: a power cut during save can no longer leave
// a half-new configuration behind (audit FIX-04). Legacy per-key values from
// firmware <= 2.1.0 are read once and migrated into the blob.
// One record holds EVERYTHING that must survive a reboot together: network,
// serial, gateway options, the password hash and the default-password flag.
// It is written to two NVS slots in turn, each with its own generation number
// and CRC, and read back to verify. Power loss at any instant therefore leaves
// at least one fully valid slot, and the configuration can never disagree with
// the password (audit FIX-A2 / FIX-A6).
#define CFG_MAGIC   0xA71Cu
#define CFG_VERSION 3u        // v1/v2 single-key blobs are migrated on first boot

struct StoredCfg {
  uint16_t magic;
  uint16_t version;
  uint32_t generation;          // higher = newer; the valid slot with the highest wins
  uint8_t  ip[4], sn[4], gw[4];
  uint16_t port;
  uint32_t baud;
  uint8_t  fmt;
  uint8_t  flags;
  uint16_t rtuTimeoutMs;
  uint8_t  pwHash[32];          // sha256("user:password")
  uint8_t  pwIsDefault;
  uint8_t  reserved[7];         // room for future fields without a new version
  uint16_t crc;                 // modbusCRC over every byte before this field
} __attribute__((packed));

// Legacy layouts, read once so that an upgrade keeps the operator's settings.
struct StoredCfgV2 {
  uint16_t magic; uint16_t version;
  uint8_t  ip[4], sn[4], gw[4];
  uint16_t port; uint32_t baud;
  uint8_t  fmt; uint8_t flags; uint16_t rtuTimeoutMs;
  uint16_t crc;
} __attribute__((packed));

static const char* CFG_SLOT[2] = { "cfgA", "cfgB" };
static uint32_t g_cfgGeneration = 0;
static uint8_t  g_cfgSlot = 0;          // slot the live configuration came from

static uint16_t cfgCrc(const StoredCfg& b) {
  return modbusCRC((const uint8_t*)&b, sizeof(StoredCfg) - sizeof(uint16_t));
}

static bool configBlobValid(const StoredCfg& b) {
  return b.magic == CFG_MAGIC && b.version == CFG_VERSION && b.crc == cfgCrc(b);
}

static void applyDefaults(GatewayConfig& c) {
  c.ip = IPAddress(192, 168, 1, 50);
  c.sn = IPAddress(255, 255, 255, 0);
  c.gw = IPAddress(192, 168, 1, 1);
  c.port = 502; c.baud = 9600; c.fmt = 0;
  c.flags = CFG_FLAG_TCP_EXCEPTION;              // MOXA's "Modbus TCP Exception" = enabled
  c.rtuTimeoutMs = RS485_DEFAULT_TIMEOUT_MS;
}

static bool configSane(const GatewayConfig& c) {
  return networkValid(c.ip, c.sn, c.gw) && portValid(c.port) && baudValid(c.baud) &&
         c.fmt < SERIAL_FMT_COUNT && c.rtuTimeoutMs >= 20 && c.rtuTimeoutMs <= 5000;
}

// Write the complete record to the slot that is NOT in use, then read it back
// and verify. Only after that does the caller's RAM state become authoritative.
bool persistConfig(const GatewayConfig& c, const uint8_t pwHash[32], bool pwDefault) {
  StoredCfg b;
  memset(&b, 0, sizeof(b));
  b.magic = CFG_MAGIC;
  b.version = CFG_VERSION;
  b.generation = g_cfgGeneration + 1;
  for (int i = 0; i < 4; i++) { b.ip[i] = c.ip[i]; b.sn[i] = c.sn[i]; b.gw[i] = c.gw[i]; }
  b.port = c.port; b.baud = c.baud; b.fmt = c.fmt; b.flags = c.flags;
  b.rtuTimeoutMs = c.rtuTimeoutMs;
  memcpy(b.pwHash, pwHash, sizeof(b.pwHash));
  b.pwIsDefault = pwDefault ? 1 : 0;
  b.crc = cfgCrc(b);

  const uint8_t target = g_cfgSlot ^ 1;            // never overwrite the live slot
  if (prefs.putBytes(CFG_SLOT[target], &b, sizeof(b)) != sizeof(b)) {
    LOGF("[CFG] write to %s failed\n", CFG_SLOT[target]);
    return false;
  }
  StoredCfg check;
  if (prefs.getBytes(CFG_SLOT[target], &check, sizeof(check)) != sizeof(check) ||
      !configBlobValid(check) || check.generation != b.generation ||
      memcmp(&check, &b, sizeof(b)) != 0) {
    LOGF("[CFG] read-back verify of %s failed\n", CFG_SLOT[target]);
    return false;
  }
  g_cfgSlot = target;                              // commit point
  g_cfgGeneration = b.generation;
  return true;
}

// Legacy migration: v1/v2 blob under "cfg" plus "pwh"/"pwdef".
static bool loadLegacyBlob(GatewayConfig& c, uint8_t pwHash[32], bool& pwDefault) {
  StoredCfgV2 b;
  if (prefs.getBytes("cfg", &b, sizeof(b)) != sizeof(b)) return false;
  if (b.magic != CFG_MAGIC || (b.version != 1u && b.version != 2u)) return false;
  if (b.crc != modbusCRC((const uint8_t*)&b, sizeof(StoredCfgV2) - sizeof(uint16_t))) return false;
  c.ip = IPAddress(b.ip[0], b.ip[1], b.ip[2], b.ip[3]);
  c.sn = IPAddress(b.sn[0], b.sn[1], b.sn[2], b.sn[3]);
  c.gw = IPAddress(b.gw[0], b.gw[1], b.gw[2], b.gw[3]);
  c.port = b.port; c.baud = b.baud; c.fmt = b.fmt;
  c.flags = (b.version >= 2u) ? b.flags : CFG_FLAG_TCP_EXCEPTION;
  c.rtuTimeoutMs = b.rtuTimeoutMs;
  if (prefs.getBytes("pwh", pwHash, 32) == 32) pwDefault = prefs.getBool("pwdef", false);
  else                                          return false;
  return configSane(c);
}

// Even older layout: one NVS key per value.
static bool loadLegacyKeys(GatewayConfig& c) {
  char buf[20];
  IPAddress ip, sn, gw;
  if (prefs.getString("l_ip", buf, sizeof(buf)) == 0 || !parseIPv4(buf, ip)) return false;
  if (prefs.getString("l_sn", buf, sizeof(buf)) == 0 || !parseIPv4(buf, sn)) return false;
  if (prefs.getString("l_gw", buf, sizeof(buf)) == 0 || !parseIPv4(buf, gw)) return false;
  c.ip = ip; c.sn = sn; c.gw = gw;
  c.port = (uint16_t)prefs.getInt("m_port", 502);
  c.baud = (uint32_t)prefs.getInt("baud", 9600);
  c.fmt  = prefs.getUChar("fmt", 0);
  c.flags = CFG_FLAG_TCP_EXCEPTION;
  c.rtuTimeoutMs = prefs.getUShort("rtu_to", RS485_DEFAULT_TIMEOUT_MS);
  return configSane(c);
}

static void dropLegacyKeys() {
  const char* keys[] = {"cfg", "pwh", "pwdef", "l_ip", "l_sn", "l_gw", "m_port", "baud", "fmt", "rtu_to"};
  for (const char* k : keys) prefs.remove(k);
}

// Boot: validate both slots, take the newest valid generation, migrate anything
// older, and fall back to factory defaults only if nothing is usable.
void loadConfig() {
  applyDefaults(cfg);

  StoredCfg slot[2];
  bool ok[2] = {false, false};
  for (int i = 0; i < 2; i++) {
    // isKey() first: reading a missing blob makes the Preferences library log an
    // alarming "nvs_get_blob len fail" error on a perfectly normal first boot.
    ok[i] = prefs.isKey(CFG_SLOT[i]) &&
            prefs.getBytes(CFG_SLOT[i], &slot[i], sizeof(StoredCfg)) == sizeof(StoredCfg) &&
            configBlobValid(slot[i]);
  }

  if (!ok[0] && !ok[1] &&
      (prefs.isKey(CFG_SLOT[0]) || prefs.isKey(CFG_SLOT[1]))) g_stat.cfgCrcFail++;

  int chosen = -1;
  if (ok[0] && ok[1]) chosen = (int32_t)(slot[0].generation - slot[1].generation) >= 0 ? 0 : 1;
  else if (ok[0])     chosen = 0;
  else if (ok[1])     chosen = 1;

  if (chosen >= 0) {
    const StoredCfg& b = slot[chosen];
    GatewayConfig tmp;
    tmp.ip = IPAddress(b.ip[0], b.ip[1], b.ip[2], b.ip[3]);
    tmp.sn = IPAddress(b.sn[0], b.sn[1], b.sn[2], b.sn[3]);
    tmp.gw = IPAddress(b.gw[0], b.gw[1], b.gw[2], b.gw[3]);
    tmp.port = b.port; tmp.baud = b.baud; tmp.fmt = b.fmt; tmp.flags = b.flags;
    tmp.rtuTimeoutMs = b.rtuTimeoutMs;
    if (configSane(tmp)) {
      cfg = tmp;
      memcpy(g_pwHash, b.pwHash, sizeof(g_pwHash));
      g_pwIsDefault = b.pwIsDefault != 0;
      g_cfgSlot = (uint8_t)chosen;
      g_cfgGeneration = b.generation;
      LOGF("[CFG] loaded slot %s generation %lu\n", CFG_SLOT[chosen], (unsigned long)b.generation);

      // Commissioning mode: make sure the known default password is the one in
      // force, whatever is stored. Also the self-heal for units flashed with the
      // broken initialisation order, where the stored hash was computed from an
      // all-zero MAC (audit FIX-01 / FIX-61). Flash is written only when the
      // hash actually differs, so a normal boot writes nothing.
      if (g_pwIsDefault || WEB_FORCE_DEFAULT_PASSWORD) {
        char def[16];
        uint8_t expect[32];
        defaultPassword(def, sizeof(def));
        hashCredentials(WEB_AUTH_USER, def, expect);
        if (!ctEqualBytes(expect, g_pwHash, sizeof(expect)) || !g_pwIsDefault) {
          memcpy(g_pwHash, expect, sizeof(g_pwHash));
          g_pwIsDefault = true;
          if (persistConfig(cfg, g_pwHash, true))
            LOGF("[SEC] web password reset to the built-in default\n");
          else
            g_stat.cfgSaveFail++;
        }
      }
      return;
    }
    LOGF("[CFG] stored configuration failed validation\n");
    g_stat.cfgCrcFail++;
  }

  // Migration paths (run once, then the A/B slots take over).
  GatewayConfig legacy;
  applyDefaults(legacy);
  uint8_t pwHash[32];
  bool pwDefault = true;
  bool haveLegacy = loadLegacyBlob(legacy, pwHash, pwDefault);
  if (!haveLegacy && loadLegacyKeys(legacy)) {
    char def[16];
    defaultPassword(def, sizeof(def));
    hashCredentials(WEB_AUTH_USER, def, pwHash);
    pwDefault = true;
    haveLegacy = true;
  }
  if (haveLegacy) {
    cfg = legacy;
    memcpy(g_pwHash, pwHash, sizeof(g_pwHash));
    g_pwIsDefault = pwDefault;
    if (persistConfig(cfg, g_pwHash, g_pwIsDefault)) {
      dropLegacyKeys();
      LOGF("[CFG] migrated older configuration into the A/B slots\n");
    }
    return;
  }

  // Nothing usable: factory defaults with the per-device default password.
  char def[16];
  defaultPassword(def, sizeof(def));
  hashCredentials(WEB_AUTH_USER, def, g_pwHash);
  g_pwIsDefault = true;
  if (persistConfig(cfg, g_pwHash, g_pwIsDefault))
    LOGF("[CFG] no valid configuration found -> factory defaults stored\n");
}

// --------------------------------------------------------------------------
// Factory reset and MAC
// --------------------------------------------------------------------------

void factoryResetCheck() {
#if FACTORY_RESET_PIN >= 0                          
  pinMode(FACTORY_RESET_PIN, INPUT_PULLUP);
  delay(10);
  if (digitalRead(FACTORY_RESET_PIN) != LOW) return;
  LOGF("[CFG] factory-reset pin held...\n");
  uint32_t start = millis();
  while (digitalRead(FACTORY_RESET_PIN) == LOW) {
    if (millis() - start >= FACTORY_RESET_HOLD_MS) {
      prefs.clear();
      LOGF("[CFG] configuration wiped (factory defaults)\n");
      for (int i = 0; i < 10; i++) { digitalWrite(LED_D3, i & 1); digitalWrite(LED_D4, i & 1); delay(100); }
      return;
    }
    pulseExternalWatchdog();
    delay(50);
  }
#endif
}

// Locally administered, unicast MAC derived from the chip's factory MAC.
// MUST run before loadConfig(): the per-device default password is derived
// from it (audit FIX-01).
void generateUniqueMac(byte* macOut) {
  uint8_t base[6];
  esp_read_mac(base, ESP_MAC_WIFI_STA);
  memcpy(macOut, base, 6);
  macOut[0] = (uint8_t)((macOut[0] | 0x02) & 0xFE);  // locally administered + unicast
  macOut[5] ^= 0x01;
}
