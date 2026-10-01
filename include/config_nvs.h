#pragma once
// ==========================================================================
// config_nvs.h — persistent configuration, credentials and shared counters
// --------------------------------------------------------------------------
// The whole configuration (network, serial, gateway options, password hash,
// default-password flag) is ONE versioned, CRC-protected record written to
// A/B slots in NVS, so a power cut during a save can never leave settings
// and password out of step. configInit() MUST run before anything else here.
// ==========================================================================
#include <Arduino.h>
#include <IPAddress.h>
#include "hw_config.h"

#define RS485_DEFAULT_TIMEOUT_MS 1000
#define UNIT_STAT_SLOTS 8                     // per-unit-id counters on the status page

// cfg.flags bits
#define CFG_FLAG_TCP_EXCEPTION 0x01   // answer RTU failures with a Modbus exception

// Commissioning password. Leave WEB_DEFAULT_PASSWORD empty ("") to go back to
// the per-device MAC-derived default ("MG-xxxxxx", printed on the label).
#ifndef WEB_DEFAULT_PASSWORD
#define WEB_DEFAULT_PASSWORD "admin123"
#endif

// 1 = re-apply the default password at EVERY boot: you can always log in, even
//     after a wrong password change or a half-written record. Console prints it.
// 0 = production: the stored password wins, and the default is used only when
//     nothing has been stored yet. Nothing is printed.
#ifndef WEB_FORCE_DEFAULT_PASSWORD
#define WEB_FORCE_DEFAULT_PASSWORD 1
#endif

struct GatewayConfig {
  IPAddress ip, sn, gw;
  uint16_t  port;
  uint32_t  baud;
  uint8_t   fmt;           // index into SERIAL_FMTS
  uint8_t   flags;
  uint16_t  rtuTimeoutMs;
};

// Supported serial subset (audit FIX-A13): 1200-115200 baud, 8 data bits,
// none/even/odd parity, 1-2 stop bits, no flow control. A MOXA MGate MB3180
// additionally offers 50 bps-921.6 kbps, 7 data bits, space/mark parity and
// RTS/CTS - none of which are common in Modbus RTU installations.
struct SerialFmt { const char* name; uint32_t conf; };
extern const SerialFmt SERIAL_FMTS[];
extern const uint8_t   SERIAL_FMT_COUNT;
extern const uint32_t  BAUDS[];
extern const uint8_t   BAUD_COUNT;
extern const char* const WEB_AUTH_USER;

// Counters are 32-bit and RAM-only: they wrap after ~4.3e9 events and reset on
// every reboot. They are a live diagnostic aid, not an audit log. Written by
// NetTask only.
struct Stats {
  uint32_t requests, rtuOk, rtuTimeout, rtuCrc, rtuFrame, rtuUnitMismatch, rtuFcMismatch;
  uint32_t broadcasts, reqRejected, reqAged, staleResults, rtuAbandoned, internalErr;
  uint32_t tcpAccepted, tcpRejected, tcpEvicted, tcpDropped, tcpDisconnects;
  uint32_t queueBackpressure, httpWriteFail, authFailures, authLockouts;
  uint32_t cfgSaveFail, cfgCrcFail, ethRecoveries;
};

// Per-unit-id health, so a single bad slave can be identified from the status
// page instead of a bus analyser (audit FIX-A11). Least-used slot is recycled.
struct UnitStat { uint8_t unit; bool used; uint32_t ok, fail; };

extern GatewayConfig cfg;          // live configuration (written only at boot)
extern byte          mac[6];
extern uint8_t       g_pwHash[32]; // sha256("user:password")
extern bool          g_pwIsDefault;
extern Stats         g_stat;
extern UnitStat      g_unitStat[UNIT_STAT_SLOTS];
extern bool          g_restartPending;
extern uint32_t      g_restartAtMs;

bool configInit();                 // open the NVS namespace - call first
void factoryResetCheck();          // optional reset pin, before loadConfig()
void generateUniqueMac(byte* macOut);  // MUST run before loadConfig() (FIX-01)
void defaultPassword(char* out, size_t cap);
void loadConfig();
bool persistConfig(const GatewayConfig& c, const uint8_t pwHash[32], bool pwDefault);
void unitStatRecord(uint8_t unit, bool ok);
bool portValid(uint32_t p);
bool baudValid(uint32_t b);
