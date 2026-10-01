#pragma once
// ==========================================================================
// utils.h — small helpers shared by every module
// --------------------------------------------------------------------------
// Logging, IPv4 parsing and validation, SHA-256 credential hashing, a
// constant-time compare, reset-reason names, the external-watchdog pulse and
// the Modbus CRC. No module state lives here.
// ==========================================================================
#include <Arduino.h>
#include <IPAddress.h>
#include <stdint.h>
#include "hw_config.h"
#include "modbus_crc.h"

// One log macro for the whole firmware; DEBUG_SERIAL=0 compiles every log out.
#if DEBUG_SERIAL
  #define LOGF(...) Serial.printf(__VA_ARGS__)
#else
  #define LOGF(...) do {} while (0)
#endif

#define WEB_PASS_MAX_LEN 32   // longest accepted web password (also sizes buffers)

uint32_t ipToU32(const IPAddress& a);
bool parseIPv4(const char* s, IPAddress& out);           // strict dotted quad
bool parseU32(const char* s, uint32_t minV, uint32_t maxV, uint32_t& out);
bool maskValid(const IPAddress& m);                      // contiguous, /1 .. /30
bool networkValid(const IPAddress& ip, const IPAddress& sn, const IPAddress& gw);

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
bool ctEqualBytes(const uint8_t* a, const uint8_t* b, size_t n);
void hashCredentials(const char* user, const char* pass, uint8_t out[32]);

const char* resetReasonName();   // why the chip last restarted
void pulseExternalWatchdog();    // one DONE pulse for the external supervisor
