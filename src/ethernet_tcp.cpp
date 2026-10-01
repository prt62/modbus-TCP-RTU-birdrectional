// ==========================================================================
// ethernet_tcp.cpp — W5500, Modbus TCP server, RTU job engine, NetTask
// --------------------------------------------------------------------------
// Sole owner of the W5500 / SPI bus / Arduino Ethernet library after setup().
// ==========================================================================
#include "ethernet_tcp.h"
#include <SPI.h>
#include <string.h>
#include "esp_task_wdt.h"
#include "config_nvs.h"
#include "rs485_rtu.h"
#include "utils.h"
#include "web_server.h"

// W5500 socket status register values (Sn_SR)
namespace SockSt {
  constexpr uint8_t CLOSED      = 0x00;
  constexpr uint8_t INIT        = 0x13;
  constexpr uint8_t LISTEN      = 0x14;
  constexpr uint8_t SYNSENT     = 0x15;
  constexpr uint8_t SYNRECV     = 0x16;
  constexpr uint8_t ESTABLISHED = 0x17;
  constexpr uint8_t CLOSE_WAIT  = 0x1C;
}

static constexpr size_t MB_TCP_ADU_MAX = 260;  // 7 MBAP + 253 PDU

// --------------------------------------------------------------------------
// Shared state (declared in ethernet_tcp.h)
// --------------------------------------------------------------------------

CustomEthernetServer modbusServer(502);        // real port applied in setup()
CustomEthernetServer httpServer(HTTP_PORT);
TaskHandle_t  g_netTask  = nullptr;             // kept for the stack high-water marks
TaskHandle_t  g_rtuTask  = nullptr;
QueueHandle_t g_rtuJobQ  = nullptr;             // NetTask -> RtuTask  ("job ready")
QueueHandle_t g_rtuDoneQ = nullptr;             // RtuTask -> NetTask  ("job done")

// Published by NetTask, read by loop(). Aligned 32-bit -> atomic on Xtensa.
volatile uint32_t g_netHeartbeatMs = 0;
volatile uint32_t g_lastTrafficMs  = 0;
volatile bool     g_linkUp         = false;
volatile bool     g_ethOk          = false;      // W5500 present & sane (for the LEDs)

// Everything below is touched ONLY by NetTask (or setup() before it starts).
bool            g_twdtSubscribed = false;   // NetTask on task-WDT
bool            g_ethReady       = false;
static uint8_t  g_ethStrikes     = 0;       // consecutive failed health reads

// Called by NetTask at every point where it may wait.
void netAlive() {
  g_netHeartbeatMs = millis();
  if (g_twdtSubscribed) esp_task_wdt_reset();
}

// --------------------------------------------------------------------------
// Socket ownership helpers (NetTask only)
// --------------------------------------------------------------------------

// Zero-initialised "no socket" client (static storage). Assigning from this
// instead of a temporary avoids core 3.x -Wuninitialized noise in Stream.
static EthernetClient kNoClient;

// One parsed, validated Modbus request waiting for the bus. Every field the
// response needs is copied here, so the raw TCP buffer can move on and the
// client's identity can never be inferred from shared state (audit FIX-A1).
struct PendingReq {
  uint8_t  tidHi, tidLo;        // transaction id: scoped to THIS connection
  uint8_t  unit, fc;
  uint16_t rtuLen;              // unit + pdu, no CRC
  uint32_t enqueuedMs;
  uint8_t  rtu[MB_RTU_MAX];
};

struct MbSession {
  EthernetClient sock;
  bool     active;
  uint16_t len;                 // raw bytes held for reassembly
  uint32_t lastRxMs;
  uint32_t frameStartMs;
  bool     busy;                // one request of this client is on the bus
  uint32_t gen;                 // bumped on every close/reuse -> stale results are dropped
  uint8_t  qHead, qCount;       // pipelined requests, FIFO -> answers keep their order
  PendingReq q[REQ_QUEUE_DEPTH];
  uint8_t  buf[MB_TCP_ADU_MAX];
};
static MbSession g_mb[MAX_CLIENTS];

// Reset a slot's bookkeeping (socket handled by the caller).
static inline void resetMbSlot(MbSession& s) {
  s.active = false; s.len = 0; s.busy = false;
  s.qHead = 0; s.qCount = 0;
  s.gen++;
}

struct HttpSession {
  EthernetClient sock;
  bool     active;
  uint16_t len;
  uint32_t startMs;
  char     buf[HTTP_BUF_SIZE];
};
static HttpSession g_http;

// Release a socket we hold. If the chip already recycled that socket for a
// listener / an incoming handshake, it is no longer ours: just forget it.
static void releaseSocket(EthernetClient& c) {
  if (c) {
    uint8_t st = c.status();
    if (st != SockSt::CLOSED && st != SockSt::LISTEN && st != SockSt::INIT &&
        st != SockSt::SYNRECV && st != SockSt::SYNSENT) {
      c.stop();
    }
  }
  c = kNoClient;
}

static void closeMbSession(MbSession& s) {
  releaseSocket(s.sock);
  resetMbSlot(s);
}

static void closeHttpSession() {
  releaseSocket(g_http.sock);
  g_http.active = false;
  g_http.len = 0;
}

// A server just handed us socket `sn`: any older slot still pointing at the
// same socket number is stale (its connection died and the socket got
// recycled). Forget it WITHOUT stop() — stop() would kill the new client.
static void forgetStaleHolders(uint8_t sn) {
  for (auto& s : g_mb) {
    if (s.active && s.sock.getSocketNumber() == sn) {
      s.sock = kNoClient; resetMbSlot(s);
    }
  }
  if (g_http.active && g_http.sock.getSocketNumber() == sn) {
    g_http.sock = kNoClient; g_http.active = false; g_http.len = 0;
  }
}

// Forget every socket without touching the chip (used after a W5500 reset).
static void forgetAllSockets() {
  for (auto& s : g_mb) { s.sock = kNoClient; resetMbSlot(s); }
  g_http.sock = kNoClient; g_http.active = false; g_http.len = 0;
}

static bool socketWritable(EthernetClient& c) {
  uint8_t st = c.status();
  return st == SockSt::ESTABLISHED || st == SockSt::CLOSE_WAIT;
}

// Chunked, bounded write. EthernetClient::write() truncates silently at the
// W5500 socket buffer size and busy-waits on a stalled peer, so never hand
// it more than it can take right now.
// Absolute deadline for the WHOLE transfer (audit FIX-07): a peer that accepts
// one byte at a time must not be able to hold NetTask indefinitely.
// (The default timeout, TCP_WRITE_TIMEOUT_MS, is declared in ethernet_tcp.h.)
bool writeAll(EthernetClient& c, const uint8_t* data, size_t len, uint32_t timeoutMs) {
  const uint32_t deadline = millis() + timeoutMs;
  while (len > 0) {
    if (!socketWritable(c)) return false;
    if ((int32_t)(millis() - deadline) > 0) return false;
    int room = c.availableForWrite();
    if (room <= 0) {
      netAlive();
      vTaskDelay(1);
      continue;
    }
    size_t chunk = len;
    if (chunk > (size_t)room) chunk = (size_t)room;
    if (chunk > 1024) chunk = 1024;
    if (c.write(data, chunk) != chunk) return false;
    data += chunk; len -= chunk;
  }
  return true;
}

// --------------------------------------------------------------------------
// W5500 init / health (setup() at boot, NetTask afterwards)
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Raw W5500 probe. The Arduino Ethernet library detects the chip at a fixed
// 14 MHz; this talks to the same chip at a chosen clock using the W5500's own
// variable-length data mode, so a wiring/level/clock problem can be told apart
// from a library problem (audit FIX-51).
//   frame: [addr hi][addr lo][control: BSB=0, read, VDM] then read one byte
// --------------------------------------------------------------------------
static uint8_t w5500RawVersion(uint32_t clockHz) {
  SPI.beginTransaction(SPISettings(clockHz, MSBFIRST, SPI_MODE0));
  digitalWrite(W5500_CS, LOW);
  SPI.transfer((uint8_t)(W5500_VERSIONR >> 8));
  SPI.transfer((uint8_t)(W5500_VERSIONR & 0xFF));
  SPI.transfer(0x00);                       // common register block, read, VDM
  uint8_t v = SPI.transfer(0x00);
  digitalWrite(W5500_CS, HIGH);
  SPI.endTransaction();
  return v;
}

// Print which SPI clocks the chip answers at. Only used when something is
// wrong, so the cost does not matter (audit FIX-52).
static void w5500ClockSweep() {
  static const uint32_t clocks[] = {1000000UL, 2000000UL, 4000000UL,
                                    8000000UL, 14000000UL, 20000000UL};
  LOGF("[ETH] SPI clock sweep (VERSIONR must read 0x%02X):\n", W5500_EXPECTED_VERSION);
  for (uint32_t hz : clocks) {
    const uint8_t v = w5500RawVersion(hz);
    (void)v;                                  // only used by the log line
    LOGF("[ETH]   %2lu MHz -> 0x%02X %s\n", (unsigned long)(hz / 1000000UL), v,
         v == W5500_EXPECTED_VERSION ? "OK" : "no answer");
  }
  LOGF("[ETH] If NOTHING answers at any clock, the most likely cause is the RESET\n"
       "[ETH] line: this build asserts reset with GPIO %s. If your board drives\n"
       "[ETH] /RESET directly instead of through a transistor, rebuild with\n"
       "[ETH] -DW5500_RST_ASSERT_HIGH=%d.\n",
       W5500_RST_ASSERT_HIGH ? "HIGH" : "LOW", W5500_RST_ASSERT_HIGH ? 0 : 1);
  LOGF("[ETH] If low clocks answer but 14 MHz does not, the wiring cannot carry\n"
       "[ETH] the library's fixed 14 MHz: shorten the SPI wires, add ground\n"
       "[ETH] return paths, or lower SPI_ETHERNET_SETTINGS in Ethernet/src/\n"
       "[ETH] utility/w5100.h (line ~21) to SPISettings(8000000, MSBFIRST, SPI_MODE0).\n"
       "[ETH] If NO clock answers: check 3V3 supply and current, MISO/MOSI not\n"
       "[ETH] swapped, CS wired to the configured pin, and RESET not held low.\n");
}

// Assert reset, release it, then WAIT FOR THE CHIP to answer instead of hoping
// a fixed delay is enough. The measured boot time is a crystal health indicator:
// a healthy W5500 answers in well under 250 ms (audit FIX-57).
static bool w5500HardwareReset(uint32_t* bootMsOut) {
  if (bootMsOut) *bootMsOut = 0;
#if W5500_RST >= 0
  digitalWrite(W5500_RST, W5500_RST_ASSERT_LEVEL);
  delay(W5500_RST_PULSE_MS);
  digitalWrite(W5500_RST, W5500_RST_RELEASE_LEVEL);
#endif
  delay(100);                                 // let the PLL start before polling

  const uint32_t start = millis();
  while (millis() - start < W5500_BOOT_TIMEOUT_MS) {
    if (w5500RawVersion(ETH_PROBE_HZ) == W5500_EXPECTED_VERSION) {
      if (bootMsOut) *bootMsOut = millis() - start;
      return true;
    }
    pulseExternalWatchdog();
    delay(5);
  }
  return false;
}

bool ethernetInit() {
  pinMode(W5500_CS, OUTPUT);
  digitalWrite(W5500_CS, HIGH);               // deselect before any transfer

  for (uint8_t attempt = 1; attempt <= ETH_INIT_ATTEMPTS; attempt++) {
    uint32_t bootMs = 0;
    const bool responding = w5500HardwareReset(&bootMs);
    pulseExternalWatchdog();

    if (responding) {
      LOGF("[ETH] attempt %u/%u: chip booted in %lu ms, VERSIONR = 0x%02X%s\n",
           attempt, (unsigned)ETH_INIT_ATTEMPTS, (unsigned long)bootMs,
           W5500_EXPECTED_VERSION,
           bootMs > 250 ? "  (slow boot - check the 25 MHz crystal and its caps)" : "");
    } else {
      LOGF("[ETH] attempt %u/%u: no answer within %u ms (probe read 0x%02X at %lu MHz)\n",
           attempt, (unsigned)ETH_INIT_ATTEMPTS, (unsigned)W5500_BOOT_TIMEOUT_MS,
           w5500RawVersion(ETH_PROBE_HZ), (unsigned long)(ETH_PROBE_HZ / 1000000UL));
    }

    Ethernet.init(W5500_CS);
    Ethernet.begin(mac, cfg.ip, cfg.gw, cfg.gw, cfg.sn);   // mac, ip, dns, gw, subnet

    if (Ethernet.hardwareStatus() != EthernetNoHardware) {
      Ethernet.setRetransmissionTimeout(W5500_RETX_TIMEOUT_MS);
      Ethernet.setRetransmissionCount(W5500_RETX_COUNT);
      modbusServer.begin();
      httpServer.begin();
      LOGF("[ETH] W5500 ready (link %s)\n",
           Ethernet.linkStatus() == LinkON ? "UP" : "down");
      return true;
    }
    LOGF("[ETH] attempt %u/%u: library did not detect the chip\n",
         attempt, (unsigned)ETH_INIT_ATTEMPTS);
    pulseExternalWatchdog();
  }

  // Out of attempts: say exactly what was seen and what to check.
  LOGF("[ETH] W5500 initialisation FAILED after %u attempts\n", (unsigned)ETH_INIT_ATTEMPTS);
  w5500ClockSweep();
  LOGF("[ETH] pins in use: SCLK %d  MISO %d  MOSI %d  CS %d  RST %d\n",
       W5500_SCLK, W5500_MISO, W5500_MOSI, W5500_CS, (int)W5500_RST);
  return false;
}

// hardwareStatus() only reports the chip id cached during init(), so it proves
// nothing about the chip right now. VERSIONR is a live read over SPI, and
// SIPR/SUBR prove the configuration the library wrote is still in the chip.
// A reset by EMI or a dead SPI bus fails all three (audit FIX-55).
static bool ethernetHealthy() {
  const uint8_t ver = w5500RawVersion(ETH_PROBE_HZ);
  if (ver != W5500_EXPECTED_VERSION) {
    LOGF("[ETH] health: VERSIONR 0x%02X (expected 0x%02X)\n", ver, W5500_EXPECTED_VERSION);
    return false;
  }
  IPAddress ip = Ethernet.localIP(), sn = Ethernet.subnetMask();
  if (ip == cfg.ip && sn == cfg.sn) return true;
  LOGF("[ETH] health: chip holds %u.%u.%u.%u/%u.%u.%u.%u, expected %u.%u.%u.%u/%u.%u.%u.%u\n",
       ip[0], ip[1], ip[2], ip[3], sn[0], sn[1], sn[2], sn[3],
       cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3], cfg.sn[0], cfg.sn[1], cfg.sn[2], cfg.sn[3]);
  return false;
}

static uint32_t g_lastRecoveryMs = 0;

static void ethernetRecover() {
  // Never thrash the chip: a reinit drops every TCP session, so it happens at
  // most once per ETH_RECOVERY_MIN_INTERVAL_MS (audit FIX-55).
  if (g_lastRecoveryMs && millis() - g_lastRecoveryMs < ETH_RECOVERY_MIN_INTERVAL_MS) return;
  g_lastRecoveryMs = millis();
  // Note: the chip reset wipes the socket state, so connected clients are
  // dropped without a FIN. Their own TCP timeout makes them reconnect; this is
  // counted so that the event can be correlated with SCADA-side alarms.
  LOGF("[ETH] W5500 unhealthy -> re-initialising\n");
  forgetAllSockets();
  netAlive();
  g_ethReady = ethernetInit();
  g_stat.ethRecoveries++;
  netAlive();
}

// --------------------------------------------------------------------------
// RTU job engine (NetTask <-> RtuTask)
// --------------------------------------------------------------------------

// --------------------------------------------------------------------------
// Asynchronous RTU engine.
// RS-485 is half-duplex, so exactly ONE job exists. Ownership of g_job is
// handed over through the queues (queue send/receive are memory barriers):
//   NetTask fills g_job -> xQueueSend(jobQ)  => RtuTask owns it
//   RtuTask fills result -> xQueueSend(doneQ) => NetTask owns it again
// NetTask never waits for the serial line; it polls doneQ with 0 timeout.
// --------------------------------------------------------------------------
struct RtuJob {
  uint32_t  jobId;               // unique, monotonic: identifies THIS transaction
  // request / response (touched by the current owner only)
  uint8_t   req[MB_RTU_MAX];     // unit + fc + data (no CRC)
  uint16_t  reqLen;
  uint8_t   rx[MB_RTU_MAX];      // full RTU reply incl. CRC
  uint16_t  rxLen;
  RtuResult result;
  // NetTask bookkeeping
  int8_t    slot;
  uint32_t  gen;
  uint8_t   tidHi, tidLo, unit, fc;
};
static RtuJob g_job;

// NetTask's view of the shared job. IDLE is the ONLY state in which g_job may
// be written; ABANDONED means the job is overdue and its client has already
// been answered, but RtuTask may still be using the buffer, so it stays
// untouched until the late completion arrives and is recognised by its id.
enum JobState { JOB_IDLE, JOB_INFLIGHT, JOB_ABANDONED };
static JobState g_jobState      = JOB_IDLE;
static uint32_t g_jobSeq        = 0;          // next job id
static uint32_t g_jobDeadlineMs = 0;
static uint8_t  g_jobLost       = 0;

void rtuTask(void* arg) {
  g_rtuTwdtSubscribed = (esp_task_wdt_add(nullptr) == ESP_OK);
  for (;;) {
    rtuAlive();
    uint32_t jobId;
    if (xQueueReceive(g_rtuJobQ, &jobId, pdMS_TO_TICKS(200)) != pdTRUE) continue;
    size_t n = 0;
    g_job.result = rtuTransaction(g_job.req, g_job.reqLen, g_job.rx, n);
    g_job.rxLen  = (uint16_t)n;
    rtuAlive();
    xQueueSend(g_rtuDoneQ, &jobId, portMAX_DELAY);   // the id travels back with it
  }
}

// --------------------------------------------------------------------------
// Modbus TCP server (NetTask only)
// --------------------------------------------------------------------------

static void acceptModbusClients() {
  for (int guard = 0; guard < MAX_SOCK_NUM; guard++) {
    EthernetClient nc = modbusServer.accept();      // each connection returned ONCE
    if (!nc) return;
    forgetStaleHolders(nc.getSocketNumber());
    nc.setConnectionTimeout(SOCKET_CLOSE_TIMEOUT_MS);

#if MODBUS_ALLOWLIST_ENABLED
    {
      const IPAddress allow[] = MODBUS_ALLOWLIST;
      IPAddress peer = nc.remoteIP();
      bool permitted = false;
      for (size_t a = 0; a < sizeof(allow) / sizeof(allow[0]); a++)
        if (allow[a] != IPAddress(0, 0, 0, 0) && allow[a] == peer) { permitted = true; break; }
      if (!permitted) {
        LOGF("[MB] connection from %u.%u.%u.%u rejected (not in allowlist)\n",
             peer[0], peer[1], peer[2], peer[3]);
        nc.stop(); g_stat.tcpRejected++;
        continue;
      }
    }
#endif

    int slot = -1;
    for (int i = 0; i < MAX_CLIENTS; i++) if (!g_mb[i].active) { slot = i; break; }
#if EVICT_OLDEST_WHEN_FULL
    // Only a STALE session may be evicted, and never one with a request on the
    // bus. "Oldest" is not the same as "dead": a historian that polls once a
    // minute is always the oldest, and dropping it caused eviction storms in
    // the field (audit FIX-05).
    if (slot < 0) {
      uint32_t now = millis(), oldestAge = 0;
      int cand = -1;
      for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_mb[i].busy || g_mb[i].qCount > 0) continue;   // never evict pending work
        uint32_t age = now - g_mb[i].lastRxMs;
        if (cand < 0 || age > oldestAge) { cand = i; oldestAge = age; }
      }
      if (cand >= 0 && oldestAge > EVICT_IDLE_THRESHOLD_MS) {
        LOGF("[MB] evicting stale slot %d (idle %lu ms)\n", cand, (unsigned long)oldestAge);
        closeMbSession(g_mb[cand]);
        g_stat.tcpEvicted++;
        slot = cand;
      }
    }
#endif
    if (slot < 0) {
      LOGF("[MB] slots full -> rejecting connection\n");
      nc.stop();
      g_stat.tcpRejected++;
      continue;
    }
    MbSession& s = g_mb[slot];
    resetMbSlot(s);                                 // new generation for this slot
    s.sock = nc;
    s.active = true;
    s.lastRxMs = millis();
    s.frameStartMs = s.lastRxMs;
    g_stat.tcpAccepted++;
    LOGF("[MB] client on socket %u -> slot %d\n", nc.getSocketNumber(), slot);
  }
}

static void sendModbusException(MbSession& s, uint8_t tidHi, uint8_t tidLo, uint8_t unit,
                                uint8_t fc, uint8_t code) {
  uint8_t r[9] = { tidHi, tidLo, 0, 0, 0, 3, unit, (uint8_t)(fc | 0x80), code };
  if (!writeAll(s.sock, r, sizeof(r))) { closeMbSession(s); g_stat.tcpDropped++; }
}

// Function-code audit table (audit FIX-07 / FIX-20). "req" is unit+fc+data, no
// CRC; "resp" is the RTU response including CRC. Anything not listed is passed
// through untouched, because a transparent gateway must not block a vendor
// function it does not know.
//
//  FC    request len   response len              limits enforced here
//  01    6             5 + byteCount             qty 1..2000
//  02    6             5 + byteCount             qty 1..2000
//  03    6             5 + byteCount             qty 1..125
//  04    6             5 + byteCount             qty 1..125
//  05    6             8 (echo)                  -
//  06    6             8 (echo)                  -
//  07    2             5                         -
//  08    6             req + 2 (echo)            -
//  0B    2             8                         -
//  0C    2             5 + byteCount             -
//  0F    7 + bc        8                         qty 1..1968, bc == ceil(qty/8)
//  10    7 + bc        8                         qty 1..123,  bc == 2*qty
//  11    2             5 + byteCount             -
//  14    variable      5 + byteCount             pass-through
//  15    variable      echo (5 + len)            pass-through
//  16    8             10                        -
//  17    11 + bc       5 + byteCount             read 1..125, write 1..121
//  18    4             6 + byteCount(2 bytes)    FIFO count <= 31, even count
//  2B    variable      variable                  pass-through, silence framing
//  exception           5                         any fc | 0x80
//
// Reject requests that no slave could ever answer, before they occupy the
// half-duplex bus for a full timeout (audit FIX-08).
// Returns 0 if the request may go out, otherwise the Modbus exception code.
static uint8_t validateRtuRequest(const uint8_t* req, size_t len) {
  if (len < 2) return 0x03;                       // illegal data value
  const uint8_t fc = req[1];
  if (fc == 0x00 || fc >= 0x80) return 0x01;      // illegal function

#if !STRICT_REQUEST_VALIDATION
  return 0;                                       // transparent mode: pass everything else
#else

  auto be16 = [&](size_t i) -> uint16_t { return (uint16_t)((req[i] << 8) | req[i + 1]); };

  switch (fc) {
    case 0x01: case 0x02: {                       // read coils / discrete inputs
      if (len != 6) return 0x03;
      uint16_t qty = be16(4);
      if (qty < 1 || qty > 2000) return 0x03;
      return 0;
    }
    case 0x03: case 0x04: {                       // read holding / input registers
      if (len != 6) return 0x03;
      uint16_t qty = be16(4);
      if (qty < 1 || qty > 125) return 0x03;
      return 0;
    }
    case 0x05: case 0x06:                         // write single coil / register
      return (len == 6) ? 0 : 0x03;
    case 0x07: case 0x0B: case 0x0C: case 0x11:   // no-data requests
      return (len == 2) ? 0 : 0x03;
    case 0x08:                                    // diagnostics
      return (len == 6) ? 0 : 0x03;
    case 0x0F: {                                  // write multiple coils
      if (len < 8) return 0x03;
      uint16_t qty = be16(4);
      uint8_t  bc  = req[6];
      if (qty < 1 || qty > 1968 || bc != (uint8_t)((qty + 7) / 8) || len != (size_t)(7 + bc))
        return 0x03;
      return 0;
    }
    case 0x10: {                                  // write multiple registers
      if (len < 8) return 0x03;
      uint16_t qty = be16(4);
      uint8_t  bc  = req[6];
      if (qty < 1 || qty > 123 || bc != (uint8_t)(qty * 2) || len != (size_t)(7 + bc))
        return 0x03;
      return 0;
    }
    case 0x16:                                    // mask write register
      return (len == 8) ? 0 : 0x03;
    case 0x17: {                                  // read/write multiple registers
      if (len < 12) return 0x03;
      uint16_t rQty = be16(4), wQty = be16(8);
      uint8_t  bc   = req[10];
      if (rQty < 1 || rQty > 125 || wQty < 1 || wQty > 121 ||
          bc != (uint8_t)(wQty * 2) || len != (size_t)(11 + bc))
        return 0x03;
      return 0;
    }
    case 0x18:                                    // read FIFO queue
      return (len == 4) ? 0 : 0x03;
    default:
      return 0;                                   // file records, encapsulated, vendor: pass through
  }
#endif
}

// Non-blocking: hand the next queued request (round-robin over clients) to
// RtuTask. The RS-485 bus stays strictly serialized; the TCP side does not.
static void dispatchRtuJob() {
  static uint8_t rr = 0;
  if (g_jobState != JOB_IDLE) return;              // g_job belongs to RtuTask

  for (int k = 0; k < MAX_CLIENTS; k++) {
    int i = (rr + k) % MAX_CLIENTS;
    MbSession& s = g_mb[i];
    if (!s.active || s.busy || s.qCount == 0) continue;

    PendingReq& r = s.q[s.qHead];

    // A request that waited longer than the master's patience is answered
    // rather than put on the bus (audit FIX-A4 / queue ageing).
    if (millis() - r.enqueuedMs > REQUEST_MAX_AGE_MS) {
      LOGF("[MB] request aged out in queue (unit %u fc %u)\n", r.unit, r.fc);
      uint8_t tidHi = r.tidHi, tidLo = r.tidLo, unit = r.unit, fc = r.fc;
      s.qHead = (uint8_t)((s.qHead + 1) % REQ_QUEUE_DEPTH);
      s.qCount--;
      g_stat.reqAged++;
      if (cfg.flags & CFG_FLAG_TCP_EXCEPTION)
        sendModbusException(s, tidHi, tidLo, unit, fc, 0x0A);   // gateway path unavailable
      rr = (uint8_t)((i + 1) % MAX_CLIENTS);
      return;
    }

    g_job.jobId  = ++g_jobSeq;
    g_job.tidHi  = r.tidHi;
    g_job.tidLo  = r.tidLo;
    g_job.unit   = r.unit;
    g_job.fc     = r.fc;
    g_job.reqLen = r.rtuLen;
    memcpy(g_job.req, r.rtu, r.rtuLen);
    g_job.slot   = (int8_t)i;
    g_job.gen    = s.gen;

    s.qHead = (uint8_t)((s.qHead + 1) % REQ_QUEUE_DEPTH);
    s.qCount--;
    s.busy = true;                                 // keep this client's answers in order

    g_stat.requests++;
    g_lastTrafficMs = millis();

    uint32_t jobId = g_job.jobId;
    if (xQueueSend(g_rtuJobQ, &jobId, 0) != pdTRUE) {   // cannot happen: depth 1, state IDLE
      LOGF("[SYS] RTU job queue refused a job\n");
      s.busy = false;
      g_stat.internalErr++;
      if (cfg.flags & CFG_FLAG_TCP_EXCEPTION)
        sendModbusException(s, g_job.tidHi, g_job.tidLo, g_job.unit, g_job.fc, 0x0A);
      return;
    }
    g_jobState      = JOB_INFLIGHT;
    g_jobDeadlineMs = millis() + cfg.rtuTimeoutMs + RTU_JOB_GRACE_MS;
    rr = (uint8_t)((i + 1) % MAX_CLIENTS);
    return;
  }
}

// Non-blocking: if RtuTask finished, send the reply to the client that asked
// (if that client is still the same connection).
//
// Exception mapping (audit FIX-03) — a field engineer must be able to tell
// these apart from the master's side:
//   0x0B Gateway target device failed to respond : nothing came back at all
//   0x04 Server device failure                   : the slave answered, but the
//                                                  answer was unusable (CRC /
//                                                  framing) -> suspect baud,
//                                                  parity, wiring, noise
//   0x0A Gateway path unavailable                : somebody else answered
//                                                  (duplicate unit id, bus
//                                                  contention), the request
//                                                  aged out, or the gateway
//                                                  itself failed internally
static void completeRtuJob() {
  if (g_jobState == JOB_IDLE) return;

  uint32_t doneId = 0;
  if (xQueueReceive(g_rtuDoneQ, &doneId, 0) != pdTRUE) {
    // Overdue. Answer the client now, but do NOT release g_job: RtuTask may
    // still be reading it, and a new request must never overwrite a buffer
    // whose owner has not finished with it (audit FIX-A1).
    if ((int32_t)(millis() - g_jobDeadlineMs) > 0) {
      if (g_jobState == JOB_INFLIGHT) {
        g_stat.internalErr++;
        MbSession& ls = g_mb[g_job.slot];
        if (ls.active && ls.gen == g_job.gen) {
          ls.busy = false;
          if (cfg.flags & CFG_FLAG_TCP_EXCEPTION)
            sendModbusException(ls, g_job.tidHi, g_job.tidLo, g_job.unit, g_job.fc, 0x0A);
        }
        g_jobState = JOB_ABANDONED;                 // buffer stays frozen
        g_rtuResyncNeeded = true;                   // next job re-syncs the bus
        g_stat.rtuAbandoned++;
        g_jobDeadlineMs = millis() + RTU_JOB_GRACE_MS;
        LOGF("[SYS] RTU job %lu overdue -> abandoned, waiting for RtuTask\n",
             (unsigned long)g_job.jobId);
      } else {
        // Still nothing after the grace period: RtuTask is not running. The bus
        // is unusable and no new job may ever be dispatched, so restart.
        if (++g_jobLost >= RTU_JOB_LOST_LIMIT) {
          LOGF("[SYS] RtuTask unresponsive (%u abandoned jobs) -> restarting\n", g_jobLost);
          Serial.flush();
          esp_restart();
        }
        g_jobDeadlineMs = millis() + RTU_JOB_GRACE_MS;
      }
    }
    return;
  }

  // A completion only counts for the job it names.
  if (doneId != g_job.jobId) {
    g_stat.staleResults++;
    LOGF("[SYS] discarding completion for job %lu (current %lu)\n",
         (unsigned long)doneId, (unsigned long)g_job.jobId);
    return;
  }

  if (g_jobState == JOB_ABANDONED) {                // late answer to a dead request
    g_stat.staleResults++;
    g_jobState = JOB_IDLE;
    g_jobLost = 0;
    LOGF("[SYS] late result for abandoned job %lu discarded\n", (unsigned long)doneId);
    return;
  }

  g_jobState = JOB_IDLE;
  g_jobLost = 0;
  g_lastTrafficMs = millis();

  const RtuJob& j = g_job;
  MbSession& s = g_mb[j.slot];
  const bool alive = s.active && s.gen == j.gen;    // client may have gone meanwhile
  if (alive) s.busy = false;

  uint8_t exception = 0;
  switch (j.result) {
    case RTU_OK: {
      g_stat.rtuOk++;
      unitStatRecord(j.unit, true);
      if (!alive) break;
      static uint8_t tx[MB_TCP_ADU_MAX + 2];
      size_t pduLen = j.rxLen - 2;                  // unit + fc + data
      tx[0] = j.tidHi; tx[1] = j.tidLo;             // transaction id, exactly as received
      tx[2] = 0;       tx[3] = 0;                   // protocol id
      tx[4] = (uint8_t)(pduLen >> 8);
      tx[5] = (uint8_t)(pduLen & 0xFF);
      memcpy(&tx[6], j.rx, pduLen);
      if (!writeAll(s.sock, tx, pduLen + 6)) { closeMbSession(s); g_stat.tcpDropped++; }
      break;
    }
    case RTU_BROADCAST:
      g_stat.broadcasts++;                          // no response for broadcast
      break;
    case RTU_TIMEOUT:
      unitStatRecord(j.unit, false);
      g_stat.rtuTimeout++;
      LOGF("[RTU] timeout unit %u fc %u\n", j.unit, j.fc);
      exception = 0x0B;
      break;
    case RTU_CRC:
      unitStatRecord(j.unit, false);
      g_stat.rtuCrc++;
      LOGF("[RTU] CRC error unit %u fc %u (%u bytes)\n", j.unit, j.fc, (unsigned)j.rxLen);
      exception = 0x04;
      break;
    case RTU_FRAME_ERROR:
      unitStatRecord(j.unit, false);
      g_stat.rtuFrame++;
      LOGF("[RTU] frame error unit %u fc %u (%u bytes: short/extra/gap/overflow)\n",
           j.unit, j.fc, (unsigned)j.rxLen);
      exception = 0x04;
      break;
    case RTU_UNIT_MISMATCH:
      unitStatRecord(j.unit, false);
      g_stat.rtuUnitMismatch++;
      LOGF("[RTU] unit %u asked, unit %u answered (duplicate address?)\n", j.unit, j.rx[0]);
      exception = 0x0A;
      break;
    case RTU_FC_MISMATCH:
      unitStatRecord(j.unit, false);
      g_stat.rtuFcMismatch++;
      LOGF("[RTU] fc %u asked, fc %u answered\n", j.fc, j.rx[1]);
      exception = 0x0A;
      break;
  }
  // MOXA's "Modbus TCP Exception" switch: some masters prefer no answer at all
  // and their own timeout, and treat an exception as a device fault (FIX-A12).
  if (exception && alive && (cfg.flags & CFG_FLAG_TCP_EXCEPTION))
    sendModbusException(s, j.tidHi, j.tidLo, j.unit, j.fc, exception);
}

// Non-blocking: read bytes, cut the stream into Modbus ADUs, queue them.
// TCP is a byte stream: one read may contain several ADUs, half an ADU, or the
// tail of one plus the head of the next. All three are handled here.
static void serviceModbusSessions() {
  for (int i = 0; i < MAX_CLIENTS; i++) {
    MbSession& s = g_mb[i];
    if (!s.active) continue;

    if (!s.sock.connected()) { closeMbSession(s); g_stat.tcpDisconnects++; continue; }

    uint32_t now = millis();
    int avail = s.sock.available();
    if (avail > 0 && s.len < MB_TCP_ADU_MAX) {
      size_t room = MB_TCP_ADU_MAX - s.len;
      size_t want = (size_t)avail < room ? (size_t)avail : room;
      int n = s.sock.read(s.buf + s.len, want);
      if (n > 0) {
        if (s.len == 0) s.frameStartMs = now;
        s.len += (uint16_t)n;
        s.lastRxMs = now;
      }
    }

    // Cut out every complete ADU the ring can still hold.
    bool blockedByQueue = false;
    bool closed = false;
    while (s.len >= 7) {
      uint16_t protocolId  = ((uint16_t)s.buf[2] << 8) | s.buf[3];
      uint16_t declaredLen = ((uint16_t)s.buf[4] << 8) | s.buf[5];
      if (protocolId != 0 || declaredLen < 2 || declaredLen > 254) {
        LOGF("[MB] bad MBAP header -> closing client\n");
        closeMbSession(s); g_stat.tcpDropped++;
        closed = true;
        break;
      }
      size_t aduLen = 6 + declaredLen;
      if (s.len < aduLen) break;                    // wait for the rest
      if (s.qCount >= REQ_QUEUE_DEPTH) {            // back-pressure, nothing dropped
        blockedByQueue = true;
        g_stat.queueBackpressure++;
        break;
      }

      const uint8_t tidHi = s.buf[0], tidLo = s.buf[1];
      const uint8_t unit  = s.buf[6], fc = s.buf[7];

      // Reject what no slave could answer before it ever reaches the bus.
      uint8_t reject = validateRtuRequest(s.buf + 6, declaredLen);
      if (reject) {
        LOGF("[MB] rejecting request unit %u fc %u -> exception 0x%02X\n", unit, fc, reject);
        g_stat.reqRejected++;
        sendModbusException(s, tidHi, tidLo, unit, fc, reject);
      } else {
        uint8_t tail = (uint8_t)((s.qHead + s.qCount) % REQ_QUEUE_DEPTH);
        PendingReq& r = s.q[tail];
        r.tidHi = tidHi; r.tidLo = tidLo;
        r.unit  = unit;  r.fc = fc;
        r.rtuLen = declaredLen;                     // unit + pdu
        memcpy(r.rtu, s.buf + 6, declaredLen);
        r.enqueuedMs = now;
        s.qCount++;
      }

      s.len -= (uint16_t)aduLen;
      if (s.len) memmove(s.buf, s.buf + aduLen, s.len);
      s.frameStartMs = now;
      if (!s.active) { closed = true; break; }      // write failure inside the reject path
    }
    if (closed) continue;

    // An incomplete ADU must not sit forever; a complete one waiting for the
    // bus, or bytes held back by a full ring, are not "incomplete".
    if (!blockedByQueue && s.len > 0 && now - s.frameStartMs > TCP_PARTIAL_FRAME_TIMEOUT_MS) {
      LOGF("[MB] incomplete frame timeout -> closing client\n");
      closeMbSession(s); g_stat.tcpDropped++;
      continue;
    }
#if CLIENT_IDLE_TIMEOUT_MS > 0
    if (!s.busy && s.qCount == 0 && s.len == 0 && now - s.lastRxMs > CLIENT_IDLE_TIMEOUT_MS) {
      LOGF("[MB] idle timeout -> closing client\n");
      closeMbSession(s);
    }
#endif
  }
}

uint8_t queuedRequests() {
  uint8_t n = 0;
  for (auto& s : g_mb) if (s.active) n = (uint8_t)(n + s.qCount);
  return n;
}

uint8_t activeModbusClients() {
  uint8_t n = 0;
  for (auto& s : g_mb) if (s.active) n++;
  return n;
}

// --------------------------------------------------------------------------
// HTTP sockets (NetTask only) — pages are built in web_server.cpp
// --------------------------------------------------------------------------

static void acceptHttpClients() {
  for (int guard = 0; guard < MAX_SOCK_NUM; guard++) {
    EthernetClient nc = httpServer.accept();
    if (!nc) return;
    forgetStaleHolders(nc.getSocketNumber());
    nc.setConnectionTimeout(SOCKET_CLOSE_TIMEOUT_MS);
    if (g_http.active && g_http.len > 0) {          // busy with a real request
      nc.stop();
      continue;
    }
    if (g_http.active) closeHttpSession();          // idle/pre-connect socket: replace
    g_http.sock = nc;
    g_http.active = true;
    g_http.len = 0;
    g_http.startMs = millis();
  }
}

static void serviceHttp() {
  if (!g_http.active) return;
  EthernetClient& c = g_http.sock;
  if (!c.connected()) { closeHttpSession(); return; }

  int avail = c.available();
  while (avail > 0 && g_http.len < HTTP_BUF_SIZE - 1) {
    size_t room = HTTP_BUF_SIZE - 1 - g_http.len;
    int n = c.read((uint8_t*)g_http.buf + g_http.len, (size_t)avail < room ? (size_t)avail : room);
    if (n <= 0) break;
    g_http.len += (uint16_t)n;
    avail = c.available();
  }
  g_http.buf[g_http.len] = '\0';

  char* hdrEnd = strstr(g_http.buf, "\r\n\r\n");
  if (hdrEnd) {
    size_t hdrLen = (size_t)(hdrEnd - g_http.buf) + 4;
    char clBuf[12];
    uint32_t contentLen = 0;
    // Any plausible length parses (up to 1 MB), so a large body gets the right
    // answer - 413 below - and only a malformed value is a 400.
    if (httpHeader(g_http.buf, hdrLen, "Content-Length", clBuf, sizeof(clBuf)) &&
        !parseU32(clBuf, 0, 1000000UL, contentLen)) {
      httpSendSimple(c, 400, "Bad Request", "Bad Content-Length.");
      closeHttpSession(); return;
    }
    if (hdrLen + contentLen >= HTTP_BUF_SIZE) {
      httpSendSimple(c, 413, "Payload Too Large", "Request too large.");
      closeHttpSession(); return;
    }
    if (g_http.len >= hdrLen + contentLen) {
      g_http.buf[hdrLen + contentLen] = '\0';
      handleHttpRequest(c, g_http.buf, hdrLen, g_http.buf + hdrLen);
      closeHttpSession();
      return;
    }
  } else if (g_http.len >= HTTP_BUF_SIZE - 1) {
    httpSendSimple(c, 431, "Request Header Fields Too Large", "Headers too large.");
    closeHttpSession(); return;
  }

  if (millis() - g_http.startMs > HTTP_REQUEST_TIMEOUT_MS) closeHttpSession();
}

// --------------------------------------------------------------------------
// NetTask — sole owner of W5500 / SPI / Ethernet library
// --------------------------------------------------------------------------

void netTask(void* arg) {
  esp_err_t e = esp_task_wdt_add(nullptr);
  g_twdtSubscribed = (e == ESP_OK);
  if (!g_twdtSubscribed) LOGF("[WDT] task WDT unavailable (%d) - relying on external WDT\n", (int)e);

  uint32_t lastLink = 0, lastHealth = millis();
  for (;;) {
    netAlive();
    uint32_t now = millis();

    if (g_restartPending && (int32_t)(now - g_restartAtMs) >= 0) {
      for (auto& s : g_mb) if (s.active) closeMbSession(s);
      if (g_http.active) closeHttpSession();
      LOGF("[SYS] restarting to apply new configuration\n");
      Serial.flush();
      esp_restart();
    }

    if (now - lastLink >= LINK_POLL_MS) {
      lastLink = now;
      g_linkUp = g_ethReady && (Ethernet.linkStatus() == LinkON);
    }
    if (now - lastHealth >= HEALTH_CHECK_MS) {
      lastHealth = now;
      // Three consecutive bad reads before acting: one glitched SPI transfer
      // must not tear down healthy TCP sessions (audit FIX-13).
      if (!g_ethReady || !ethernetHealthy()) {
        if (++g_ethStrikes >= ETH_HEALTH_STRIKES) {
          g_ethStrikes = 0;
          ethernetRecover();
          g_ethOk = g_ethReady;                     // fault LED only after a real recovery
        }
      } else {
        g_ethStrikes = 0;
        g_ethOk = g_ethReady;
      }
    }

    // Collect a finished RTU job on EVERY pass, also while the W5500 is down:
    // the job state machine (overdue -> abandoned -> lost-job restart) must
    // keep running through an Ethernet outage. It never touches the chip then:
    // a recovery forgets every session first, so no client is "alive".
    completeRtuJob();            // reply to the master if RtuTask finished

    if (g_ethReady) {
      // Order matters: all accept() calls (which may recycle sockets) run
      // before any session reads, so a stale slot can never read a new
      // connection's data.
      acceptModbusClients();
      acceptHttpClients();
      serviceModbusSessions();
      dispatchRtuJob();          // start next RS-485 transaction (non-blocking)
      serviceHttp();
    }
    vTaskDelay(1);
  }
}
