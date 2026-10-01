#pragma once
// ==========================================================================
// ethernet_tcp.h — W5500, Modbus TCP server, RTU job engine, NetTask
// --------------------------------------------------------------------------
// OWNERSHIP: after setup() only NetTask touches the W5500, the SPI bus and the
// Arduino Ethernet library (not thread-safe). RtuTask owns only the UART; the
// two exchange one job at a time through two depth-1 FreeRTOS queues.
// ==========================================================================
#include <Arduino.h>
#include <Ethernet.h>
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "hw_config.h"

// ---- Modbus TCP ----
#define MAX_CLIENTS 4
#define TCP_PARTIAL_FRAME_TIMEOUT_MS 1000UL   // incomplete ADU -> drop client
#define CLIENT_IDLE_TIMEOUT_MS 300000UL       // no traffic -> close (0 = never)
#ifndef EVICT_OLDEST_WHEN_FULL
#define EVICT_OLDEST_WHEN_FULL 1              // only STALE sessions may be evicted
#endif
#define EVICT_IDLE_THRESHOLD_MS 30000UL       // a session must be silent this long to be evictable
#define SOCKET_CLOSE_TIMEOUT_MS 100           // EthernetClient::stop() wait
#define TCP_WRITE_TIMEOUT_MS 500UL            // one Modbus response (<= 260 bytes)
#define HTTP_WRITE_TIMEOUT_MS 1500UL          // page write must not delay Modbus (FIX-08)

// Per-client pipelining. A Modbus TCP master may legitimately have several
// requests outstanding on one connection; the RS-485 bus stays serialized.
// RAM arithmetic before changing these: each PendingReq is ~268 B, so one
// client costs REQ_QUEUE_DEPTH*268 + 260 (reassembly) ~= 1.1 kB, and four
// clients ~4.4 kB of static RAM. The hard ceiling is the W5500's 8 sockets
// (see the socket arithmetic below), which allows MAX_CLIENTS <= 5.
#define REQ_QUEUE_DEPTH 3                     // requests buffered per client
#define REQUEST_MAX_AGE_MS 5000UL             // queued longer than this -> 0x0A

// 1 = enforce function-specific request lengths and quantity limits.
// 0 = reject only impossible function codes and let vendor-specific uses of
//     standard function codes through (a transparent gateway is expected to
//     pass "valid but uncommon" traffic). Rejections are counted either way.
#ifndef STRICT_REQUEST_VALIDATION
#define STRICT_REQUEST_VALIDATION 1
#endif

// Optional: only these hosts may open a Modbus TCP connection (0.0.0.0 = unused).
// Modbus TCP has no authentication of its own; this is a crude but effective
// second line of defence when the gateway cannot be put on an isolated VLAN.
#ifndef MODBUS_ALLOWLIST_ENABLED
#define MODBUS_ALLOWLIST_ENABLED 0
#endif
#define MODBUS_ALLOWLIST { IPAddress(0,0,0,0), IPAddress(0,0,0,0) }

// ---- HTTP request framing (the page itself is built in web_server.cpp) ----
#define HTTP_BUF_SIZE 1536
#define HTTP_REQUEST_TIMEOUT_MS 3000UL

// ---- W5500 ----
// TCP retransmission: RTR doubles each retry -> 100+200+400+800 = 1.5 s
#define W5500_RETX_TIMEOUT_MS 100
#define W5500_RETX_COUNT 3
#define ETH_HEALTH_STRIKES 3                  // consecutive bad reads before re-initialising
#define ETH_INIT_ATTEMPTS 3                   // detection attempts per initialisation
#define ETH_RECOVERY_MIN_INTERVAL_MS 30000UL  // never reinitialise more often than this
#define W5500_VERSIONR 0x0039                 // common register: always reads 0x04
#define W5500_EXPECTED_VERSION 0x04
#define ETH_PROBE_HZ 1000000UL                // probe clock: slow on purpose, bare PCB traces

// ---- supervision ----
#define LINK_POLL_MS 250UL
#define HEALTH_CHECK_MS 5000UL
#define NET_HEARTBEAT_MAX_AGE_MS 3000UL       // NetTask silent longer -> starve ext. WDT
#define RTU_JOB_GRACE_MS 3000UL               // job overdue by this much => RtuTask is gone
// Watchdog ladder (audit FIX-04). These layers must never overlap:
//
//   a slow slave / normal Modbus timeout  -> handled inside RtuTask, a result
//                                            always comes back: NO reboot
//   no completion at all after the timeout -> grace period, then ABANDONED and
//     + RTU_JOB_GRACE_MS                     the client gets exception 0x0A
//   RTU_JOB_LOST_LIMIT abandoned jobs      -> RtuTask is stuck: controlled
//                                             esp_restart()
//   NetTask silent > NET_HEARTBEAT_MAX_AGE  -> external watchdog stops being fed
//   RtuTask silent > that + rtuTimeout + 1s -> external watchdog stops being fed
//
// Worst case before the self-restart: RTU_JOB_LOST_LIMIT x (rtuTimeoutMs +
// RTU_JOB_GRACE_MS) ~= 12 s with the default timeout. The external watchdog
// window must be longer than that, otherwise it fires first.
#define RTU_JOB_LOST_LIMIT 3                  // that many lost jobs -> controlled restart
#define EXT_WDT_FEED_MS 1000UL
#define NET_TASK_STACK 8192
#define RTU_TASK_STACK 4096
#define RTU_TASK_PRIORITY 2

// Socket arithmetic (audit FIX-A14): the W5500 has 8 hardware sockets. This
// firmware uses 4 Modbus clients + 1 Modbus listener + 1 HTTP listener + 1 HTTP
// client = 7, so MAX_CLIENTS can go to 5 at most. A MOXA MGate MB3180 accepts
// 16 simultaneous TCP masters; matching that is not a firmware change - it needs
// a MAC/PHY with a real TCP stack (ESP32 EMAC + LAN8720 + lwIP) instead of the
// W5500's fixed socket set.
static_assert(MAX_SOCK_NUM >= MAX_CLIENTS + 3,
              "Need sockets for: Modbus clients + Modbus listener + HTTP listener + HTTP client");

// Core 2.x: Server has pure virtual begin(uint16_t) but the Ethernet lib only
// provides begin() -> EthernetServer is abstract; this wrapper fixes that.
// Core 3.x: Server::begin() matches the Ethernet lib already, so the wrapper
// must NOT override anything (an `override` there is a compile error).
#include "esp_arduino_version.h"
#ifndef ESP_ARDUINO_VERSION_MAJOR
#define ESP_ARDUINO_VERSION_MAJOR 2
#endif
class CustomEthernetServer : public EthernetServer {
  public:
    explicit CustomEthernetServer(uint16_t port) : EthernetServer(port) {}
#if ESP_ARDUINO_VERSION_MAJOR < 3
    void begin(uint16_t port = 0) override { (void)port; EthernetServer::begin(); }
#endif
};

extern CustomEthernetServer modbusServer;   // real port applied in setup()
extern CustomEthernetServer httpServer;
extern QueueHandle_t g_rtuJobQ;             // NetTask -> RtuTask  ("job ready")
extern QueueHandle_t g_rtuDoneQ;            // RtuTask -> NetTask  ("job done")
extern TaskHandle_t  g_netTask;
extern TaskHandle_t  g_rtuTask;

// Published by NetTask, read by loop() / the web page. Aligned 32-bit -> atomic.
extern volatile uint32_t g_netHeartbeatMs;
extern volatile uint32_t g_lastTrafficMs;
extern volatile bool     g_linkUp;
extern volatile bool     g_ethOk;           // W5500 present & sane (for the LEDs)
extern bool              g_ethReady;        // NetTask only (and setup())
extern bool              g_twdtSubscribed;  // NetTask on the task watchdog

void netAlive();                 // heartbeat + task-WDT feed (NetTask only)
bool ethernetInit();             // setup() at boot, NetTask afterwards
void netTask(void* arg);
void rtuTask(void* arg);
uint8_t activeModbusClients();
uint8_t queuedRequests();

// Chunked, deadline-bounded write (also used by the web server).
bool writeAll(EthernetClient& c, const uint8_t* data, size_t len,
              uint32_t timeoutMs = TCP_WRITE_TIMEOUT_MS);
