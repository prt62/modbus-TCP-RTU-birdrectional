// ==========================================================================
// Ajeevi / Modbus Industrial Gateway  —  v3.6.0 (modular PlatformIO project)
// Modbus TCP (W5500 Ethernet)  <->  Modbus RTU (RS-485)  transparent bridge
// Target: ESP32 + W5500, Arduino core 2.0.x / 3.x, Arduino Ethernet >= 2.0.2
// ==========================================================================
//
// YE GATEWAY KIS LIYE HAI?
// ------------------------
// Ye ek protocol converter / translator hai: Ethernet network aur purane
// RS-485 industrial devices ke beech "dubhashiya".
//
//   SCADA PC --Ethernet (Modbus TCP)--> [ESP32 + W5500] --RS-485 (Modbus RTU)--> Meter/VFD/PLC
//            <------- response -------                 <------- response -------
//
//  * Field devices (energy meters, VFD, PLC, temp controllers, solar
//    inverters, flow meters) Modbus RTU bolte hain, RS-485 ki 2 wires par.
//    Ye LAN par nahi chalta, aur ek time par sirf EK master baat kar sakta hai.
//  * Control room ka SCADA / HMI (WinCC, Ignition, Wonderware) ya koi
//    Node.js / Python dashboard Modbus TCP bolta hai (Ethernet, port 502).
//
//  Flow:
//   1. SCADA gateway ke IP (e.g. 192.168.1.50:502) par TCP request bhejta hai
//      ("unit 5 ke register 100-110 padho").
//   2. Gateway MBAP header hata ke RTU frame banata hai, CRC jodta hai, aur
//      RS-485 bus par bhejta hai.
//   3. Device ka jawab aata hai -> CRC check -> wapas TCP format -> SCADA.
//   4. Device jawab na de to SCADA ko exception 0x0B milta hai
//      ("gateway target device failed to respond").
//  Gateway data ka matlab nahi samajhta, sirf format badalta hai
//  ("transparent bridge").
//
//  Use cases: building ke energy meters office LAN se padhna, solar plant ka
//  inverter data SCADA/cloud par, purani RS-485 machines ko naye Ethernet
//  network se jodna, aur 4 SCADA/HMI clients ko ek hi RTU bus share karwana
//  (gateway requests ko queue karke ek-ek karke bhejta hai).
//  Commercial equivalent: Moxa MGate MB3180 jaise gateways.
//
// PROJECT LAYOUT (ek module = ek zimmedari)
// -----------------------------------------
//   include/hw_config.h     pins, W5500 reset polarity, RS-485 DE, LEDs, ext. WDT,
//                           factory-reset pin, FW_VERSION, DEBUG_SERIAL
//   include/utils.h         LOGF, IPv4 parse/validate, SHA-256, CRC, reset reason
//   include/modbus_crc.h    modbusCRC() - the single declaration
//   include/config_nvs.h    GatewayConfig, A/B NVS record, password, counters
//   include/rs485_rtu.h     RS-485 UART + Modbus RTU master (RtuTask side)
//   include/ethernet_tcp.h  W5500, Modbus TCP server, RTU job engine, NetTask
//   include/web_server.h    login, CSRF, config/status page, /save, /config.json
//   src/<same name>.cpp     the implementations
//   src/main.cpp            boot order (setup), LEDs + external watchdog (loop)
//   CHANGELOG.md            every fix, [1] .. [76]
//
// BUILD: PlatformIO -> Build / Upload / Monitor (115200 baud). Options go into
// build_flags in platformio.ini, e.g. -DWEB_FORCE_DEFAULT_PASSWORD=0 or
// -DRS485_DE_PIN=4; every such option is #ifndef-guarded in the headers.
// Web login (commissioning build): admin / admin123 at http://192.168.1.50/
//
// ARCHITECTURE (why it is shaped like this)
// -----------------------------------------
//  * ONE task ("NetTask") owns the W5500 / SPI bus / Ethernet library. Modbus
//    TCP server, HTTP config server, link polling and W5500 health checks all
//    run inside it. Nobody else ever calls an Ethernet.* / EthernetClient /
//    EthernetServer API. The Arduino Ethernet library keeps global socket
//    state and is NOT thread-safe, so single ownership is the only design
//    that is correct by construction (a mutex around "SPI" is not enough —
//    the library's own socket bookkeeping would still race).
//  * ONE task ("RtuTask", other core) owns the RS-485 UART. It is the only
//    code that waits for a meter's reply. NetTask hands it a job through a
//    FreeRTOS queue and polls for the result with zero timeout, so a slow or
//    dead meter (up to the RTU timeout) never freezes TCP, HTTP, new SCADA
//    connections, link polling or the W5500 health check. The one remaining
//    place where NetTask can wait on a peer is writeAll(), and that wait has
//    a hard deadline of TCP_WRITE_TIMEOUT_MS for the whole transfer.
//  * loop() only drives LEDs and the external watchdog. It reads 32-bit
//    volatile values published by the tasks — no SPI / UART access at all.
//  * Serial side: Modbus RTU only. Modbus ASCII is NOT supported (a MOXA
//    MGate MB3180 supports both) - a capability difference, not a defect.
//  * NO RETRIES. A failed transaction is reported to the master, never
//    repeated by the gateway: silently retrying a write function (05/06/0F/10)
//    could apply it twice if only the response was lost. Retry policy belongs
//    to the master, which knows whether its request is idempotent.
//  * No heap use in the request path: servers are static globals, every buffer
//    is a fixed-size static array, the HTTP server has its own zero-alloc
//    parser. (The two job queues are allocated once at boot, and the NVS layer
//    allocates while an operator saves the configuration - neither is in the
//    Modbus or HTTP data path.)
//  * The heartbeats prove that each task is still looping. Progress is checked
//    separately: an RTU job that does not come back within its deadline is
//    detected and, if it keeps happening, the device restarts itself.
// ==========================================================================

#include <Arduino.h>
#include <SPI.h>
#include "hw_config.h"
#include "utils.h"
#include "config_nvs.h"
#include "rs485_rtu.h"
#include "ethernet_tcp.h"
#include "web_server.h"

// --------------------------------------------------------------------------
// LEDs + external watchdog supervisor (loop task, no SPI / UART access)
// --------------------------------------------------------------------------

static void handleLEDs() {
  static int8_t lastD3 = -1, lastD4 = -1;
  uint32_t traffic = g_lastTrafficMs;
  uint32_t now = millis();
  int d3, d4;
  if (g_linkUp) {
    d4 = HIGH;                                              // link: steady ON
    d3 = (now - traffic < 80) ? HIGH : LOW;                 // Modbus activity flash
  } else if (!g_ethOk) {
    bool blink = (now % 400) < 200;                         // W5500 fault: ALTERNATING
    d3 = blink ? HIGH : LOW;
    d4 = blink ? LOW : HIGH;
  } else {
    bool blink = (now % 400) < 200;                         // cable unplugged: both together
    d3 = d4 = blink ? HIGH : LOW;
  }
  if (d3 != lastD3) { digitalWrite(LED_D3, d3); lastD3 = (int8_t)d3; }
  if (d4 != lastD4) { digitalWrite(LED_D4, d4); lastD4 = (int8_t)d4; }
}

static void superviseExternalWatchdog() {
  static uint32_t lastFeed = 0;
  uint32_t hbNet = g_netHeartbeatMs;                        // read BEFORE millis()
  uint32_t hbRtu = g_rtuHeartbeatMs;
  uint32_t now = millis();
  if (now - hbNet > NET_HEARTBEAT_MAX_AGE_MS) return;       // NetTask hung: let ext. WDT reset us
  // A legitimate transaction (bus-free wait + TX + response timeout) must fit
  // inside this window, or a slow slave would look like a hung task (FIX-04).
  if (now - hbRtu > NET_HEARTBEAT_MAX_AGE_MS + cfg.rtuTimeoutMs + 1000UL) return;
  if (now - lastFeed >= EXT_WDT_FEED_MS) { lastFeed = now; pulseExternalWatchdog(); }
}

// --------------------------------------------------------------------------
// Setup / loop
// --------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);

  pinMode(LED_D3, OUTPUT);
  pinMode(LED_D4, OUTPUT);
  pinMode(WDT_DONE_PIN, OUTPUT);
  digitalWrite(WDT_DONE_PIN, LOW);
  digitalWrite(LED_D3, LOW);
  digitalWrite(LED_D4, LOW);
  pulseExternalWatchdog();

#if (RS485_DE_PIN >= 0) && !RS485_USE_HW_DE
  pinMode(RS485_DE_PIN, OUTPUT);
  digitalWrite(RS485_DE_PIN, LOW);                          // receive by default
#endif

  // ORDER IS LOAD-BEARING (audit FIX-01): the per-device default password is
  // derived from the MAC, and loadConfig() may have to derive/store it (first
  // boot, migration, corrupted record). The MAC must therefore exist before any
  // persistence code runs. Nothing above this line may touch credentials.
  generateUniqueMac(mac);

  configInit();                 // open NVS: every config / password access needs it
  factoryResetCheck();
  loadConfig();
  computeRtuTiming();
  authReport();

  rs485Init();

#if W5500_RST >= 0
  pinMode(W5500_RST, OUTPUT);
  digitalWrite(W5500_RST, W5500_RST_RELEASE_LEVEL);   // do NOT hold the chip in reset
#endif
  // SS = -1: the Ethernet library drives CS by hand, so the ESP32 must not also
  // route a hardware CS signal onto the same pin (audit FIX-58).
  SPI.begin(W5500_SCLK, W5500_MISO, W5500_MOSI, -1);
  pinMode(W5500_CS, OUTPUT);
  digitalWrite(W5500_CS, HIGH);

  // Apply the configured port to the STATIC server object (no heap).
  modbusServer = CustomEthernetServer(cfg.port);

  pulseExternalWatchdog();
  g_ethReady = ethernetInit();                              // retried by NetTask if it fails
  pulseExternalWatchdog();

  LOGF("\n=== Ajeevi Modbus Gateway v%s ===\n", FW_VERSION);
  LOGF("Last reset: %s\n", resetReasonName());
  LOGF("MAC  %02X:%02X:%02X:%02X:%02X:%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  LOGF("IP   %u.%u.%u.%u  mask %u.%u.%u.%u  gw %u.%u.%u.%u\n",
       cfg.ip[0], cfg.ip[1], cfg.ip[2], cfg.ip[3], cfg.sn[0], cfg.sn[1], cfg.sn[2], cfg.sn[3],
       cfg.gw[0], cfg.gw[1], cfg.gw[2], cfg.gw[3]);
  LOGF("Modbus TCP :%u  HTTP :%u  RTU %lu %s timeout %u ms  W5500 %s\n",
       cfg.port, HTTP_PORT, (unsigned long)cfg.baud, SERIAL_FMTS[cfg.fmt].name, cfg.rtuTimeoutMs,
       g_ethReady ? "OK" : "NOT FOUND");
  LOGF("Web login user '%s', password %s\n", WEB_AUTH_USER,
       g_pwIsDefault ? "= built-in default (change it!)" : "set by operator");

  // From here on ONLY NetTask touches the W5500. Same core as loop() and
  // same priority, so the Ethernet library's yield()-based busy waits
  // round-robin with loop() instead of starving it.
  g_rtuJobQ  = xQueueCreate(1, sizeof(uint32_t));
  g_rtuDoneQ = xQueueCreate(1, sizeof(uint32_t));
  if (!g_rtuJobQ || !g_rtuDoneQ) { LOGF("[SYS] queue alloc failed -> restart\n"); delay(100); esp_restart(); }
  g_ethOk = g_ethReady;

  // RtuTask owns ONLY the UART (never the W5500), so it can run on the other
  // core and block on the serial line without stalling the network.
  g_rtuHeartbeatMs = millis();
  BaseType_t okRtu = xTaskCreatePinnedToCore(rtuTask, "RtuTask", RTU_TASK_STACK, nullptr,
                                             RTU_TASK_PRIORITY, &g_rtuTask,
                                             xPortGetCoreID() == 0 ? 1 : 0);

  g_netHeartbeatMs = millis();
  BaseType_t okNet = xTaskCreatePinnedToCore(netTask, "NetTask", NET_TASK_STACK, nullptr,
                                             uxTaskPriorityGet(nullptr), &g_netTask,
                                             xPortGetCoreID());
  if (okRtu != pdPASS || okNet != pdPASS) {         // nothing works without both (audit FIX-17)
    LOGF("[SYS] task creation failed (rtu=%d net=%d) -> restart\n", (int)okRtu, (int)okNet);
    Serial.flush();
    delay(100);
    esp_restart();
  }
}

void loop() {
  handleLEDs();
  superviseExternalWatchdog();
  vTaskDelay(pdMS_TO_TICKS(20));
}
