# Ajeevi Modbus Gateway — change log

Modbus TCP (W5500) <-> Modbus RTU (RS-485) transparent gateway for ESP32.
Newest release first; the numbers in brackets are referenced from the code comments.

## v3.6.0 — modular PlatformIO project

**Kya hua (summary):** single-file firmware v3.5.0 (poori tarah tested) ko is modular
project me merge kiya gaya — har module ki ek zimmedari. Har function ki body v3.5.0 se
*bina badle* aayi hai; sirf neeche likhe changes hain. Pehle wale modular draft
(FW "3.5.1") ki galtiyan bhi theek ki gayi hain:

| # | Severity | Where | Problem in the earlier modular draft | Fix |
|---|---|---|---|---|
| [63] | CRITICAL | config_nvs | `prefs.begin()` was never called, so every NVS read/write failed: settings and password could never be saved (every *Save* answered 500 "Nothing was changed") and every boot ran on factory defaults | `configInit()` opens the NVS namespace; `setup()` calls it before `factoryResetCheck()` / `loadConfig()` |
| [64] | HIGH | ethernet_tcp | `serviceHttp()` handled a request as soon as the headers arrived. Browsers often send the POST body in a second TCP segment, so `/save` ran with an empty body ("403 Stale or missing form token") | waits for `Content-Length` bytes; 400 bad length, 413 too large, 431 header flood |
| [65] | HIGH | web_server | `httpSend()` used raw `client.write()`: the ~6 kB status page was cut at the W5500's 2 kB socket buffer, and a browser that stopped reading could hold NetTask (and with it all Modbus traffic) for as long as it stalled | `writeAll()` with `HTTP_WRITE_TIMEOUT_MS`; failures counted |
| [66] | HIGH | ethernet_tcp | accept path lost the idle timeout, the stale-session eviction and the optional allowlist: half-open connections (cable pulled, SCADA PC crashed) kept all 4 slots busy for ever and new masters were refused | restored: `CLIENT_IDLE_TIMEOUT_MS`, eviction only of sessions idle > 30 s with no pending work, `MODBUS_ALLOWLIST` |
| [67] | HIGH | ethernet_tcp | `completeRtuJob()` released the job buffer on a completion carrying a *foreign* job id while RtuTask still owned it, so the next request could overwrite a buffer in use (crossed answers) | only the completion that names the current job frees it (ownership rule [38]) |
| [68] | MEDIUM | ethernet_tcp | `validateRtuRequest()` was reduced to a function-code check: malformed requests (bad length / quantity) went on the bus and cost a full timeout each | strict per-function validation restored (`STRICT_REQUEST_VALIDATION`) |
| [69] | MEDIUM | config_nvs | `configSane()` accepted Modbus port 80 and any baud rate, so a damaged or legacy record could put Modbus on the web port or the UART on a nonsense baud | `portValid()` + `baudValid()` |
| [70] | MEDIUM | config_nvs | legacy migration missing: units upgraded from v2.x firmware lost their settings | v1/v2 blob and per-key migration restored |
| [71] | MEDIUM | config_nvs | factory-reset pin support removed | `factoryResetCheck()` restored (`FACTORY_RESET_PIN`, default off) |
| [72] | LOW | main, ethernet_tcp | no boot banner, no W5500 attempt log / SPI clock sweep / reset-polarity hint, task creation unchecked, no login note at boot | all restored; failed task creation restarts the device |
| [73] | LOW | web_server | status page always showed "Stack left 0 / 0" (task handles were private to `main.cpp`) | handles exported, real high-water marks shown |
| [74] | LOW | web_server, ethernet_tcp | password error said "8-32 characters" (minimum is 5); a `Content-Length` above the buffer got 400 instead of 413; after a HEAD request the next early error page could go out without its body | message built from `WEB_PASS_MIN_LEN`/`WEB_PASS_MAX_LEN`; 413; HEAD flag cleared after every request |
| [75] | LOW | ethernet_tcp | `completeRtuJob()` ran only while the W5500 was up | runs on every NetTask pass, so the job state machine and the lost-job restart keep working through an Ethernet outage (it never touches the chip then) |
| [76] | BUILD | all | `LOGF` defined in five files; `modbusCRC` declared twice; `[cite: 1]` junk in comments; options not overridable (`#ifndef` missing); dense one-line `if` chains (10 misleading-indentation warnings); `volatile++`; dangling `../modbus_tcp_rtuu` folder in the workspace | one `LOGF` (switch `DEBUG_SERIAL`) in `utils.h`; one `modbusCRC` declaration (`modbus_crc.h`); every option `#ifndef`-guarded; readable code, 0 warnings with `-Wall -Wextra`; workspace and `platformio.ini` cleaned up |

### Verification of v3.6.0

- **Compile**: arduino-esp32 **2.0.14** (the exact core of `espressif32@6.5.0`), 2.0.17 and 3.3.12,
  Ethernet 2.0.2 — 0 errors, 0 warnings (`-Wall -Wextra`); plus 13 option variants
  (`DEBUG_SERIAL=0`, hardware DE, firmware DE, factory-reset pin, allowlist, relaxed validation,
  no reset pin, MAC-derived password, …).
- **Full link** against 2.0.14: firmware image ≈ 319 kB (≈ 24 % of the 1.25 MB app partition),
  static RAM ≈ 41 kB. No duplicate or missing symbols between modules.
- **Merge check**: 93 functions/structs of v3.5.0 compared one by one — 88 byte-identical,
  5 differ only by the changes listed above.
- **Host tests (x86), 181 checks, all passed**: SHA-256 (FIPS vectors + padding edges),
  Modbus CRC, IPv4/mask/gateway validation, NVS A/B record (first boot, save → reboot,
  corrupted slot fallback, legacy migration, forced default password, factory reset),
  HTTP framing (split POST, 400/413/431, timeout), form decoding, CSRF ring, and the RTU job
  engine (foreign completion, overdue → abandoned → late result, exception mapping 0x0B/0x04/0x0A,
  broadcast, round-robin, queue ageing, lost-job restart). The same tests run against the old
  draft reproduce bugs [64] and [67]. The status page built with every counter at its
  maximum is 5.9 kB, well inside the 12 kB buffer.
- **Not yet tested on hardware** — flash it and check the boot log and the web page first.

---

## Earlier versions (single-file firmware)

### v2.0.x — first rewrite (the 4 reported bugs)

- **[1]** server.available() -> server.accept(): each new connection is handed over exactly once, plus socket-number de-duplication. (SCADA drop)
- **[2]** Single-owner W5500 (see ARCHITECTURE in `src/main.cpp`). Old draft touched SPI from core 0 (Modbus task) and core 1 (Ethernet.linkStatus() in loop()). (panic)
- **[3]** RS-485 DE released only after uart_wait_tx_done() (last STOP bit physically left the shift register) + 2-bit guard. Optional hardware RS485 half-duplex mode (UART drives DE itself). (CRC cut)
- **[4]** `new CustomEthernetServer` removed -> static global objects. (heap)

*Hidden bugs fixed in the same round:*

- **[5]** WebServer.h is the *WiFi* web server -> config page was never reachable over W5500. Replaced by an Ethernet HTTP server on port 80.
- **[6]** Partial MBAP header was consumed then "retried" -> TCP stream desync. Now a per-client non-blocking reassembly buffer (also handles pipelined requests and never lets one slow client stall the others).
- **[7]** Half-open sockets (cable pulled / SCADA PC crash) held slots forever. Idle timeout + evict-oldest when all slots are busy.
- **[8]** Stale slot aliasing: a dead slot's socket number can be reused by the listener for a NEW connection -> two slots on one socket / cross-talk between the Modbus and HTTP servers. Socket ownership reconciliation.
- **[9]** EthernetClient::write() silently truncates at the W5500 socket buffer (2 KB) and can spin for tens of seconds on a dead peer (W5500 retry back-off doubles each time: 200ms x 8 retries). Chunked, bounded writes + shorter retransmission settings.
- **[10]** EthernetClient::stop() blocks up to 1000 ms -> now 100 ms.
- **[11]** RTU RX: ESP32 UART only pushes bytes to the ring buffer every 120 bytes or after a 10-symbol idle. At 9600 baud that is 11.5 ms > the old 10 ms gap -> long frames were cut and failed CRC. FIFO threshold set to 1, and end-of-frame is decided from the Modbus function code (exact expected length) with a baud-derived t3.5 gap as fallback. Old loop also read only 1 byte per 1 ms tick.
- **[12]** Response not checked against request (unit id / function code) -> a late reply from a previous timed-out poll was forwarded to SCADA.
- **[13]** Broadcast (unit 0) waited 1 s and returned a bogus 0x0B exception.
- **[14]** No inter-frame t3.5 silence enforced between consecutive RTU frames.
- **[15]** External watchdog was fed from inside blocking wait loops (so a hung task could never be detected). Now fed by a supervisor only while NetTask proves it is alive; NetTask is also on the ESP task WDT.
- **[16]** W5500 lock-up / spontaneous reset (EMI) was never detected. Periodic register sanity check + automatic W5500 re-initialisation.
- **[17]** HTML template contained "100%;" inside a printf format string (UB).
- **[18]** NVS values not validated at boot (corrupt baud -> UART failure), Modbus port 80 would collide with the web server, subnet mask / gateway not sanity-checked, MAC could get multicast bit.
- **[19]** Basic-auth brute force: lockout after repeated failures.

### v2.1.0 — asynchronous RTU engine

- **[20]** Synchronous serial wait: the RTU response wait used to run inside the network task (up to rtuTimeoutMs, 5 s max) -> web page, accept(), other clients' reads and W5500 health checks froze meanwhile. Now an asynchronous job queue to a dedicated RtuTask; NetTask never blocks on RS-485. Late results for a client that disconnected are dropped (generation counter), and replies stay in request order per client.

### v2.2.0 audit fixes (FIX-01 .. FIX-28 of the v2.1.0 production audit)

- **[21]** RTU frame boundary: reaching the expected byte count no longer ends the frame on its own — a t3.5 silence must follow and the length must match exactly. Extra bytes are a FRAME ERROR now, never silently truncated.
- **[22]** RTU errors are classified: TIMEOUT / CRC / FRAME / UNIT MISMATCH / FC MISMATCH, each with its own counter, each mapped to a different Modbus exception (0x0B / 0x04 / 0x0A) instead of everything being 0x0B.
- **[23]** Requests are validated before they reach the bus (illegal function -> 0x01, impossible length/quantity -> 0x03), so a broken client cannot occupy the RS-485 line with frames no slave can answer.
- **[24]** Configuration is stored as ONE versioned CRC-protected blob -> a power cut during save can no longer leave a half-new configuration.
- **[25]** Eviction only removes sessions idle beyond EVICT_IDLE_THRESHOLD_MS and never one with a request in flight; otherwise the new connection is refused (a busy SCADA link is no longer dropped for a newcomer).
- **[26]** Web password: per-device default derived from the MAC, SHA-256 hash in NVS, change-password form, per-IP lockout, CSRF token on /save.
- **[27]** writeAll() has an absolute deadline; a stalled peer cannot hold NetTask.
- **[28]** Lost RTU job detection, sliced TX wait (watchdog-safe at 1200 baud), stronger W5500 health check (live MAC register) with a 3-strike filter, UART framing/parity/overflow counters, stack/heap diagnostics.

### v2.3.0 audit-#2 fixes (MOXA MGate MB3180 used as the behavioural reference)

- **[29]** The t3.5 silence window no longer busy-waits: above 3 ms (i.e. at <= 19200 baud, where t3.5 reaches 32 ms at 1200) the task yields instead of spinning on the UART lock.
- **[30]** t3.5 is charged ONCE per transaction: the silence just observed at the frame boundary IS the inter-frame gap.
- **[31]** Separate write deadlines: 500 ms for a Modbus response, 3 s for the (much larger) web page, so a slow browser cannot truncate the page and a stalled Modbus peer still cannot hold the network task.
- **[32]** Configuration save is all-or-nothing across BOTH stores: if the password write fails, the configuration blob is rolled back.
- **[33]** Brute force: per-IP lockout PLUS a global failed-login rate cap, so rotating source addresses no longer bypass it.
- **[34]** MOXA-style switch: "return a Modbus exception when the slave does not answer" can be turned off (some masters prefer silence and their own timeout). Applies to RTU failures, not to locally rejected requests.
- **[35]** Measured slave turnaround (min/max) recorded and shown with a suggested response timeout - the manual equivalent of MOXA's "Auto Detection".
- **[36]** Per-unit-id success/failure counters, so one bad slave can be found without a bus analyser.
- **[37]** Legacy NVS keys removed after migration; strict request validation can be relaxed for vendor-specific frames; /config.json export endpoint.

### v3.0.0 — universal-gateway hardening (audit #3)

The TCP side makes NO assumption about who the master is: SCADA, PLC, HMI, BMS, EMS, DCS, a Python or Node client, another gateway — all are ordinary Modbus TCP clients.
- **[38]** RTU JOB OWNERSHIP (was a real stale-result race): the shared job buffer is never rewritten while RtuTask may still own it. Every job carries a unique 32-bit id; the completion queue carries that id; an overdue job moves to an ABANDONED state where its late result is recognised and discarded instead of being taken for the next request's answer.
- **[39]** PER-CLIENT REQUEST QUEUES: each TCP client may pipeline up to REQ_QUEUE_DEPTH requests. Requests are parsed out of the byte stream into a per-client ring, dispatched round-robin, and answered in order on the connection they came from. Transaction ids are scoped to their connection, never compared globally. A full ring simply stops draining the socket (TCP back-pressure) instead of dropping anything.
- **[40]** Queued requests age out (REQUEST_MAX_AGE_MS) with exception 0x0A rather than occupying the bus long after the master has given up.
- **[41]** ATOMIC PERSISTENCE: network settings, serial settings, gateway options, password hash and the default-password flag now live in ONE versioned, CRC-protected blob written to A/B slots with a generation counter and a read-back verify. Power loss at any instant leaves exactly one valid slot; config and password can no longer disagree.
- **[42]** t1.5 inter-character gap detection (advisory above 19200 baud, where the gap is shorter than the scheduler's resolution — see RTU_GAP_FLOOR_US).
- **[43]** The serial log no longer prints the default password; it says only that the device default is active. The password itself is on the label.

### v3.1.0 fixes (audit #4)

- **[44]** CRITICAL, initialisation order: loadConfig() derives the per-device default password from mac[], but generateUniqueMac() ran AFTER it. On a fresh device (or a legacy migration) the stored hash was therefore computed from 00:00:00:00:00:00 while the label-derived password was the real one -> nobody could log in. The MAC is now produced before any persistence code runs, and a device already flashed with the broken order heals itself on the next boot (see loadConfig).
- **[45]** CSRF: a ring of four tokens, each with its own expiry, replaces the single global token, so several open configuration tabs all stay usable. Tokens are still unpredictable, single-use and expiring.
- **[46]** After an abandoned RTU job the UART is explicitly re-synchronised (drain to silence) before the next transaction is allowed on the bus.
- **[47]** Watchdog ladder documented and widened: a slow slave or a normal Modbus timeout can never reboot the device; only a genuinely stuck task can.
- **[48]** HTTP: real HEAD support, shorter write deadline so a slow browser cannot delay Modbus, and write failures are detected and counted.
- **[49]** Eviction never touches a client that has queued requests.
- **[50]** Diagnostics: boot/reset reason plus counters for disconnects, queue back-pressure, abandoned jobs, late completions, auth failures and lockouts, and configuration write/CRC failures.

### v3.2.0 — W5500 bring-up hardening and diagnostics

Field issue: "W5500 not detected" on hardware that works with other firmware.
- **[51]** The chip is now probed DIRECTLY over SPI (VERSIONR at 0x0039 must read 0x04) before the Ethernet library is asked to detect it, and the result is logged. That separates "SPI/wiring/speed problem" from "library detection problem" in one line of console output.
- **[52]** If detection fails, the firmware sweeps 1/2/4/8/14/20 MHz with the raw probe and prints which clocks answer, because the Arduino Ethernet library talks to the W5500 at a fixed 14 MHz that long jumper wires or a breadboard often cannot sustain.
- **[53]** Init is retried (hardware reset between attempts) instead of giving up after one try, with the external watchdog fed between attempts.
- **[54]** The hardware reset pin is optional now (W5500_RST -1) for boards that tie RESET to a supervisor chip instead of a GPIO.
- **[55]** The health check no longer compares the MAC register; it uses the raw VERSIONR probe plus SIPR/SUBR, logs expected-vs-actual on the first mismatch, and cannot re-initialise more often than once per 30 s.

### v3.3.0 — the W5500 was held in hardware reset

Field bug, found by comparing with the factory test firmware that worked on the same PCB.
- **[56]** RESET POLARITY. On this PCB the ESP32 pin drives a TRANSISTOR, so a HIGH on the GPIO pulls the W5500 /RESET pin LOW (reset asserted) and a LOW releases it through the pull-up. The firmware did the opposite and left the GPIO high, i.e. the chip stayed in reset for ever and every register read returned 0x00 at every SPI clock. Polarity is now an explicit, documented option (W5500_RST_ASSERT_HIGH).
- **[57]** After releasing reset the firmware polls VERSIONR until the chip answers (up to W5500_BOOT_TIMEOUT_MS) and logs the measured boot time, instead of assuming a fixed delay: a weak 25 MHz crystal shows up here.
- **[58]** SPI.begin() is called with SS = -1 so the ESP32 does not route a hardware CS onto GPIO5 while the Ethernet library drives the same pin by hand.
- **[59]** The raw probe runs at 1 MHz (the factory test's proven speed for these PCB traces) - it is a diagnostic, it does not need to be fast.
- **[60]** First boot no longer prints the scary "nvs_get_blob len fail" error: the slot is checked with isKey() before it is read.

### v3.4.0 — commissioning login

- **[61]** The web password is a plain, known value again (admin / admin123 by default) because the MAC-derived one is impossible to guess in the field without the label. WEB_FORCE_DEFAULT_PASSWORD keeps it in force at every boot, so the device can never lock you out. Set that option to 0 (and change the password from the web page) before shipping: while it is 1, every unit has the same password and the console prints it.

### v3.5.0 — "500 Internal Error / Page buffer overflow" on the config page

- **[62]** The status page grew past the 4 kB build buffer as diagnostics were added. The buffer is now 12 kB (static, still no heap), the real page size is logged every time the page is served, and an overflow reports how many bytes were needed instead of just saying "overflow".
