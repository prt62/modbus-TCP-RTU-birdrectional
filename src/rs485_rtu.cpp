// ==========================================================================
// rs485_rtu.cpp — RS-485 UART and the Modbus RTU master transaction
// --------------------------------------------------------------------------
// After setup() only RtuTask (ethernet_tcp.cpp) calls into this file.
// ==========================================================================
#include "rs485_rtu.h"
#include <string.h>
#include "driver/uart.h"
#include "esp_task_wdt.h"
#include "config_nvs.h"
#include "utils.h"

static HardwareSerial& rs485 = Serial2;               // UART2 (avoid a 2nd object on same UART)

volatile uint32_t g_rtuHeartbeatMs    = 0;          // published by RtuTask
bool              g_rtuTwdtSubscribed = false;      // RtuTask on task-WDT (written only by RtuTask)

// RTU timing derived from baud rate
static uint32_t g_charTimeUs = 0;   // 11-bit character
static uint32_t g_t15Us      = 0;   // inter-character limit inside a frame
static uint32_t g_t35Us      = 0;   // inter-frame silence
static uint32_t g_txGuardUs  = 0;   // DE hold after TX-done
static uint32_t g_busFreeAtUs = 0;  // micros() when bus may be driven again

// Set by NetTask when a job is abandoned, cleared by RtuTask before the next
// transaction: the UART must be drained to silence before the bus is used
// again, because an abandoned transaction may have left bytes in flight
// (audit FIX-03). Single writer in each direction; a lost update only costs
// one extra drain.
volatile bool g_rtuResyncNeeded = false;

// Measured slave turnaround (TX complete -> first response byte). RtuTask
// writes, NetTask reads for the status page: the manual equivalent of MOXA's
// response-timeout "Auto Detection" (audit FIX-A16).
volatile uint32_t g_turnaroundLastUs = 0;
volatile uint32_t g_turnaroundMaxUs  = 0;
volatile uint32_t g_turnaroundMinUs  = 0xFFFFFFFFUL;

// Written by the UART event task, read by the web page -> volatile, 32-bit.
volatile uint32_t g_uartFrameErr  = 0;
volatile uint32_t g_uartParityErr = 0;
volatile uint32_t g_uartOverflow  = 0;

// Called by RtuTask at every point where it may wait.
void rtuAlive() {
  g_rtuHeartbeatMs = millis();
  if (g_rtuTwdtSubscribed) esp_task_wdt_reset();
}

// Character time and the t1.5 / t3.5 limits follow the configured baud rate.
// Above 19200 baud the Modbus spec fixes t1.5 = 750 us and t3.5 = 1750 us.
void computeRtuTiming() {
  g_charTimeUs = (11UL * 1000000UL + cfg.baud - 1) / cfg.baud;
  g_t15Us      = (cfg.baud > 19200) ? 750  : (g_charTimeUs * 3 + 1) / 2;  // 1.5 chars
  g_t35Us      = (cfg.baud > 19200) ? 1750 : (g_charTimeUs * 7 + 1) / 2;  // 3.5 chars
  g_txGuardUs  = (2UL * 1000000UL + cfg.baud - 1) / cfg.baud + 5;          // ~2 bit times
}

// UART error events (wrong baud, wrong parity, noise, overrun) are counted so
// that a bad line can be told apart from a dead slave (audit FIX-10).
static void rs485ErrorCb(hardwareSerial_error_t err) {
  switch (err) {
    // Explicit read-modify-write: "volatile++" is deprecated in C++20 and the
    // UART event task is the only writer, so this is race-free as written.
    case UART_FRAME_ERROR:       g_uartFrameErr  = g_uartFrameErr  + 1; break;
    case UART_PARITY_ERROR:      g_uartParityErr = g_uartParityErr + 1; break;
    case UART_BUFFER_FULL_ERROR:
    case UART_FIFO_OVF_ERROR:    g_uartOverflow  = g_uartOverflow  + 1; break;
    default: break;
  }
}

#if DEBUG_SERIAL
static void logHex(const char* tag, const uint8_t* d, size_t n) {
  const size_t kMax = 48;
  LOGF("[RTU]   %s (%u B):", tag, (unsigned)n);
  for (size_t i = 0; i < n && i < kMax; i++) LOGF(" %02X", d[i]);
  if (n > kMax) LOGF(" ...");
  LOGF("\n");
}
static const char* rtuResultName(RtuResult r) {
  switch (r) {
    case RTU_OK:            return "OK";
    case RTU_BROADCAST:     return "BROADCAST";
    case RTU_TIMEOUT:       return "TIMEOUT";
    case RTU_CRC:           return "CRC_ERROR";
    case RTU_FRAME_ERROR:   return "FRAME_ERROR";
    case RTU_UNIT_MISMATCH: return "UNIT_MISMATCH";
    case RTU_FC_MISMATCH:   return "FC_MISMATCH";
  }
  return "?";
}
static const char* modbusExceptionName(uint8_t c) {
  switch (c) {
    case 0x01: return "illegal function";
    case 0x02: return "illegal data address (register not in meter)";
    case 0x03: return "illegal data value (e.g. quantity too big)";
    case 0x04: return "slave device failure";
    case 0x05: return "acknowledge";
    case 0x06: return "slave busy";
    case 0x08: return "memory parity error";
    case 0x0A: return "gateway path unavailable";
    case 0x0B: return "gateway target failed to respond";
  }
  return "other";
}
#endif

void rs485Init() {
  if (!rs485.setRxBufferSize(RS485_RX_BUFFER)) LOGF("[RTU] RX buffer alloc failed\n");
  rs485.begin(cfg.baud, SERIAL_FMTS[cfg.fmt].conf, RXD2, TXD2);
#if RS485_USE_HW_DE
  rs485.setPins(RXD2, TXD2, -1, RS485_DE_PIN);     // RTS = DE
  if (!rs485.setMode(UART_MODE_RS485_HALF_DUPLEX)) LOGF("[RTU] HW RS485 mode failed\n");
#endif
  // Deliver bytes to the ring buffer promptly. The IDF default (every 120
  // bytes, or after 10 idle symbols) breaks silence-based framing. One
  // interrupt per byte is affordable at low baud; above 38400 a small batch
  // keeps the interrupt load down while setRxTimeout still delimits frames.
  uint8_t fifoThreshold = (cfg.baud <= 38400) ? 1 : 8;
  if (!rs485.setRxFIFOFull(fifoThreshold)) LOGF("[RTU] setRxFIFOFull failed\n");
  if (!rs485.setRxTimeout(2))              LOGF("[RTU] setRxTimeout failed\n");
  rs485.onReceiveError(rs485ErrorCb);
#if RS485_DE_PIN >= 0
  LOGF("[RTU] UART2 RX=GPIO%d TX=GPIO%d, DE/RE=GPIO%d (%s direction control)\n",
       RXD2, TXD2, RS485_DE_PIN, RS485_USE_HW_DE ? "hardware" : "firmware");
#else
  LOGF("[RTU] UART2 RX=GPIO%d TX=GPIO%d, no DE pin (transceiver must switch direction by itself)\n",
       RXD2, TXD2);
#endif
}

// Read and discard everything on the line until it has been silent for t3.5
// (bounded). Used after a failed transaction so that a late reply cannot
// become the first bytes of the next one (audit FIX-03).
static void drainUntilSilent(uint32_t maxMs) {
  uint32_t start = millis();
  uint32_t lastByte = start;
  while (millis() - start < maxMs) {
    if (rs485.available() > 0) {
      while (rs485.available() > 0) rs485.read();
      lastByte = millis();
      continue;
    }
    if ((millis() - lastByte) * 1000UL > g_t35Us) return;
    rtuAlive();
    vTaskDelay(1);
  }
}

static inline void rs485TxBegin() {
#if (RS485_DE_PIN >= 0) && !RS485_USE_HW_DE
  digitalWrite(RS485_DE_PIN, HIGH);
  delayMicroseconds(RS485_DE_SETUP_US);
#endif
}

// Returns only after the last STOP bit has physically left the UART.
// HardwareSerial::flush() alone is not enough on every core version (it may
// return when the FIFO is empty while the final byte is still shifting out).
static void rs485TxEnd(size_t frameLen) {
  uint32_t budgetMs = (uint32_t)((frameLen * g_charTimeUs) / 1000UL) + 20;
  rs485.flush();
  // Sliced wait: at 1200 baud a full frame takes >2 s, and the task watchdog
  // must keep seeing this task alive (audit FIX-12).
  bool done = false;
  while (budgetMs > 0) {
    uint32_t slice = budgetMs > 100 ? 100 : budgetMs;
    if (uart_wait_tx_done(RS485_UART_NUM, pdMS_TO_TICKS(slice)) == ESP_OK) { done = true; break; }
    budgetMs -= slice;
    rtuAlive();
  }
  if (!done) delayMicroseconds(g_charTimeUs);      // fallback: one full character time
#if (RS485_DE_PIN >= 0) && !RS485_USE_HW_DE
  delayMicroseconds(g_txGuardUs);                  // stop bit fully on the wire
  digitalWrite(RS485_DE_PIN, LOW);
#endif
}

// Expected RTU response length from what has been received so far.
// -1 = not yet known / function code with no fixed rule (fall back to t3.5 gap).
static int expectedRtuLen(size_t reqLen, const uint8_t* rx, size_t n) {
  if (n < 2) return -1;
  uint8_t fc = rx[1];
  int len = -1;
  if (fc & 0x80) return 5;                           // exception: unit fc code crc crc
  switch (fc) {
    case 1: case 2: case 3: case 4: case 12: case 17: case 20: case 21: case 23:
      if (n >= 3) len = 5 + rx[2];                   // unit fc bytecount data.. crc crc
      break;
    case 5: case 6: case 11: case 15: case 16: len = 8;  break;
    case 7:  len = 5;  break;
    case 22: len = 10; break;
    case 8:  len = (int)reqLen + 2; break;           // diagnostics echo
    case 24: {                                   // Read FIFO Queue: 2-byte byte count
      if (n < 4) break;
      int byteCount = ((int)rx[2] << 8) | rx[3]; // = 2 * FIFO count + 2
      // Spec limit: FIFO count <= 31, so byteCount <= 64 and always even.
      if (byteCount < 2 || byteCount > 64 || (byteCount & 1)) return -1;
      len = 6 + byteCount;
      break;
    }
    default: break;
  }
  return (len > 0 && len <= (int)MB_RTU_MAX) ? len : -1;
}

static void waitBusFree() {
  for (;;) {
    int32_t remaining = (int32_t)(g_busFreeAtUs - micros());
    if (remaining <= 0) return;
    if (remaining > 2000) { rtuAlive(); vTaskDelay(1); }
    else { delayMicroseconds((uint32_t)remaining); return; }
  }
}

// req = unit + fc + data (no CRC). rx receives the full RTU reply incl. CRC.
RtuResult rtuTransaction(const uint8_t* req, size_t reqLen, uint8_t* rx, size_t& rxLen) {
  static uint8_t frame[MB_RTU_MAX];
  rxLen = 0;
  memcpy(frame, req, reqLen);
  uint16_t crc = modbusCRC(frame, reqLen);
  frame[reqLen]     = (uint8_t)(crc & 0xFF);
  frame[reqLen + 1] = (uint8_t)(crc >> 8);
  const size_t frameLen = reqLen + 2;
  const bool broadcast = (req[0] == 0);
#if DEBUG_SERIAL
  const uint32_t dbgFe0 = g_uartFrameErr, dbgPe0 = g_uartParityErr, dbgOv0 = g_uartOverflow;
#endif

  if (g_rtuResyncNeeded) {                        // recover from an abandoned job
    g_rtuResyncNeeded = false;
    drainUntilSilent(100);
#if (RS485_DE_PIN >= 0) && !RS485_USE_HW_DE
    digitalWrite(RS485_DE_PIN, LOW);              // guarantee receive mode
#endif
    g_busFreeAtUs = micros() + g_t35Us;
  }
  waitBusFree();
  while (rs485.available() > 0) rs485.read();      // discard stale / late bytes

  rs485TxBegin();
  rs485.write(frame, frameLen);
  rs485TxEnd(frameLen);
  const uint32_t txDoneUs = micros();

  if (broadcast) {                                  // slaves never answer unit 0
    g_busFreeAtUs = micros() + BROADCAST_TURNAROUND_MS * 1000UL;
    return RTU_BROADCAST;
  }

  // Silence-based framing. NOTE (audit FIX-09): t1.5 (750 us above 19200 baud)
  // cannot be observed from software at a 1 ms tick, so a gap *inside* a frame
  // is not detected as such — the CRC plus the exact-length + t3.5 silence
  // check below is what protects the frame. Documented limitation.
  const uint32_t gapMs   = max<uint32_t>(RS485_MIN_GAP_MS, (g_t35Us * 2) / 1000 + 2);
  const uint32_t stallMs = gapMs + (120UL * g_charTimeUs) / 1000;  // tolerance once length is known
  const uint32_t start   = millis();
  uint32_t lastByteMs = start;
  int  expected  = -1;
  bool overflow  = false;
  bool extraByte = false;
  bool silenceObserved = false;      // t3.5 of silence already proven at the boundary
  bool gapViolation = false;         // inter-character gap longer than t1.5
#if RTU_GAP_CHECK
  uint32_t lastByteUs = txDoneUs;
#endif

  // This wait blocks ONLY RtuTask (which owns nothing but the UART).
  // NetTask keeps serving TCP / HTTP / accept / health checks meanwhile.
  while (millis() - start < cfg.rtuTimeoutMs) {
    rtuAlive();
    int avail = rs485.available();
    if (avail > 0) {
      const uint32_t nowUs = micros();
      if (rxLen == 0) {                              // first byte: record turnaround
        uint32_t t = nowUs - txDoneUs;
        g_turnaroundLastUs = t;
        if (t > g_turnaroundMaxUs) g_turnaroundMaxUs = t;
        if (t < g_turnaroundMinUs) g_turnaroundMinUs = t;
      }
#if RTU_GAP_CHECK
      else {
        // Modbus RTU: a gap longer than t1.5 inside a frame makes the frame
        // invalid. What we can observe is limited by the tick and by the UART
        // driver's batching, so the check uses a floor (RTU_GAP_FLOOR_US) and
        // is effectively advisory above 19200 baud (audit FIX-A3).
        const uint32_t limit = (g_t15Us > RTU_GAP_FLOOR_US) ? g_t15Us : RTU_GAP_FLOOR_US;
        if ((uint32_t)(nowUs - lastByteUs) > limit) gapViolation = true;
      }
#endif
#if RTU_GAP_CHECK
      lastByteUs = nowUs;
#endif
      while (avail-- > 0) {
        int b = rs485.read();
        if (b < 0) break;
        if (rxLen < MB_RTU_MAX) rx[rxLen++] = (uint8_t)b; else overflow = true;
      }
      lastByteMs = millis();
      if (expected < 0) expected = expectedRtuLen(reqLen, rx, rxLen);
      if (expected > 0 && rxLen >= (size_t)expected) {
        // A byte count is a hint, not a frame delimiter: the frame is only
        // complete once the line has been silent for t3.5 (audit FIX-02).
        // Do not spin for the whole window: t3.5 is 1750 us above 19200 baud
        // but ~32 ms at 1200, and this loop takes the UART lock every pass
        // (audit FIX-A02).
        const uint32_t quietStart = micros();
        const bool yieldWhileWaiting = (g_t35Us > 3000);
        while ((int32_t)(micros() - quietStart) < (int32_t)g_t35Us) {
          if (rs485.available() > 0) break;
          if (yieldWhileWaiting) { rtuAlive(); vTaskDelay(1); }
        }
        if (rs485.available() > 0) extraByte = true;   // somebody is still talking
        else                       silenceObserved = true;
        break;
      }
      continue;
    }
    if (rxLen > 0) {
      uint32_t silent = millis() - lastByteMs;
      if (expected < 0 && silent > gapMs)   { silenceObserved = true; break; }
      if (expected > 0 && silent > stallMs) break;
    }
    vTaskDelay(1);
  }

  // Classify. Anything that is not a complete, correctly framed, CRC-valid
  // answer from the addressed unit gets its own result code (audit FIX-03).
  RtuResult result;
  if (rxLen == 0) {
    result = RTU_TIMEOUT;
  } else if (overflow || extraByte || gapViolation || rxLen < 4) {
    result = RTU_FRAME_ERROR;
  } else if (expected > 0 && rxLen != (size_t)expected) {
    result = RTU_FRAME_ERROR;                       // short or over-long frame
  } else {
    uint16_t calc = modbusCRC(rx, rxLen - 2);
    uint16_t recv = (uint16_t)(rx[rxLen - 2] | ((uint16_t)rx[rxLen - 1] << 8));
    if (calc != recv)                     result = RTU_CRC;
    else if (rx[0] != req[0])             result = RTU_UNIT_MISMATCH;
    else if ((rx[1] & 0x7F) != req[1])    result = RTU_FC_MISMATCH;
    else                                  result = RTU_OK;   // incl. slave exception replies
  }

  if (result != RTU_OK) {
    drainUntilSilent(50);                           // never let leftovers start the next frame
    silenceObserved = false;
  }
  // t3.5 is required ONCE between frames. When the frame boundary was already
  // proven by t3.5 of silence, waiting it again just wastes bus time - at 1200
  // baud that was 32 ms on every single poll (audit FIX-A03).
  g_busFreeAtUs = micros() + (silenceObserved ? 0 : g_t35Us);

#if DEBUG_SERIAL
  // Logged AFTER the transaction, so printing never disturbs RS-485 timing.
  {
    const uint32_t dFe = g_uartFrameErr - dbgFe0, dPe = g_uartParityErr - dbgPe0,
                   dOv = g_uartOverflow - dbgOv0;
    if (result != RTU_OK) {
      LOGF("[RTU] FAIL unit %u fc %u -> %s (waited %lu ms of %u ms, %lu baud)\n",
           req[0], req[1], rtuResultName(result), (unsigned long)(millis() - start),
           cfg.rtuTimeoutMs, (unsigned long)cfg.baud);
      logHex("TX sent    ", frame, frameLen);
      logHex("RX received", rx, rxLen);
      LOGF("[RTU]   UART errors during this request: framing +%lu, parity +%lu, overflow +%lu\n",
           (unsigned long)dFe, (unsigned long)dPe, (unsigned long)dOv);
      switch (result) {
        case RTU_TIMEOUT:
          if (dFe || dPe)
            LOGF("[RTU]   reason: line is active but bytes are garbled -> baud rate / parity / stop bits mismatch\n");
          else
            LOGF("[RTU]   reason: ZERO bytes came back -> check A/B swap, GND, slave power, slave address (unit %u), baud/parity, DE pin, timeout too short\n", req[0]);
          break;
        case RTU_CRC:
          LOGF("[RTU]   reason: full frame received but CRC wrong -> baud/parity mismatch, noise, missing termination\n");
          break;
        case RTU_FRAME_ERROR:
          LOGF("[RTU]   reason: bad frame (got %u bytes, expected %d, overflow=%d, extra bytes=%d, gap>t1.5=%d) -> noise, two devices answering, or wrong length\n",
               (unsigned)rxLen, expected, (int)overflow, (int)extraByte, (int)gapViolation);
          break;
        case RTU_UNIT_MISMATCH:
          LOGF("[RTU]   reason: unit %u answered but %u was asked -> duplicate address or wrong unit id\n", rx[0], req[0]);
          break;
        case RTU_FC_MISMATCH:
          LOGF("[RTU]   reason: answer carries function code %u, request was %u\n", rx[1] & 0x7F, req[1]);
          break;
        default: break;
      }
    } else {
      if (rx[1] & 0x80)
        LOGF("[RTU] unit %u fc %u -> meter answered with EXCEPTION 0x%02X (%s) - meter is alive, request is the problem\n",
             req[0], req[1], rx[2], modbusExceptionName(rx[2]));
#if DEBUG_TRAFFIC
      LOGF("[RTU] OK unit %u fc %u, %u B reply, turnaround %lu us\n",
           req[0], req[1], (unsigned)rxLen, (unsigned long)g_turnaroundLastUs);
      logHex("TX sent    ", frame, frameLen);
      logHex("RX received", rx, rxLen);
#endif
    }
  }
#endif
  return result;
}