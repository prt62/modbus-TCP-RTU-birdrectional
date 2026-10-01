#pragma once
// ==========================================================================
// rs485_rtu.h — Modbus RTU master on the RS-485 UART
// --------------------------------------------------------------------------
// OWNERSHIP: only RtuTask touches the UART after setup(). NetTask hands it one
// job at a time (ethernet_tcp.cpp) and never waits for the serial line.
// ==========================================================================
#include <Arduino.h>
#include "hw_config.h"

static constexpr size_t MB_RTU_MAX = 256;    // 1 unit + 253 PDU + 2 CRC

#define RS485_MIN_GAP_MS 5                    // floor for silence-based end-of-frame
#define BROADCAST_TURNAROUND_MS 100
#define RS485_RX_BUFFER 1024

// Inter-character gap check. Below ~1 ms the observed gap is dominated by task
// scheduling rather than by the wire, so the check uses a floor: above 19200
// baud (t1.5 = 750 us) it is effectively disabled and the CRC plus the exact
// length and t3.5 checks carry the frame. Documented robustness gap.
#ifndef RTU_GAP_CHECK
#define RTU_GAP_CHECK 1
#endif
#define RTU_GAP_FLOOR_US 3000UL

// Every failure mode is distinct: the exception code and the counter a field
// engineer sees must tell "no answer" apart from "answer was unusable" and
// from "somebody else answered" (audit FIX-03).
enum RtuResult {
  RTU_OK,
  RTU_BROADCAST,
  RTU_TIMEOUT,          // not a single byte came back
  RTU_CRC,              // complete, correctly framed, CRC wrong
  RTU_FRAME_ERROR,      // too short / extra bytes / no silence / RX overflow
  RTU_UNIT_MISMATCH,    // a different unit id answered
  RTU_FC_MISMATCH       // answer to a different function code
};

// Published by RtuTask (or the UART event task), read elsewhere: volatile, 32-bit.
extern volatile uint32_t g_turnaroundLastUs;
extern volatile uint32_t g_turnaroundMaxUs;
extern volatile uint32_t g_turnaroundMinUs;
extern volatile uint32_t g_uartFrameErr;
extern volatile uint32_t g_uartParityErr;
extern volatile uint32_t g_uartOverflow;
extern volatile bool     g_rtuResyncNeeded;   // NetTask sets, RtuTask clears
extern volatile uint32_t g_rtuHeartbeatMs;
extern bool              g_rtuTwdtSubscribed;

void rtuAlive();                 // heartbeat + task-WDT feed (RtuTask only)
void computeRtuTiming();         // after loadConfig(): char time, t1.5, t3.5
void rs485Init();
RtuResult rtuTransaction(const uint8_t* req, size_t reqLen, uint8_t* rx, size_t& rxLen);
