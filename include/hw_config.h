#pragma once
// ==========================================================================
// hw_config.h — board wiring and build-wide options
// --------------------------------------------------------------------------
// Everything that depends on the PCB lives here: pins, reset polarity, LEDs,
// the external watchdog, the optional factory-reset pin, plus the firmware
// version and the serial-debug switch. Every option guarded by #ifndef can be
// overridden from platformio.ini (build_flags = -DNAME=value).
// ==========================================================================
#include <Arduino.h>

#define FW_VERSION "3.6.0"

// ---- serial debug log (LOGF in utils.h) ----
#ifndef DEBUG_SERIAL
#define DEBUG_SERIAL 1
#endif
// Extra-detailed traffic log (every request / reply / RTU frame in hex).
// 0 = only state changes and errors are printed. Needs DEBUG_SERIAL=1.
#ifndef DEBUG_TRAFFIC
#define DEBUG_TRAFFIC 1
#endif
// Periodic one-line status summary on the serial port, in ms (0 = off).
#ifndef DEBUG_STATUS_MS
#define DEBUG_STATUS_MS 10000UL
#endif

// ---- W5500 Ethernet (SPI) ----
#define W5500_MOSI 23
#define W5500_MISO 19
#define W5500_SCLK 18
#define W5500_CS   5
// Set to -1 if RESET is not wired to a GPIO on your board (a supervisor chip
// or an RC network drives it). The library still performs a software reset.
#ifndef W5500_RST
#define W5500_RST  25
#endif

// RESET POLARITY — get this wrong and the chip never runs (audit FIX-56).
//   1 = the GPIO drives an inverting stage (transistor): GPIO HIGH asserts the
//       W5500 reset, GPIO LOW releases it through the board's pull-up.
//       This is the Ajeevi PCB.
//   0 = the GPIO goes straight to the W5500 /RESET pin: LOW asserts reset.
#ifndef W5500_RST_ASSERT_HIGH
#define W5500_RST_ASSERT_HIGH 1
#endif
#define W5500_RST_ASSERT_LEVEL  (W5500_RST_ASSERT_HIGH ? HIGH : LOW)
#define W5500_RST_RELEASE_LEVEL (W5500_RST_ASSERT_HIGH ? LOW  : HIGH)
#define W5500_RST_PULSE_MS 250                // factory test measured this as reliable
#define W5500_BOOT_TIMEOUT_MS 1500            // crystal + PLL + internal boot

// The web configuration server always listens here (not configurable), so the
// Modbus TCP port may never be set to the same value.
#define HTTP_PORT 80

// ---- RS-485 (UART2) ----
#define RXD2 16
#define TXD2 17
#define RS485_UART_NUM UART_NUM_2

// RS-485 direction control (DE and /RE tied together).
//  -1  : transceiver has automatic direction control (no DE pin used)
//  >=0 : GPIO driving DE/RE
#ifndef RS485_DE_PIN
#define RS485_DE_PIN -1
#endif
//  0 : firmware drives DE (waits for TX-complete, then releases)       [default]
//  1 : UART hardware drives DE via its RTS line (UART_MODE_RS485_HALF_DUPLEX).
//      Most precise option; requires RS485_DE_PIN >= 0.
#ifndef RS485_USE_HW_DE
#define RS485_USE_HW_DE 0
#endif
#define RS485_DE_SETUP_US 10   // DE asserted -> first start bit

#if RS485_USE_HW_DE && (RS485_DE_PIN < 0)
#error "RS485_USE_HW_DE requires RS485_DE_PIN >= 0"
#endif

// ---- status LEDs & external watchdog (DONE pin, e.g. TPL5010) ----
//
// !! HARDWARE WARNING (audit FIX-01) !!
// GPIO12 is the MTDI strapping pin: it selects the flash voltage at reset and
// MUST be below ~0.8 V while the chip comes out of reset. An LED circuit that
// can pull it high at power-up makes the board boot with 1.8 V flash settings
// -> intermittent or total boot failure in the field. Verify with a scope. If
// the PCB cannot be changed, burn the flash voltage eFuse
// (espefuse.py set_flash_voltage 3.3V) during production programming, or move
// the LED to a non-strapping GPIO (13, 26, 27, 32, 33 are safe here).
// ESP32 strapping pins: 0, 2, 4, 5, 12, 15.
#define LED_D3 14
#define LED_D4 12
#define WDT_DONE_PIN 33

// ---- optional factory reset ----
// Hold this pin LOW during power-up for FACTORY_RESET_HOLD_MS to wipe the
// saved configuration and password. -1 = disabled.
#ifndef FACTORY_RESET_PIN
#define FACTORY_RESET_PIN -1
#endif
#define FACTORY_RESET_HOLD_MS 5000