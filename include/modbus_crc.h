#pragma once
// Modbus RTU CRC-16 (polynomial 0xA001, initial value 0xFFFF).
// The LOW byte goes on the wire first. Implemented in utils.cpp.
#include <stddef.h>
#include <stdint.h>

uint16_t modbusCRC(const uint8_t* buf, size_t len);
