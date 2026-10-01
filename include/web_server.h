#pragma once
// ==========================================================================
// web_server.h — authenticated configuration / status pages (HTTP, port 80)
// --------------------------------------------------------------------------
// The socket side (accept, request framing, Content-Length) is in
// ethernet_tcp.cpp; this module turns one complete request into one response.
// Everything runs inside NetTask. Zero heap: one static page buffer.
// ==========================================================================
#include <Arduino.h>
#include <Ethernet.h>

#define AUTH_MAX_FAILS 5
#define AUTH_LOCKOUT_MS 30000UL
#define AUTH_TRACKED_HOSTS 4                  // per-source-IP lockout table
#define CSRF_TOKEN_TTL_MS 300000UL
#define CSRF_TOKEN_SLOTS 4                    // several config tabs may be open at once
#define WEB_PASS_MIN_LEN 5

// The configuration page carries the form plus ~25 diagnostic rows plus the
// per-slave table (measured: ~6 kB worst case), so it needs real room (FIX-62).
#define PAGE_BUFFER_SIZE 12288

void authReport();   // boot-time note about the web login (setup())
void handleHttpRequest(EthernetClient& c, char* req, size_t hdrLen, const char* body);
// Case-insensitive header lookup inside the header block. Also used by the
// request framing in ethernet_tcp.cpp (Content-Length).
bool httpHeader(const char* req, size_t hdrLen, const char* name, char* out, size_t outCap);
void httpSendSimple(EthernetClient& c, int code, const char* reason, const char* msg,
                    const char* extraHeaders = "");
