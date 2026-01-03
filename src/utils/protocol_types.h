#ifndef PROTOCOL_TYPES
#define PROTOCOL_TYPES

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netinet/ip.h>

/**
 * @brief recognize if it is a Client hello pkt.
 *  TLS record layer:
 *      0x16: Content Type(Handshake) 0x03: Version Major(TLS) 0x01(0x03):
 *      Versoin Minor(TLS) xxxx: Length    0x01 Handshake Type(*Client Hello*)
 *      [ IP Header ] [ TCP Header ] [ TLS Record Header (5 bytes) ] [ TLS
 * Content (Payload) ]
 * @param payload
 * @param len
 * @return int 1: changed successfully 0:changed failed.
 */
static int is_tls_hello(const uint8_t *payload, int len) {
  if (len < 9)
    return 0;
  // Content Type = 0x16:Handshake
  if (payload[0] != 0x16)
    return 0;
  // Version Major = 0x03 (SSL 3.0 / TLS 1.x)
  if (payload[1] != 0x03)
    return 0;
  // Handshake Type = 0x01 Client Hello
  if (payload[5] != 0x01)
    return 0;

  return 1;
}

/**
 * @brief judge whether a method is a http method
 *
 * @param payload
 * @param len
 * @return int 1: is a http request 0:not a http request.
 */
static int is_http_request(const uint8_t *payload, int len) {
  if (len < 4)
    return 0;
  if (memcmp(payload, "GET ", 4) == 0)
    return 1;
  if (memcmp(payload, "POST", 4) == 0)
    return 1;
  if (memcmp(payload, "HEAD", 4) == 0)
    return 1;
  if (memcmp(payload, "PUT ", 4) == 0)
    return 1;
  if (memcmp(payload, "DELE", 4) == 0)
    return 1;
  return 0;
}

#endif