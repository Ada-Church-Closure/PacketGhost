#ifndef PG_CONFIG_H
#define PG_CONFIG_H

#include <stdint.h>

// Lightweight runtime configuration for PacketGhost.
// Simple key=value parser implemented in config.c

typedef struct {
  int enabled;               // 0/1 toggle
  int ttl;                   // TTL value for decoy
  int apply_once_per_flow;   // 1: only inject once per flow
} cfg_ttl_decoy_t;

typedef struct {
  int enabled;        // enable fake RST injection
  int bad_checksum;   // 1: send with bad TCP checksum
  int with_ack;       // 1: set ACK together with RST (not required)
  int small_ttl;      // 1: also set a small TTL for the fake RST (decoy)
} cfg_rst_t;

typedef struct {
  int enabled;            // payload fragmentation
  int out_of_order;       // send second slice first
  int http_split_pos;     // bytes to keep in first HTTP slice
  int tls_split_pos;      // bytes to keep in first TLS slice
} cfg_fragment_t;

typedef struct {
  int enabled;            // enable UA replacement
  char target[32];        // substring to replace, e.g. "curl/"
  char replace[64];       // replacement, e.g. "Mozilla/"
} cfg_ua_replace_t;

typedef struct {
  int disable;            // 1: disable SACK permitted option on SYN
} cfg_sack_t;

typedef struct {
  cfg_ttl_decoy_t ttl_decoy;
  cfg_rst_t       rst;
  cfg_fragment_t  fragment;
  cfg_ua_replace_t ua_replace;
  cfg_sack_t      sack;
} pg_config_t;

// Global configuration instance
extern pg_config_t g_config;

// Initialize with defaults and optionally load from file.
// If path is NULL, only defaults are applied.
int config_load(const char *path);

#endif

