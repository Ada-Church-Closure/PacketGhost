#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

pg_config_t g_config;

static void set_defaults() {
  memset(&g_config, 0, sizeof(g_config));

  g_config.ttl_decoy.enabled = 1;
  g_config.ttl_decoy.ttl = 2;
  g_config.ttl_decoy.apply_once_per_flow = 1;

  g_config.rst.enabled = 1;
  g_config.rst.bad_checksum = 1;
  g_config.rst.with_ack = 0;
  g_config.rst.small_ttl = 0; // off by default; can be enabled in config

  g_config.fragment.enabled = 0;
  g_config.fragment.out_of_order = 1;
  g_config.fragment.http_split_pos = 2;
  g_config.fragment.tls_split_pos = 1;

  g_config.ua_replace.enabled = 1;
  strncpy(g_config.ua_replace.target, "curl/", sizeof(g_config.ua_replace.target)-1);
  strncpy(g_config.ua_replace.replace, "Mozilla/", sizeof(g_config.ua_replace.replace)-1);

  g_config.sack.disable = 1;
}

// Very small INI-like parser: key=value per line, '#' and ';' are comments
static void parse_line(char *line) {
  // trim leading spaces
  while (*line == ' ' || *line == '\t') line++;
  if (*line == '\0' || *line == '\n' || *line == '#' || *line == ';') return;

  char *eq = strchr(line, '=');
  if (!eq) return;
  *eq = '\0';
  char *key = line;
  char *val = eq + 1;

  // trim trailing spaces of key
  for (int i = strlen(key) - 1; i >= 0 && (key[i] == ' ' || key[i] == '\t'); --i) key[i] = '\0';
  // trim trailing newline/spaces of val
  size_t vl = strlen(val);
  while (vl > 0 && (val[vl-1] == '\n' || val[vl-1] == '\r' || val[vl-1] == ' ' || val[vl-1] == '\t')) { val[--vl] = '\0'; }

  int iv = atoi(val);

  // Map keys
  if (strcmp(key, "ttl_decoy.enabled") == 0) g_config.ttl_decoy.enabled = iv;
  else if (strcmp(key, "ttl_decoy.ttl") == 0) g_config.ttl_decoy.ttl = iv;
  else if (strcmp(key, "ttl_decoy.apply_once_per_flow") == 0) g_config.ttl_decoy.apply_once_per_flow = iv;

  else if (strcmp(key, "rst.enabled") == 0) g_config.rst.enabled = iv;
  else if (strcmp(key, "rst.bad_checksum") == 0) g_config.rst.bad_checksum = iv;
  else if (strcmp(key, "rst.with_ack") == 0) g_config.rst.with_ack = iv;
  else if (strcmp(key, "rst.small_ttl") == 0) g_config.rst.small_ttl = iv;

  else if (strcmp(key, "fragment.enabled") == 0) g_config.fragment.enabled = iv;
  else if (strcmp(key, "fragment.out_of_order") == 0) g_config.fragment.out_of_order = iv;
  else if (strcmp(key, "fragment.http_split_pos") == 0) g_config.fragment.http_split_pos = iv;
  else if (strcmp(key, "fragment.tls_split_pos") == 0) g_config.fragment.tls_split_pos = iv;

  else if (strcmp(key, "ua_replace.enabled") == 0) g_config.ua_replace.enabled = iv;
  else if (strcmp(key, "ua_replace.target") == 0) {
    strncpy(g_config.ua_replace.target, val, sizeof(g_config.ua_replace.target)-1);
    g_config.ua_replace.target[sizeof(g_config.ua_replace.target)-1] = '\0';
  }
  else if (strcmp(key, "ua_replace.replace") == 0) {
    strncpy(g_config.ua_replace.replace, val, sizeof(g_config.ua_replace.replace)-1);
    g_config.ua_replace.replace[sizeof(g_config.ua_replace.replace)-1] = '\0';
  }

  else if (strcmp(key, "sack.disable") == 0) g_config.sack.disable = iv;
}

int config_load(const char *path) {
  set_defaults();
  if (!path) return 0;
  FILE *f = fopen(path, "r");
  if (!f) return -1; // keep defaults
  char line[256];
  while (fgets(line, sizeof(line), f)) parse_line(line);
  fclose(f);
  return 0;
}

