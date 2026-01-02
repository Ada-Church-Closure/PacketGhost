#ifndef INJECTOR_H
#define INJECTOR_H

#include <stdint.h>
#include <stddef.h>

// init raw socket
int injector_init();

// send raw ip packet
int injector_send(const uint8_t *packet_data, size_t len);

// close
void injector_close();

#endif