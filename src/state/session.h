#ifndef SESSION_H
#define SESSION_H

// The session.h session.c mainly are used to record the state of the data
// when it goes to the Server, it has to be resemmbled suucessfully.
#include <netinet/tcp.h>
#include <stdint.h>
#include "../utils/uthash.h"

// 定义 Key 的结构
struct flow_key_v4 {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

// TODO: add more state of TCP
typedef enum {
    TCP_STATE_NONE,
    TCP_STATE_SYN_SENT,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT,
    TCP_STATE_CLOSED
} tcp_state_e;

// 会话结构体
typedef struct {
    struct flow_key_v4 key; // Key 必须在结构体里
    
    tcp_state_e state;
    uint32_t seq;
    uint32_t ack;

    UT_hash_handle hh; // uthash 必须包含这个句柄
} session_t;

// API
void session_init();
session_t* session_find(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport);
session_t* session_create(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport);
void session_destroy(session_t *s);
void session_print_stats();
void session_update(session_t *s, struct tcphdr *tcp);

#endif