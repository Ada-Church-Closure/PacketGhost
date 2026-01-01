#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 全局哈希表头指针 (必须初始化为 NULL)
static session_t *g_sessions = NULL;

void session_init() {
    g_sessions = NULL;
    printf("[Session] Table initialized.\n");
}

session_t* session_find(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
    session_t *s = NULL;
    
    // 构造查找 Key
    // 必须清零内存，防止 padding 里的垃圾数据影响 Hash 计算
    struct flow_key_v4 k;
    memset(&k, 0, sizeof(k)); 
    k.src_ip = saddr;
    k.dst_ip = daddr;
    k.src_port = sport;
    k.dst_port = dport;

    // HASH_FIND(hh, 头指针, Key指针, Key长度, 输出指针)
    HASH_FIND(hh, g_sessions, &k, sizeof(struct flow_key_v4), s);
    return s;
}

session_t* session_create(uint32_t saddr, uint32_t daddr, uint16_t sport, uint16_t dport) {
    session_t *s = (session_t*)malloc(sizeof(session_t));
    if (!s) return NULL;

    // 初始化内存
    memset(s, 0, sizeof(session_t));

    // 填充 Key
    s->key.src_ip = saddr;
    s->key.dst_ip = daddr;
    s->key.src_port = sport;
    s->key.dst_port = dport;

    // 初始化状态
    s->state = TCP_STATE_SYN_SENT; // 假设刚创建就是握手

    // 添加到哈希表
    // HASH_ADD(hh, 头指针, Key字段名, Key长度, item指针)
    HASH_ADD(hh, g_sessions, key, sizeof(struct flow_key_v4), s);

    printf("[Session] New flow created: %u -> %u\n", sport, dport);
    return s;
}

void session_destroy(session_t *s) {
    if (!s) return;
    // 从哈希表中移除
    HASH_DELETE(hh, g_sessions, s);
    // 释放内存
    free(s);
}

void session_print_stats() {
    unsigned int count = HASH_COUNT(g_sessions);
    printf("[Session] Current active flows: %u\n", count);
}