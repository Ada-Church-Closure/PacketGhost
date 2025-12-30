#include <netinet/in.h>      // ntohl


#include "interceptor.h"
#include <iostream>

Interceptor::Interceptor() {}

Interceptor::~Interceptor() {
    if (_qh) nfq_destroy_queue(_qh);
    if (_h) nfq_close(_h);
}

bool Interceptor::init(uint16_t queue_num) {
    _queue_num = queue_num;

    // 1. 打开句柄
    _h = nfq_open();
    if (!_h) {
        std::cerr << "Failed to open NFQ handle" << std::endl;
        return false;
    }

    // 2. 解绑并重新绑定协议族 (AF_INET = IPv4)
    nfq_unbind_pf(_h, AF_INET);
    if (nfq_bind_pf(_h, AF_INET) < 0) {
        std::cerr << "Failed to bind NFQ handler" << std::endl;
        return false;
    }

    // 3. 创建队列并绑定回调
    // 注意：把 'this' 指针传给 callback 的最后一个参数 data
    _qh = nfq_create_queue(_h, _queue_num, &Interceptor::_nfq_callback, this);
    if (!_qh) {
        std::cerr << "Failed to create queue " << _queue_num << std::endl;
        return false;
    }

    // 4. 设置模式：我们要把整个包的内容拷过来 (COPY_PACKET)
    // 0xffff 是拷贝的最大长度
    if (nfq_set_mode(_qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        std::cerr << "Failed to set copy mode" << std::endl;
        return false;
    }

    _fd = nfq_fd(_h);
    return true;
}

void Interceptor::run() {
    char buf[4096] __attribute__ ((aligned));
    int rv;

    std::cout << "[Interceptor] Listening on queue " << _queue_num << "..." << std::endl;

    // 循环读取内核发来的消息
    while ((rv = recv(_fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(_h, buf, rv);
    }
}

void Interceptor::set_packet_handler(PacketHandler handler) {
    _handler = handler;
}

int Interceptor::set_verdict(uint32_t id, int verdict) {
    // TODO
    // 这里的 0, NULL 表示不修改包的内容，直接放行/丢弃
    // 如果你要修改包，以后要传新的 data 和 len
    return nfq_set_verdict(_qh, id, verdict, 0, NULL);
}

// 静态回调函数
int Interceptor::_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                               struct nfq_data *nfa, void *data) {
    (void)qh; (void)nfmsg; // 消除 unused warning

    // 拿到 'this' 指针
    Interceptor* self = static_cast<Interceptor*>(data);
    if (!self || !self->_handler) return 0;

    // 获取 Packet ID
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    // 获取 Payload
    unsigned char *payload_data = nullptr;
    int payload_len = nfq_get_payload(nfa, &payload_data);

    if (payload_len >= 0) {
        // 调用我们 C++ 的处理逻辑
        return self->_handler(payload_data, static_cast<size_t>(payload_len), id);
    }

    return 0;
}