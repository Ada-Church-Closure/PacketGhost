#pragma once

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <functional>
#include <vector>
#include <cstdint>

// 拦截层:linux内核直接把网络包给我们的程序来处理

// 定义一个回调函数类型：接收原始数据和长度，返回 verdict (放行或丢弃)
using PacketHandler = std::function<int(uint8_t* data, size_t len, uint32_t id)>;

class Interceptor {
public:
    Interceptor();
    ~Interceptor();

    // 初始化：绑定到指定的队列编号 (例如 iptables ... --queue-num 0)
    bool init(uint16_t queue_num);

    // 启动循环：开始处理包 (阻塞函数)
    void run();

    // 注册处理函数
    void set_packet_handler(PacketHandler handler);

    // 辅助：发送判定结果给内核
    // verdict: NF_ACCEPT (放行), NF_DROP (丢弃)
    int set_verdict(uint32_t id, int verdict);

private:
    // 静态的回调函数 (因为 C 库不能直接调 C++ 成员函数)
    static int _nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                             struct nfq_data *nfa, void *data);

    struct nfq_handle *_h {nullptr};
    struct nfq_q_handle *_qh {nullptr};
    int _fd {-1};
    PacketHandler _handler;
    uint16_t _queue_num {0};
};