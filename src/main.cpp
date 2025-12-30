#include "core/interceptor.h"
#include "protocol/headers.h" // 你的 PacketView
#include <iostream>
#include <linux/netfilter.h>

int main() {
    Interceptor interceptor;

    // 初始化队列 0
    if (!interceptor.init(0)) {
        return -1;
    }

    // 注册核心处理逻辑 (Lambda 表达式)
    interceptor.set_packet_handler([&](uint8_t* data, size_t len, uint32_t id) -> int {
        
        // 1. 使用你的 PacketView 解析
        PacketView packet(data, len);

        // 2. 检查是不是 TCP--->ping我们不管,我们只会拦截传输层和应用层的packet并且进行处理.
        const auto* ip = packet.ip_header();
        const auto* tcp = packet.tcp_header();

        if (ip && tcp) {
            // 打印信息：源IP -> 目的IP (Seq: ...)
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ip->daddr), dst_ip, INET_ADDRSTRLEN);

            std::cout << "[TCP] " << src_ip << ":" << ntohs(tcp->source) 
                      << " -> " << dst_ip << ":" << ntohs(tcp->dest)
                      << " Seq=" << ntohl(tcp->seq)
                      << " Len=" << packet.payload_length() << std::endl;
        }

        // 3. 默认放行 (NF_ACCEPT)
        return interceptor.set_verdict(id, NF_ACCEPT);
    });

    // 开始运行
    interceptor.run();

    return 0;
}