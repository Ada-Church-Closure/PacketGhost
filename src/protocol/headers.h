#pragma once
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstdint>
#include <arpa/inet.h>

class PacketView {
public:
    PacketView(uint8_t* data, size_t len) : _raw_data(data), _len(len) {}

    const struct iphdr* ip_header() const {
        if (_len < sizeof(struct iphdr)) return nullptr;
        return reinterpret_cast<const struct iphdr*>(_raw_data);
    }

    const struct tcphdr* tcp_header() const {
        const auto* ip = ip_header();
        if (!ip) return nullptr;
        
        // IP 头长度是 4字节的倍数 (ihl * 4)
        size_t ip_len = ip->ihl * 4;
        if (_len < ip_len + sizeof(struct tcphdr)) return nullptr;

        // 显然IP肯定在tcp头部的前面
        return reinterpret_cast<const struct tcphdr*>(_raw_data + ip_len);
    }
    
    /**
     * 获取 Payload
     * 这里payload是uint8*指针
     */
    const uint8_t* payload() const {
        const auto* tcp = tcp_header();
        if (!tcp) return nullptr;
        
        const auto* ip = ip_header();
        size_t ip_len = ip->ihl * 4;
        size_t tcp_len = tcp->doff * 4; // Data Offset
        
        size_t total_header_len = ip_len + tcp_len;
        if (_len <= total_header_len) return nullptr; // 没数据
        
        return _raw_data + total_header_len;
    }

    /**
     * 返回pakcet的payload的长度
     */
    size_t payload_length() const {
        const auto* ip = ip_header();
        if (!ip) return 0;
        size_t total_len = ntohs(ip->tot_len);
        
        const auto* tcp = tcp_header();
        if (!tcp) return 0;
        
        size_t ip_len = ip->ihl * 4;
        size_t tcp_len = tcp->doff * 4;
        
        return total_len - ip_len - tcp_len;
    }

private:
    uint8_t* _raw_data;
    size_t _len;
};
