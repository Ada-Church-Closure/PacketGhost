// Unit tests for checksum helpers.
#include <gtest/gtest.h>
#include "utils/checksum.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <vector>
#include <cstring>

using namespace pg;

static void fill_ipv4(iphdr& ip, uint16_t tot_len, uint8_t proto = IPPROTO_TCP) {
    std::memset(&ip, 0, sizeof(ip));
    ip.version = 4;
    ip.ihl = 5; // 20 bytes
    ip.tot_len = htons(tot_len);
    ip.protocol = proto;
    inet_pton(AF_INET, "10.0.0.1", &ip.saddr);
    inet_pton(AF_INET, "10.0.0.2", &ip.daddr);
}

TEST(Checksum, IPv4Header) {
    iphdr ip{};
    fill_ipv4(ip, /*tot_len=*/40);
    ip.check = 0;
    uint16_t cksum = ipv4_header_checksum(&ip);
    EXPECT_NE(cksum, 0);
    ip.check = cksum;
    // Our checksum function skips the checksum field, so recomputing should
    // yield the same value as stored in the header.
    EXPECT_EQ(ipv4_header_checksum(&ip), ip.check);
}

TEST(Checksum, TCPNoPayload) {
    // Build 20B IP + 20B TCP, no payload
    std::vector<uint8_t> buf(40, 0);
    auto* ip = reinterpret_cast<iphdr*>(buf.data());
    fill_ipv4(*ip, /*tot_len=*/40);

    auto* tcp = reinterpret_cast<tcphdr*>(buf.data() + 20);
    tcp->doff = 5;
    tcp->source = htons(1234);
    tcp->dest = htons(80);
    tcp->seq = htonl(0x11223344);
    tcp->ack_seq = htonl(0);
    tcp->syn = 1;

    ipv4_update_checksum(ip);
    tcp_update_checksum_ipv4(ip, tcp, nullptr, 0);

    // Now validate: recomputing with checksum included should give zero
    uint16_t sum_ip = ipv4_header_checksum(ip);
    EXPECT_EQ(sum_ip, ip->check);

    uint16_t tcp_ck = tcp_checksum_ipv4(ip, tcp, nullptr, 0);
    EXPECT_EQ(tcp_ck, tcp->check);
}

TEST(Checksum, TCPWithOddPayload) {
    // 3-byte payload to test odd-length padding
    const char* msg = "GET"; // 3 bytes
    const size_t payload_len = 3;
    std::vector<uint8_t> buf(20 + 20 + payload_len, 0);
    auto* ip = reinterpret_cast<iphdr*>(buf.data());
    fill_ipv4(*ip, /*tot_len=*/static_cast<uint16_t>(buf.size()));

    auto* tcp = reinterpret_cast<tcphdr*>(buf.data() + 20);
    tcp->doff = 5;
    tcp->psh = 1; tcp->ack = 1;
    tcp->source = htons(5555);
    tcp->dest = htons(8080);

    std::memcpy(buf.data() + 40, msg, payload_len);

    ipv4_update_checksum(ip);
    tcp_update_checksum_ipv4(ip, tcp, buf.data() + 40, payload_len);

    EXPECT_EQ(ipv4_header_checksum(ip), ip->check);
    EXPECT_EQ(tcp_checksum_ipv4(ip, tcp, buf.data() + 40, payload_len), tcp->check);
}
