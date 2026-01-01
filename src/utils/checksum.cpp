// IPv4 and TCP checksum routines.
#include "utils/checksum.h"

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstddef>
#include <cstdint>
#include <arpa/inet.h>

namespace pg {

// Fold a 32/64-bit accumulator to 16 bits and return one's complement.
static inline uint16_t fold_to_u16(uint64_t sum) {
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum & 0xFFFF);
}

// Sum a byte buffer as 16-bit words in network order. Optionally skip a range
// [skip_start, skip_start+skip_len) within the buffer (used to zero checksum fields).
static uint64_t sum_bytes16(const uint8_t* data, size_t len,
                            size_t skip_start = SIZE_MAX, size_t skip_len = 0) {
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        if (i >= skip_start && i < skip_start + skip_len) {
            // skip these two bytes (treated as zeros)
            continue;
        }
        uint16_t word = (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
        sum += word;
    }
    if ((len & 1u) != 0) {
        // Odd length: last byte padded with zero at the end
        if (!(len - 1 >= skip_start && len - 1 < skip_start + skip_len)) {
            uint16_t last = static_cast<uint16_t>(data[len - 1]) << 8; // high byte
            sum += last;
        }
    }
    return sum;
}

uint16_t ipv4_header_checksum(const iphdr* ip) {
    if (!ip) return 0;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(ip);
    const size_t ihl_bytes = static_cast<size_t>(ip->ihl) * 4u; // 4-byte units
    if (ihl_bytes < sizeof(iphdr)) {
        return 0; // malformed header length
    }
    const size_t cksum_off = offsetof(iphdr, check);
    uint64_t sum = sum_bytes16(bytes, ihl_bytes, cksum_off, 2);
    return fold_to_u16(sum);
}

void ipv4_update_checksum(iphdr* ip) {
    if (!ip) return;
    ip->check = 0;
    ip->check = ipv4_header_checksum(ip);
}

uint16_t tcp_checksum_ipv4(const iphdr* ip,
                           const tcphdr* tcp,
                           const uint8_t* payload,
                           size_t payload_len) {
    if (!ip || !tcp) return 0;
    const size_t ip_len = static_cast<size_t>(ip->ihl) * 4u;
    if (ip_len < sizeof(iphdr)) return 0;

    const size_t tcp_hlen = static_cast<size_t>(tcp->doff) * 4u; // data offset
    if (tcp_hlen < sizeof(tcphdr)) return 0;

    uint64_t sum = 0;

    // Pseudo header: src addr + dst addr
    const uint8_t* saddr = reinterpret_cast<const uint8_t*>(&ip->saddr);
    const uint8_t* daddr = reinterpret_cast<const uint8_t*>(&ip->daddr);
    sum += sum_bytes16(saddr, 4);
    sum += sum_bytes16(daddr, 4);

    // Protocol and TCP length via pseudo header buffer to keep byte order strict
    const uint16_t tcp_len = static_cast<uint16_t>(tcp_hlen + payload_len);
    const uint16_t tcp_len_n = htons(tcp_len);
    uint8_t phdr[12];
    phdr[0] = saddr[0]; phdr[1] = saddr[1]; phdr[2] = saddr[2]; phdr[3] = saddr[3];
    phdr[4] = daddr[0]; phdr[5] = daddr[1]; phdr[6] = daddr[2]; phdr[7] = daddr[3];
    phdr[8] = 0;                      // zero
    phdr[9] = static_cast<uint8_t>(IPPROTO_TCP);
    phdr[10] = static_cast<uint8_t>(tcp_len_n >> 8);
    phdr[11] = static_cast<uint8_t>(tcp_len_n & 0xFF);
    sum += sum_bytes16(phdr + 8, 4);  // only add last 4 bytes here; add src/dst above

    // TCP header (with checksum field zeroed)
    const uint8_t* tcp_bytes = reinterpret_cast<const uint8_t*>(tcp);
    const size_t cksum_off = offsetof(tcphdr, check);
    sum += sum_bytes16(tcp_bytes, tcp_hlen, cksum_off, 2);

    // TCP payload
    if (payload && payload_len) {
        sum += sum_bytes16(payload, payload_len);
    }

    return fold_to_u16(sum);
}

void tcp_update_checksum_ipv4(const iphdr* ip,
                              tcphdr* tcp,
                              const uint8_t* payload,
                              size_t payload_len) {
    if (!ip || !tcp) return;
    tcp->check = 0;
    tcp->check = tcp_checksum_ipv4(ip, tcp, payload, payload_len);
}

} // namespace pg
