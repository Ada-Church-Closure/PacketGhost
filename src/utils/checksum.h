// Lightweight IPv4 and TCP checksum helpers.
// These are used when we need to modify a packet and recompute checksums
// before returning it to the kernel via NFQUEUE.
#pragma once

#include <cstddef>
#include <cstdint>

// Forward declarations to avoid pulling platform headers into the interface.
struct iphdr;
struct tcphdr;

namespace pg {

// Compute the IPv4 header checksum for the header pointed to by `ip`.
// The checksum is calculated as if the checksum field were zero.
// Returns the 16-bit internet checksum in network order.
uint16_t ipv4_header_checksum(const iphdr* ip);

// Convenience: recompute and write the IPv4 header checksum into ip->check.
void ipv4_update_checksum(iphdr* ip);

// Compute the TCP checksum for an IPv4 packet using the pseudo-header.
// - `ip` is the enclosing IPv4 header
// - `tcp` is the start of the TCP header
// - `payload` points to TCP payload bytes (may be nullptr if length is 0)
// - `payload_len` is the length of the TCP payload in bytes
// The TCP header length is taken from tcp->doff (data offset).
// Returns the 16-bit internet checksum in network order.
uint16_t tcp_checksum_ipv4(const iphdr* ip,
                           const tcphdr* tcp,
                           const uint8_t* payload,
                           size_t payload_len);

// Convenience: recompute and write the TCP checksum into tcp->check.
void tcp_update_checksum_ipv4(const iphdr* ip,
                              tcphdr* tcp,
                              const uint8_t* payload,
                              size_t payload_len);

} // namespace pg

