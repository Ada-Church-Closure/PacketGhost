# PacketGhost: A High-Performance Network Traffic Mutation Framework

**PacketGhost** is a lightweight, userspace network traffic mutation engine written in **pure C**. It leverages **Linux Netfilter** and **Raw Sockets** to **intercept**, **analyze**, and **manipulate** TCP/IP packets in real-time.

The primary goal of this project is to research **Deep Packet Inspection (DPI) evasion strategies** by exploiting the implementation asymmetries between middleboxes (firewalls, IDS) and end-host TCP stacks. Currently, it implements advanced **TCP Fragmentation** and **Payload Splitting** strategies capable of bypassing SNI-based blocking (HTTPS) and Keyword filtering (HTTP).

**Geneva Strategy Integration:** While [Geneva (CCS '19)](https://geneva.cs.umd.edu/) utilizes a genetic algorithm to *discover* evasion strategies, PacketGhost focuses on the **deterministic, high-performance execution** of these strategies. It ports Geneva's core primitives (Tamper, Duplicate, Fragment, Drop) from Python to **pure C**, enabling deployment on resource-constrained devices (e.g., OpenWrt routers) with minimal overhead.

------

## 📖 Motivation

In modern network environments, middleboxes often rely on **signature-based detection** to block specific traffic. However, due to performance constraints, many DPI devices operate in a "stateless" or "weakly stateful" mode, analyzing packets in isolation or with limited reassembly buffers.

PacketGhost validates the hypothesis that **semantic-preserving mutations**—such as splitting a TLS ClientHello into multiple TCP segments—can effectively blind these middleboxes while maintaining the integrity of the end-to-end connection.

------

## 🏗️ Architecture

PacketGhost utilizes a **Hybrid User-Kernel architecture** to achieve fine-grained control over packet transmission.

```pleintext
+---------------------------------------------------------------+
|                  USER SPACE (PacketGhost)                     |
|                                                               |
|   +-------------+      +------------------+      +---------+  |
|   | NFQ Listener| ---> | Strategy Engine  | ---> | Injector|  |
|   +------+------+      | (Split/Tamper)   |      +----+----+  |
|          ^             +------------------+           |       |
|          |                  Verdict: DROP             |       |
|          |                 (Original Pkt)             |       |
+----------|------------------------|-------------------|-------+
|          | libnetfilter_queue     |                   | raw   |
|          |                        v                   | sock  |
|   +------+------+          +------+------+       +----+----+  |
|   | iptables    | <------- | Output Chain| <---- | SO_MARK |  |
|   | (NFQUEUE)   |          +------+------+       | (0x100) |  |
|   +-------------+                 ^              +---------+  |
|          ^                        |                   |       |
|          | (Normal Traffic)       | (Loop Avoidance)  |       |
|   +------+------+          +------+------+       +----+----+  |
|   | Application |          | Routing /   | ----> |   NIC   |  |
|   | (Browser)   |          | Network Stack|      | (WLAN0) |  |
|   +-------------+          +-------------+       +---------+  |
|                                                               |
|                  KERNEL SPACE (Linux)                         |
+---------------------------------------------------------------+
```

### Workflow

1. **Interception**: `iptables` rules redirect specific outbound TCP traffic (ports 80, 443) to `NFQUEUE`.
2. **Decision**: The PacketGhost userspace agent analyzes the packet payload.
   - **HTTP**: Detects methods (GET, POST) and fragments the header.
   - **TLS**: Detects the `ClientHello` handshake and fragments the SNI field.
3. **Injection**: Instead of modifying the packet in place (which requires complex SEQ/ACK NAT), PacketGhost:
   - Constructs multiple smaller packets (slices).
   - Injects them directly into the network interface using **Raw Sockets** (`SOCK_RAW`).
   - **Drops (`NF_DROP`)** the original packet from the kernel queue.
4. **Loop Avoidance**: Injected packets are tagged with a specific `SO_MARK` (0x100) to bypass the `iptables` interception rule, preventing infinite routing loops.

5. **Configuration**: At startup PacketGhost loads a simple `key=value` configuration (optional). Each strategy can be enabled/disabled and tuned without recompiling.

------

## 📂 Project Structure

The project is modularized to separate core logic, network interaction, and protocol parsing.

```sh
.
├── common.h                  # Global configuration macros and shared definitions
├── main.c                    # Application entry point; initializes Netfilter hooks and event loops
├── core/                     # Central logic for traffic analysis and manipulation
│   ├── apply_strategies.c    # Strategy Dispatcher: matches traffic features to specific evasion logic
│   ├── strategies.c          # Implementation of Geneva primitives (e.g., Fake RST, TTL Decoy)
│   ├── fragmenter.c          # TCP Segmentation engine (HTTP/TLS splitting & Out-of-Order injection)
│   └── mutator.c             # Payload modification logic (Legacy/Direct modification)
├── network/                  # Low-level network I/O abstraction
│   └── injector.c            # Raw Socket wrapper; handles SO_MARK to prevent routing loops
├── protocol/                 # Protocol parsing and construction
│   └── packet.c              # Lightweight parser for IP/TCP headers (Zero-copy approach)
├── state/                    # Stateful TCP tracking (Optional/Experimental)
│   └── session.c             # Manages TCP flow contexts and session tables
└── utils/                    # Helper utilities
    ├── csum.h                # Algorithms for IP/TCP checksum recalculation (Critical for tampering)
    ├── protocol_types.h      # Struct definitions for protocol headers
    └── uthash.h              # C macro for hash table implementation
```

------

## ⚡ Key Technical Features

### 1. Stateful Payload Modification (NAT)

To support **Length-Changing Modifications** (e.g., replacing the short User-Agent `"curl"` with the longer `"Mozilla/5.0"`), PacketGhost implements a custom TCP Network Address Translation (NAT) mechanism.

- **Mechanism**: It tracks the difference in length (`delta`) introduced by the modification.
- **Result**: The engine dynamically corrects the **Sequence Numbers (SEQ)** of outgoing packets and the **Acknowledgment Numbers (ACK)** of incoming packets in real-time, preventing TCP connection desynchronization.

### 2. TLS ClientHello Fragmentation

To bypass HTTPS SNI blocking, PacketGhost identifies the TLS Record Layer and fragments the packet at the very first byte of the handshake header:

- **Packet A**: Contains only the first byte (`0x16`).
- **Packet B**: Contains the rest of the payload (`0x03 0x01 ... SNI ...`).
- **Result**: The DPI device fails to recognize the TLS handshake signature in either packet and allows the traffic to pass, while the destination server reassembles it seamlessly.

### 3. Out-of-Order Packet Injection

PacketGhost implements **TCP Reordering** to exploit the lack of reassembly buffers in stateless DPI middleboxes.

- **Mechanism**: When splitting a packet, the engine injects the *second* fragment (Slice 2) into the network **before** the first fragment (Slice 1).
- **Result**:
  - **DPI**: Receives the second slice first (which lacks protocol headers), fails to identify the protocol, and allows it to pass.
  - **Server**: Buffers the out-of-order slice and waits for the first slice to arrive, successfully reconstructing the stream.

### 4. TCP Resync (Fake RST Injection)

This strategy utilizes the **"Geneva" Tamper primitive** to desynchronize the state of the middlebox from the server.

- **Mechanism**: The engine injects a fabricated TCP Reset (RST) packet with an **intentionally incorrect TCP Checksum** but a valid IP Checksum.
- **Result**:
  - **DPI**: Often ignores the checksum for performance reasons, processes the RST, and stops inspecting the connection (believing it is closed).
  - **Server**: Validates the checksum, detects the error, and discards the fake RST packet, keeping the legitimate connection alive.

### 5. TTL Decoy (Early-Expiring Duplicate)

This strategy creates a duplicate of the original packet but lowers the IP TTL so that the decoy expires on‑path before reaching the server.

- Mechanism: Duplicate the current packet (e.g., HTTP request or TLS ClientHello), set `IP.ttl` to a small value (e.g., 1–2), recompute checksums, and inject via RAW socket.
- Result:
  - DPI sees the decoy and may change or drop tracking for the flow.
  - Server never sees the decoy (expires en route), so end‑to‑end state remains intact.
  - Optional: apply the same small TTL to injected RST to make it visible to DPI but not to the server.

### 6. The "Ouroboros" Loop Avoidance

A common challenge in raw socket injection is the "infinite loop," where injected packets are re-intercepted by Netfilter. PacketGhost solves this by marking injected packets at the socket level:

```C
// src/network/injector.c
int mark = 0x100;
setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
```

Coupled with the `iptables` rule `! --mark 0x100`, this ensures a clean egress path for modified traffic.

### 7. Zero-Copy Analysis

The project minimizes memory overhead by parsing protocol headers directly from the Netfilter buffer pointers where possible. It adheres to a **Zero-Copy** philosophy for analysis, allocating new memory only during the fragmentation or injection phase.

------

## 🛠️ Build & Usage

### Prerequisites

- Linux Kernel (with Netfilter support)
- `libnetfilter-queue-dev`
- `iptables`
- `cmake` or `make`

### Installation

```bash
mkdir build && cd build
cmake ..
make
```

### Configuration & Run

PacketGhost requires `root` privileges to manipulate network interfaces.

1. Setup Firewall Rules:

   Intercept HTTP/HTTPS traffic but exclude PacketGhost's own injected packets.

   ```bash
   # Flush existing rules
   sudo iptables -F OUTPUT
   
   # Add interception rule
   sudo iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m mark ! --mark 0x100 -j NFQUEUE --queue-num 0
   ```

2. Optional: Create/Edit Configuration

   A minimal example (see `sample.config` in the repo):

   ```ini
   # TTL decoy
   ttl_decoy.enabled=1
   ttl_decoy.ttl=2            # choose 1 for first-hop expiry, or 2–3 for slightly further
   ttl_decoy.apply_once_per_flow=1

   # Fake RST
   rst.enabled=1
   rst.bad_checksum=1
   rst.with_ack=0
   rst.small_ttl=0            # set to 1 to also apply small TTL to fake RST

   # Fragmentation
   fragment.enabled=0         # set to 1 to enable HTTP/TLS splitting
   fragment.out_of_order=1
   fragment.http_split_pos=2  # e.g., split GET header after first 2 bytes
   fragment.tls_split_pos=1   # e.g., split TLS ClientHello after first byte

   # User-Agent replacement
   ua_replace.enabled=1
   ua_replace.target=curl/
   ua_replace.replace=Mozilla/

   # TCP options
   sack.disable=1
   ```

3. **Start the Engine**:

  ```bash
  # without config -> defaults
  sudo ./packet_ghost

  # with config file
  sudo ./packet_ghost ./sample.config
  ```

4. **Verify**:

   ```bash
   curl -v https://www.google.com
   # Logs will show: [Fragmenter] TLS Client Hello detected. Splitting...
   sudo tcpdump -ni wlan0 'tcp and ip[8] == 2' -vvv -s 0
   ```
- Optionally, confirm the decoy expires in flight by looking for ICMP Time Exceeded:

```bash
sudo tcpdump -ni wlan0 'icmp and icmp[0] == 11'
```

- If you cannot see the decoy, set `ttl_decoy.ttl=1` or verify there is no iptables TTL-rewrite (check `iptables -t mangle -S`).

------

## 🔮 Future Work

- **Strategy Registry**: Pluggable per‑flow strategies with ordering and predicates, to ease experimentation.
- **Adaptive TTL**: Infer hop count from SYN‑ACK TTL and choose a decoy TTL that expires one hop before the server.
- **eBPF / XDP Integration:** Currently, PacketGhost uses `NFQUEUE` (userspace). Future plans involve offloading the packet classification (filtering) logic to **eBPF/XDP** to avoid context switches for non-target traffic, reserving userspace processing only for complex mutations.
- **Richer Config**: Switch from key=value to JSON/YAML when needed; current parser keeps footprint minimal.

------
