# PacketGhost: A High-Performance Network Traffic Mutation Framework

**PacketGhost** is a lightweight, userspace network traffic mutation engine written in pure C. It leverages Linux Netfilter and Raw Sockets to intercept, analyze, and manipulate TCP/IP packets in real-time.

The primary goal of this project is to research **Deep Packet Inspection (DPI) evasion strategies** by exploiting the implementation asymmetries between middleboxes (firewalls, IDS) and end-host TCP stacks. Currently, it implements advanced **TCP Fragmentation** and **Payload Splitting** strategies capable of bypassing SNI-based blocking (HTTPS) and Keyword filtering (HTTP).

------

## 📖 Motivation

In modern network environments, middleboxes often rely on **signature-based detection** to block specific traffic. However, due to performance constraints, many DPI devices operate in a "stateless" or "weakly stateful" mode, analyzing packets in isolation or with limited reassembly buffers.

PacketGhost validates the hypothesis that **semantic-preserving mutations**—such as splitting a TLS ClientHello into multiple TCP segments—can effectively blind these middleboxes while maintaining the integrity of the end-to-end connection.

------

## 🏗️ Architecture

PacketGhost utilizes a **Hybrid User-Kernel architecture** to achieve fine-grained control over packet transmission.

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

------

## 📂 Project Structure

The project is modularized to separate core logic, network interaction, and protocol parsing.

```sh
.
├── common.h            # Global definitions and configurations
├── core/               # Core Logic for Traffic Manipulation
│   ├── fragmenter.c    # Implementation of TCP fragmentation strategies (HTTP/TLS)
│   ├── mutator.c       # Payload modification and replacement logic
│   └── ...
├── network/            # Low-level Network I/O
│   ├── injector.c      # Raw Socket wrapper with SO_MARK support
│   └── ...
├── protocol/           # Protocol Parsing & Construction
│   ├── packet.c        # Helpers for parsing IP/TCP headers from raw buffers
│   └── ...
├── state/              # Stateful Tracking (Experimental)
│   ├── session.c       # TCP flow tracking and state machine management
│   └── ...
├── utils/              # Utilities
│   ├── csum.h          # IP/TCP Checksum recalculation algorithms
│   └── uthash.h        # Hash table implementation for session management
└── main.c              # Entry point and Netfilter callback loop
```

------

## ⚡ Key Technical Features

### 1. TLS ClientHello Fragmentation

To bypass HTTPS SNI blocking, PacketGhost identifies the TLS Record Layer. It fragments the packet at the first byte of the handshake header:

- **Packet A**: Contains only the first byte (`0x16`).
- **Packet B**: Contains the rest of the payload (`0x03 0x01 ... SNI ...`).
- **Result**: The DPI device fails to recognize the TLS handshake signature in either packet and allows the traffic to pass.

### 2. The "Ouroboros" Loop Avoidance

A common challenge in raw socket injection is the "infinite loop," where injected packets are re-intercepted by Netfilter. PacketGhost solves this by marking injected packets at the socket level:

```C
// src/network/injector.c
int mark = 0x100;
setsockopt(sock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
```

Coupled with the `iptables` rule `! --mark 0x100`, this ensures a clean egress path.

### 3. Zero-Copy Analysis (Partially Implemented)

The project minimizes memory overhead by parsing protocol headers directly from the Netfilter buffer pointers where possible, only allocating memory during the fragmentation/injection phase.

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

2. **Start the Engine**:

   ```bash
   sudo ./packet_ghost
   ```

3. **Verify**:

   ```bash
   curl -v https://www.google.com
   # Logs will show: [Fragmenter] TLS Client Hello detected. Splitting...
   ```

------

## 🔮 Future Work

- **eBPF / XDP Integration**: Moving the packet classification logic into the kernel using eBPF to reduce context switching overhead and achieve 10Gbps+ performance.
- **Geneva Strategy Integration**: Implementing genetic algorithms to automatically discover new evasion strategies (e.g., TCP window manipulation, out-of-order injection) as proposed in the [Geneva (CCS '19)](https://geneva.cs.umd.edu/) paper.
- **Configuration Parsing**: Supporting dynamic rule loading via JSON/YAML.

------