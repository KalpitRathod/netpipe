# Networking from First Principles

If you are new to low-level networking, it can feel like magic. Browsers load pages, apps send messages, and video streams continuously—all over invisible airwaves or copper wires. 

But underneath, **everything is just packets**. 

This guide teaches you how networking actually works from first principles, using `netpipe` to prove it with real code and data.

---

## Concept 1: The Packet (The Basic Unit of the Internet)

When you download a 10MB image, the server doesn't send a continuous 10MB "stream" of data. The Internet is not a hose; it is a postal service. 

Your 10MB image is chopped up into thousands of tiny envelopes, usually 1500 bytes each. These are called **Packets**. They are sent independently, and your computer reassembles them.

**Test it with netpipe:**
```bash
# Capture 3 packets and print them as raw hex bytes
sudo ./build/bin/netpipe -i wlo1 -c 3
```
You will see walls of raw hexadecimal numbers. This is what the internet *actually* looks like. Every image, video, and text message boils down to these raw bytes flying across the wire.

---

## Concept 2: Encapsulation (The Russian Nesting Doll)

How does a packet know where to go? It uses **Encapsulation**. 
Think of it like putting a letter inside an envelope, putting that envelope inside a FedEx box, and putting that box inside a shipping container.

Every packet has **Layers**:
1. **Layer 2 (Link):** `Ethernet` or `Wi-Fi`. Gets the packet to the next physical router.
2. **Layer 3 (Network):** `IPv4` or `IPv6`. Gets the packet across the world to the destination computer.
3. **Layer 4 (Transport):** `TCP` or `UDP`. Gets the packet to the correct *application* (e.g., your browser vs. your game).
4. **Layer 7 (Application):** `HTTP`, `DNS`, `TLS`. The actual data you care about.

### How `netpipe` sees this in C:
When `netpipe` captures a raw packet, the demuxer (`np_demux.c`) peels these layers back one by one. In C, you access them like this:

```c
// Inside a netpipe C processor:
if (pkt->eth)       printf("MAC Address: %02x:%02x...\n", pkt->eth->data[0]);
if (pkt->net)       printf("IP Version: %s\n", pkt->net->proto == NP_PROTO_IP4 ? "v4" : "v6");
if (pkt->transport) printf("Port: %d\n", ...);
if (pkt->app)       printf("App data size: %zu bytes\n", pkt->app->len);
```

### How `netpipe` sees this in Python:
```bash
sudo ./build/bin/netpipe -i wlo1 -fmt json -c 1
```
Output:
```json
{
  "layers": [
    {"proto": "ethernet", "len": 14},
    {"proto": "ipv4", "len": 20},
    {"proto": "tcp", "len": 32},
    {"proto": "tls", "len": 85}
  ]
}
```
You can physically see the nesting doll! 14 bytes of Ethernet wrap 20 bytes of IP, which wrap 32 bytes of TCP, which hold 85 bytes of TLS (encrypted web data).

---

## Concept 3: Addressing (MAC vs IP vs Port)

Why do we need so many different types of addresses?

* **MAC Address (Layer 2):** Your computer's physical hardware address. It only matters on your local Wi-Fi or LAN. Routers use this to hop from one physical device to the next.
* **IP Address (Layer 3):** E.g., `142.250.190.46` (Google). This is global. It tells the internet exactly which computer in the world to deliver the packet to.
* **Port Number (Layer 4):** E.g., `Port 443`. Your computer only has one IP address, but you might have Spotify, Chrome, and Discord all running at once. Ports identify which specific app gets the data.

**Test it:** 
Run the passive firewall script:
```bash
sudo python3 examples/python/07_packet_firewall.py wlo1
```
It extracts the IP (`src_ip`, `dst_ip`) and the Ports (`src_port`, `dst_port`) from the Layer 3 and Layer 4 headers to decide if a connection is allowed.

---

## Concept 4: TCP vs UDP (Reliability vs Speed)

At Layer 4, there are two main protocols:

1. **UDP (User Datagram Protocol):** "Fire and forget." Used for DNS, Video Calls, and Multiplayer Games. If a packet gets lost, UDP doesn't care. It prioritizes speed.
2. **TCP (Transmission Control Protocol):** "Guaranteed delivery." Used for Webpages (HTTP) and File Downloads. TCP forces the receiver to send an "ACK" (acknowledgment) for every packet. If an ACK isn't received, TCP resends the packet.

**Test it in Python:**
```python
import subprocess, json
cmd = ["./build/bin/netpipe", "-i", "wlo1", "-fmt", "json"]
with subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True) as p:
    for line in p.stdout:
        pkt = json.loads(line)
        protos = [l["proto"] for l in pkt["layers"]]
        if "udp" in protos:
            print("Fast/Unreliable packet")
        elif "tcp" in protos:
            print("Reliable/Acknowledged packet")
```

---

## Concept 5: Flows (Connecting the Dots)

Because packets arrive individually, how do we know which packets belong to the same download? 

Network engineers use a **Flow ID** (or 5-tuple hash). A flow is uniquely identified by 5 things:
1. Source IP
2. Destination IP
3. Source Port
4. Destination Port
5. Protocol (TCP or UDP)

If two packets share these 5 things, they are part of the exact same conversation.

`netpipe` automatically calculates this for you.
**Test it:** Look at the terminal dashboard script (`02_traffic_dashboard.py`). It groups packets by `flow_id` to show you which connections are downloading the most data!

---

## Concept 6: DNS (The Internet's Phonebook)

Computers only understand IP addresses (`142.250.190.46`), but humans like names (`google.com`). 
**DNS (Domain Name System)** is the protocol that translates names to IPs. It happens *before* you connect to a website, and it almost always happens in plaintext over UDP Port 53.

**Test it:**
```bash
sudo python3 examples/python/01_dns_monitor.py wlo1
```
Open a browser and go to `netflix.com`. You will instantly see your computer ask the network: "Who is netflix.com?", and the network replying with the IP address.

---

## Concept 7: TLS / HTTPS (Encryption)

Once your computer has the IP address, it connects. In the past, this was done via HTTP (Port 80) in plaintext. Today, it is done via HTTPS/TLS (Port 443).

When TLS encrypts data, it encrypts the **Application Layer (Layer 7)**. It CANNOT encrypt the IP or TCP layers, because routers wouldn't know where to deliver the packet!

Interestingly, during the very first step of the TLS handshake (the `ClientHello`), your browser tells the server which website it wants to talk to (the **SNI**, or Server Name Indication). This is sent in **plaintext**.

**Test it:**
```bash
sudo python3 examples/python/08_browser_spy.py wlo1
```
Even though the website is fully encrypted and secure, `netpipe` is able to extract the plaintext SNI from the TLS ClientHello packet. This proves that while your *passwords and data* are hidden, the *domain you are visiting* is completely visible to your ISP or anyone sniffing your Wi-Fi.

---

## Concept 8: TCP Stream Reassembly (Stitching the Pieces)

Up to this point, we've treated every packet as an isolated, standalone event. However, network applications don't think in terms of "packets"—they think in terms of "streams". When you download a 10MB image, your browser doesn't receive one massive 10MB packet. The web server breaks the image down into roughly 7,000 tiny packets (usually 1500 bytes each) and sends them individually over TCP.

If a script just inspects single packets, it can only see fragments of the image. The true power of Deep Packet Inspection (DPI) lies in **TCP Stream Reassembly**: buffering all those individual packets in memory, ordering them by their `TCP Sequence Number`, and stitching them back into a contiguous byte stream.

**The Code Experiment:**
`netpipe` includes a C-level stream processor that maintains an internal buffer for active TCP flows. When enabled, it outputs a `stream_hex` field alongside `raw_hex`. Let's test it out using our new script.

Open two terminals. In Terminal 1, run the stream follower script:
```bash
sudo python3 examples/python/09_stream_follower.py wlo1
```

In Terminal 2, use `curl` to make a plaintext HTTP request:
```bash
curl http://neverssl.com
```

**What you will see:**
The Python script is completely ignoring individual packet boundaries. Instead, it reads the cumulative `stream_hex` buffer maintained by `netpipe`. You will see the literal ASCII text of the HTTP request and response printed directly to your terminal exactly as the applications see it!

```text
[Flow 302194883] GET / HTTP/1.1
[Flow 302194883] Host: neverssl.com
[Flow 302194883] User-Agent: curl/7.88.1
[Flow 302194883] Accept: */*
[Flow 302194883] 
[Flow 302194883] HTTP/1.1 200 OK
[Flow 302194883] Content-Type: text/html
...
```

By reconstructing the stream, `netpipe` transcends from a low-level packet capture tool into an application-layer analysis engine!

---

## Concept 9: TLS Decryption & The Illusion of Privacy

Earlier, we learned that HTTPS traffic is entirely encrypted and looks like garbled text on the wire (Concept 6). Because modern TLS uses *Forward Secrecy*, passively recording the packets is not enough to decrypt them later—the encryption keys are ephemeral and discarded immediately.

However, HTTPS only protects your data **in transit**. If an attacker compromises one of the endpoints (like your laptop or the server), they can extract the symmetric encryption keys (the "Pre-Master Secrets") directly from the application's memory before the encryption happens. 

If you have both the captured packets (`.pcap`) and the session keys (`tls_keys.log`), you can completely decrypt the HTTPS tunnel.

**The Code Experiment:**
We have built two scripts to demonstrate this:
1. The Capture Tool forces `curl` to dump its encryption keys while `netpipe` silently records the structured PCAP traffic:
```bash
sudo python3 examples/python/10_tls_capture.py wlo1
```

2. The Decryptor Tool takes the captured traffic and the stolen keys, and completely strips away the TLS encryption:
```bash
python3 examples/python/11_tls_decryptor.py encrypted_traffic.pcap tls_keys.log
```

**Can this decrypt passwords?**
**YES.** Once the TLS tunnel is decrypted using the session keys, *everything* inside it becomes 100% visible in plaintext. If you logged into a website during the capture, your exact password, your session cookies, credit card numbers, and every API request you made are exposed. 

This proves a fundamental cybersecurity principle: **Encryption protects the pipe, but endpoint security protects the data.** If a virus on your computer can log your `SSLKEYLOGFILE`, your HTTPS traffic is fully compromised.

**The "Gotcha" of Decryption:**
To decrypt a TLS session, you **must** capture the very first packets of the connection (the `ClientHello` and `ServerHello` handshake). If your packet sniffer starts recording even a millisecond *after* the connection is established, the decryptor will fail because it cannot match the captured keys to the specific stream. This is why our capture script intentionally pauses for 3 seconds to ensure `netpipe` is fully listening before it launches `curl`.

---

## Concept 10: Interface Encapsulation & Linux Cooked Capture (SLL)

You might assume that all network interfaces output standard **Ethernet** packets (which start with a 14-byte MAC address header). However, when you use packet sniffing libraries (`libpcap`), the Operating System abstracts the physical hardware. 

Different interfaces return data encapsulated differently (this is called the **Data Link Type** or **DLT**):
* A standard wired connection (`eth0`) usually returns `DLT_EN10MB` (Ethernet).
* The "any" interface or certain Wi-Fi adapters (`wlo1`) often return `DLT_LINUX_SLL` (Linux Cooked Capture).
* A VPN interface (`tun0`) might return `DLT_RAW` (Raw IP, with no hardware addresses at all).

**The Bug We Encountered:**
During our extreme HTTPS capture test, the `netpipe` engine did not know how to handle the 16-byte `LINUX_SLL` header. It accidentally classified the packets as "Raw IP", which caused Wireshark to misinterpret the MAC addresses as invalid IP addresses. This broke the entire decryption pipeline because Wireshark could not find the TCP layer! 

**The Lesson:**
Network engines cannot blindly assume a packet starts with an IP header. They must read the interface's Link-Layer Type and apply the correct byte-offsets. We fixed `netpipe` by teaching its core Demuxer (`np_demux.c`) to parse SLL headers before extracting the IP packets.

## Concept 11: Application-Layer Decoding & Zero-Copy Extraction (HTTP & DNS)

In early concepts, we treated packet payloads as opaque "raw bytes" or strings. However, real-world protocols like HTTP and DNS are structurally complex: HTTP uses unpredictable variable-length strings separated by `\r\n`, and DNS uses advanced pointer-based compression to encode domain names efficiently.

Most network tools fail to scale because they allocate and copy memory for every HTTP header or DNS record they parse. 

**The `netpipe` Zero-Copy Architecture:**
To achieve near-instantaneous Deep Packet Inspection (DPI), `netpipe` relies on a **Packet Scratch Buffer** and **Zero-Copy Strings (`np_str_t`)**.
When a packet arrives:
1. `netpipe` reserves an internal 8KB buffer exclusively for that packet.
2. The Demuxer builds C structs (`np_http_msg_t`, `np_dns_msg_t`) directly inside this scratch area without calling `malloc()`.
3. Strings like `google.com` or `User-Agent` are not copied. Instead, `np_str_t` simply stores a pointer directly into the live ethernet frame's memory along with a length.

**The Code Experiment:**
Run these scripts to see zero-copy DPI natively dump fully structured JSON:
```bash
# Capture raw HTTP traffic and parse methods/headers instantly
sudo python3 examples/python/12_http_parser_demo.py wlo1

# See how pointer-compressed DNS queries are unrolled and decoded
sudo python3 examples/python/13_dns_spy.py wlo1
```

---

## Concept 12: TUN/TAP Injection (Active MitM and Traffic Forging)

Passive capture is only half of network engineering. **Active injection** allows us to forge packets or replay captures back into a live network environment. 

Linux provides virtual network devices:
* **TUN** (Layer 3): Reads and writes raw IP packets.
* **TAP** (Layer 2): Reads and writes raw Ethernet frames.

By writing raw binary packet arrays to the `/dev/net/tun` character device descriptor with the `IFF_TAP` flag enabled, the kernel's network stack processes those bytes exactly as if they arrived from a physical network interface card (NIC). 

`netpipe` natively includes a `tuntap` sink. When you set the output to `tun://tun0`, it asks the kernel to create a transient virtual `tun0` interface and blindly injects every packet from the pipeline directly into the system routing tables.

**The Code Experiment:**
```bash
sudo python3 examples/python/14_tun_replay.py
```
You will watch `netpipe` natively capturing injected packets directly off the kernel `tun0` interface, proving the kernel believes the traffic is real. The underlying C call is simply:
```c
write(tap_fd, pkt->raw, pkt->caplen);  // kernel receives this as a physical frame
```

**Real-world use-cases:**
- VPN tunneling: OpenVPN and WireGuard do exactly this to route encrypted packets into the kernel
- Network simulation: replay production traffic in a lab at any speed
- Active MitM tools: intercept, modify, then re-inject traffic

---

## Concept 13: Traffic Shaping with Token Bucket Rate Limiting

Network processors can modify and delay data. If you replay a 1GB offline PCAP file into a TAP interface, `netpipe` will inject the entire payload in milliseconds. The kernel queue will overflow, and massive packet loss will occur.

To simulate realistic network conditions or throttle attacks, `netpipe` implements a **Token Bucket Rate Limiter**. 
Instead of a simple constant delay, this mathematical algorithm accumulates "tokens" based on CPU clock elapsed time. If the bucket has enough tokens for the size of the packet (`wirelen`), it subtracts them and transmits instantly (allowing initial bursting). If it is empty, it accurately pauses the thread in microseconds until enough clock ticks have passed.

**The Code Experiment:**
```bash
sudo python3 examples/python/14_tun_replay.py
```
The script replays `encrypted_traffic.pcap` at exactly 500 bytes per second. You will see `tshark` capturing packets with timestamps spread seconds apart, not milliseconds—proof that the token bucket is mathematically controlling the injection cadence.

You can also replay at wire speed with no limit:
```bash
sudo ./build/bin/netpipe -r encrypted_traffic.pcap -o tun://tun0
```

---

## Concept 14: Socket Sinks & Remote Agent Forwarding

The final piece of advanced pipeline architecture is remote forwarding. What if you want to capture packets on a headless cloud server, but analyse them on your local machine using Wireshark's GUI?

A **Socket Sink** connects the output of the pipeline directly to a TCP socket. Critically, `netpipe` doesn't just stream raw bytes—it writes a **valid PCAP binary format**: first a 24-byte PCAP global header (with magic number, version, and link type), then a 16-byte packet record header before each raw frame. This means the receiver can pipe the stream directly into `tshark -r -` or save it as a `.pcap` file that Wireshark can open.

**The Code Experiment:**
```bash
sudo python3 examples/python/15_socket_forward.py wlo1
```
The script spins up a Python "remote agent" server, captures 20 live packets, and forwards them as a PCAP stream. The agent validates the magic bytes to confirm you received a legitimate PCAP file.

**Real-world — stream live into tshark on a remote machine:**
```bash
# On the remote machine (receiving side):
nc -l -p 9999 | tshark -r -

# On the capture machine:
sudo ./build/bin/netpipe -i wlo1 -c 50 -o socket://REMOTE_IP:9999
```

# Concept 15: Concurrent Multi-Interface Capture & Queue Fan-In

To capture traffic across multiple network interfaces in parallel (e.g. `eth0` and `wlan0`), a single-threaded round-robin capture loop faces major bottlenecks. If one interface has a high read timeout or gets blocked waiting for packets, the entire capture pipeline stalls.

To solve this, `netpipe` implements a **Multi-threaded Producer-Consumer Architecture**:
1. **Source Worker Threads**: The pipeline spawns a dedicated worker thread (`pthread_create`) for every configured packet source.
2. **Thread-Safe Packet Queue**: A central bounded queue managed by a mutex and condition variables (`pthread_mutex_t`, `pthread_cond_t`) accumulates incoming packets.
3. **Pipeline Consumer**: The main thread runs the processing loop, popping packets from the queue as they arrive and executing filters, processors, and sinks in an interleaved, order-preserved fashion.

**Test it in Python:**
```bash
# Capture from two sources concurrently and verify they interleave
python3 examples/python/20_multi_interface_parallel.py
```

---

# Concept 16: Zero-Copy Ring-Buffer Capture (AF_PACKET + PACKET_MMAP)

Standard packet capture (via standard system read/recv calls) introduces substantial kernel-to-user-space context switching overhead, copying every packet's data from kernel memory space to user-allocated buffers.

Linux provides a high-performance alternative: **`AF_PACKET` + `PACKET_MMAP` (zero-copy ring buffers)**.
1. **Raw Sockets**: By opening a raw socket with `AF_PACKET`, we gain direct access to raw layer 2 Ethernet frames.
2. **Circular RX Ring**: By setting the `PACKET_RX_RING` socket option (`TPACKET_V2`), we configure a shared circular memory ring buffer between the kernel and the user application.
3. **Zero-Copy Memory Mapping**: Using `mmap()`, the user process maps this circular buffer directly into its address space. When a packet arrives, the kernel writes it directly to the shared memory. The user space reads the data by checking status flags on the frames (e.g. `TP_STATUS_USER`), eliminating standard copy syscall overhead entirely.

**Test it in Python:**
```bash
# Validate zero-copy CLI registration and run live ring-buffer capture (requires root)
sudo python3 examples/python/21_zero_copy_ring.py lo
```

---

## Build Your Own Experiment

You now know that:
1. Packets are raw bytes.
2. They are structured in layers (Eth/SLL → IP → TCP → App).
3. `netpipe` turns these raw bytes into simple C structs or Python JSON objects.
4. Streams are just ordered sequences of these packets.
5. TLS encryption can be entirely bypassed if the endpoint's memory is compromised.
6. The Link Layer determines exactly how to slice the first bytes of a packet.
7. Application layers (like HTTP and DNS) can be natively parsed into zero-copy structures for high-performance extraction.
8. Multiple packet sources can capture concurrently in parallel threads, and fan-in packets to a single thread.
9. Linux `PACKET_MMAP` ring-buffers enable zero-copy capture directly from raw sockets.

Go into `examples/python/00_quickstart.py` and modify the code. Try to write a script that only prints packets where `pkt["caplen"] > 1000` (finding large data transfers), or write a script that counts how many times your computer uses `udp` versus `tcp`. 

You are now interacting directly with the pulse of the Internet.

