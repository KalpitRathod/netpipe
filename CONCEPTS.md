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

## Build Your Own Experiment

You now know that:
1. Packets are raw bytes.
2. They are structured in layers (Eth → IP → TCP → App).
3. `netpipe` turns these raw bytes into simple C structs or Python JSON objects.

Go into `examples/python/00_quickstart.py` and modify the code. Try to write a script that only prints packets where `pkt["caplen"] > 1000` (finding large data transfers), or write a script that counts how many times your computer uses `udp` versus `tcp`. 

You are now interacting directly with the pulse of the Internet.
