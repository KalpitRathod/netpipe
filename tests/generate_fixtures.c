#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* PCAP headers */
struct pcap_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets */
    uint32_t network;        /* data link type */
};

struct pcaprec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
};

static void write_pcap(const char *filename, const uint8_t *pkt_data, size_t pkt_len)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        perror("fopen");
        exit(1);
    }

    struct pcap_hdr ghdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1 /* DLT_EN10MB (Ethernet) */
    };
    fwrite(&ghdr, sizeof(ghdr), 1, fp);

    struct pcaprec_hdr phdr = {
        .ts_sec = 1718445600, /* Mon Jun 15 10:00:00 2026 UTC */
        .ts_usec = 123456,
        .incl_len = (uint32_t)pkt_len,
        .orig_len = (uint32_t)pkt_len
    };
    fwrite(&phdr, sizeof(phdr), 1, fp);
    fwrite(pkt_data, 1, pkt_len, fp);
    fclose(fp);
}

static void merge_fixtures(const char *outfile, const char **infiles, int num_infiles)
{
    FILE *out = fopen(outfile, "wb");
    if (!out) {
        perror("fopen out");
        exit(1);
    }

    struct pcap_hdr ghdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1 /* DLT_EN10MB */
    };
    fwrite(&ghdr, sizeof(ghdr), 1, out);

    for (int i = 0; i < num_infiles; i++) {
        FILE *in = fopen(infiles[i], "rb");
        if (!in) {
            perror("fopen in");
            exit(1);
        }

        fseek(in, sizeof(struct pcap_hdr), SEEK_SET);

        uint8_t buf[65536];
        struct pcaprec_hdr phdr;
        while (fread(&phdr, sizeof(phdr), 1, in) == 1) {
            fwrite(&phdr, sizeof(phdr), 1, out);
            size_t bytes_read = fread(buf, 1, phdr.incl_len, in);
            fwrite(buf, 1, bytes_read, out);
        }
        fclose(in);
    }
    fclose(out);
}

int main(void)
{
    uint8_t pkt[1500];
    size_t len;

    /* 1. ARP Request Fixture */
    memset(pkt, 0, sizeof(pkt));
    /* Eth header */
    memset(pkt, 0xff, 6); /* dst: broadcast */
    pkt[6] = 0x00; pkt[7] = 0x11; pkt[8] = 0x22; pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55; /* src */
    pkt[12] = 0x08; pkt[13] = 0x06; /* ethertype: ARP */
    /* ARP Body */
    pkt[14] = 0x00; pkt[15] = 0x01; /* HTYPE: Ethernet */
    pkt[16] = 0x08; pkt[17] = 0x00; /* PTYPE: IPv4 */
    pkt[18] = 6;    pkt[19] = 4;    /* HLEN, PLEN */
    pkt[20] = 0x00; pkt[21] = 0x01; /* OPER: Request */
    /* Sender MAC: 00:11:22:33:44:55 */
    pkt[22] = 0x00; pkt[23] = 0x11; pkt[24] = 0x22; pkt[25] = 0x33; pkt[26] = 0x44; pkt[27] = 0x55;
    /* Sender IP: 192.168.1.1 */
    pkt[28] = 192;  pkt[29] = 168;  pkt[30] = 1;    pkt[31] = 1;
    /* Target MAC: 00:00:00:00:00:00 */
    memset(pkt + 32, 0, 6);
    /* Target IP: 192.168.1.2 */
    pkt[38] = 192;  pkt[39] = 168;  pkt[40] = 1;    pkt[41] = 2;
    len = 42;
    write_pcap("tests/fixtures/arp.pcap", pkt, len);

    /* 2. IPv4 + TCP + HTTP Fixture */
    memset(pkt, 0, sizeof(pkt));
    /* Eth header */
    pkt[0] = 0x00; pkt[1] = 0xaa; pkt[2] = 0xbb; pkt[3] = 0xcc; pkt[4] = 0xdd; pkt[5] = 0xee; /* dst */
    pkt[6] = 0x00; pkt[7] = 0x11; pkt[8] = 0x22; pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55; /* src */
    pkt[12] = 0x08; pkt[13] = 0x00; /* ethertype: IPv4 */
    
    /* IPv4 header */
    pkt[14] = 0x45; /* Version=4, IHL=5 */
    pkt[15] = 0x00; /* DSCP/ECN */
    /* Total length (placeholder) */
    pkt[18] = 0x12; pkt[19] = 0x34; /* Identification */
    pkt[20] = 0x40; pkt[21] = 0x00; /* Flags: Don't Fragment */
    pkt[22] = 64;   /* TTL */
    pkt[23] = 6;    /* Protocol: TCP */
    /* Checksum placeholder */
    /* Src IP: 192.168.1.1 */
    pkt[26] = 192;  pkt[27] = 168;  pkt[28] = 1;    pkt[29] = 1;
    /* Dst IP: 192.168.1.2 */
    pkt[30] = 192;  pkt[31] = 168;  pkt[32] = 1;    pkt[33] = 2;

    /* TCP header */
    pkt[34] = 0x30; pkt[35] = 0x39; /* Src Port: 12345 */
    pkt[36] = 0x00; pkt[37] = 0x50; /* Dst Port: 80 */
    /* Seq number = 1000 */
    pkt[38] = 0x00; pkt[39] = 0x00; pkt[40] = 0x03; pkt[41] = 0xe8;
    /* Ack number = 2000 */
    pkt[42] = 0x00; pkt[43] = 0x00; pkt[44] = 0x07; pkt[45] = 0xd0;
    pkt[46] = 0x50; /* Data offset = 5 (20 bytes), reserved */
    pkt[47] = 0x18; /* Flags: PSH, ACK */
    pkt[48] = 0x10; pkt[49] = 0x00; /* Window size */
    
    /* HTTP payload */
    const char *http_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
    size_t http_len = strlen(http_payload);
    memcpy(pkt + 54, http_payload, http_len);
    
    /* Fill in IPv4 Total Length */
    uint16_t ip_total_len = (uint16_t)(20 + 20 + http_len);
    pkt[16] = (uint8_t)(ip_total_len >> 8);
    pkt[17] = (uint8_t)(ip_total_len & 0xff);
    
    len = (size_t)(14 + ip_total_len);
    write_pcap("tests/fixtures/ipv4_tcp_http.pcap", pkt, len);

    /* 3. IPv4 + UDP + DNS Fixture */
    memset(pkt, 0, sizeof(pkt));
    /* Eth header */
    pkt[0] = 0x00; pkt[1] = 0xaa; pkt[2] = 0xbb; pkt[3] = 0xcc; pkt[4] = 0xdd; pkt[5] = 0xee;
    pkt[6] = 0x00; pkt[7] = 0x11; pkt[8] = 0x22; pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55;
    pkt[12] = 0x08; pkt[13] = 0x00;
    
    /* IPv4 header */
    pkt[14] = 0x45;
    pkt[23] = 17; /* Protocol: UDP */
    pkt[26] = 192;  pkt[27] = 168;  pkt[28] = 1;    pkt[29] = 1;
    pkt[30] = 8;    pkt[31] = 8;    pkt[32] = 8;    pkt[33] = 8; /* Dst IP: 8.8.8.8 */

    /* UDP header */
    pkt[34] = 0xd4; pkt[35] = 0x31; /* Src Port: 54321 */
    pkt[36] = 0x00; pkt[37] = 0x35; /* Dst Port: 53 */
    /* UDP Length (placeholder) */

    /* DNS payload */
    uint8_t *dns = pkt + 42;
    dns[0] = 0x12; dns[1] = 0x34; /* ID */
    dns[2] = 0x01; dns[3] = 0x00; /* Flags: standard query */
    dns[4] = 0x00; dns[5] = 0x01; /* QDCount = 1 */
    dns[6] = 0x00; dns[7] = 0x00; /* ANCount = 0 */
    dns[8] = 0x00; dns[9] = 0x00; /* NSCount = 0 */
    dns[10] = 0x00; dns[11] = 0x00; /* ARCount = 0 */
    /* Query Name: example.com */
    dns[12] = 7;
    memcpy(dns + 13, "example", 7);
    dns[20] = 3;
    memcpy(dns + 21, "com", 3);
    dns[24] = 0; /* Null terminator */
    dns[25] = 0x00; dns[26] = 0x01; /* Type A */
    dns[27] = 0x00; dns[28] = 0x01; /* Class IN */
    size_t dns_len = 29;

    /* Fill in UDP Length */
    uint16_t udp_total_len = (uint16_t)(8 + dns_len);
    pkt[38] = (uint8_t)(udp_total_len >> 8);
    pkt[39] = (uint8_t)(udp_total_len & 0xff);

    /* Fill in IPv4 Total Length */
    ip_total_len = (uint16_t)(20 + udp_total_len);
    pkt[16] = (uint8_t)(ip_total_len >> 8);
    pkt[17] = (uint8_t)(ip_total_len & 0xff);

    len = (size_t)(14 + ip_total_len);
    write_pcap("tests/fixtures/ipv4_udp_dns.pcap", pkt, len);

    /* 4. IPv6 + TCP + TLS Fixture */
    memset(pkt, 0, sizeof(pkt));
    /* Eth header */
    pkt[0] = 0x00; pkt[1] = 0xaa; pkt[2] = 0xbb; pkt[3] = 0xcc; pkt[4] = 0xdd; pkt[5] = 0xee;
    pkt[6] = 0x00; pkt[7] = 0x11; pkt[8] = 0x22; pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55;
    pkt[12] = 0x86; pkt[13] = 0xdd; /* ethertype: IPv6 */

    /* IPv6 Header */
    pkt[14] = 0x60; /* Version = 6 */
    pkt[15] = 0x00; pkt[16] = 0x00; pkt[17] = 0x00; /* Traffic class & Flow label */
    /* Payload length (placeholder) */
    pkt[20] = 6;    /* Next Header: TCP */
    pkt[21] = 64;   /* Hop Limit */
    /* Src IP: fe80::1 */
    pkt[22] = 0xfe; pkt[23] = 0x80;
    pkt[37] = 1;
    /* Dst IP: fe80::2 */
    pkt[38] = 0xfe; pkt[39] = 0x80;
    pkt[53] = 2;

    /* TCP Header */
    pkt[54] = 0xd4; pkt[55] = 0x32; /* Src Port: 54322 */
    pkt[56] = 0x01; pkt[57] = 0xbb; /* Dst Port: 443 (HTTPS) */
    /* Seq number = 3000 */
    pkt[58] = 0x00; pkt[59] = 0x00; pkt[60] = 0x0b; pkt[61] = 0xb8;
    /* Ack number = 4000 */
    pkt[62] = 0x00; pkt[63] = 0x00; pkt[64] = 0x0f; pkt[65] = 0xa0;
    pkt[66] = 0x50; /* Data offset = 5 (20 bytes) */
    pkt[67] = 0x18; /* Flags: PSH, ACK */

    /* TLS Handshake (Client Hello) record */
    uint8_t *tls = pkt + 74;
    tls[0] = 22;   /* Content Type: Handshake */
    tls[1] = 0x03; tls[2] = 0x03; /* Version: TLS 1.2 */
    tls[3] = 0x00; tls[4] = 0x08; /* Length = 8 */
    /* Handshake Header */
    tls[5] = 1;    /* Handshake Type: Client Hello */
    tls[6] = 0x00; tls[7] = 0x00; tls[8] = 0x04; /* Length = 4 */
    tls[9] = 0x03; tls[10] = 0x03; /* Version TLS 1.2 */
    tls[11] = 0xaa; tls[12] = 0xbb; /* Random bytes */
    size_t tls_len = 13;

    /* Fill in TCP Payload / IPv6 lengths */
    uint16_t tcp_payload_len = (uint16_t)tls_len;
    uint16_t ipv6_payload_len = (uint16_t)(20 + tcp_payload_len);
    pkt[18] = (uint8_t)(ipv6_payload_len >> 8);
    pkt[19] = (uint8_t)(ipv6_payload_len & 0xff);

    len = (size_t)(54 + ipv6_payload_len);
    write_pcap("tests/fixtures/ipv6_tcp_tls.pcap", pkt, len);

    /* 5. IPv4 + ICMP Fixture */
    memset(pkt, 0, sizeof(pkt));
    /* Eth header */
    pkt[0] = 0x00; pkt[1] = 0xaa; pkt[2] = 0xbb; pkt[3] = 0xcc; pkt[4] = 0xdd; pkt[5] = 0xee;
    pkt[6] = 0x00; pkt[7] = 0x11; pkt[8] = 0x22; pkt[9] = 0x33; pkt[10] = 0x44; pkt[11] = 0x55;
    pkt[12] = 0x08; pkt[13] = 0x00;

    /* IPv4 header */
    pkt[14] = 0x45;
    pkt[23] = 1; /* Protocol: ICMP */
    pkt[26] = 192;  pkt[27] = 168;  pkt[28] = 1;    pkt[29] = 1;
    pkt[30] = 192;  pkt[31] = 168;  pkt[32] = 1;    pkt[33] = 2;

    /* ICMP Header */
    pkt[34] = 8;   /* Type: Echo Request */
    pkt[35] = 0;   /* Code: 0 */
    pkt[36] = 0x00; pkt[37] = 0x00; /* Checksum placeholder */
    pkt[38] = 0x12; pkt[39] = 0x34; /* ID */
    pkt[40] = 0x00; pkt[41] = 0x01; /* Sequence */
    /* Data */
    memset(pkt + 42, 'A', 32);
    size_t icmp_len = 40;

    /* Fill in IPv4 Total Length */
    ip_total_len = (uint16_t)(20 + icmp_len);
    pkt[16] = (uint8_t)(ip_total_len >> 8);
    pkt[17] = (uint8_t)(ip_total_len & 0xff);

    len = (size_t)(14 + ip_total_len);
    write_pcap("tests/fixtures/ipv4_icmp.pcap", pkt, len);

    /* 6. Merge all into tests/fixtures/all.pcap */
    const char *infiles[] = {
        "tests/fixtures/arp.pcap",
        "tests/fixtures/ipv4_tcp_http.pcap",
        "tests/fixtures/ipv4_udp_dns.pcap",
        "tests/fixtures/ipv6_tcp_tls.pcap",
        "tests/fixtures/ipv4_icmp.pcap"
    };
    merge_fixtures("tests/fixtures/all.pcap", infiles, 5);

    printf("Generated fixture pcap files (including all.pcap) in tests/fixtures/\n");
    return 0;
}
