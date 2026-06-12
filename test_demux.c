#include <stdio.h>
#include <string.h>
#include "netpipe.h"

int main() {
    np_init();
    
    // Create a mock Ethernet + IPv4 + TCP + HTTP packet
    uint8_t pkt_data[1500] = {0};
    size_t len = 0;
    
    // Fake Ethernet (14)
    len += 14;
    pkt_data[12] = 0x08; pkt_data[13] = 0x00; // IPv4
    
    // Fake IPv4 (20)
    uint8_t *ip = pkt_data + len;
    ip[0] = 0x45; // v4, 5 words
    ip[9] = 6;    // TCP
    len += 20;
    
    // Fake TCP (20)
    uint8_t *tcp = pkt_data + len;
    tcp[0] = 0; tcp[1] = 80; // src port 80
    tcp[2] = 0; tcp[3] = 80; // dst port 80
    tcp[12] = (5 << 4); // data offset 5 words
    len += 20;
    
    // Fake HTTP
    const char *http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    memcpy(pkt_data + len, http, strlen(http));
    len += strlen(http);
    
    np_packet_t *pkt = np_packet_alloc(len);
    memcpy(pkt->raw, pkt_data, len);
    pkt->caplen = len;
    pkt->wirelen = len;
    
    np_err_t err = np_demux_packet(pkt, NP_LINK_ETHERNET);
    printf("Demux returned %d\n", err);
    printf("nlayers: %d\n", pkt->nlayers);
    
    if (pkt->app) {
        printf("App proto: %d\n", pkt->app->proto);
        if (pkt->app->proto == NP_PROTO_HTTP && pkt->app->decoded) {
            np_http_msg_t *msg = pkt->app->decoded;
            printf("HTTP method: %.*s\n", (int)msg->method.len, msg->method.str);
            printf("HTTP path: %.*s\n", (int)msg->path.len, msg->path.str);
            printf("HTTP headers: %d\n", msg->num_headers);
            for (int i=0; i < msg->num_headers; i++) {
                printf("  %.*s : %.*s\n", 
                    (int)msg->headers[i].name.len, msg->headers[i].name.str,
                    (int)msg->headers[i].value.len, msg->headers[i].value.str);
            }
        }
    }
    
    np_packet_free(pkt);
    np_cleanup();
    return 0;
}
