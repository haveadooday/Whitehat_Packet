#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define MAX_MESSAGE_LEN 100

/* Callback 함수 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    if (ntohs(eth->h_proto) == ETH_P_IP) { // IP 패킷인 경우
        struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
        if (ip->protocol == IPPROTO_TCP) { // TCP 패킷인 경우
            struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip->ihl*4);
            printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                   eth->h_source[0], eth->h_source[1], eth->h_source[2], 
                   eth->h_source[3], eth->h_source[4], eth->h_source[5]);
            printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                   eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
                   eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
            printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
            printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));
            printf("Source Port: %d\n", ntohs(tcp->source));
            printf("Destination Port: %d\n", ntohs(tcp->dest));
            printf("Message: ");
            int tcp_data_offset = ip->ihl*4 + tcp->doff*4;
            int message_len = ntohs(ip->tot_len) - tcp_data_offset;
            if (message_len > 0) {
                for (int i = tcp_data_offset; i < tcp_data_offset + MAX_MESSAGE_LEN && i < ntohs(ip->tot_len); ++i) {
                    printf("%c", packet[i]);
                }
                if (message_len > MAX_MESSAGE_LEN)
                    printf("..."); // 메시지가 최대 길이를 초과할 경우 "..." 출력
            }
            printf("\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

    // 네트워크 디바이스 열기
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device: %s\n", errbuf);
        return(2);
    }

    // 필터 컴파일 및 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    // 패킷 캡처
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    
    return(0);
}
