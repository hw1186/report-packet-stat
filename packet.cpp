#include <pcap.h>
#include <iostream>
#include <map>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

struct ip_stats {
    unsigned int tx_packets;
    unsigned int rx_packets;
    unsigned int tx_bytes;
    unsigned int rx_bytes;
};

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto *stats_map = reinterpret_cast<std::map<std::string, ip_stats> *>(user_data);
    const struct ether_header *eth_header;
    const struct ip *ip_header;

    eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        unsigned int data_len = pkthdr->len - (sizeof(struct ether_header) + ip_header->ip_hl * 4);

        (*stats_map)[src_ip].tx_packets++;
        (*stats_map)[src_ip].tx_bytes += data_len;

        (*stats_map)[dst_ip].rx_packets++;
        (*stats_map)[dst_ip].rx_bytes += data_len;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Syntax: packet-stat <pcap file>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_offline() failed: " << errbuf << "\n";
        return 1;
    }

    std::map<std::string, ip_stats> stats_map;
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char *>(&stats_map)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle) << "\n";
        return 1;
    }

    for (const auto &entry : stats_map) {
        std::cout << "IP: " << entry.first
                  << ", TX Packets: " << entry.second.tx_packets
                  << ", RX Packets: " << entry.second.rx_packets
                  << ", TX Bytes: " << entry.second.tx_bytes
                  << ", RX Bytes: " << entry.second.rx_bytes << "\n";
    }

    pcap_close(handle);
    return 0;
}
