#include <iostream>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345

struct pseudo_header {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short leftover;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        leftover = 0;
        *((unsigned char *)&leftover) = *((unsigned char *)ptr);
        sum += leftover;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

void send_syn(int sock, struct sockaddr_in *server_addr) {
    char packet[4096];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = server_addr->sin_addr.s_addr;
    ip->check = 0;

    tcp->source = htons(54321);
    tcp->dest = htons(SERVER_PORT);
    tcp->seq = htonl(200);
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;
    tcp->ack = 0;
    tcp->fin = 0;
    tcp->rst = 0;
    tcp->psh = 0;
    tcp->urg = 0;
    tcp->window = htons(8192);
    tcp->check = 0;
    tcp->urg_ptr = 0;

    struct pseudo_header psh;
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char checksum_buf[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
    memcpy(checksum_buf, &psh, sizeof(struct pseudo_header));
    memcpy(checksum_buf + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    tcp->check = checksum((unsigned short *)checksum_buf, sizeof(checksum_buf));

    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
        perror("sendto() failed for SYN");
    } else {
        std::cout << "[+] Sent SYN (Seq=200)" << std::endl;
    }
}

void receive_syn_ack_and_send_ack(int sock, struct sockaddr_in *server_addr) {
    char buffer[65536];
    struct sockaddr_in source_addr;
    socklen_t addr_len = sizeof(source_addr);

    while (true) {
        int data_size = recvfrom(sock, buffer, sizeof(buffer), 0,
                                 (struct sockaddr *)&source_addr, &addr_len);
        if (data_size < 0) {
            perror("recvfrom() failed");
            continue;
        }

        struct iphdr *ip = (struct iphdr *)buffer;
        struct tcphdr *tcp = (struct tcphdr *)(buffer + (ip->ihl * 4));

        if (ntohs(tcp->source) != SERVER_PORT || ntohs(tcp->dest) != 54321) {
            continue;
        }

        if (tcp->syn == 1 && tcp->ack == 1 && ntohl(tcp->seq) == 400 && ntohl(tcp->ack_seq) == 201) {
            std::cout << "[+] Received SYN-ACK (Seq=400, Ack=201)" << std::endl;

            char packet[4096];
            memset(packet, 0, sizeof(packet));

            struct iphdr *ip_resp = (struct iphdr *)packet;
            struct tcphdr *tcp_resp = (struct tcphdr *)(packet + sizeof(struct iphdr));

            ip_resp->ihl = 5;
            ip_resp->version = 4;
            ip_resp->tos = 0;
            ip_resp->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip_resp->id = htons(12345);
            ip_resp->frag_off = 0;
            ip_resp->ttl = 64;
            ip_resp->protocol = IPPROTO_TCP;
            ip_resp->saddr = inet_addr("127.0.0.1");
            ip_resp->daddr = server_addr->sin_addr.s_addr;
            ip_resp->check = 0;

            tcp_resp->source = htons(54321);
            tcp_resp->dest = htons(SERVER_PORT);
            tcp_resp->seq = htonl(600);
            tcp_resp->ack_seq = htonl(ntohl(tcp->seq) + 1);
            tcp_resp->doff = 5;
            tcp_resp->ack = 1;
            tcp_resp->syn = 0;
            tcp_resp->fin = 0;
            tcp_resp->rst = 0;
            tcp_resp->psh = 0;
            tcp_resp->urg = 0;
            tcp_resp->window = htons(8192);
            tcp_resp->check = 0;
            tcp_resp->urg_ptr = 0;

            struct pseudo_header psh_ack;
            psh_ack.src_addr = ip_resp->saddr;
            psh_ack.dst_addr = ip_resp->daddr;
            psh_ack.placeholder = 0;
            psh_ack.protocol = IPPROTO_TCP;
            psh_ack.tcp_length = htons(sizeof(struct tcphdr));

            char checksum_buf_ack[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
            memcpy(checksum_buf_ack, &psh_ack, sizeof(struct pseudo_header));
            memcpy(checksum_buf_ack + sizeof(struct pseudo_header), tcp_resp, sizeof(struct tcphdr));

            tcp_resp->check = checksum((unsigned short *)checksum_buf_ack, sizeof(checksum_buf_ack));

            if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                       (struct sockaddr *)server_addr, sizeof(*server_addr)) < 0) {
                perror("sendto() failed for ACK");
            } else {
                std::cout << "[+] Sent final ACK (Seq=600, Ack=401). Handshake complete!" << std::endl;
            }

            break;
        }
    }
}

int main() {
    int sock;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("Raw socket creation failed (requires root privileges)");
        exit(EXIT_FAILURE);
    }
    std::cout << "[+] Raw socket created." << std::endl;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt(IP_HDRINCL) failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    std::cout << "[+] IP_HDRINCL option set." << std::endl;

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    send_syn(sock, &server_addr);
    receive_syn_ack_and_send_ack(sock, &server_addr);

    close(sock);
    std::cout << "[+] Socket closed." << std::endl;

    return 0;
}