/*
PackerSender tool,abbreviated as pser,Packet sending tool.
Author: newStar2099,@20250217
version:v1.0
compiled:gcc -std=c99 SourceCode.c -o pser
*/

#include <stdio.h>              // 引入标准输入输出库，用于打印信息
#include <stdlib.h>             // 引入标准库，用于内存分配和程序退出
#include <string.h>             // 引入字符串处理库，用于字符串拷贝和比较
#include <unistd.h>             // 引入unistd库，用于close函数
#include <sys/socket.h>         // 引入socket库，用于socket编程
#include <netinet/in.h>         // 引入netinet/in库，用于定义sockaddr_in结构体
#include <netinet/ip.h>         // 引入netinet/ip库，用于定义ip头结构体
#include <netinet/tcp.h>        // 引入netinet/tcp库，用于定义tcp头结构体
#include <netinet/udp.h>        // 引入netinet/udp库，用于定义udp头结构体
#include <netinet/ip_icmp.h>    // 引入netinet/ip_icmp库，用于定义icmp头结构体
#include <arpa/inet.h>          // 引入arpa/inet库，用于IP地址转换
#include <sys/time.h>           // 引入sys/time库，用于计时
#include <errno.h>              // 引入errno库，用于错误处理
#include <getopt.h>             // 引入getopt库，用于解析命令行参数
#include <time.h>               // 引入time库，用于生成随机数
#include <signal.h>             // 引入signal库，用于处理信号

#define PROTOCOL_TCP 6          // 定义TCP协议号为6
#define PROTOCOL_UDP 17         // 定义UDP协议号为17
#define PROTOCOL_ICMP 1         // 定义ICMP协议号为1

#define TCP_FLAG_FIN 0x01       // 定义TCP FIN标志位
#define TCP_FLAG_SYN 0x02       // 定义TCP SYN标志位
#define TCP_FLAG_RST 0x04       // 定义TCP RST标志位
#define TCP_FLAG_PSH 0x08       // 定义TCP PSH标志位
#define TCP_FLAG_ACK 0x10       // 定义TCP ACK标志位
#define TCP_FLAG_URG 0x20       // 定义TCP URG标志位
#define TCP_FLAG_ECE 0x40       // 定义TCP ECE标志位
#define TCP_FLAG_CWR 0x80       // 定义TCP CWR标志位

#define MAX_PAYLOAD_SIZE 1500   // 定义最大payload大小，确保数据包大小不超过MTU

// 定义版本号
#define VERSION "pser v1.0，lxh@20250217"

// 函数声明
void print_usage();  // 声明打印帮助信息的函数
int send_packets(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int protocol, int packet_count, int tcp_flags, const char *payload, int payload_len, int icmp_type, int icmp_code);  // 声明发送数据包函数
unsigned short checksum(unsigned short *buffer, int size);  // 声明校验和计算函数
int parse_tcp_flags(const char *flag_str); // 声明解析TCP标志的函数
int parse_protocol(const char *proto_str); // 声明解析协议的函数
char *read_payload(const char *filename, int max_payload_len, int *payload_len); // 声明读取payload文件的函数
void handle_signal(int signal); // 声明信号处理函数

// 定义IP头结构体
struct ip_header {
    unsigned char ip_verlen;       // IP版本和头长
    unsigned char ip_tos;          // 服务类型
    unsigned short ip_len;         // 总长度
    unsigned short ip_id;          // 标识
    unsigned short ip_off;         // 分片偏移
    unsigned char ip_ttl;          // 生存时间
    unsigned char ip_protocol;     // 协议
    unsigned short ip_checksum;    // 校验和
    struct in_addr ip_srcaddr;     // 源IP地址
    struct in_addr ip_dstaddr;     // 目标IP地址
};

// 定义TCP头结构体
struct tcp_header {
    unsigned short tcp_sport;      // 源端口
    unsigned short tcp_dport;      // 目标端口
    unsigned int tcp_seq;          // 序列号
    unsigned int tcp_ack;          // 确认号
    unsigned char tcp_offset;      // 数据偏移
    unsigned char tcp_flags;       // 标志位
    unsigned short tcp_window;     // 窗口大小
    unsigned short tcp_checksum;   // 校验和
    unsigned short tcp_urgent;     // 紧急指针
};

// 定义UDP头结构体
struct udp_header {
    unsigned short udp_sport;      // 源端口
    unsigned short udp_dport;      // 目标端口
    unsigned short udp_len;        // 长度
    unsigned short udp_checksum;   // 校验和
};

// 定义ICMP头结构体
struct icmp_header {
    unsigned char icmp_type;       // ICMP 类型
    unsigned char icmp_code;       // ICMP 代码
    unsigned short icmp_checksum;  // 校验和
    unsigned short icmp_id;        // 标识符
    unsigned short icmp_sequence;  // 序列号
};

// 定义TCP伪头部结构体
struct pseudo_header {
    unsigned int source_address;   // 源IP地址
    unsigned int dest_address;     // 目标IP地址
    unsigned char placeholder;      // 占位符
    unsigned char protocol;         // 协议
    unsigned short tcp_length;      // TCP 长度
};

// 全局变量
long long g_total_packets = 0;  // 发送的数据包总数
struct timeval g_start_time;    // 程序开始时间
struct timeval g_end_time;      // 程序结束时间

// 打印程序使用说明
void print_usage() {
    printf("Usage: -d <dst_ip> [-s <src_ip>] [-sp <src_port>] [-dp <dst_port>] [-p <protocol>] [-n <count>] [-f <tcp_flags>] [-l <payload_file>] [-t <icmp_type>] [-c <icmp_code>] [-h] [-v]\n");
    printf("Options:\n");
    printf("  -d <dst_ip>         Destination IP address (!!!Only required!!!)\n");
    printf("  -s <src_ip>         Source IP address (optional, random if not specified)\n");
    printf("  -sp <src_port>      Source port number (optional, random if not specified)\n");
    printf("  -dp <dst_port>      Destination port number (optional, default is 22)\n");
    printf("  -p <protocol>       Protocol (tcp, udp, icmp, default is tcp)\n");
    printf("  -n <count>          Number of packets to send (default is 5, 0 is continuous)\n");
    printf("  -f <tcp_flags>      TCP flags (FIN,SYN,RST,PSH,ACK,URG,ECE,CWR, only for TCP)\n");
    printf("  -l <payload_file>   Payload file\n");
    printf("  -t <icmp_type>      ICMP type (only for ICMP, default is 2)\n");
    printf("  -c <icmp_code>      ICMP code (only for ICMP, default is 4)\n");
    printf("  -h                  Show help message\n");
    printf("  -v                  Show version information\n");
    printf("Example:\n");
    printf("  sudo pser -d 127.0.0.1 -p icmp -n 5 -t 8 -c 0\n");
    printf("  sudo pser -s 1.2.3.4 -d 2.3.4.5 -sp 1234 -dp 443 -p tcp -f SYN,urg,ACK -l payload.txt -n 0\n");
}

// 解析TCP标志字符串
int parse_tcp_flags(const char *flag_str) {
    int flags = 0;
    char *token = NULL, *tmp = NULL;
    char temp[256];

    strncpy(temp, flag_str, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = '\0';

    tmp = strdup(temp);
    token = strtok(tmp, ",");
    while (token != NULL) {
        if (strcasecmp(token, "FIN") == 0) flags |= TCP_FLAG_FIN;
        else if (strcasecmp(token, "SYN") == 0) flags |= TCP_FLAG_SYN;
        else if (strcasecmp(token, "RST") == 0) flags |= TCP_FLAG_RST;
        else if (strcasecmp(token, "PSH") == 0) flags |= TCP_FLAG_PSH;
        else if (strcasecmp(token, "ACK") == 0) flags |= TCP_FLAG_ACK;
        else if (strcasecmp(token, "URG") == 0) flags |= TCP_FLAG_URG;
        else if (strcasecmp(token, "ECE") == 0) flags |= TCP_FLAG_ECE;
        else if (strcasecmp(token, "CWR") == 0) flags |= TCP_FLAG_CWR;
        token = strtok(NULL, ",");
    }
    free(tmp);
    return flags;
}

// 解析协议字符串
int parse_protocol(const char *proto_str) {
    if (strcasecmp(proto_str, "tcp") == 0) return PROTOCOL_TCP;
    else if (strcasecmp(proto_str, "udp") == 0) return PROTOCOL_UDP;
    else if (strcasecmp(proto_str, "icmp") == 0) return PROTOCOL_ICMP;
    else {
        int proto = atoi(proto_str);
        if (proto == PROTOCOL_TCP || proto == PROTOCOL_UDP || proto == PROTOCOL_ICMP)
            return proto;
        else
            return -1;
    }
}

// 从文件读取payload，并进行裁剪和校验
char *read_payload(const char *filename, int max_payload_len, int *payload_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("fopen");
        return NULL;
    }

    char *buffer = (char *)malloc(max_payload_len);
    if (!buffer) {
        perror("malloc");
        fclose(f);
        return NULL;
    }

    *payload_len = fread(buffer, 1, max_payload_len, f);
    if (*payload_len < 0) {
        perror("fread");
        free(buffer);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return buffer;
}

// 计算校验和
unsigned short checksum(unsigned short *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        cksum += *(unsigned char *)buffer;
    }

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);

    return (unsigned short)(~cksum);
}

// 信号处理函数
void handle_signal(int signal) {
    gettimeofday(&g_end_time, NULL);
    long long elapsed_us = (g_end_time.tv_sec - g_start_time.tv_sec) * 1000000LL + (g_end_time.tv_usec - g_start_time.tv_usec);
    printf("\nSent %lld packets in %lld μs\n", g_total_packets, elapsed_us);
    printf("PPS (Packets Per Second): %.2f\n", (double)g_total_packets / (double)elapsed_us * 1000000);
    exit(0);
}

// 发送数据包
int send_packets(const char *src_ip, int src_port, const char *dst_ip, int dst_port, int protocol, int packet_count, int tcp_flags, const char *payload, int payload_len, int icmp_type, int icmp_code) {
    int sock;
    struct sockaddr_in dest_addr;
    struct ip_header *ip;
    struct tcp_header *tcp;
    struct udp_header *udp;
    struct icmp_header *icmp;
    char *packet;
    int ip_header_len, tcp_header_len, udp_header_len, icmp_header_len, total_len, data_len;
    int one = 1;
    struct timeval tv_start, tv_end;
    long long elapsed_us;
    int i, sent_packets = 0;

    // 创建 RAW socket
    if ((sock = socket(AF_INET, SOCK_RAW, protocol)) < 0) {
        perror("socket");
        return 1;
    }

    // 设置 IP_HDRINCL 选项，手动构造 IP 头部
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock);
        return 1;
    }

    // 设置目标地址
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dst_port);
    if (inet_pton(AF_INET, dst_ip, &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return 1;
    }

    // 记录发送开始时间
    gettimeofday(&g_start_time, NULL);

    // 循环发送数据包
    for (i = 0; packet_count == 0 || i < packet_count; i++) {
        // 如果未指定源IP，则生成随机源IP地址
        struct in_addr src_addr;
        char src_ip_buf[INET_ADDRSTRLEN];
        if (src_ip == NULL) {
            src_addr.s_addr = htonl((rand() % 0xFFFFFF00) + 1);
            inet_ntop(AF_INET, &src_addr, src_ip_buf, INET_ADDRSTRLEN);
            src_ip = src_ip_buf;
        }

        // 如果未指定源端口，则生成随机源端口
        if (src_port == 0) {
            src_port = (rand() % 65535) + 1;
        }

        // 如果未指定TCP标志，则设置为SYN
        if (tcp_flags == 0) {
            tcp_flags = TCP_FLAG_SYN;
        }

        // 计算数据包长度
        ip_header_len = sizeof(struct ip_header);
        tcp_header_len = sizeof(struct tcp_header);
        udp_header_len = sizeof(struct udp_header);
        icmp_header_len = sizeof(struct icmp_header);

        switch (protocol) {
            case PROTOCOL_TCP:
                data_len = payload_len;
                total_len = ip_header_len + tcp_header_len + data_len;
                break;
            case PROTOCOL_UDP:
                data_len = payload_len > 0 ? payload_len : 8; // 默认UDP数据长度为8
                total_len = ip_header_len + udp_header_len + data_len;
                break;
            case PROTOCOL_ICMP:
                data_len = payload_len > 0 ? payload_len : 56; // 默认ICMP数据长度为56
                total_len = ip_header_len + icmp_header_len + data_len;
                break;
            default:
                fprintf(stderr, "Unsupported protocol\n");
                close(sock);
                return 1;
        }

        // 构造完整数据包并发送
        packet = (char *)malloc(total_len);
        if (!packet) {
            perror("malloc");
            close(sock);
            return 1;
        }
        memset(packet, 0, total_len);

        // 填充 IP 头部
        ip = (struct ip_header *)packet;
        ip->ip_verlen = 0x45; // IPv4, 头部长度为 5 个 32 位字
        ip->ip_tos = 0;
        ip->ip_len = htons(total_len);
        ip->ip_id = htons(12345);
        ip->ip_off = 0;
        ip->ip_ttl = 64;
        ip->ip_protocol = protocol;
        inet_pton(AF_INET, src_ip, &ip->ip_srcaddr);
        inet_pton(AF_INET, dst_ip, &ip->ip_dstaddr);
        ip->ip_checksum = checksum((unsigned short *)ip, ip_header_len);

        // 填充 TCP/UDP/ICMP 头部
        switch (protocol) {
            case PROTOCOL_TCP: {
                tcp = (struct tcp_header *)(packet + ip_header_len);
                tcp->tcp_sport = htons(src_port);
                tcp->tcp_dport = htons(dst_port);
                tcp->tcp_seq = htonl(i);
                tcp->tcp_ack = 0;
                tcp->tcp_offset = (sizeof(struct tcp_header) / 4) << 4; // 设置数据偏移
                tcp->tcp_flags = tcp_flags; // 设置 TCP 标志
                tcp->tcp_window = htons(8192);
                tcp->tcp_urgent = 0;

                // 复制 payload
                if (payload != NULL) {
                    memcpy(packet + ip_header_len + sizeof(struct tcp_header), payload, data_len);
                }

                // 计算 TCP 校验和
                struct pseudo_header psh;
                psh.source_address = ip->ip_srcaddr.s_addr;
                psh.dest_address = ip->ip_dstaddr.s_addr;
                psh.placeholder = 0;
                psh.protocol = IPPROTO_TCP;
                psh.tcp_length = htons(tcp_header_len + data_len);

                int psize = sizeof(struct pseudo_header) + tcp_header_len + data_len;
                char *pseudogram = malloc(psize);
                if (!pseudogram) { perror("malloc"); free(packet); close(sock); return 1; }
                memset(pseudogram, 0, psize);
                memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
                memcpy(pseudogram + sizeof(struct pseudo_header), tcp, tcp_header_len);
                memcpy(pseudogram + sizeof(struct pseudo_header) + tcp_header_len, payload, data_len);
                tcp->tcp_checksum = checksum((unsigned short*)pseudogram, psize);
                free(pseudogram);
                break;
            }
            case PROTOCOL_UDP: {
                udp = (struct udp_header *)(packet + ip_header_len);
                udp->udp_sport = htons(src_port);
                udp->udp_dport = htons(dst_port);
                udp->udp_len = htons(udp_header_len + data_len);
                udp->udp_checksum = 0; // UDP 校验和是可选的
                if (payload) {
                    memcpy(packet + ip_header_len + sizeof(struct udp_header), payload, data_len);
                }
                break;
            }
            case PROTOCOL_ICMP: {
                icmp = (struct icmp_header *)(packet + ip_header_len);
                icmp->icmp_type = icmp_type;
                icmp->icmp_code = icmp_code;
                icmp->icmp_id = htons(12345);
                icmp->icmp_sequence = htons(i);
                icmp->icmp_checksum = 0;
                if (payload) {
                    memcpy(packet + ip_header_len + sizeof(struct icmp_header), payload, data_len);
                }
                icmp->icmp_checksum = checksum((unsigned short*)icmp, sizeof(struct icmp_header) + data_len);
                break;
            }
        }

        // 发送数据包
        if (sendto(sock, packet, total_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("sendto");
            free(packet);
            close(sock);
            return 1;
        }
        free(packet);
        g_total_packets++;
    }

    // 记录发送结束时间
    gettimeofday(&tv_end, NULL);
    elapsed_us = (tv_end.tv_sec - g_start_time.tv_sec) * 1000000LL + (tv_end.tv_usec - g_start_time.tv_usec);
    printf("Sent %lld packets in %lld μs\n", g_total_packets, elapsed_us);
    printf("PPS (Packets Per Second): %.2f\n", (double)g_total_packets / (double)elapsed_us * 1000000);

    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    int opt;
    char *src_ip = NULL, *dst_ip = NULL, *payload_file = NULL;
    int src_port = 0, dst_port = 22, protocol = PROTOCOL_TCP, packet_count = 5, tcp_flags = 0, icmp_type = 2, icmp_code = 4;
    char *payload = NULL;
    int payload_len = 0;

    // 注册信号处理函数
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    while ((opt = getopt(argc, argv, "hvs:d:sp:dp:p:n:f:l:t:c:")) != -1) {
        switch (opt) {
            case 'h':
                print_usage();
                return 0;
            case 'v':
                printf("Version: %s\n", VERSION);
                return 0;
            case 's':
                src_ip = optarg;
                break;
            case 'd':
                dst_ip = optarg;
                break;
            case 'sp':
                src_port = atoi(optarg);
                break;
            case 'dp':
                dst_port = atoi(optarg);
                break;
            case 'p':
                protocol = parse_protocol(optarg);
                if (protocol == -1) {
                    fprintf(stderr, "Invalid protocol: %s\n", optarg);
                    return 1;
                }
                break;
            case 'n':
                packet_count = atoi(optarg);
                break;
            case 'f':
                tcp_flags = parse_tcp_flags(optarg);
                break;
            case 'l':
                payload_file = optarg;
                break;
            case 't':
                icmp_type = atoi(optarg);
                break;
            case 'c':
                icmp_code = atoi(optarg);
                break;
            default:
                print_usage();
                return 1;
        }
    }

    if (!dst_ip) {
        fprintf(stderr, "Destination IP address is required\n");
        print_usage();
        return 1;
    }

    if (payload_file) {
        payload = read_payload(payload_file, MAX_PAYLOAD_SIZE, &payload_len);
        if (!payload) {
            fprintf(stderr, "Failed to read payload file: %s\n", payload_file);
            return 1;
        }
    }

    // 发送数据包
    int result = send_packets(src_ip, src_port, dst_ip, dst_port, protocol, packet_count, tcp_flags, payload, payload_len, icmp_type, icmp_code);

    if (payload) {
        free(payload);
    }

    return result;
}