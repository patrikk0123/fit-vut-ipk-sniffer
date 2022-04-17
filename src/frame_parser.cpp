/**
 * @file
 * @brief Frame parsing module.
 */

#include "frame_parser.h"

#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

void parse_frame(u_char *user, const struct pcap_pkthdr *header,
                 const u_char *frame)
{
  (void)user;

  print_timestamp(header);
  std::cout << "captured length: " << header->caplen << "\n";
  print_ether_info(frame, header->len);
  std::cout << "\n";

  print_frame(frame, header->len);
  std::cout << "\n";
  std::cout << std::flush;
}

void print_ether_info(const u_char *frame, int frame_len)
{
  std::cout << "L2 protocol: ETHERNET\n";
  auto ether = (struct ether_header*)frame;

  std::cout << "src MAC: ";
  print_mac_addr(ether->ether_shost);
  std::cout << "dst MAC: ";
  print_mac_addr(ether->ether_dhost);
  std::cout << "frame length: " << frame_len << "\n";

  auto ether_type = ntohs(ether->ether_type);
  if(ether_type == ETHERTYPE_IP) {
    print_ip4_info(frame);
  }
  else if(ether_type == ETHERTYPE_IPV6) {
    print_ip6_info(frame);
  }
  else if(ether_type == ETHERTYPE_ARP) {
    print_arp_info(frame);
  }
}

void print_arp_info(const u_char *frame)
{
  std::cout << "L2.5 protocol: ARP\n";
  auto arp = (struct arpheader*)(frame + sizeof(struct ether_header));
  
  std::cout << "src MAC: ";
  print_mac_addr(arp->sha);
  std::cout << "dst MAC: ";
  print_mac_addr(arp->tha);
  std::cout << "src IP: " << inet_ntoa(*((in_addr*)(&arp->spa))) << "\n";
  std::cout << "dst IP: " << inet_ntoa(*((in_addr*)(&arp->tpa))) << "\n";
  std::cout << "ARP operation: " << ntohs(arp->operation) << "\n";
}

void print_ip4_info(const u_char *frame)
{
  std::cout << "L3 protocol: IPv4\n";
  auto ip4 = (struct ip*)(frame + sizeof(struct ether_header));

  std::cout << "src IP: " << inet_ntoa(ip4->ip_src) << "\n";
  std::cout << "dst IP: " << inet_ntoa(ip4->ip_dst) << "\n";
  std::cout << "time to live: " << unsigned(ip4->ip_ttl) << "\n";

  int ip_header_len = ip4->ip_hl * 4;
  if(ip4->ip_p == IPPROTO_ICMP) {
    print_icmp_info(frame, ip_header_len);
  }
  else if(ip4->ip_p == IPPROTO_TCP) {
    print_tcp_info(frame, ip_header_len);
  }
  else if(ip4->ip_p == IPPROTO_UDP) {
    print_udp_info(frame, ip_header_len);
  }
}

// buffer to store ipv6
char ip6_addr[INET6_ADDRSTRLEN];

void print_ip6_info(const u_char *frame)
{
  std::cout << "L3 protocol: IPv6\n";
  auto ip6 = (struct ip6_hdr*)(frame + sizeof(struct ether_header));

  inet_ntop(AF_INET6, &(ip6->ip6_src), ip6_addr, INET6_ADDRSTRLEN);
  std::cout << "src IP: " << ip6_addr << "\n";
  inet_ntop(AF_INET6, &(ip6->ip6_dst), ip6_addr, INET6_ADDRSTRLEN);
  std::cout << "dst IP: " << ip6_addr << "\n";
  std::cout << "hop limit: " << unsigned(ip6->ip6_hlim) << "\n";

  int ip_header_len = sizeof(struct ip6_hdr);
  if(ip6->ip6_nxt == IPPROTO_ICMPV6) {
    print_icmp_info(frame, ip_header_len);
  }
  else if(ip6->ip6_nxt == IPPROTO_TCP) {
    print_tcp_info(frame, ip_header_len);
  }
  else if(ip6->ip6_nxt == IPPROTO_UDP) {
    print_udp_info(frame, ip_header_len);
  }
}

void print_icmp_info(const u_char *frame, int ip_header_len)
{
  std::cout << "L3 protocol: ICMP\n";
  auto icmp = (struct icmphdr*)(frame + sizeof(struct ether_header) +
                                ip_header_len);

  std::cout << "ICMP type: " << unsigned(icmp->type) << "\n";
}

void print_tcp_info(const u_char *frame, int ip_header_len)
{
  std::cout << "L4 protocol: TCP\n";
  auto tcp = (struct tcphdr*)(frame + sizeof(struct ether_header) +
                              ip_header_len);

  std::cout << "src port: " << ntohs(tcp->source) << "\n";
  std::cout << "dst port: " << ntohs(tcp->dest) << "\n";
}

void print_udp_info(const u_char *frame, int ip_header_len)
{
  std::cout << "L4 protocol: UDP\n";
  auto udp = (struct udphdr*)(frame + sizeof(struct ether_header) +
                              ip_header_len);

  std::cout << "src port: " << ntohs(udp->source) << "\n";
  std::cout << "dst port: " << ntohs(udp->dest) << "\n";
}

void print_mac_addr(u_char mac_arr[6])
{
  for(int i = 0; i < 6; i++) {
    printf("%02x", mac_arr[i]);
    if(i < 5)
      printf(":");
  }
  printf("\n");
}

void print_frame(const u_char *frame, int frame_len)
{
  for(int i = 0; i < frame_len; i++)
  {
    int line_pos = i % 16; // column number (from 0 to 15)
    if(line_pos == 0)
      printf("0x%04X ", i);

    printf("%02x ", frame[i]);
    // larger gap in the middle
    if(i % 16 == 7)
      printf(" ");

    // last column or last line
    if(line_pos == 15 || i == frame_len - 1) {
      // gap if there are less than 16 bytes on line
      for(int j = 0; j < 15 - line_pos; j++) printf("   ");
      if(line_pos < 7) printf(" ");

      print_frame_ascii(frame, i - line_pos, i);
      printf("\n");
    }
  }
}

void print_frame_ascii(const u_char *packet, int start, int end)
{
  for(int i = start; i <= end; i++)
  {
    if(is_char_visible(packet[i]))
      printf("%c", packet[i]);
    else
      printf(".");
    
    // space in the middle
    if(i % 16 == 7)
      printf(" ");
  }
}

bool is_char_visible(u_char character)
{
  return character >= 33 && character <= 126;
}

void print_timestamp(const struct pcap_pkthdr *header)
{
  struct tm* time_data = localtime(&(header->ts.tv_sec));
  
  char datetime[20];
  strftime(datetime, 20, "%FT%T", time_data);
  char time_zone[10];
  strftime(time_zone, 10, "%z", time_data);
  auto mili_secs = header->ts.tv_usec / 1000;

  printf("timestamp: %s.%03lu%.3s:%.2s\n", datetime, mili_secs, time_zone, time_zone + 3);
}
