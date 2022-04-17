/**
 * @file
 * @brief Sniffer module.
 */

#include "sniffer.h"
#include "utils.h"
#include "frame_parser.h"

#include <iostream>
#include <pcap.h>

// pcap error buffer
char errbuf[PCAP_ERRBUF_SIZE];

void print_interfaces()
{
  pcap_if_t* interface_list;
  if(pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR) {
    error_exit(PCAPERR_ERR, errbuf);
  }

  while(interface_list != NULL) {
    std::cout << interface_list->name << "\n";
    interface_list = interface_list->next;
  }

  pcap_freealldevs(interface_list);
}

// packet buffer timeout in ms
constexpr int buffer_timeout = 1000;

void sniff(Arguments args)
{
  auto pcap_handle = pcap_open_live(args.interface.c_str(), BUFSIZ, true,
                                    buffer_timeout, errbuf);
  if(!pcap_handle) {
    error_exit(PCAPERR_ERR, errbuf);
  }

  if(pcap_datalink(pcap_handle) != DLT_EN10MB) {
    error_exit(PCAPERR_ERR, "Ethernet not supported on specified interface");
  } 

  set_filter(pcap_handle, args);
  pcap_loop(pcap_handle, args.num, parse_frame, NULL);
}

void set_filter(pcap_t* pcap_handle, Arguments args)
{
  auto filter_str = filter_string(args);

  bpf_u_int32 net;
  bpf_u_int32 mask;
  if(pcap_lookupnet(args.interface.c_str(), &net, &mask, errbuf) == PCAP_ERROR) {
    error_exit(PCAPERR_ERR, errbuf);
  }

  struct bpf_program bpf_prog;
  if(pcap_compile(pcap_handle, &bpf_prog, filter_str.c_str(), 0, mask) == PCAP_ERROR) {
    error_exit(INTERNAL_ERR, "Internal error");
  }
  if(pcap_setfilter(pcap_handle, &bpf_prog) == PCAP_ERROR) {
    error_exit(INTERNAL_ERR, "Internal error");
  }
}

std::string filter_string(Arguments args)
{
  // len < 0 => never true, but makes creating string simpler
  std::string filter = "len < 0 ";
  if(args.all) {
    filter += "or arp or icmp or icmp6 or tcp ";
    if(args.port != -1)
      filter += "port " + std::to_string(args.port) + " ";
    filter += "or udp ";
    if(args.port != -1)
      filter += "port " + std::to_string(args.port) + " ";
  }
  else {
    if(args.arp) {
      filter += "or arp ";
    }
    if(args.icmp) {
      filter += "or icmp or icmp6 ";
    }
    if(args.tcp) {
      filter += "or tcp ";
      if(args.port != -1)
        filter += "port " + std::to_string(args.port) + " ";
    }
    if(args.udp) {
      filter += "or udp ";
      if(args.port != -1)
        filter += "port " + std::to_string(args.port) + " ";
    }
    if(!args.tcp && !args.udp && args.port != -1) {
      filter += "or udp port " + std::to_string(args.port) +
                " or tcp port " + std::to_string(args.port);
    }
  }
 
  return filter;
}
