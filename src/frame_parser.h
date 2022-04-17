/**
 * @file
 * @brief Frame parsing module API.
 *
 * Functions for parsing data from frames
 * and printing it to STDOUT.
 */

#ifndef __FRAME_PARSER_H__
#define __FRAME_PARSER_H__

#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>

// not properly included in system`s header files
// inspiration from:
// https://static.javatpoint.com/tutorial/computer-network/images/arp-packet-format.png
struct arpheader { 
    u_int16_t htype;
    u_int16_t ptype;
    u_char    hlen;
    u_char    plen;
    u_int16_t operation;
    u_char    sha[6];
    u_char    spa[4];
    u_char    tha[6];
    u_char    tpa[4];
};
// ------------------

/**
 * Callback for pcap_loop function.
 * Parses frame data and prints headers' contents
 * and whole frame (in hexa and ASCII format) to STDOUT.
 * @param user   Not used.
 * @param header Generic info about frame.
 * @param frame  Array of frame contents.
 */
void parse_frame(u_char *user, const struct pcap_pkthdr *header,
                 const u_char *frame);

/**
 * Print header data from ethernet header
 * and encapsulated headers.
 * @param frame     Array of frame contents.
 * @param frame_len Length of frame.
 */
void print_ether_info(const u_char *frame, int frame_len);

/**
 * Print header data from ARP header.
 * @param frame Array of frame contents.
 */
void print_arp_info(const u_char *frame);

/**
 * Print header data from IPv4 header
 * and encapsulated headers.
 * @param frame Array of frame contents.
 */
void print_ip4_info(const u_char *frame);

/**
 * Print header data from IPv6 header
 * and encapsulated headers.
 * @param frame Array of frame contents.
 */
void print_ip6_info(const u_char *frame);

/**
 * Print header data from ICMP header.
 * @param frame         Array of frame contents.
 * @param ip_header_len Length of IP header.
 */
void print_icmp_info(const u_char *frame, int ip_header_len);

/**
 * Print header data from TCP header.
 * @param frame         Array of frame contents.
 * @param ip_header_len Length of IP header.
 */
void print_tcp_info(const u_char *frame, int ip_header_len);

/**
 * Print header data from UDP header.
 * @param frame         Array of frame contents.
 * @param ip_header_len Length of IP header.
 */
void print_udp_info(const u_char *frame, int ip_header_len);

/**
 * Print MAC address.
 * @param mac_arr Array of MAC address bytes.
 */
void print_mac_addr(u_char mac_arr[6]);

/**
 * Print all frame bytes in hex and ASCII format.
 * @param frame     Array of frame contents.
 * @param frame_len Length of frame.
 */
void print_frame(const u_char *frame, int frame_len);

/**
 * Print all frame bytes in ASCII format.
 * If frame byte is not in the ASCII range 33-126,
 * dot is printed.
 * @param frame Array of frame contents.
 * @param start Index of first byte to print.
 * @param end   Index of last byte to print.
 */
void print_frame_ascii(const u_char *frame, int start, int end);

/**
 * Is character visible?
 * (in the ASCII range 33-126)
 * @param character Character to check.
 * @return True if visible. False otherwise. 
 */
bool is_char_visible(u_char character);

/**
 * Print frame timestamp.
 * @param header Generic info about frame.
 */
void print_timestamp(const struct pcap_pkthdr *header);

#endif // __FRAME_PARSER_H__
