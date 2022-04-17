/**
 * @file
 * @brief Sniffer module API.
 *
 * Functions to create pcap sniffer,
 * filter and start sniffing.
 */

#ifndef __SNIFFER__
#define __SNIFFER__

#include "utils.h"

#include <pcap.h>

/**
 * Lookup interfaces available on device
 * and print them.
 */
void print_interfaces();

/**
 * Create sniffer and filter from CLI arguments
 * and start sniffing.
 * @param args Arguments data.
 */
void sniff(Arguments args);

/**
 * Set filter on pcap interface handle.
 * @param pcap_handle pcap interface handle.
 * @param args        Arguments data.
 */
void set_filter(pcap_t* pcap_handle, Arguments args);

/**
 * Create filter string for pcap filter
 * from entered CLI arguments.
 * @param args Arguments data.
 */
std::string filter_string(Arguments args);

#endif // __SNIFFER__
