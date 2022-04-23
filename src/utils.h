/**
 * @file
 * @brief Generic functions module API.
 *
 * Generic functionality.
 * Provides functions for argument parsing
 * and error exit function.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <string>

// ERROR EXIT CODES
// invalid CLI argument
#define INVARG_ERR   1
// pcap error
#define PCAPERR_ERR  2
// internal program error
#define INTERNAL_ERR 3

/**
 * @struct Arguments
 * @brief CLI argument settings.
 */
struct Arguments {
  std::string interface = "";
  int         port = -1;
  bool        all = true;
  bool        tcp = false;
  bool        udp = false;
  bool        arp = false;
  bool        icmp = false;
  bool        ipv4 = false;
  bool        ipv6 = false;
  int         num = 1;
};

/**
 * Get parsed data from CLI arguments.
 * Exits with error code if invalid
 * argument input.
 * @param argc CLI argument count.
 * @param argv CLI arguments array.
 * @return Arguments data.
 */
Arguments get_args(int argc, char* argv[]);

/**
 * Get string argument.
 * Exits with error code if missing.
 * @param pos  Argument position.
 * @param argc CLI argument count.
 * @param argv CLI arguments array.
 * @return Pointer to string argument.
 */
char* get_arg_str(int pos, int argc, char* argv[]);

/**
 * Convert string argument to number
 * and return it.
 * Exits with error code if missing
 * or not a number.
 * @param pos  Argument position.
 * @param argc CLI argument count.
 * @param argv CLI arguments array.
 * @return Number argument.
 */
int get_arg_num(int pos, int argc, char* argv[]);

/**
 * Print help message (how to use program) to the STDOUT.
 */
void print_help();

/**
 * Print error message to STDERR
 * and exit with error code.
 * @param error_code Error code to exit with.
 * @param message    Message to print to STDERR.
 */
void error_exit(int error_code, std::string message);

#endif // __UTILS_H__
