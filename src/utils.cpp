/**
 * @file
 * @brief Generic functions module.
 */

#include "utils.h"

#include <iostream>
#include <string>
#include <string.h>

Arguments get_args(int argc, char*argv[])
{
  Arguments args;

  for(int i = 1; i < argc; i++)
  {
    if(!strcmp(argv[i], "-i") || !strcmp(argv[i], "--interface")) {
      // no interface entered
      if(i + 1 == argc || argv[i + 1][0] == '-') {
        args.interface = "";
      }
      else {
        args.interface = get_arg_str(i + 1, argc, argv);
        i++;
      }
    }
    else if(!strcmp(argv[i], "-p")) {
      args.port = get_arg_num(i + 1, argc, argv);
      if(args.port < 0 || args.port > 65535) {
        error_exit(INVARG_ERR,
                   std::string("port number invalid: ") + argv[i + 1]);
      }
      i++;
    }
    else if(!strcmp(argv[i], "-t") || !strcmp(argv[i], "--tcp")) {
      args.all = false;
      args.tcp = true;
    }
    else if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--udp")) {
      args.all = false;
      args.udp = true;
    }
    else if(!strcmp(argv[i], "--arp")) {
      args.all = false;
      args.arp = true;
    }
    else if(!strcmp(argv[i], "--icmp")) {
      args.all = false;
      args.icmp = true;
    }
    else if(!strcmp(argv[i], "-n")) {
      args.num = get_arg_num(i + 1, argc, argv);
      if(args.num < 0) {
        error_exit(INVARG_ERR,
                   std::string("-n number negative: ") + argv[i + 1]);
      }
      i++;
    }
    else {
      error_exit(INVARG_ERR,
                 std::string("unknown argument: ") + argv[i]);
    }
  }

  return args;
}

char* get_arg_str(int pos, int argc, char* argv[])
{
  if(pos < argc) {
    return argv[pos];
  }
  else {
    error_exit(INVARG_ERR,
               argv[pos - 1] + std::string(": no argument entered"));
  }

  return NULL;
}

int get_arg_num(int pos, int argc, char* argv[])
{
  if(pos < argc) {
    try {
      return std::stoi(argv[pos]);
    }
    catch(const std::invalid_argument& e) {
      error_exit(INVARG_ERR,
                 argv[pos] + std::string(": not a number"));
    }
  }
  else {
    error_exit(INVARG_ERR,
               argv[pos - 1] + std::string(": no argument entered"));
  }

  return 0;
}

void error_exit(int error_code, std::string message)
{
  std::cerr << "ERROR: " << message << "\n";
  std::exit(error_code);
}
