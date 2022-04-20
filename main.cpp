#include "src/utils.h"
#include "src/sniffer.h"

#include <signal.h>

/**
 * Handle SIGINT signal by exiting
 * with zero code.
 * @param pid process ID 
 */
void sigint_handle(int pid);

int main(int argc, char*argv[])
{
  signal(SIGINT, sigint_handle);

  Arguments args = get_args(argc, argv);
  if(args.interface == "") {
    print_interfaces();
  }
  else {
    sniff(args);
  }

  return 0;
}

void sigint_handle(int pid)
{
  (void)pid;

  exit(0);
}
