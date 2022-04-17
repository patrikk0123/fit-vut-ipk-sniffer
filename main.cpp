#include "src/utils.h"
#include "src/sniffer.h"

int main(int argc, char*argv[])
{
  Arguments args = get_args(argc, argv);
  if(args.interface == "") {
    print_interfaces();
  }
  else {
    sniff(args);
  }

  return 0;
}
