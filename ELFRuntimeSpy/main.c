#include "elf-arch.h"
#include "utils.h"
#include "cli.h"

int main(int argc, char *argv[])
{
    int pid;

	if (argc < 2) {
		xdebug(("usage: %s <pid>" , argv[0]));
		exit(-1);
	}

    pid = atoi(argv[1]);
    print_welcome();

    ptrace_attach(pid);
    xdebug(printf("attached to pid %d", pid));
    elf_rt_t target;
    set_pid(&target, pid);
    parse_elf(&target);
    print_elf(&target);
    ptrace_detach(pid);

}