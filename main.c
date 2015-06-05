#include <stdio.h>
#include <stdlib.h>
#include "so_info.h"

static
void usage()
{
	printf("Usage: debuginfo <path/to/file>\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	struct so_info *so;

	if (argc != 2) {
		usage();
	}

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s\n",
			elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	if ((so = so_info_create(argv[1])) == NULL) {
		exit(EXIT_FAILURE);
	}

	printf("%s\n", so->path);
	so_info_destroy(so);

	return EXIT_SUCCESS;
}
