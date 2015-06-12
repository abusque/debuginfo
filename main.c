#include <stdio.h>
#include <stdlib.h>
#include "so_info.h"

#define TEST_ADDR 0x401405

static
void usage()
{
	printf("Usage: debuginfo <path/to/file>\n");
	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[])
{
	struct so_info *so;
	const char *func_name;
	struct source_location *src_loc;

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

	func_name = get_function_name(so, TEST_ADDR);
	src_loc = get_source_location(so, TEST_ADDR);
	printf("executable: %s - file: %s - function: %s - line: %llu\n",
	so->path, src_loc->filename, func_name, src_loc->line_no);

	so_info_destroy(so);
	source_location_destroy(src_loc);

	return EXIT_SUCCESS;
}
