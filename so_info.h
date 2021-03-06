#ifndef _SO_INFO_H
#define _SO_INFO_H

#include <stdint.h>
#include <gelf.h>
#include <libdwarf/libdwarf.h>

struct so_info {
	const char *path;
	int fd;
	Elf *elf_file;
	GElf_Ehdr *ehdr;
	Dwarf_Debug *dwarf_info;
	uint8_t is_pic : 1;	/* Denotes whether the executable is
				 * position independent code or not */
	uint8_t is_elf_only : 1; /* Denotes whether the SO only has
				  * ELF symbols, and not DWARF info,
				  * available for lookup */
	uint64_t low_addr;	/* Base virtual memory address */
	uint64_t high_addr;	/* Upper bound of exec address space */
	uint64_t memsz;		/* Size of exec address space */
};

struct source_location {
	char* filename;
	long long unsigned int line_no;
};

struct so_info *so_info_create(const char *path);
void so_info_destroy(struct so_info *so);

void source_location_destroy(struct source_location *src_loc);

const char *so_info_lookup_function_name(struct so_info *so, uint64_t addr);
struct source_location *so_info_lookup_source_location(struct so_info *so,
						uint64_t addr);

#endif	/* _SO_INFO_H */
