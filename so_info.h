#ifndef SO_INFO_H
#define SO_INFO_H

#include <stdint.h>
#include <gelf.h>

struct so_info {
	const char *path;
	int fd;
	void *elf_file; 	/* Of Elf type */
	GElf_Ehdr *ehdr;
	uint8_t is_pic : 1;	/* Denotes whether the executable is
				 * position independent code or not */
	uint64_t memsz;
};

struct so_info *so_info_create(const char *path);
void so_info_destroy(struct so_info *so);

#endif	/* SO_INFO_H */
