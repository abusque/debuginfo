#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "so_info.h"

/*
 * Computes a shared object's in-memory size.
 *
 * Returns 0 if the computation failed, the memsz (a positive
 * integer) if succesful.
 */
static
uint64_t so_info_compute_memsz(struct so_info *so)
{
	GElf_Phdr phdr;
	size_t i, phdrnum;
	so->memsz = 0;

	if (elf_getphdrnum(so->elf_file, &phdrnum) != 0) {
		goto end;
	}

	for (i = 0; i < phdrnum; ++i) {
		double p_memsz, segment_size;

		if (gelf_getphdr(so->elf_file, i, &phdr) != &phdr) {
			so->memsz = 0;
			goto end;
		}

		/* Only PT_LOAD segments contribute to memsz. Skip the
		 * rest */
		if (phdr.p_type != PT_LOAD) {
			continue;
		}

		/* Take into account the segment alignment when
		 * computing its memory size */
		p_memsz = (double) phdr.p_memsz;
		segment_size = ceil(p_memsz / phdr.p_align) * phdr.p_align;
		so->memsz += (int) segment_size;
	}

end:
	return so->memsz;
}

struct so_info *so_info_create(const char *path)
{
	struct so_info *so = malloc(sizeof(struct so_info));

	so->path = path;

	if ((so->fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Failed to open %s\n", path);
		goto err;
	}

	if ((so->elf_file = elf_begin(so->fd, ELF_C_READ, NULL)) == NULL) {
		fprintf(stderr, "elf_begin failed: %s\n",
			elf_errmsg(-1));
		goto err;
	}

	if (elf_kind(so->elf_file) != ELF_K_ELF) {
		fprintf(stderr, "Error: %s is not and ELF object\n", so->path);
		goto err;
	}

	so->ehdr = malloc(sizeof(GElf_Ehdr));

	if (gelf_getehdr(so->elf_file, so->ehdr) == NULL) {
		fprintf(stderr, "Error: couldn't get ehdr for %s\n", so->path);
		goto err;
	}

	/* Position independent code has an e_type value of ET_DYN */
	so->is_pic = so->ehdr->e_type == ET_DYN;

	if(!so_info_compute_memsz(so)) {
		fprintf(stderr, "Error: unable to compute memsz for %s\n",
			so->path);
		goto err;
	}

	return so;

err:
	if (so->ehdr != NULL) {
		free(so->ehdr);
	}
	if (so->elf_file != NULL) {
		elf_end(so->elf_file);
	}
	close(so->fd);
	free(so);

	return NULL;
}

void so_info_destroy(struct so_info *so)
{
	free(so->ehdr);
	elf_end(so->elf_file);
	close(so->fd);
	free(so);
}
