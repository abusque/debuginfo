#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libdwarf/dwarf.h> 	/* Used for DWARF constants
				 * definitions, such as DW_TAG_* */
#include "durin.h"
#include "so_info.h"

/*
 * Computes a shared object's in-memory size.
 *
 * Returns -1 if the computation failed, 0 if successful
 */
static
int so_info_compute_memsz(struct so_info *so)
{
	GElf_Phdr phdr;
	size_t i, phdrnum;
	so->memsz = 0;

	if (elf_getphdrnum(so->elf_file, &phdrnum)) {
		goto err;
	}

	for (i = 0; i < phdrnum; ++i) {
		double p_memsz, segment_size;

		if (gelf_getphdr(so->elf_file, i, &phdr) != &phdr) {
			goto err;
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

	return 0;

err:
	so->memsz = 0;
	return -1;
}

static
int so_info_set_dwarf_info(struct so_info *so)
{
	int ret;
	Dwarf_Error error;

	so->dwarf_info = malloc(sizeof(Dwarf_Debug));

	ret = dwarf_init(so->fd, DW_DLC_READ, NULL, NULL, so->dwarf_info,
			 &error);
	if (ret != DW_DLV_OK) {
		fprintf(stderr, "Failed do initialize DWARF info for %s\n",
			so->path);
		goto err;
	}

	return 0;

err:
	free(so->dwarf_info);
	return -1;
}

struct so_info *so_info_create(const char *path)
{
	struct so_info *so = malloc(sizeof(struct so_info));

	so->path = path;
	/* Only set dwarf_info the first time it is read, to avoid
	 * setting uselessly */
	so->dwarf_info = NULL;

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

	if (so_info_compute_memsz(so)) {
		fprintf(stderr, "Error: unable to compute memsz for %s\n",
			so->path);
		goto err;
	}

	so->low_addr = 0;	/* TODO: set from a baddr argument */
	so->high_addr = so->low_addr + so->memsz;

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
	if (so->dwarf_info != NULL) {
		dwarf_finish(*so->dwarf_info, NULL);
		free(so->dwarf_info);
	}
	free(so->ehdr);
	elf_end(so->elf_file);
	close(so->fd);
	free(so);
}

const char *get_function_name(struct so_info *so, uint64_t addr)
{
	const char *func_name = NULL;
	struct durin_cu *cu;

	/* Set DWARF info if it hasn't been accessed yet */
	if (so->dwarf_info == NULL) {
		if (so_info_set_dwarf_info(so)) {
			/* Failed to set DWARF info */
			return NULL;
		}
	}

	/* Addresses in DWARF are relative to base address for PIC, so make
	 * the address argument relative too if needed */
	if (so->is_pic) {
		addr -= so->low_addr;
	}

	for (cu = durin_cu_begin(so->dwarf_info); cu != NULL;
	cu = durin_cu_next(cu)) {
		struct durin_die *die;
		for (die = durin_die_begin(cu); die != NULL;
		die = durin_die_next(die)) {
			if (durin_die_get_tag(die) == DW_TAG_subprogram) {
				if (durin_die_contains_addr(die, addr)) {
					func_name = durin_die_get_name(die);
					break;
				}
			}
		}

		if (func_name != NULL) {
			/* Found the corresponding function, end iteration */
			break;
		}
	}

	return func_name;
}
