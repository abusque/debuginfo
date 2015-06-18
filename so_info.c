#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libdwarf/dwarf.h> 	/* Used for DWARF constants
				 * definitions, such as DW_TAG_* */
#include "durin.h"
#include "so_info.h"

/* The an adress printed in hex is at most 19 characters (16 for
 64-bits + leading 0x + optional leading '+' if addr is an offset +
 null character) */
#define ADDR_STR_LEN 20

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

	/* Check if the dwarf info has any CU. If not, the SO's object
	 * file contains no DWARF info */
	if (durin_cu_begin(so->dwarf_info) == NULL) {
		/* TODO: try to find separate debug info using
		 * build-id and debuglink methods before failing */
		goto err;
	}

	return 0;

err:
	dwarf_finish(*so->dwarf_info, NULL);
	free(so->dwarf_info);
	so->dwarf_info = NULL;
	return -1;
}

struct so_info *so_info_create(const char *path)
{
	struct so_info *so = malloc(sizeof(struct so_info));

	so->path = path;
	/* Only set dwarf_info the first time it is read, to avoid
	 * setting uselessly */
	so->dwarf_info = NULL;
	so->is_elf_only = 0;

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

void source_location_destroy(struct source_location *src_loc)
{
	free(src_loc);
}

static
const char *so_info_lookup_elf_function_name(struct so_info *so, uint64_t addr)
{
	/* TODO: add flag to so_info indicating whether the ELF file
	 * is stripped, and behave accordingly */
	char *func_name = NULL, *sym_name = NULL;
	char offset_str[ADDR_STR_LEN];
	Elf_Scn *scn = NULL;
	GElf_Shdr nearest_shdr;
	GElf_Sym nearest_sym;
	int nearest_sym_set = 0;
	uint64_t offset;

	while ((scn = elf_nextscn(so->elf_file, scn)) != NULL) {
		Elf_Data *data;
		GElf_Shdr shdr;
		int i, symbol_count;

		gelf_getshdr(scn, &shdr);
		if (shdr.sh_type != SHT_SYMTAB) {
			/* We are only interested in symbol table
			 * (symtab) sections, skip the rest */
			continue;
		}

		data = elf_getdata(scn, NULL);
		symbol_count = shdr.sh_size / shdr.sh_entsize;

		for (i = 0; i < symbol_count; ++i) {
			GElf_Sym cur_sym;
			gelf_getsym(data, i, &cur_sym);
			if (GELF_ST_TYPE(cur_sym.st_info) != STT_FUNC) {
				/* We're only interested in the functions */
				continue;
			}

			if (!nearest_sym_set) {
				if (cur_sym.st_value <= addr) {
					nearest_sym = cur_sym;
					nearest_sym_set = 1;
				}
				continue;
			}

			if (cur_sym.st_value <= addr &&
			cur_sym.st_value > nearest_sym.st_value) {
				nearest_shdr = shdr;
				nearest_sym = cur_sym;
			}
		}
	}

	if (!nearest_sym_set) {
		/* No associated function found */
		goto end;
	}

	sym_name = elf_strptr(so->elf_file, nearest_shdr.sh_link,
			nearest_sym.st_name);
	offset = addr - nearest_sym.st_value;
	snprintf(offset_str, ADDR_STR_LEN, "+%#018lx", offset);

	func_name = malloc(strlen(sym_name) + strlen(offset_str) + 1);
	strcpy(func_name, sym_name);
	strcat(func_name, offset_str);

end:
	return func_name;
}

static
const char *so_info_lookup_dwarf_function_name(struct so_info *so,
					uint64_t addr)
{
	const char *func_name = NULL;
	struct durin_cu *cu;

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
					durin_die_destroy(die);
					break;
				}
			}
		}

		if (func_name != NULL) {
			/* Found the corresponding function, end iteration */
			durin_cu_destroy(cu);
			break;
		}
	}

	return func_name;
}

const char *so_info_lookup_function_name(struct so_info *so, uint64_t addr)
{
	const char *func_name = NULL;

	/* Set DWARF info if it hasn't been accessed yet */
	if (so->dwarf_info == NULL && !so->is_elf_only) {
		if (so_info_set_dwarf_info(so)) {
			/* Failed to set DWARF info */
			so->is_elf_only = 1;
		}
	}

	if (so->is_elf_only) {
		func_name = so_info_lookup_elf_function_name(so, addr);
	} else {
		func_name = so_info_lookup_dwarf_function_name(so, addr);
	}

	return func_name;
}

struct source_location *so_info_lookup_source_location(struct so_info *so,
						uint64_t addr)
{
	struct source_location *src_loc = NULL;
	struct durin_cu *cu;

	/* Set DWARF info if it hasn't been accessed yet */
	if (so->dwarf_info == NULL && !so->is_elf_only) {
		if (so_info_set_dwarf_info(so)) {
			/* Failed to set DWARF info */
			so->is_elf_only = 1;
		}
	}

	if (so->is_elf_only) {
		/* We cannot lookup source location without DWARF info */
		return NULL;
	}

	/* Addresses in DWARF are relative to base address for PIC, so make
	 * the address argument relative too if needed */
	if (so->is_pic) {
		addr -= so->low_addr;
	}

	for (cu = durin_cu_begin(so->dwarf_info); cu != NULL;
	cu = durin_cu_next(cu)) {
		struct durin_die *die = durin_die_begin(cu);

		int i, ret;
		Dwarf_Line *line_buf = NULL;
		Dwarf_Line prev_line = NULL;
		Dwarf_Signed line_count = 0;
		Dwarf_Error error;

		ret = dwarf_srclines(*die->dwarf_die, &line_buf, &line_count,
				&error);
		if (ret) {
			durin_die_destroy(die);
			durin_cu_destroy(cu);
			goto end;
		}

		for (i = 0; i < line_count; ++i) {
			Dwarf_Line cur_line = line_buf[i];
			Dwarf_Addr low_pc, high_pc, tmp_pc;

			if (prev_line == NULL) {
				prev_line = cur_line;
				continue;
			}

			dwarf_lineaddr(prev_line, &low_pc, &error);
			dwarf_lineaddr(cur_line, &high_pc, &error);

			if (low_pc > high_pc) {
				tmp_pc = low_pc;
				low_pc = high_pc;
				high_pc = tmp_pc;
			}

			if (low_pc <= addr && addr <= high_pc) {
				src_loc = malloc(
					sizeof(struct source_location));
				dwarf_linesrc(prev_line, &src_loc->filename,
					&error);
				dwarf_lineno(prev_line, &src_loc->line_no,
					&error);

				durin_die_destroy(die);
				durin_cu_destroy(cu);

				goto end;
			}

			prev_line = cur_line;
		}

		durin_die_destroy(die);
	}

end:
	return src_loc;
}
