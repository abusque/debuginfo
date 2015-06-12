#include "durin.h"

static
int durin_cu_next_header(Dwarf_Debug *dwarf_info, Dwarf_Unsigned *cu_offset)
{
	return dwarf_next_cu_header(
		*dwarf_info, NULL, NULL, NULL, NULL, cu_offset, NULL);
}

static
void durin_cu_reset_internal_state(Dwarf_Debug *dwarf_info)
{
	/*
	 * XXX: So it turns out libdwarf keeps a the value of the last
	 * reader CU header's offset, stored internally within the
	 * opaque Dwarf_Debug structure, from which it then computes
	 * the offset of the next header and fetches it. Therefore,
	 * the only apparent way to reset this offset is to iterate
	 * over all CUs until they wrap over, short of instantiating a
	 * new Dwarf_Debug structure. This makes reading from a random
	 * offset, which should be a trivial task, completely
	 * impractical.
	 */
	Dwarf_Unsigned cu_offset;
	while (dwarf_next_cu_header(*dwarf_info, NULL, NULL, NULL, NULL,
				   &cu_offset, NULL) != DW_DLV_NO_ENTRY) {
		/* Do nothing, just iterate until the end of CUs to
		 * reset the internal state. There is no other way,
		 * unfortunately. */
	}
}

struct durin_cu *durin_cu_begin(Dwarf_Debug *dwarf_info)
{
	struct durin_cu *cu;
	Dwarf_Unsigned cu_offset = 0;

	durin_cu_reset_internal_state(dwarf_info);
	if (durin_cu_next_header(dwarf_info, &cu_offset)) {
		/* Failed to fetch beginning CU */
		goto err;
	}

	cu = malloc(sizeof(struct durin_cu));
	cu->dwarf_info = dwarf_info;
	cu->offset = cu_offset;

	return cu;

err:
	return NULL;
}

void durin_cu_destroy(struct durin_cu *cu)
{
	free(cu);
}

struct durin_cu *durin_cu_next(struct durin_cu *cu)
{
	Dwarf_Unsigned cu_offset;

	if (durin_cu_next_header(cu->dwarf_info, &cu_offset)) {
		/* Failed to fetch beginning CU */
		goto err;
	}

	cu->offset = cu_offset;

	return cu;

err:
	durin_cu_destroy(cu);
	return NULL;
}

struct durin_die *durin_die_begin(struct durin_cu *cu)
{
	struct durin_die *die;
	Dwarf_Die *dwarf_die = malloc(sizeof(Dwarf_Die));
	Dwarf_Error error;

	dwarf_siblingof(*cu->dwarf_info, NULL, dwarf_die, &error);

	die = malloc(sizeof(struct durin_die));
	die->cu = cu;
	die->dwarf_die = dwarf_die;
	die->depth = 0;		/* Depth 0 for root DIE */

	return die;
}

void durin_die_destroy(struct durin_die *die)
{
	dwarf_dealloc(*die->cu->dwarf_info, *die->dwarf_die, DW_DLA_DIE);
	free(die->dwarf_die);
	free(die);
}

struct durin_die *durin_die_next(struct durin_die *die)
{
	int ret;
	Dwarf_Die *next_die = malloc(sizeof(Dwarf_Die));
	Dwarf_Error error;

	if (die->depth == 0) {
		ret = dwarf_child(*die->dwarf_die, next_die, &error);
		if (ret != DW_DLV_OK) {
			/* No child DIE */
			goto err;
		}

		die->depth = 1;
	} else {
		ret = dwarf_siblingof(*die->cu->dwarf_info, *die->dwarf_die,
				next_die, &error);
		if (ret == DW_DLV_NO_ENTRY) {
			/* Reached end of DIEs at this depth */
			goto err;
		}
	}

	dwarf_dealloc(*die->cu->dwarf_info, *die->dwarf_die, DW_DLA_DIE);
	free(die->dwarf_die);
	die->dwarf_die = next_die;
	return die;

err:
	free(next_die);
	durin_die_destroy(die);
	return NULL;
}

Dwarf_Half durin_die_get_tag(struct durin_die *die)
{
	Dwarf_Half tag;
	Dwarf_Error error;

	dwarf_tag(*die->dwarf_die, &tag, &error);
	return tag;
}

char *durin_die_get_name(struct durin_die *die)
{
	char *name;
	Dwarf_Error error;

	dwarf_diename(*die->dwarf_die, &name, &error);
	return name;
}

int durin_die_contains_addr(struct durin_die *die, uint64_t addr)
{
	int ret;
	Dwarf_Addr low_pc, high_pc;
	Dwarf_Half form;
	enum Dwarf_Form_Class class;
	Dwarf_Error error;

	ret = dwarf_lowpc(*die->dwarf_die, &low_pc, &error);
	if (ret != DW_DLV_OK) {
		goto err;
	}

	ret = dwarf_highpc_b(*die->dwarf_die, &high_pc, &form, &class, &error);
	if (ret != DW_DLV_OK) {
		goto err;
	}

	if (class != DW_FORM_CLASS_ADDRESS) {
		/* high_pc is an offset relative to low_pc, compute
		 * the absolute address */
		high_pc += low_pc;
	}

	return low_pc <= addr && addr <= high_pc;

err:
	return 0;
}
