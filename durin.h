#ifndef _DURIN_H
#define _DURIN_H

#include <stdint.h>
#include <stdlib.h>
#include <libdwarf/libdwarf.h>

/*
 * Durin is a wrapper over libdwarf providing a nicer, higher-level
 * interface, to access basic debug information. Durin is also the
 * eldest of the seven Fathers of the Dwarves created by the Vala Aulë
 * in the lore of Tolkien's Middle-earth.
 */

/*
 * This structure corresponds to a single compilation unit (CU) for a
 * given set of debug information (Dwarf_Debug type).
 */
struct durin_cu {
	Dwarf_Debug *dwarf_info;
	/* Offset in bytes within the DWARF
	 * file to beginning of CU header */
	Dwarf_Unsigned offset;
};

/*
 * This structure represents a single debug information entry (or DIE
 * for short), within a compilation unit (CU).
 */
struct durin_die {
	struct durin_cu *cu;
	Dwarf_Die *dwarf_die;
	/* A depth of 0 represents a root DIE, located in the DWARF
	 * layout on the same level as its corresponding CU entry. Its
	 * children DIEs will have a depth of 1, and so forth. All
	 * "interesting" DIEs for the present use case will be located
	 * at depth 1, however. */
	unsigned int depth;
};

struct durin_cu *durin_cu_begin(Dwarf_Debug *dwarf_info);
void durin_cu_destroy(struct durin_cu *cu);
struct durin_cu *durin_cu_next(struct durin_cu *cu);

struct durin_die *durin_die_begin(struct durin_cu *cu);
void durin_die_destroy(struct durin_die *die);
struct durin_die *durin_die_next(struct durin_die *die);
Dwarf_Half durin_die_get_tag(struct durin_die *die);
char *durin_die_get_name(struct durin_die *die);
int durin_die_contains_addr(struct durin_die *die, uint64_t addr);

#endif	/* _DURIN_H */
