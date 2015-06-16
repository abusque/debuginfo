#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "so_info.h"

#define TEST_ADDR 0x401405

/*
 * For testing purposes only. Remove when implementing so_info_cache
 */
static struct so_info *so;
/*
 * Key: base address (uint64_t)
 * Value: SO Info (struct so_info *)
 */
static GHashTable *so_info_cache;
/*
 * Key: address (uint64_t)
 * Value: function name (char *)
 */
static GHashTable *function_names;
/*
 * Key: address (uint64_t)
 * Value: source location (struct source_location *)
 */
static GHashTable *source_locations;

static
void usage()
{
	printf("Usage: debuginfo <path/to/file>\n");
	exit(EXIT_SUCCESS);
}

/* Following hash/equal code based on g_int64_* */
static
guint g_uint64_hash(gconstpointer v)
{
	return (guint) *(const uint64_t *) v;
}

static
gboolean g_uint64_equal(gconstpointer v1, gconstpointer v2)
{
	return *((const uint64_t *) v1) == *((const uint64_t *) v2);
}

static
struct so_info *get_so_info_by_address(uint64_t address)
{
	/* TODO: implement lookup through so_info_cache */
	return so;
}

static
void destroy_free_data(gpointer data)
{
	free(data);
}

static
void destroy_source_location_data(gpointer data)
{
	source_location_destroy((struct source_location *) data);
}

static
const char *get_function_name(uint64_t address)
{
	gpointer value;
	const char *func_name;

	if ((value = g_hash_table_lookup(function_names, &address)) != NULL) {
		func_name = (const char *) value;
	} else {
		struct so_info *so = get_so_info_by_address(address);
		uint64_t *key = malloc(sizeof(uint64_t));

		func_name = so_info_lookup_function_name(so, address);
		*key = address;
		value = strdup(func_name);

		g_hash_table_insert(function_names, key, value);
	}

	return func_name;
}

static
struct source_location *get_source_location(uint64_t address)
{
	gpointer value;
	struct source_location *src_loc;

	if ((value = g_hash_table_lookup(source_locations, &address)) != NULL) {
		src_loc = (struct source_location *) value;
	} else {
		struct so_info *so = get_so_info_by_address(address);
		uint64_t *key = malloc(sizeof(uint64_t));

		src_loc = so_info_lookup_source_location(so, address);
		*key = address;
		value = src_loc;

		g_hash_table_insert(source_locations, key, value);
	}

	return src_loc;
}

static
void initialize(int argc, char *argv[])
{
	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed: %s\n",
			elf_errmsg(-1));
		exit(EXIT_FAILURE);
	}

	if ((so = so_info_create(argv[1])) == NULL) {
		exit(EXIT_FAILURE);
	}

	function_names = g_hash_table_new_full(g_uint64_hash, g_uint64_equal,
					destroy_free_data, destroy_free_data);
	source_locations = g_hash_table_new_full(g_uint64_hash, g_uint64_equal,
					destroy_free_data,
					destroy_source_location_data);
}

static
void teardown()
{
	so_info_destroy(so);
	g_hash_table_destroy(function_names);
	g_hash_table_destroy(source_locations);
}

int main(int argc, char *argv[])
{
	int i;

	if (argc != 2) {
		usage();
	}

	initialize(argc, argv);

	for (i = 0; i < 2; ++i) {
		uint64_t addr = TEST_ADDR + i * 2048;
		const char *func_name;
		struct source_location *src_loc;

		func_name = get_function_name(addr);
		src_loc = get_source_location(addr);
		printf("executable: %s - file: %s - function: %s - line: %llu\n",
		so->path, src_loc->filename, func_name, src_loc->line_no);
	}

	for (i = 0; i < 2; ++i) {
		uint64_t addr = TEST_ADDR + i * 2048;
		const char *func_name;
		struct source_location *src_loc;

		func_name = get_function_name(addr);
		src_loc = get_source_location(addr);
		printf("executable: %s - file: %s - function: %s - line: %llu\n",
		so->path, src_loc->filename, func_name, src_loc->line_no);
	}

	teardown();

	return EXIT_SUCCESS;
}
