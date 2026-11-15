/*
 * lib.c - a linked file (ET_DYN) for test_elf_real: a shared object built with -nostdlib, so it keeps its symbol table and has
 * what a real one has: .dynsym, .rela.dyn and .rela.plt (relocations against the dynamic symbols, not .symtab), .plt, .got.
 */
extern int ext_a(int);
extern int ext_data;
extern void (*weak_hook)(void) __attribute__((weak));

int exported_counter = 5;
static int local_counter;
int (*fp_table[3])(int) = { ext_a, 0, ext_a };

int api_call(int x) { return ext_a(x) + ext_data + exported_counter + local_counter++; }
void *get_hook(void) { return (void *)weak_hook; }
