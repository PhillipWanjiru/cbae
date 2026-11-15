/*
 * kmod.c - a kernel-module-shaped relocatable object, built by a real compiler for test_elf_real: init/exit entry points, calls
 * that need relocations (PLT32), a data reference to an import, a function-pointer table, .modinfo and __ksymtab_strings written
 * the way <linux/module.h> leaves them. Compiled with the kernel code model, so addresses are 32-bit absolute (R_X86_64_32S).
 */
typedef unsigned long size_t;

extern int printk(const char *fmt, ...);
extern void *kmalloc(size_t n, unsigned flags);
extern void kfree(const void *p);
extern long jiffies_64;

static char *buffer;
static unsigned counter;
static unsigned char scratch[4096];

int exported_value = 42;
int table[4] __attribute__((section(".data.tbl"))) = { 1, 2, 3, 4 };

static int helper(int x) { return x * 3 + (int)counter + scratch[x & 255]; }

int exported_fn(int a) { counter++; return helper(a) + (int)jiffies_64; }

typedef int (*op_t)(int);
const op_t ops[] = { exported_fn, helper, 0 };

int init_module(void)
{
    printk("kmod: loading %d\n", exported_value);
    buffer = kmalloc(64, 0x20);
    return buffer ? 0 : -12;
}

void cleanup_module(void)
{
    kfree(buffer);
    printk("kmod: gone\n");
}

#define MODINFO(name, text) static const char name[] __attribute__((section(".modinfo"), used, aligned(1))) = text
MODINFO(mi_license,  "license=GPL");
MODINFO(mi_author,   "author=DELTA OPERATOR 771");
MODINFO(mi_desc,     "description=a fixture for the ELF loader tests");
MODINFO(mi_vermagic, "vermagic=6.8.0-fixture SMP mod_unload modversions");
#define KSYM(name, text) static const char name[] __attribute__((section("__ksymtab_strings"), used, aligned(1))) = text
KSYM(ks_fn,  "exported_fn");
KSYM(ks_val, "exported_value");
KSYM(ks_ghost, "ghost_export");                    /* named here, defined elsewhere: an export without a symbol */
