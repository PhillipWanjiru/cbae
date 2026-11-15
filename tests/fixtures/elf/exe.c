/* exe.c - a linked file (ET_EXEC) for test_elf_real: static, no libc, an entry point and a few functions and data. */
static int table[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
int zeroed[16];
int sum(int n) { int s = 0; for (int i = 0; i < n && i < 8; i++) s += table[i]; return s; }
int apply(int (*f)(int), int v) { return f(v); }
void _start(void)
{
    int r = apply(sum, 5) + zeroed[3];
    __asm__ volatile("mov %0, %%edi\n\tmov $60, %%eax\n\tsyscall" : : "r"(r) : "rax", "rdi");
    for (;;) {}
}
