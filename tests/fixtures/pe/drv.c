/*
 * drv.c - a Windows-driver-shaped image for test_pe_real, built by clang and lld-link without an SDK: DriverEntry in the INIT
 * section (discardable), imports by name from ntoskrnl.exe and from HAL.dll, one import by ordinal, functions with unwind data
 * (.pdata, .xdata), initialised and zero-filled data, a table of function pointers (so base relocations), a CodeView PDB path.
 */
typedef long NTSTATUS;
typedef unsigned long long SIZE_T;

__declspec(dllimport) NTSTATUS IoCreateDevice(void *drv, unsigned ext, void *name, unsigned type, unsigned chars, unsigned char excl, void **dev);
__declspec(dllimport) void IoDeleteDevice(void *dev);
__declspec(dllimport) void *ExAllocatePoolWithTag(int type, SIZE_T n, unsigned tag);
__declspec(dllimport) void ExFreePoolWithTag(void *p, unsigned tag);
__declspec(dllimport) unsigned DbgPrint(const char *fmt, ...);
__declspec(dllimport) void KeStallExecutionProcessor(unsigned long us);
__declspec(dllimport) unsigned long long HalQueryCounterByOrdinal(void);

static unsigned long long counter;
static unsigned char scratch[8192];                         /* .bss */
const char banner[] = "fixture driver";                      /* .rdata */
long long table[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };             /* .data */

static NTSTATUS on_create(void *irp) { counter += (unsigned long long)irp; return 0; }
static NTSTATUS on_close(void *irp) { scratch[(unsigned long long)irp & 4095] = 1; return (NTSTATUS)counter; }
typedef NTSTATUS (*handler_t)(void *);
handler_t handlers[3] = { on_create, on_close, 0 };          /* .data, with a base relocation for each pointer */
handler_t many[601] = { [0 ... 600] = on_create };           /* 601 more: base relocations over two 4 KiB pages, one block with an odd count (padded) */

static void *device;

__attribute__((section("INIT"))) NTSTATUS DriverEntry(void *drv, void *registry_path)
{
    void *buf = ExAllocatePoolWithTag(1, 64, 'xtfD');
    DbgPrint("fixture: loaded %s %p\n", banner, buf);
    KeStallExecutionProcessor(5);
    counter = HalQueryCounterByOrdinal() + scratch[3];
    NTSTATUS st = IoCreateDevice(drv, 0, 0, 0x22, 0, 0, &device);
    ExFreePoolWithTag(buf, 'xtfD');
    return st + (NTSTATUS)(handlers[0](registry_path) + (int)table[3] + many[(unsigned long long)drv % 601](drv));
}

void DriverUnload(void *drv)
{
    IoDeleteDevice(device);
    DbgPrint("fixture: unloaded %p\n", drv);
}
