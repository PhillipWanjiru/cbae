// cxx.cc - a C++ relocatable object for test_elf_real: COMDAT groups (SHT_GROUP, SHF_GROUP), weak symbols, a vtable and type
// information, a template, a function-local static with a guard, thread-local storage, exceptions (.eh_frame, .gcc_except_table),
// a global constructor (.init_array). Nothing here is meant to run.
extern "C" int external_c(int);

struct Base { virtual ~Base() {} virtual int f(int) = 0; };

template <typename T> T twice(T x) { return x + x; }
inline int inl(int x) { return external_c(x) + 1; }

struct Derived : Base { int f(int x) override { return inl(x) + twice(x) + twice(2.5) > 0; } };

static thread_local int tl_counter;
int use_tl() { return ++tl_counter; }

int guarded() { static int v = inl(3); return v; }

int thrower(int x) { if (x) throw x; return 0; }
int catcher(int x) { try { return thrower(x); } catch (int e) { return e; } }

Derived global_derived;
int global_initialised = inl(7);
