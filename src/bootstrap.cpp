#include <Windows.h>

typedef HMODULE (*load_library_w_f)(LPCWSTR);

typedef FARPROC (*get_proc_address_f)(HMODULE, LPCWSTR);

struct args {
    load_library_w_f load_library_w;
    get_proc_address_f get_proc_address;
    LPCWSTR dll_name;
    LPCWSTR inj_main_name;
};

static_assert(sizeof(args) == 32);

typedef void (*inj_main_f)();

int bootstrap(args *arg) {
    HMODULE dll = arg->load_library_w(arg->dll_name);
    FARPROC inj_main = arg->get_proc_address(dll, arg->inj_main_name);

    auto func = reinterpret_cast<inj_main_f>(inj_main);
    func();
    return 0;
}
