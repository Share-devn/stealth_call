#pragma once
#include "common.hpp"
#include "hash.hpp"
#include "peb.hpp"
#include "xorstr.hpp"

namespace stealth::sc {
    namespace h {
        constexpr unsigned int ntdll           = HASH_CI ("ntdll.dll");
        constexpr unsigned int kernel32        = HASH_CI ("kernel32.dll");
        constexpr unsigned int NtCreateSection = HASH ("NtCreateSection");
        constexpr unsigned int NtOpenSection   = HASH ("NtOpenSection");
        constexpr unsigned int NtMapView       = HASH ("NtMapViewOfSection");
        constexpr unsigned int NtUnmapView     = HASH ("NtUnmapViewOfSection");
        constexpr unsigned int NtClose         = HASH ("NtClose");
        constexpr unsigned int NtAllocVM       = HASH ("NtAllocateVirtualMemory");
        constexpr unsigned int NtFreeVM        = HASH ("NtFreeVirtualMemory");
        constexpr unsigned int NtProtectVM     = HASH ("NtProtectVirtualMemory");
        constexpr unsigned int NtTerminate     = HASH ("NtTerminateProcess");
        constexpr unsigned int NtWriteFile     = HASH ("NtWriteFile");
        constexpr unsigned int NtReadFile      = HASH ("NtReadFile");
        constexpr unsigned int NtQueryInfoProc = HASH ("NtQueryInformationProcess");
        constexpr unsigned int FlushIC         = HASH ("NtFlushInstructionCache");
        constexpr unsigned int LdrLoadDll      = HASH ("LdrLoadDll");
        constexpr unsigned int RtlInitUniStr   = HASH ("RtlInitUnicodeString");
        constexpr unsigned int GetStdHandle    = HASH ("GetStdHandle");
        constexpr unsigned int RtlAddVEH       = HASH ("RtlAddVectoredExceptionHandler");
        constexpr unsigned int RtlRemoveVEH    = HASH ("RtlRemoveVectoredExceptionHandler");
        // For trampoline
        constexpr unsigned int CreateFileW     = HASH ("CreateFileW");
        constexpr unsigned int GetFileSize_h   = HASH ("GetFileSize");
        constexpr unsigned int ReadFile_h      = HASH ("ReadFile");
        constexpr unsigned int SetFilePointer  = HASH ("SetFilePointer");
        constexpr unsigned int CloseHandle     = HASH ("CloseHandle");
    }

    // NT types
    using fn_NtCreateSection      = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    using fn_NtOpenSection        = NTSTATUS (NTAPI*)(PHANDLE, ACCESS_MASK, PVOID);
    using fn_NtMapViewOfSection   = NTSTATUS (NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
    using fn_NtUnmapViewOfSection = NTSTATUS (NTAPI*)(HANDLE, PVOID);
    using fn_NtClose              = NTSTATUS (NTAPI*)(HANDLE);
    using fn_NtAllocVM            = NTSTATUS (NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    using fn_NtFreeVM             = NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);
    using fn_NtProtectVM          = NTSTATUS (NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

    struct syscall_entry {
        unsigned int name_hash;
        unsigned int number;
        unsigned int xor_key;
    };

    inline static_map<syscall_entry, 2048> g_map;
    inline uintptr_t g_syscall_ret_addr = 0; 
    inline uintptr_t g_ret_gadget = 0;        
    inline bool g_initialized = false;
    inline spinlock g_lock;
    inline constexpr unsigned int sig_key = 0x7A3F19E2u;
    inline constexpr unsigned int sig_xored = 0xB8D18B4Cu ^ sig_key;
    struct scratch_page { void* base; SIZE_T size; };
    inline static_map<scratch_page, 64> g_scratch_pages;
    inline spinlock g_scratch_lock;

    __forceinline void emit_b (unsigned char*& p, unsigned char val, xorshift64& rng) {
        volatile unsigned char mask = static_cast<unsigned char>(rng.next ());
        *p++ = (val ^ mask) ^ mask;
    }

    namespace opc_store {
        inline constexpr unsigned char tmpl_a[] = { 0x51, 0x41, 0x5A };              // push rcx; pop r10
        inline constexpr unsigned char tmpl_b[] = { 0x49, 0x89, 0xCA };              // mov r10, rcx
        inline constexpr unsigned char tmpl_mov_eax = 0xB8;
        inline constexpr unsigned char tmpl_xor_eax = 0x35;
        inline constexpr unsigned char tmpl_jmp[] = { 0xFF, 0x25 };
        inline void emit_encrypted (unsigned char*& p, const unsigned char* src,
                                     size_t len, unsigned char key) {
            for (size_t i = 0; i < len; i++) {
                volatile unsigned char k = key;
                unsigned char enc = src[i] ^ k;
                *p++ = enc ^ k;
            }
        }
    }

    namespace junk {
        struct entry { unsigned char raw[6]; size_t len; };

        inline constexpr entry pool[] = {
            { { 0x90 },                             1 },
            { { 0x66, 0x90 },                       2 },
            { { 0x0F, 0x1F, 0x00 },                 3 },
            { { 0x48, 0x87, 0xC9 },                 3 },
            { { 0x48, 0x87, 0xD2 },                 3 },
            { { 0x50, 0x58 },                        2 },
            { { 0x53, 0x5B },                        2 },
            { { 0x4D, 0x31, 0xDB },                  3 },
            { { 0xF5 },                              1 },
            { { 0xF8 },                              1 },
            { { 0x48, 0x8D, 0x40, 0x00 },            4 },
            { { 0x0F, 0x1F, 0x40, 0x00 },            4 },
        };

        inline constexpr size_t count = sizeof(pool) / sizeof(pool[0]);

        __forceinline void emit (unsigned char*& p, size_t idx, unsigned char call_key) {
            for (size_t i = 0; i < pool[idx].len; i++) {
                volatile unsigned char k = call_key;
                volatile unsigned char enc = pool[idx].raw[i] ^ k;
                *p++ = enc ^ k;
            }
        }
    }

    namespace detail {

        inline unsigned int get_tid () {
            return static_cast<unsigned int>(
                *reinterpret_cast<uint64_t*>(__readgsqword (0x30) + 0x48));
        }

        inline void* get_scratch_page () {
            unsigned int tid = get_tid ();
            {
                lock_guard guard (g_scratch_lock);
                auto* sp = g_scratch_pages.find (tid);
                if (sp && sp->base) return sp->base;
            }

            uintptr_t ntdll = peb::get_module_base (h::ntdll);
            auto nt_alloc = reinterpret_cast<fn_NtAllocVM>(peb::get_export (ntdll, h::NtAllocVM));
            if (!nt_alloc) return nullptr;

            void* base = nullptr;
            xorshift64 size_rng (__rdtsc () ^ tid);
            SIZE_T sz = 0x1000 * (1 + size_rng.next_range (2));
            NTSTATUS status = nt_alloc (NtCurrentProcess (), &base, 0, &sz,
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS (status)) return nullptr;

            scratch_page sp;
            sp.base = base;
            sp.size = sz;

            lock_guard guard (g_scratch_lock);
            g_scratch_pages.insert (tid, sp);
            return base;
        }

        // Protect scratch page
        inline bool protect_page (void* base, SIZE_T size, ULONG prot) {
            uintptr_t ntdll = peb::get_module_base (h::ntdll);
            auto nt_protect = reinterpret_cast<fn_NtProtectVM>(peb::get_export (ntdll, h::NtProtectVM));
            if (!nt_protect) return false;
            ULONG old;
            PVOID b = base;
            SIZE_T s = size;
            return NT_SUCCESS (nt_protect (NtCurrentProcess (), &b, &s, prot, &old));
        }

        inline uintptr_t find_syscall_ret (uintptr_t ntdll_base) {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_base);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ntdll_base + dos->e_lfanew);
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION (nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    auto* s = reinterpret_cast<unsigned char*>(ntdll_base + sec[i].VirtualAddress);
                    size_t sz = sec[i].Misc.VirtualSize;
                    for (size_t j = 0; j + 2 < sz; j++) {
                        if (s[j] == 0x0F && s[j + 1] == 0x05 && s[j + 2] == 0xC3)
                            return reinterpret_cast<uintptr_t>(s + j);
                    }
                }
            }
            return 0;
        }

        inline uintptr_t find_ret_gadget (uintptr_t base) {
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION (nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                    auto* s = reinterpret_cast<unsigned char*>(base + sec[i].VirtualAddress);
                    for (size_t j = 0; j < sec[i].Misc.VirtualSize; j++) {
                        if (s[j] == 0xC3) return reinterpret_cast<uintptr_t>(s + j);
                    }
                }
            }
            return 0;
        }

        inline unsigned int rva_to_offset (unsigned int rva, IMAGE_NT_HEADERS* nt) {
            IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION (nt);
            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
                if (rva >= sec[i].VirtualAddress &&
                    rva < sec[i].VirtualAddress + sec[i].Misc.VirtualSize)
                    return rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
            }
            return rva;
        }

        inline unsigned char* map_ntdll_from_knowndlls (size_t* out_size) {
            uintptr_t ntdll = peb::get_module_base (h::ntdll);
            if (!ntdll) return nullptr;

            auto nt_open_section = reinterpret_cast<fn_NtOpenSection>(peb::get_export (ntdll, h::NtOpenSection));
            auto nt_map_view = reinterpret_cast<fn_NtMapViewOfSection>(peb::get_export (ntdll, h::NtMapView));
            auto nt_close = reinterpret_cast<fn_NtClose>(peb::get_export (ntdll, h::NtClose));
            if (!nt_open_section || !nt_map_view || !nt_close) return nullptr;

            wchar_t section_name[22];
            XOR_W_STACK (L"\\KnownDlls\\ntdll.dll", section_name);

            UNICODE_STRING us;
            us.Length = 20 * sizeof (wchar_t);
            us.MaximumLength = 21 * sizeof (wchar_t);
            us.Buffer = section_name;

            OBJECT_ATTRIBUTES oa;
            oa.Length = sizeof (OBJECT_ATTRIBUTES);
            oa.RootDirectory = nullptr;
            oa.ObjectName = &us;
            oa.Attributes = OBJ_CASE_INSENSITIVE;
            oa.SecurityDescriptor = nullptr;
            oa.SecurityQualityOfService = nullptr;

            HANDLE sh = nullptr;
            NTSTATUS status = nt_open_section (&sh, SECTION_MAP_READ, &oa);
            mem_set (section_name, 0, sizeof (section_name));
            if (!NT_SUCCESS (status)) return nullptr;

            void* view = nullptr;
            SIZE_T view_size = 0;
            status = nt_map_view (sh, NtCurrentProcess (), &view, 0, 0, nullptr, &view_size, 1, 0, PAGE_READONLY);
            nt_close (sh);
            if (!NT_SUCCESS (status) || !view) return nullptr;

            *out_size = view_size;
            return reinterpret_cast<unsigned char*>(view);
        }

        inline bool extract_syscalls () {
            size_t ntdll_size = 0;
            unsigned char* ntdll_data = map_ntdll_from_knowndlls (&ntdll_size);
            if (!ntdll_data || ntdll_size == 0) return false;

            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(ntdll_data);
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(ntdll_data + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

            unsigned int export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(ntdll_data + rva_to_offset (export_rva, nt));
            auto* funcs = reinterpret_cast<unsigned int*>(ntdll_data + rva_to_offset (exp->AddressOfFunctions, nt));
            auto* names = reinterpret_cast<unsigned int*>(ntdll_data + rva_to_offset (exp->AddressOfNames, nt));
            auto* ords = reinterpret_cast<unsigned short*>(ntdll_data + rva_to_offset (exp->AddressOfNameOrdinals, nt));

            // XOR'd signature — volatile prevents const-folding
            volatile unsigned int sig_k = sig_key;
            unsigned int sig = sig_xored ^ sig_k;

            xorshift64 rng (__rdtsc () ^ reinterpret_cast<uint64_t>(peb::get_peb ()));

            for (unsigned int i = 0; i < exp->NumberOfNames; i++) {
                const char* name = reinterpret_cast<const char*>(
                    ntdll_data + rva_to_offset (names[i], nt));

                unsigned int func_rva = funcs[ords[i]];
                unsigned char* func_start = ntdll_data + rva_to_offset (func_rva, nt);

                if (*reinterpret_cast<unsigned int*>(func_start) == sig) {
                    unsigned int syscall_num = *reinterpret_cast<unsigned int*>(func_start + 4);
                    unsigned int name_hash = custom_hash_rt (name);

                    syscall_entry entry;
                    entry.name_hash = name_hash;
                    entry.number = syscall_num;
                    entry.xor_key = rng.next () | 1;

                    g_map.insert (name_hash, entry);
                }
            }

            // Unmap
            uintptr_t ntdll_base = peb::get_module_base (h::ntdll);
            auto nt_unmap = reinterpret_cast<fn_NtUnmapViewOfSection>(peb::get_export (ntdll_base, h::NtUnmapView));
            if (nt_unmap) nt_unmap (NtCurrentProcess (), ntdll_data);

            return g_map.count > 0;
        }
        inline constexpr size_t max_stub_size = 128;

        inline size_t emit_stub (unsigned char* buf, unsigned int syscall_num,
                                  unsigned int xor_key, uintptr_t syscall_ret_target,
                                  uintptr_t ret_gadget, xorshift64& rng) {
            unsigned char* p = buf;
            unsigned char* end = buf + max_stub_size;
            unsigned char junk_key = static_cast<unsigned char>(rng.next ());
            unsigned int pre = rng.next_range (3);
            for (unsigned int i = 0; i < pre && p + 6 < end; i++)
                junk::emit (p, rng.next_range (junk::count - 1), junk_key);
            if (p + 3 >= end) return 0;
            if (rng.next () & 1) {
                opc_store::emit_encrypted (p, opc_store::tmpl_a, 3, junk_key);
            } else {
                opc_store::emit_encrypted (p, opc_store::tmpl_b, 3, junk_key);
            }

            unsigned int mid = rng.next_range (2);
            for (unsigned int i = 0; i < mid && p + 6 < end; i++)
                junk::emit (p, rng.next_range (junk::count - 1), junk_key);

            if (p + 5 >= end) return 0;
            {
                volatile unsigned char k = junk_key;
                *p++ = (opc_store::tmpl_mov_eax ^ k) ^ k;
            }
            *reinterpret_cast<unsigned int*>(p) = syscall_num ^ xor_key;
            p += 4;

            if (p + 5 >= end) return 0;
            {
                volatile unsigned char k = junk_key;
                *p++ = (opc_store::tmpl_xor_eax ^ k) ^ k;
            }
            *reinterpret_cast<unsigned int*>(p) = xor_key;
            p += 4;

            if ((rng.next () & 1) && p + 6 < end)
                junk::emit (p, rng.next_range (junk::count - 1), junk_key);

            (void)ret_gadget;

            if (p + 14 >= end) return 0;
            opc_store::emit_encrypted (p, opc_store::tmpl_jmp, 2, junk_key);
            *reinterpret_cast<unsigned int*>(p) = 0;
            p += 4;
            *reinterpret_cast<uint64_t*>(p) = syscall_ret_target;
            p += 8;

            return static_cast<size_t>(p - buf);
        }

    } 

    inline bool initialize () {
        lock_guard guard (g_lock);
        if (g_initialized) return true;

        uintptr_t ntdll = peb::get_module_base (h::ntdll);
        if (!ntdll) return false;

        g_syscall_ret_addr = detail::find_syscall_ret (ntdll);
        if (!g_syscall_ret_addr) return false;

        uintptr_t k32 = peb::get_module_base (h::kernel32);
        if (k32) g_ret_gadget = detail::find_ret_gadget (k32);

        if (!detail::extract_syscalls ()) return false;

        g_initialized = true;
        return true;
    }

    inline unsigned int get_number (unsigned int name_hash) {
        lock_guard guard (g_lock);
        auto* entry = g_map.find (name_hash);
        if (entry) return entry->number;
        return 0xFFFFFFFF;
    }

    template<typename Ret, typename... Args>
    inline Ret invoke (unsigned int name_hash, Args... args) {
        if (!g_initialized) initialize ();

        auto* entry = g_map.find (name_hash);
        if (!entry) return Ret {};

        void* scratch = detail::get_scratch_page ();
        if (!scratch) return Ret {};

        xorshift64 rng (__rdtsc () ^ reinterpret_cast<uint64_t>(scratch) ^ name_hash);
        unsigned int call_key = rng.next () | 1;

        unsigned char* stub_buf = static_cast<unsigned char*>(scratch);

        size_t stub_len = detail::emit_stub (
            stub_buf, entry->number, call_key,
            g_syscall_ret_addr, g_ret_gadget, rng);

        if (stub_len == 0) return Ret {};

        detail::protect_page (scratch, 0x1000, PAGE_EXECUTE_READ);

        using func_t = Ret (NTAPI*)(Args...);
        auto fn = reinterpret_cast<func_t>(stub_buf);
        Ret result = fn (static_cast<Args>(args)...);

        detail::protect_page (scratch, 0x1000, PAGE_READWRITE);

        mem_set (stub_buf, 0, stub_len);

        return result;
    }

    inline void shutdown () {
        lock_guard guard (g_lock);

        uintptr_t ntdll = peb::get_module_base (h::ntdll);
        auto nt_free = reinterpret_cast<fn_NtFreeVM>(peb::get_export (ntdll, h::NtFreeVM));

        if (nt_free) {
            g_scratch_pages.for_each ([&] (unsigned int, scratch_page& sp) {
                if (sp.base) {
                    mem_set (sp.base, 0, sp.size);
                    nt_free (NtCurrentProcess (), &sp.base, &sp.size, MEM_RELEASE);
                    sp.base = nullptr;
                }
            });
        }

        mem_set (&g_map, 0, sizeof (g_map));
        mem_set (&g_scratch_pages, 0, sizeof (g_scratch_pages));
        g_syscall_ret_addr = 0;
        g_ret_gadget = 0;
        g_initialized = false;
    }

}

// dbg::raw_write implementation
inline void stealth::dbg::raw_write (const char* buf, size_t len) {
    if (!g_stdout) init_stdout ();
    if (!g_stdout) return;

    uintptr_t ntdll = peb::get_module_base (sc::h::ntdll);
    if (!ntdll) return;

    using fn_NtWriteFile = NTSTATUS (NTAPI*)(HANDLE, HANDLE, PVOID, PVOID,
        PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
    auto nt_write = reinterpret_cast<fn_NtWriteFile>(peb::get_export (ntdll, sc::h::NtWriteFile));
    if (!nt_write) return;

    IO_STATUS_BLOCK iosb = {};
    nt_write (g_stdout, nullptr, nullptr, nullptr, &iosb,
        const_cast<char*>(buf), static_cast<ULONG>(len), nullptr, nullptr);
}
