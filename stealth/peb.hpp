#pragma once
#include "common.hpp"
#include "hash.hpp"

namespace stealth::peb {

    inline PEB* get_peb () {
        return reinterpret_cast<PEB*>(__readgsqword (0x60));
    }

    inline uintptr_t get_module_base (unsigned int module_hash) {
        PEB* peb = get_peb ();
        if (!peb || !peb->Ldr) return 0;
        LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* entry = head->Flink;
        while (entry != head) {
            auto* ldr_entry = CONTAINING_RECORD (entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (ldr_entry->FullDllName.Length > 0 && ldr_entry->FullDllName.Buffer) {
                wchar_t* name = ldr_entry->FullDllName.Buffer;
                size_t name_len = ldr_entry->FullDllName.Length / sizeof (wchar_t);
                size_t start = 0;
                for (size_t i = 0; i < name_len; i++)
                    if (name[i] == L'\\') start = i + 1;
                if (custom_hash_wci (name + start, name_len - start) == module_hash)
                    return reinterpret_cast<uintptr_t>(ldr_entry->DllBase);
            }
            entry = entry->Flink;
        }
        return 0;
    }

    inline uintptr_t get_export (uintptr_t module_base, unsigned int func_hash) {
        if (!module_base) return 0;
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        if (dos->e_lfanew < 0 || dos->e_lfanew > 0x10000) return 0;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module_base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        auto& export_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_dir_entry.VirtualAddress || !export_dir_entry.Size) return 0;
        auto* export_dir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module_base + export_dir_entry.VirtualAddress);
        auto* functions = reinterpret_cast<unsigned int*>(module_base + export_dir->AddressOfFunctions);
        auto* names = reinterpret_cast<unsigned int*>(module_base + export_dir->AddressOfNames);
        auto* ordinals = reinterpret_cast<unsigned short*>(module_base + export_dir->AddressOfNameOrdinals);
        for (unsigned int i = 0; i < export_dir->NumberOfNames; i++) {
            const char* name = reinterpret_cast<const char*>(module_base + names[i]);
            if (custom_hash_rt (name) == func_hash) {
                unsigned int rva = functions[ordinals[i]];
                uintptr_t addr = module_base + rva;
                if (addr >= reinterpret_cast<uintptr_t>(export_dir) &&
                    addr < reinterpret_cast<uintptr_t>(export_dir) + export_dir_entry.Size)
                    return 0;
                return addr;
            }
        }
        return 0;
    }

    inline uintptr_t resolve (unsigned int module_hash, unsigned int func_hash) {
        return get_export (get_module_base (module_hash), func_hash);
    }

    inline bool get_module_path (unsigned int module_hash, wchar_t* out_path, size_t max_len) {
        PEB* peb = get_peb ();
        if (!peb || !peb->Ldr) return false;
        LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY* entry = head->Flink;
        while (entry != head) {
            auto* ldr_entry = CONTAINING_RECORD (entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            if (ldr_entry->FullDllName.Length > 0 && ldr_entry->FullDllName.Buffer) {
                wchar_t* name = ldr_entry->FullDllName.Buffer;
                size_t name_len = ldr_entry->FullDllName.Length / sizeof (wchar_t);
                size_t start = 0;
                for (size_t i = 0; i < name_len; i++)
                    if (name[i] == L'\\') start = i + 1;
                if (custom_hash_wci (name + start, name_len - start) == module_hash) {
                    size_t copy_len = name_len < max_len - 1 ? name_len : max_len - 1;
                    mem_copy (out_path, name, copy_len * sizeof (wchar_t));
                    out_path[copy_len] = L'\0';
                    return true;
                }
            }
            entry = entry->Flink;
        }
        return false;
    }

    inline bool is_function_hooked (uintptr_t func_addr) {
        if (!func_addr) return true;
        auto* b = reinterpret_cast<const unsigned char*>(func_addr);
        if (b[0] == 0xE9) return true;
        if (b[0] == 0xFF && b[1] == 0x25) return true;
        if (b[0] == 0x48 && b[1] == 0xB8 && b[10] == 0xFF && b[11] == 0xE0) return true;
        if (b[0] == 0xCC) return true;
        return false;
    }
}
