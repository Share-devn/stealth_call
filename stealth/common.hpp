#pragma once
#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

using uint8_t = unsigned char;
using uint16_t = unsigned short;
using uint32_t = unsigned int;
using uint64_t = unsigned long long;
using int64_t = long long;

extern "C" int __CxxFrameHandler4 (void* rec, void* frame, void* ctx, void* disp) {
    if (rec) {
        unsigned int flags = *reinterpret_cast<unsigned int*>(
            reinterpret_cast<unsigned char*>(rec) + 4);
        if (flags & 0x66) return 1;
    }
    (void)frame; (void)ctx; (void)disp;
    return 1;
}

extern "C" void __chkstk () {}

#pragma function(memset)
extern "C" void* memset (void* dst, int val, size_t n) {
    __stosb (static_cast<unsigned char*>(dst), static_cast<unsigned char>(val), n);
    return dst;
}

#pragma function(memcpy)
extern "C" void* memcpy (void* dst, const void* src, size_t n) {
    __movsb (static_cast<unsigned char*>(dst), static_cast<const unsigned char*>(src), n);
    return dst;
}

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

#ifndef NtCurrentProcess
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#endif

namespace stealth {

    __forceinline void* mem_copy (void* dst, const void* src, size_t n) {
        __movsb (static_cast<unsigned char*>(dst),
                 static_cast<const unsigned char*>(src), n);
        return dst;
    }

    __forceinline void* mem_set (void* dst, int val, size_t n) {
        __stosb (static_cast<unsigned char*>(dst),
                 static_cast<unsigned char>(val), n);
        return dst;
    }

    __forceinline int mem_cmp (const void* a, const void* b, size_t n) {
        auto pa = static_cast<const unsigned char*>(a);
        auto pb = static_cast<const unsigned char*>(b);
        for (size_t i = 0; i < n; i++) {
            if (pa[i] != pb[i]) return pa[i] - pb[i];
        }
        return 0;
    }

    __forceinline size_t str_len (const char* s) {
        size_t n = 0;
        while (s[n]) n++;
        return n;
    }

    __forceinline size_t wstr_len (const wchar_t* s) {
        size_t n = 0;
        while (s[n]) n++;
        return n;
    }

    struct spinlock {
        volatile long state = 0;
        __forceinline void acquire () {
            while (_InterlockedCompareExchange (&state, 1, 0) != 0)
                _mm_pause ();
        }
        __forceinline void release () { _InterlockedExchange (&state, 0); }
    };

    struct lock_guard {
        spinlock& lk;
        __forceinline lock_guard (spinlock& l) : lk (l) { lk.acquire (); }
        __forceinline ~lock_guard () { lk.release (); }
    };

    struct xorshift64 {
        uint64_t state;
        __forceinline xorshift64 (uint64_t seed) : state (seed ? seed : 1) {}
        __forceinline uint32_t next () {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            return static_cast<uint32_t>(state);
        }
        __forceinline uint32_t next_range (uint32_t max) { return next () % (max + 1); }
    };

    template<typename V, size_t Capacity>
    struct static_map {
        struct slot { uint32_t key; V value; bool occupied; };
        slot entries[Capacity] = {};
        size_t count = 0;

        __forceinline V* find (uint32_t key) {
            uint32_t idx = key % Capacity;
            for (size_t i = 0; i < Capacity; i++) {
                uint32_t probe = (idx + i) % Capacity;
                if (!entries[probe].occupied) return nullptr;
                if (entries[probe].key == key) return &entries[probe].value;
            }
            return nullptr;
        }

        __forceinline bool insert (uint32_t key, const V& val) {
            if (count >= Capacity) return false;
            uint32_t idx = key % Capacity;
            for (size_t i = 0; i < Capacity; i++) {
                uint32_t probe = (idx + i) % Capacity;
                if (!entries[probe].occupied) {
                    entries[probe].key = key;
                    entries[probe].value = val;
                    entries[probe].occupied = true;
                    count++;
                    return true;
                }
                if (entries[probe].key == key) {
                    entries[probe].value = val;
                    return true;
                }
            }
            return false;
        }

        template<typename Fn>
        __forceinline void for_each (Fn&& fn) {
            for (size_t i = 0; i < Capacity; i++)
                if (entries[i].occupied) fn (entries[i].key, entries[i].value);
        }
    };

    template<typename V, size_t Capacity>
    struct static_map64 {
        struct slot { uint64_t key; V value; bool occupied; };
        slot entries[Capacity] = {};
        size_t count = 0;

        __forceinline V* find (uint64_t key) {
            uint32_t idx = static_cast<uint32_t>(key) % Capacity;
            for (size_t i = 0; i < Capacity; i++) {
                uint32_t probe = (idx + static_cast<uint32_t>(i)) % Capacity;
                if (!entries[probe].occupied) return nullptr;
                if (entries[probe].key == key) return &entries[probe].value;
            }
            return nullptr;
        }

        __forceinline bool insert (uint64_t key, const V& val) {
            if (count >= Capacity) return false;
            uint32_t idx = static_cast<uint32_t>(key) % Capacity;
            for (size_t i = 0; i < Capacity; i++) {
                uint32_t probe = (idx + static_cast<uint32_t>(i)) % Capacity;
                if (!entries[probe].occupied) {
                    entries[probe].key = key;
                    entries[probe].value = val;
                    entries[probe].occupied = true;
                    count++;
                    return true;
                }
                if (entries[probe].key == key) {
                    entries[probe].value = val;
                    return true;
                }
            }
            return false;
        }

        template<typename Fn>
        __forceinline void for_each (Fn&& fn) {
            for (size_t i = 0; i < Capacity; i++)
                if (entries[i].occupied) fn (entries[i].key, entries[i].value);
        }
    };

    namespace dbg {

        inline void* g_stdout = nullptr;

        inline void init_stdout () {
            auto* peb = reinterpret_cast<PEB*>(__readgsqword (0x60));
            if (!peb || !peb->Ldr) return;

            constexpr unsigned int k32_hash = 0xDCF84923u;
            LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
            LIST_ENTRY* entry = head->Flink;
            uintptr_t k32_base = 0;

            while (entry != head) {
                auto* ldr = CONTAINING_RECORD (entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (ldr->FullDllName.Length > 0 && ldr->FullDllName.Buffer) {
                    wchar_t* name = ldr->FullDllName.Buffer;
                    size_t len = ldr->FullDllName.Length / sizeof (wchar_t);
                    size_t start = 0;
                    for (size_t i = 0; i < len; i++) if (name[i] == L'\\') start = i + 1;

                    volatile unsigned int vb1 = 0xA3B1799Du, vb2 = 0xFDA6D5A0u;
                    volatile unsigned int vp1 = 0x46685257u, vp2 = 0xC383983Cu;
                    unsigned int h = vb1 ^ vb2;
                    unsigned int hprime = vp1 ^ vp2;
                    for (size_t i = start; i < len; i++) {
                        wchar_t c = name[i];
                        if (c >= L'A' && c <= L'Z') c += 0x20;
                        h = _rotl (h, 7) ^ static_cast<unsigned char>(c & 0xFF);
                        h *= hprime;
                    }
                    if (h == k32_hash) { k32_base = reinterpret_cast<uintptr_t>(ldr->DllBase); break; }
                }
                entry = entry->Flink;
            }

            if (!k32_base) return;

            constexpr unsigned int gsh_hash = 0x440C9877u;
            auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(k32_base);
            auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(k32_base + dos->e_lfanew);
            auto& exp_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(k32_base + exp_entry.VirtualAddress);
            auto* funcs = reinterpret_cast<unsigned int*>(k32_base + exp->AddressOfFunctions);
            auto* names = reinterpret_cast<unsigned int*>(k32_base + exp->AddressOfNames);
            auto* ords = reinterpret_cast<unsigned short*>(k32_base + exp->AddressOfNameOrdinals);

            for (unsigned int i = 0; i < exp->NumberOfNames; i++) {
                const char* n = reinterpret_cast<const char*>(k32_base + names[i]);
                volatile unsigned int vb1x = 0xA3B1799Du, vb2x = 0xFDA6D5A0u;
                volatile unsigned int vp1x = 0x46685257u, vp2x = 0xC383983Cu;
                unsigned int h = vb1x ^ vb2x;
                unsigned int hpx = vp1x ^ vp2x;
                while (*n) { h = _rotl (h, 7) ^ static_cast<unsigned char>(*n++); h *= hpx; }
                if (h == gsh_hash) {
                    using fn_GetStdHandle = HANDLE (WINAPI*)(DWORD);
                    auto get_std = reinterpret_cast<fn_GetStdHandle>(k32_base + funcs[ords[i]]);
                    g_stdout = get_std (STD_OUTPUT_HANDLE);
                    return;
                }
            }
        }

        inline void raw_write (const char* buf, size_t len);

        inline size_t to_hex (uint64_t val, char* buf, int width = 0) {
            static const char hex[] = "0123456789ABCDEF";
            char tmp[17];
            int pos = 0;
            if (val == 0) { tmp[pos++] = '0'; }
            else { while (val) { tmp[pos++] = hex[val & 0xF]; val >>= 4; } }
            while (pos < width) tmp[pos++] = '0';
            size_t out = 0;
            for (int i = pos - 1; i >= 0; i--) buf[out++] = tmp[i];
            buf[out] = 0;
            return out;
        }

        inline size_t to_dec (uint64_t val, char* buf) {
            char tmp[21];
            int pos = 0;
            if (val == 0) { tmp[pos++] = '0'; }
            else { while (val) { tmp[pos++] = '0' + (val % 10); val /= 10; } }
            size_t out = 0;
            for (int i = pos - 1; i >= 0; i--) buf[out++] = tmp[i];
            buf[out] = 0;
            return out;
        }

        inline size_t to_ptr (const void* p, char* buf) {
            buf[0] = '0'; buf[1] = 'x';
            return 2 + to_hex (reinterpret_cast<uint64_t>(p), buf + 2, 16);
        }

        inline void print (const char* fmt, ...) {
            if (!g_stdout) init_stdout ();
            char out[1024];
            size_t pos = 0;
            va_list args;
            va_start (args, fmt);
            while (*fmt && pos < sizeof (out) - 32) {
                if (*fmt != '%') { out[pos++] = *fmt++; continue; }
                fmt++;
                int width = 0;
                if (*fmt == '0') { fmt++; }
                while (*fmt >= '0' && *fmt <= '9') { width = width * 10 + (*fmt - '0'); fmt++; }
                switch (*fmt) {
                    case 's': { const char* s = va_arg (args, const char*); while (*s && pos < sizeof (out) - 2) out[pos++] = *s++; break; }
                    case 'p': { pos += to_ptr (va_arg (args, const void*), out + pos); break; }
                    case 'X': case 'x': { pos += to_hex (va_arg (args, unsigned int), out + pos, width); break; }
                    case 'd': { int v = va_arg (args, int); if (v < 0) { out[pos++] = '-'; v = -v; } pos += to_dec (v, out + pos); break; }
                    case 'z': { fmt++; pos += to_dec (va_arg (args, size_t), out + pos); break; }
                    case 'l': { fmt++; pos += to_dec (va_arg (args, unsigned long), out + pos); break; }
                    case '%': { out[pos++] = '%'; break; }
                    default: out[pos++] = '%'; out[pos++] = *fmt; break;
                }
                fmt++;
            }
            va_end (args);
            raw_write (out, pos);
        }
    }
}

#define DBG stealth::dbg::print
