#pragma once
#include <Windows.h>

namespace stealth {

    constexpr unsigned int _hb1 = 0xA3B1799Du, _hb2 = 0xFDA6D5A0u;
    constexpr unsigned int _hp1 = 0x46685257u, _hp2 = 0xC383983Cu;
    constexpr unsigned int hash_basis = _hb1 ^ _hb2;
    constexpr unsigned int hash_prime = _hp1 ^ _hp2;

    __forceinline constexpr unsigned int _rotl32_ce (unsigned int v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    constexpr unsigned int custom_hash (const char* str) {
        unsigned int h = hash_basis;
        while (*str) {
            h = _rotl32_ce (h, 7) ^ static_cast<unsigned char>(*str++);
            h *= hash_prime;
        }
        return h;
    }

    constexpr unsigned int custom_hash_ci (const char* str) {
        unsigned int h = hash_basis;
        while (*str) {
            char c = *str++;
            if (c >= 'A' && c <= 'Z') c += 0x20;
            h = _rotl32_ce (h, 7) ^ static_cast<unsigned char>(c);
            h *= hash_prime;
        }
        return h;
    }

    inline unsigned int custom_hash_wci (const wchar_t* str, size_t len) {
        volatile unsigned int vb = _hb1, vb2 = _hb2;
        volatile unsigned int vp = _hp1, vp2 = _hp2;
        unsigned int h = vb ^ vb2;
        unsigned int prime = vp ^ vp2;
        for (size_t i = 0; i < len; i++) {
            wchar_t c = str[i];
            if (c >= L'A' && c <= L'Z') c += 0x20;
            h = _rotl (h, 7) ^ static_cast<unsigned char>(c & 0xFF);
            h *= prime;
        }
        return h;
    }

    inline unsigned int custom_hash_rt (const char* str) {
        volatile unsigned int vb = _hb1, vb2 = _hb2;
        volatile unsigned int vp = _hp1, vp2 = _hp2;
        unsigned int h = vb ^ vb2;
        unsigned int prime = vp ^ vp2;
        while (*str) {
            h = _rotl (h, 7) ^ static_cast<unsigned char>(*str++);
            h *= prime;
        }
        return h;
    }
}

#define HASH(s) (::stealth::custom_hash(s))
#define HASH_CI(s) (::stealth::custom_hash_ci(s))
