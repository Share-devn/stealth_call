#pragma once

namespace stealth {

    template<unsigned int Key, size_t N>
    struct xor_string {
        char data[N];
        __forceinline constexpr xor_string (const char (&s)[N]) : data {} {
            for (size_t i = 0; i < N; i++)
                data[i] = s[i] ^ static_cast<char>((Key >> ((i % 4) * 8)) & 0xFF);
        }
        __forceinline void decrypt (char* out) const {
            for (size_t i = 0; i < N; i++)
                out[i] = data[i] ^ static_cast<char>((Key >> ((i % 4) * 8)) & 0xFF);
        }
        static constexpr size_t size = N;
    };

    template<unsigned int Key, size_t N>
    struct xor_wstring {
        wchar_t data[N];
        __forceinline constexpr xor_wstring (const wchar_t (&s)[N]) : data {} {
            for (size_t i = 0; i < N; i++)
                data[i] = s[i] ^ static_cast<wchar_t>((Key >> ((i % 2) * 16)) & 0xFFFF);
        }
        __forceinline void decrypt (wchar_t* out) const {
            for (size_t i = 0; i < N; i++)
                out[i] = data[i] ^ static_cast<wchar_t>((Key >> ((i % 2) * 16)) & 0xFFFF);
        }
        static constexpr size_t size = N;
    };
}

#define XOR_A(s) \
    [&]() -> const char* { \
        constexpr auto _xenc = ::stealth::xor_string<0x5E17AC3Du ^ (__LINE__ * 0x01000193u), sizeof(s)>(s); \
        static thread_local char _xtls[sizeof(s)]; \
        _xenc.decrypt(_xtls); \
        return _xtls; \
    }()

#define XOR_W(s) \
    [&]() -> const wchar_t* { \
        constexpr auto _xenc = ::stealth::xor_wstring<0x5E17AC3Du ^ (__LINE__ * 0x01000193u), sizeof(s)/sizeof(wchar_t)>(s); \
        static thread_local wchar_t _xtls[sizeof(s)/sizeof(wchar_t)]; \
        _xenc.decrypt(_xtls); \
        return _xtls; \
    }()

#define XOR_A_STACK(s, buf) \
    do { \
        constexpr auto _xenc = ::stealth::xor_string<0x5E17AC3Du ^ (__LINE__ * 0x01000193u), sizeof(s)>(s); \
        _xenc.decrypt(buf); \
    } while(0)

#define XOR_W_STACK(s, buf) \
    do { \
        constexpr auto _xenc = ::stealth::xor_wstring<0x5E17AC3Du ^ (__LINE__ * 0x01000193u), sizeof(s)/sizeof(wchar_t)>(s); \
        _xenc.decrypt(buf); \
    } while(0)
