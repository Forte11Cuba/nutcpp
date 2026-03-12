#pragma once

// Portable secure memory zeroing.
// Ensures sensitive data (keys, seeds, hashes) is wiped from memory
// without the compiler optimizing the operation away.

#include <cstddef>

#if defined(_WIN32)
#include <windows.h>
#endif

namespace nutcpp {
namespace internal {

inline void secure_zero(void* ptr, std::size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(ptr, len);
#elif defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
    explicit_bzero(ptr, len);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
#endif
}

} // namespace internal
} // namespace nutcpp
