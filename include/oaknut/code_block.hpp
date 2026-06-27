// SPDX-FileCopyrightText: Copyright (c) 2022 merryhime <https://mary.rs>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(_WIN32)
#    define NOMINMAX
#    include <windows.h>
#elif defined(__APPLE__)
#    include <TargetConditionals.h>
#    include <libkern/OSCacheControl.h>
#    include <pthread.h>
#    include <sys/mman.h>
#    include <unistd.h>
#elif defined(__SWITCH__)
#    include <cstdio>
#    include <switch.h>
// libnx defines a BIT(n) macro that collides with this BIT SIMD instruction.
#    undef BIT
#else
#    include <sys/mman.h>
#endif

namespace oaknut {

class CodeBlock {
public:
    explicit CodeBlock(std::size_t size)
        : m_size(size)
    {
#if defined(_WIN32)
        m_memory = (std::uint32_t*)VirtualAlloc(nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#elif defined(__APPLE__)
#    if TARGET_OS_IPHONE
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#    else
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_JIT, -1, 0);
#    endif
#elif defined(__NetBSD__)
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_MPROTECT(PROT_READ | PROT_WRITE | PROT_EXEC), MAP_ANON | MAP_PRIVATE, -1, 0);
#elif defined(__OpenBSD__)
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#elif defined(__SWITCH__)
        // Horizon enforces W^X. Libnx's Jit hands back two aliases of the same physical pages so we can have both.
        if (R_FAILED(jitCreate(&m_jit, size))) {
            // Most likely opened in applet mode.
            std::fprintf(stderr,
                         "oaknut: jitCreate(%zu) failed. The process likely lacks the JIT "
                         "capability. Make sure you aren't running in Applet Mode.\n",
                         size);
            m_memory = nullptr;
        } else if (R_FAILED(jitTransitionToExecutable(&m_jit))) {
            std::fprintf(stderr, "oaknut: jitTransitionToExecutable failed.\n");
            jitClose(&m_jit);
            m_memory = nullptr;
        } else {
            m_rw = (std::uint32_t*)jitGetRwAddr(&m_jit);
            m_rx = (std::uint32_t*)jitGetRxAddr(&m_jit);
            m_memory = m_rx;
        }
#else
        m_memory = (std::uint32_t*)mmap(nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#endif

        if (m_memory == nullptr)
            throw std::bad_alloc{};
    }

    ~CodeBlock()
    {
        if (m_memory == nullptr)
            return;

#if defined(_WIN32)
        VirtualFree((void*)m_memory, 0, MEM_RELEASE);
#elif defined(__SWITCH__)
        jitClose(&m_jit);
#else
        munmap(m_memory, m_size);
#endif
    }

    CodeBlock(const CodeBlock&) = delete;
    CodeBlock& operator=(const CodeBlock&) = delete;
    CodeBlock(CodeBlock&&) = delete;
    CodeBlock& operator=(CodeBlock&&) = delete;

    std::uint32_t* ptr() const
    {
        return m_memory;
    }

    // Base of the alias generated code is written through. Equals ptr() except on platforms with a separate RW/RX dual mapping.
    std::uint32_t* wptr() const
    {
#if defined(__SWITCH__)
        return m_rw;
#else
        return m_memory;
#endif
    }

    // Base of the alias the CPU executes from.
    std::uint32_t* xptr() const
    {
#if defined(__SWITCH__)
        return m_rx;
#else
        return m_memory;
#endif
    }

    void protect()
    {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(1);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_memory, m_size, PROT_READ | PROT_EXEC);
#endif
    }

    void unprotect()
    {
#if defined(__APPLE__) && !TARGET_OS_IPHONE
        pthread_jit_write_protect_np(0);
#elif defined(__APPLE__) || defined(__NetBSD__) || defined(__OpenBSD__)
        mprotect(m_memory, m_size, PROT_READ | PROT_WRITE);
#endif
    }

    void invalidate(std::uint32_t* mem, std::size_t size)
    {
#if defined(__SWITCH__)
        // mem points into the RX alias.
        char* const rx = reinterpret_cast<char*>(mem);
        char* const rw = reinterpret_cast<char*>(m_rw) + (rx - reinterpret_cast<char*>(m_rx));
        __builtin___clear_cache(rw, rw + size);
        __builtin___clear_cache(rx, rx + size);
#elif defined(__APPLE__)
        sys_icache_invalidate(mem, size);
#elif defined(_WIN32)
        FlushInstructionCache(GetCurrentProcess(), mem, size);
#else
        static std::size_t icache_line_size = 0x10000, dcache_line_size = 0x10000;

        std::uint64_t ctr;
        __asm__ volatile("mrs %0, ctr_el0"
                         : "=r"(ctr));

        const std::size_t isize = icache_line_size = std::min<std::size_t>(icache_line_size, 4 << ((ctr >> 0) & 0xf));
        const std::size_t dsize = dcache_line_size = std::min<std::size_t>(dcache_line_size, 4 << ((ctr >> 16) & 0xf));

        const std::uintptr_t end = (std::uintptr_t)mem + size;

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(dsize - 1); addr < end; addr += dsize) {
            __asm__ volatile("dc cvau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\n"
                         :
                         :
                         : "memory");

        for (std::uintptr_t addr = ((std::uintptr_t)mem) & ~(isize - 1); addr < end; addr += isize) {
            __asm__ volatile("ic ivau, %0"
                             :
                             : "r"(addr)
                             : "memory");
        }
        __asm__ volatile("dsb ish\nisb\n"
                         :
                         :
                         : "memory");
#endif
    }

    void invalidate_all()
    {
        invalidate(m_memory, m_size);
    }

protected:
#if defined(__SWITCH__)
    Jit m_jit{};
    std::uint32_t* m_rw = nullptr;
    std::uint32_t* m_rx = nullptr;
#endif
    std::uint32_t* m_memory;
    std::size_t m_size = 0;
};

}  // namespace oaknut
