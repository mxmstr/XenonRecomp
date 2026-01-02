#ifndef X86_CONTEXT_H_INCLUDED
#define X86_CONTEXT_H_INCLUDED

#ifndef X86_CONFIG_H_INCLUDED
#error "x86_config.h must be included before x86_context.h"
#endif

#include <climits>
#include <cmath>
#include <csetjmp>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <x86/avx.h>
#include <x86/sse.h>
#include <x86/sse2.h>
#include <x86/sse4.1.h>
#include <x86/mmx.h>

#define X86_JOIN(x, y) x##y
#define X86_XSTRINGIFY(x) #x
#define X86_STRINGIFY(x) X86_XSTRINGIFY(x)
#define X86_FUNC(x) void x(X86Context& __restrict ctx, uint8_t* base)
#define X86_FUNC_IMPL(x) extern "C" X86_FUNC(x)
#define X86_EXTERN_FUNC(x) extern X86_FUNC(x)
#define X86_WEAK_FUNC(x) __attribute__((weak,noinline)) X86_FUNC(x)

#define X86_FUNC_PROLOGUE() __builtin_assume(((size_t)base & 0xF) == 0)

// x86 is little-endian, so no byte swapping needed for memory operations
#ifndef X86_LOAD_U8
#define X86_LOAD_U8(x) *(volatile uint8_t*)(base + (x))
#endif

#ifndef X86_LOAD_U16
#define X86_LOAD_U16(x) *(volatile uint16_t*)(base + (x))
#endif

#ifndef X86_LOAD_U32
#define X86_LOAD_U32(x) *(volatile uint32_t*)(base + (x))
#endif

#ifndef X86_LOAD_U64
#define X86_LOAD_U64(x) *(volatile uint64_t*)(base + (x))
#endif

#ifndef X86_LOAD_S8
#define X86_LOAD_S8(x) *(volatile int8_t*)(base + (x))
#endif

#ifndef X86_LOAD_S16
#define X86_LOAD_S16(x) *(volatile int16_t*)(base + (x))
#endif

#ifndef X86_LOAD_S32
#define X86_LOAD_S32(x) *(volatile int32_t*)(base + (x))
#endif

#ifndef X86_LOAD_F32
#define X86_LOAD_F32(x) *(volatile float*)(base + (x))
#endif

#ifndef X86_LOAD_F64
#define X86_LOAD_F64(x) *(volatile double*)(base + (x))
#endif

#ifndef X86_STORE_U8
#define X86_STORE_U8(x, y) *(volatile uint8_t*)(base + (x)) = (y)
#endif

#ifndef X86_STORE_U16
#define X86_STORE_U16(x, y) *(volatile uint16_t*)(base + (x)) = (y)
#endif

#ifndef X86_STORE_U32
#define X86_STORE_U32(x, y) *(volatile uint32_t*)(base + (x)) = (y)
#endif

#ifndef X86_STORE_U64
#define X86_STORE_U64(x, y) *(volatile uint64_t*)(base + (x)) = (y)
#endif

#ifndef X86_STORE_F32
#define X86_STORE_F32(x, y) *(volatile float*)(base + (x)) = (y)
#endif

#ifndef X86_STORE_F64
#define X86_STORE_F64(x, y) *(volatile double*)(base + (x)) = (y)
#endif

// Port I/O operations - these need to be implemented by the runtime
// Default implementations just return 0 / do nothing (stub)
#ifndef X86_PORT_IN_U8
#define X86_PORT_IN_U8(port) x86_port_in_u8(port)
#endif

#ifndef X86_PORT_IN_U16
#define X86_PORT_IN_U16(port) x86_port_in_u16(port)
#endif

#ifndef X86_PORT_IN_U32
#define X86_PORT_IN_U32(port) x86_port_in_u32(port)
#endif

#ifndef X86_PORT_OUT_U8
#define X86_PORT_OUT_U8(port, value) x86_port_out_u8(port, value)
#endif

#ifndef X86_PORT_OUT_U16
#define X86_PORT_OUT_U16(port, value) x86_port_out_u16(port, value)
#endif

#ifndef X86_PORT_OUT_U32
#define X86_PORT_OUT_U32(port, value) x86_port_out_u32(port, value)
#endif

// Default stub implementations for port I/O
// Override these in your runtime by defining the macros before including this header
inline uint8_t x86_port_in_u8([[maybe_unused]] uint16_t port) { return 0; }
inline uint16_t x86_port_in_u16([[maybe_unused]] uint16_t port) { return 0; }
inline uint32_t x86_port_in_u32([[maybe_unused]] uint16_t port) { return 0; }
inline void x86_port_out_u8([[maybe_unused]] uint16_t port, [[maybe_unused]] uint8_t value) {}
inline void x86_port_out_u16([[maybe_unused]] uint16_t port, [[maybe_unused]] uint16_t value) {}
inline void x86_port_out_u32([[maybe_unused]] uint16_t port, [[maybe_unused]] uint32_t value) {}

// 80-bit extended precision float - note: x87 long double is 80-bit (10 bytes)
// This is a simplified implementation that stores as double (loses precision)
#ifndef X86_LOAD_F80
#define X86_LOAD_F80(x) x86_load_f80(base + (x))
#endif

#ifndef X86_STORE_F80
#define X86_STORE_F80(x, y) x86_store_f80(base + (x), y)
#endif

// Helper functions for 80-bit float - defined inline for portability
inline long double x86_load_f80(const void* ptr)
{
    // x87 80-bit format: 1 sign + 15 exponent + 64 mantissa (with explicit integer bit)
    // For simplicity, we just load as 10-byte struct and reinterpret
    // This works on x86 where long double is 80-bit
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    long double result;
    std::memcpy(&result, ptr, 10);
    return result;
#else
    // Fallback: load as double (loses precision)
    return static_cast<long double>(*(const double*)ptr);
#endif
}

inline void x86_store_f80(void* ptr, long double value)
{
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    std::memcpy(ptr, &value, 10);
#else
    // Fallback: store as double
    *(double*)ptr = static_cast<double>(value);
#endif
}

// SSE XMM memory operations
#ifndef X86_LOAD_XMM
#define X86_LOAD_XMM(x) simde_mm_loadu_ps((const float*)(base + (x)))
#endif

#ifndef X86_LOAD_XMM_ALIGNED
#define X86_LOAD_XMM_ALIGNED(x) simde_mm_load_ps((const float*)(base + (x)))
#endif

#ifndef X86_STORE_XMM
#define X86_STORE_XMM(x, y) simde_mm_storeu_ps((float*)(base + (x)), (y))
#endif

#ifndef X86_STORE_XMM_ALIGNED
#define X86_STORE_XMM_ALIGNED(x, y) simde_mm_store_ps((float*)(base + (x)), (y))
#endif

// SSE scalar float operations (loads/stores single float, upper bits undefined or preserved)
#ifndef X86_LOAD_XMM_SS
#define X86_LOAD_XMM_SS(x) simde_mm_load_ss((const float*)(base + (x)))
#endif

#ifndef X86_STORE_XMM_SS
#define X86_STORE_XMM_SS(x, y) simde_mm_store_ss((float*)(base + (x)), (y))
#endif

// SSE2 double operations
#ifndef X86_LOAD_XMM_SD
#define X86_LOAD_XMM_SD(x) simde_mm_load_sd((const double*)(base + (x)))
#endif

#ifndef X86_STORE_XMM_SD
#define X86_STORE_XMM_SD(x, y) simde_mm_store_sd((double*)(base + (x)), (y))
#endif

// SSE2 packed double operations
#ifndef X86_LOAD_XMM_PD
#define X86_LOAD_XMM_PD(x) simde_mm_loadu_pd((const double*)(base + (x)))
#endif

#ifndef X86_STORE_XMM_PD
#define X86_STORE_XMM_PD(x, y) simde_mm_storeu_pd((double*)(base + (x)), (y))
#endif

// SSE2 integer operations
#ifndef X86_LOAD_XMM_SI128
#define X86_LOAD_XMM_SI128(x) simde_mm_loadu_si128((const simde__m128i*)(base + (x)))
#endif

#ifndef X86_STORE_XMM_SI128
#define X86_STORE_XMM_SI128(x, y) simde_mm_storeu_si128((simde__m128i*)(base + (x)), (y))
#endif

#ifndef X86_CALL_FUNC
#define X86_CALL_FUNC(x) x(ctx, base)
#endif

// Xbox memory is 64MB, but we allocate more for the lookup table
#define X86_MEMORY_SIZE 0x4000000ull

#define X86_LOOKUP_FUNC(x, y) *(X86Func**)(x + X86_IMAGE_BASE + X86_IMAGE_SIZE + (uint64_t(uint32_t(y) - X86_CODE_BASE) * 2))

#ifndef X86_CALL_INDIRECT_FUNC
#define X86_CALL_INDIRECT_FUNC(x) (X86_LOOKUP_FUNC(base, x))(ctx, base)
#endif

typedef void X86Func(struct X86Context& __restrict__ ctx, uint8_t* base);

struct X86FuncMapping
{
    size_t guest;
    X86Func* host;
};

extern X86FuncMapping X86FuncMappings[];

// General purpose register (can be accessed as 8, 16, or 32-bit)
union X86GPRegister
{
    int8_t s8;
    uint8_t u8;
    int16_t s16;
    uint16_t u16;
    int32_t s32;
    uint32_t u32;
    
    // High byte access (AH, BH, CH, DH)
    struct {
        uint8_t lo;
        uint8_t hi;
    } bytes;
};

// EFLAGS register bits
struct X86EFlags
{
    uint8_t cf;  // Carry Flag (bit 0)
    uint8_t pf;  // Parity Flag (bit 2)
    uint8_t af;  // Auxiliary Carry Flag (bit 4)
    uint8_t zf;  // Zero Flag (bit 6)
    uint8_t sf;  // Sign Flag (bit 7)
    uint8_t of;  // Overflow Flag (bit 11)
    uint8_t df;  // Direction Flag (bit 10)
    
    // Set flags based on result of arithmetic operation
    template<typename T>
    inline void setArithmeticFlags(T result) noexcept
    {
        zf = (result == 0);
        sf = (result < 0);
        // Parity flag: set if low byte has even number of 1 bits
        uint8_t lowByte = static_cast<uint8_t>(result);
        pf = !(__builtin_popcount(lowByte) & 1);
    }
    
    // Set flags for comparison (SUB without storing result)
    template<typename T>
    inline void compare(T left, T right) noexcept
    {
        using UT = typename std::make_unsigned<T>::type;
        T result = left - right;
        zf = (result == 0);
        sf = (result < 0);
        cf = static_cast<UT>(left) < static_cast<UT>(right);
        of = ((left ^ right) & (left ^ result)) < 0;
        uint8_t lowByte = static_cast<uint8_t>(result);
        pf = !(__builtin_popcount(lowByte) & 1);
    }
    
    // Set flags for TEST (AND without storing result)
    template<typename T>
    inline void test(T result) noexcept
    {
        zf = (result == 0);
        sf = (result < 0);
        cf = 0;
        of = 0;
        uint8_t lowByte = static_cast<uint8_t>(result);
        pf = !(__builtin_popcount(lowByte) & 1);
    }
    
    // Pack flags into a 32-bit value
    inline uint32_t pack() const noexcept
    {
        return (cf << 0) | (pf << 2) | (af << 4) | (zf << 6) | 
               (sf << 7) | (df << 10) | (of << 11) | 0x2; // bit 1 always set
    }
    
    // Unpack flags from a 32-bit value
    inline void unpack(uint32_t flags) noexcept
    {
        cf = (flags >> 0) & 1;
        pf = (flags >> 2) & 1;
        af = (flags >> 4) & 1;
        zf = (flags >> 6) & 1;
        sf = (flags >> 7) & 1;
        df = (flags >> 10) & 1;
        of = (flags >> 11) & 1;
    }
};

// x87 FPU Status Word bits
struct X87StatusWord
{
    uint16_t ie   : 1;  // Invalid Operation Exception
    uint16_t de   : 1;  // Denormalized Operand Exception
    uint16_t ze   : 1;  // Zero Divide Exception
    uint16_t oe   : 1;  // Overflow Exception
    uint16_t ue   : 1;  // Underflow Exception
    uint16_t pe   : 1;  // Precision Exception
    uint16_t sf   : 1;  // Stack Fault
    uint16_t es   : 1;  // Exception Summary Status
    uint16_t c0   : 1;  // Condition Code 0
    uint16_t c1   : 1;  // Condition Code 1
    uint16_t c2   : 1;  // Condition Code 2
    uint16_t top  : 3;  // Top of Stack Pointer
    uint16_t c3   : 1;  // Condition Code 3
    uint16_t b    : 1;  // FPU Busy
};

// x87 FPU Control Word bits
struct X87ControlWord
{
    uint16_t im   : 1;  // Invalid Operation Mask
    uint16_t dm   : 1;  // Denormalized Operand Mask
    uint16_t zm   : 1;  // Zero Divide Mask
    uint16_t om   : 1;  // Overflow Mask
    uint16_t um   : 1;  // Underflow Mask
    uint16_t pm   : 1;  // Precision Mask
    uint16_t res1 : 2;  // Reserved
    uint16_t pc   : 2;  // Precision Control (00=24bit, 10=53bit, 11=64bit)
    uint16_t rc   : 2;  // Rounding Control (00=nearest, 01=down, 10=up, 11=trunc)
    uint16_t ic   : 1;  // Infinity Control (ignored on 387+)
    uint16_t res2 : 3;  // Reserved
};

// x87 FPU Tag Word (2 bits per register)
// 00 = Valid, 01 = Zero, 10 = Special (NaN, Inf, Denormal), 11 = Empty
struct X87TagWord
{
    uint16_t tags;
    
    inline uint8_t getTag(int reg) const noexcept
    {
        return (tags >> (reg * 2)) & 0x3;
    }
    
    inline void setTag(int reg, uint8_t tag) noexcept
    {
        tags = (tags & ~(0x3 << (reg * 2))) | ((tag & 0x3) << (reg * 2));
    }
    
    inline void setEmpty(int reg) noexcept
    {
        setTag(reg, 3);
    }
    
    inline void setValid(int reg) noexcept
    {
        setTag(reg, 0);
    }
};

// x87 FPU Register (80-bit extended precision stored as long double)
union X87Register
{
    long double f80;
    double f64;
    float f32;
    uint8_t bytes[16]; // Padded for alignment
};

// x87 FPU State
struct X87FPUState
{
    X87ControlWord control;
    X87StatusWord status;
    X87TagWord tags;
    X87Register st[8];  // ST(0) through ST(7)
    
    // Get the physical register index for ST(i)
    inline int getPhysicalIndex(int i) const noexcept
    {
        return (status.top + i) & 7;
    }
    
    // Access ST(i) 
    inline X87Register& ST(int i) noexcept
    {
        return st[getPhysicalIndex(i)];
    }
    
    inline const X87Register& ST(int i) const noexcept
    {
        return st[getPhysicalIndex(i)];
    }
    
    // Push value onto FPU stack
    inline void push(long double value) noexcept
    {
        status.top = (status.top - 1) & 7;
        st[status.top].f80 = value;
        tags.setValid(status.top);
    }
    
    // Pop value from FPU stack
    inline long double pop() noexcept
    {
        long double value = st[status.top].f80;
        tags.setEmpty(status.top);
        status.top = (status.top + 1) & 7;
        return value;
    }
    
    // Set condition codes for comparison
    inline void setCompareResult(long double a, long double b) noexcept
    {
        if (__builtin_isnan(a) || __builtin_isnan(b))
        {
            status.c3 = 1;
            status.c2 = 1;
            status.c0 = 1;
        }
        else if (a > b)
        {
            status.c3 = 0;
            status.c2 = 0;
            status.c0 = 0;
        }
        else if (a < b)
        {
            status.c3 = 0;
            status.c2 = 0;
            status.c0 = 1;
        }
        else // equal
        {
            status.c3 = 1;
            status.c2 = 0;
            status.c0 = 0;
        }
    }
};

// SSE MXCSR register
struct X86MXCSR
{
    uint32_t value;
    
    static constexpr uint32_t IE_MASK = 1 << 0;   // Invalid Operation Flag
    static constexpr uint32_t DE_MASK = 1 << 1;   // Denormal Flag
    static constexpr uint32_t ZE_MASK = 1 << 2;   // Divide-by-Zero Flag
    static constexpr uint32_t OE_MASK = 1 << 3;   // Overflow Flag
    static constexpr uint32_t UE_MASK = 1 << 4;   // Underflow Flag
    static constexpr uint32_t PE_MASK = 1 << 5;   // Precision Flag
    static constexpr uint32_t DAZ_MASK = 1 << 6;  // Denormals Are Zeros
    static constexpr uint32_t IM_MASK = 1 << 7;   // Invalid Operation Mask
    static constexpr uint32_t DM_MASK = 1 << 8;   // Denormal Mask
    static constexpr uint32_t ZM_MASK = 1 << 9;   // Divide-by-Zero Mask
    static constexpr uint32_t OM_MASK = 1 << 10;  // Overflow Mask
    static constexpr uint32_t UM_MASK = 1 << 11;  // Underflow Mask
    static constexpr uint32_t PM_MASK = 1 << 12;  // Precision Mask
    static constexpr uint32_t RC_MASK = 3 << 13;  // Rounding Control
    static constexpr uint32_t FZ_MASK = 1 << 15;  // Flush to Zero
    
    inline uint32_t getRoundingMode() const noexcept
    {
        return (value & RC_MASK) >> 13;
    }
    
    inline void setRoundingMode(uint32_t mode) noexcept
    {
        value = (value & ~RC_MASK) | ((mode & 3) << 13);
    }
    
    inline void loadFromHost() noexcept
    {
        value = simde_mm_getcsr();
    }
    
    inline void storeToHost() noexcept
    {
        simde_mm_setcsr(value);
    }
};

// MMX Register (64-bit, shared with x87 FPU registers)
union alignas(8) MMXRegister
{
    int8_t s8[8];
    uint8_t u8[8];
    int16_t s16[4];
    uint16_t u16[4];
    int32_t s32[2];
    uint32_t u32[2];
    int64_t s64;
    uint64_t u64;
};

// SSE XMM Register (128-bit)
union alignas(16) XMMRegister
{
    int8_t s8[16];
    uint8_t u8[16];
    int16_t s16[8];
    uint16_t u16[8];
    int32_t s32[4];
    uint32_t u32[4];
    int64_t s64[2];
    uint64_t u64[2];
    float f32[4];
    double f64[2];
    simde__m128 m128;
    simde__m128i m128i;
    simde__m128d m128d;
};

// Main x86 CPU Context structure
struct alignas(64) X86Context
{
    // General Purpose Registers
    X86GPRegister eax;
    X86GPRegister ecx;
    X86GPRegister edx;
    X86GPRegister ebx;
    X86GPRegister esp;
    X86GPRegister ebp;
    X86GPRegister esi;
    X86GPRegister edi;
    
    // EFLAGS
    X86EFlags eflags;
    
    // x87 FPU State
    X87FPUState fpu;
    
    // MMX Registers (technically share storage with FPU but we keep separate for simplicity)
    // On real hardware, mm0-mm7 overlay the mantissa of st0-st7
    // EMMS instruction should be called to reset FPU state after MMX use
    MMXRegister mm[8];
    
    // MXCSR for SSE
    X86MXCSR mxcsr;
    
    // SSE XMM Registers (Xbox has SSE2)
    XMMRegister xmm0;
    XMMRegister xmm1;
    XMMRegister xmm2;
    XMMRegister xmm3;
    XMMRegister xmm4;
    XMMRegister xmm5;
    XMMRegister xmm6;
    XMMRegister xmm7;
    
    // Segment registers (mostly unused in flat memory model but kept for completeness)
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t fs;
    uint16_t gs;
    uint16_t ss;
    
    // FS and GS base addresses (for TLS and kernel data)
    uint32_t fs_base;
    uint32_t gs_base;
};

// Helper macros for register access
#define X86_REG_AL(ctx) (ctx).eax.u8
#define X86_REG_AH(ctx) (ctx).eax.bytes.hi
#define X86_REG_AX(ctx) (ctx).eax.u16
#define X86_REG_EAX(ctx) (ctx).eax.u32

#define X86_REG_CL(ctx) (ctx).ecx.u8
#define X86_REG_CH(ctx) (ctx).ecx.bytes.hi
#define X86_REG_CX(ctx) (ctx).ecx.u16
#define X86_REG_ECX(ctx) (ctx).ecx.u32

#define X86_REG_DL(ctx) (ctx).edx.u8
#define X86_REG_DH(ctx) (ctx).edx.bytes.hi
#define X86_REG_DX(ctx) (ctx).edx.u16
#define X86_REG_EDX(ctx) (ctx).edx.u32

#define X86_REG_BL(ctx) (ctx).ebx.u8
#define X86_REG_BH(ctx) (ctx).ebx.bytes.hi
#define X86_REG_BX(ctx) (ctx).ebx.u16
#define X86_REG_EBX(ctx) (ctx).ebx.u32

#define X86_REG_SPL(ctx) (ctx).esp.u8
#define X86_REG_SP(ctx) (ctx).esp.u16
#define X86_REG_ESP(ctx) (ctx).esp.u32

#define X86_REG_BPL(ctx) (ctx).ebp.u8
#define X86_REG_BP(ctx) (ctx).ebp.u16
#define X86_REG_EBP(ctx) (ctx).ebp.u32

#define X86_REG_SIL(ctx) (ctx).esi.u8
#define X86_REG_SI(ctx) (ctx).esi.u16
#define X86_REG_ESI(ctx) (ctx).esi.u32

#define X86_REG_DIL(ctx) (ctx).edi.u8
#define X86_REG_DI(ctx) (ctx).edi.u16
#define X86_REG_EDI(ctx) (ctx).edi.u32

// Stack operations
#define X86_PUSH32(ctx, base, val) \
    do { \
        X86_REG_ESP(ctx) -= 4; \
        X86_STORE_U32(X86_REG_ESP(ctx), (val)); \
    } while(0)

#define X86_POP32(ctx, base) \
    ([&]() -> uint32_t { \
        uint32_t _val = X86_LOAD_U32(X86_REG_ESP(ctx)); \
        X86_REG_ESP(ctx) += 4; \
        return _val; \
    })()

#define X86_PUSH16(ctx, base, val) \
    do { \
        X86_REG_ESP(ctx) -= 2; \
        X86_STORE_U16(X86_REG_ESP(ctx), (val)); \
    } while(0)

#define X86_POP16(ctx, base) \
    ([&]() -> uint16_t { \
        uint16_t _val = X86_LOAD_U16(X86_REG_ESP(ctx)); \
        X86_REG_ESP(ctx) += 2; \
        return _val; \
    })()

// Condition code helpers for conditional jumps
#define X86_COND_O(ctx)   ((ctx).eflags.of)
#define X86_COND_NO(ctx)  (!(ctx).eflags.of)
#define X86_COND_B(ctx)   ((ctx).eflags.cf)
#define X86_COND_C(ctx)   ((ctx).eflags.cf)
#define X86_COND_NAE(ctx) ((ctx).eflags.cf)
#define X86_COND_NB(ctx)  (!(ctx).eflags.cf)
#define X86_COND_NC(ctx)  (!(ctx).eflags.cf)
#define X86_COND_AE(ctx)  (!(ctx).eflags.cf)
#define X86_COND_Z(ctx)   ((ctx).eflags.zf)
#define X86_COND_E(ctx)   ((ctx).eflags.zf)
#define X86_COND_NZ(ctx)  (!(ctx).eflags.zf)
#define X86_COND_NE(ctx)  (!(ctx).eflags.zf)
#define X86_COND_BE(ctx)  ((ctx).eflags.cf || (ctx).eflags.zf)
#define X86_COND_NA(ctx)  ((ctx).eflags.cf || (ctx).eflags.zf)
#define X86_COND_A(ctx)   (!(ctx).eflags.cf && !(ctx).eflags.zf)
#define X86_COND_NBE(ctx) (!(ctx).eflags.cf && !(ctx).eflags.zf)
#define X86_COND_S(ctx)   ((ctx).eflags.sf)
#define X86_COND_NS(ctx)  (!(ctx).eflags.sf)
#define X86_COND_P(ctx)   ((ctx).eflags.pf)
#define X86_COND_PE(ctx)  ((ctx).eflags.pf)
#define X86_COND_NP(ctx)  (!(ctx).eflags.pf)
#define X86_COND_PO(ctx)  (!(ctx).eflags.pf)
#define X86_COND_L(ctx)   ((ctx).eflags.sf != (ctx).eflags.of)
#define X86_COND_NGE(ctx) ((ctx).eflags.sf != (ctx).eflags.of)
#define X86_COND_GE(ctx)  ((ctx).eflags.sf == (ctx).eflags.of)
#define X86_COND_NL(ctx)  ((ctx).eflags.sf == (ctx).eflags.of)
#define X86_COND_LE(ctx)  ((ctx).eflags.zf || ((ctx).eflags.sf != (ctx).eflags.of))
#define X86_COND_NG(ctx)  ((ctx).eflags.zf || ((ctx).eflags.sf != (ctx).eflags.of))
#define X86_COND_G(ctx)   (!(ctx).eflags.zf && ((ctx).eflags.sf == (ctx).eflags.of))
#define X86_COND_NLE(ctx) (!(ctx).eflags.zf && ((ctx).eflags.sf == (ctx).eflags.of))

// String operation direction
#define X86_STRING_DIRECTION(ctx) ((ctx).eflags.df ? -1 : 1)

// Arithmetic helpers with flag updates
template<typename T>
inline T x86_add(T a, T b, X86EFlags& flags) noexcept
{
    using UT = typename std::make_unsigned<T>::type;
    T result = a + b;
    
    flags.cf = static_cast<UT>(result) < static_cast<UT>(a);
    flags.of = ((a ^ result) & (b ^ result)) < 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_adc(T a, T b, X86EFlags& flags) noexcept
{
    using UT = typename std::make_unsigned<T>::type;
    T result = a + b + flags.cf;
    
    flags.cf = (static_cast<UT>(result) < static_cast<UT>(a)) || 
               (flags.cf && static_cast<UT>(result) == static_cast<UT>(a));
    flags.of = ((a ^ result) & (b ^ result)) < 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_sub(T a, T b, X86EFlags& flags) noexcept
{
    using UT = typename std::make_unsigned<T>::type;
    T result = a - b;
    
    flags.cf = static_cast<UT>(a) < static_cast<UT>(b);
    flags.of = ((a ^ b) & (a ^ result)) < 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_sbb(T a, T b, X86EFlags& flags) noexcept
{
    using UT = typename std::make_unsigned<T>::type;
    T result = a - b - flags.cf;
    
    flags.cf = (static_cast<UT>(a) < static_cast<UT>(b)) ||
               (flags.cf && static_cast<UT>(a) == static_cast<UT>(b));
    flags.of = ((a ^ b) & (a ^ result)) < 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_and(T a, T b, X86EFlags& flags) noexcept
{
    T result = a & b;
    
    flags.cf = 0;
    flags.of = 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_or(T a, T b, X86EFlags& flags) noexcept
{
    T result = a | b;
    
    flags.cf = 0;
    flags.of = 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_xor(T a, T b, X86EFlags& flags) noexcept
{
    T result = a ^ b;
    
    flags.cf = 0;
    flags.of = 0;
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_inc(T a, X86EFlags& flags) noexcept
{
    T result = a + 1;
    
    // INC does not affect CF
    flags.of = (a == static_cast<T>(~(typename std::make_unsigned<T>::type(0)) >> 1));
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_dec(T a, X86EFlags& flags) noexcept
{
    T result = a - 1;
    
    // DEC does not affect CF
    flags.of = (a == static_cast<T>(typename std::make_unsigned<T>::type(1) << (sizeof(T) * 8 - 1)));
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_neg(T a, X86EFlags& flags) noexcept
{
    T result = -a;
    
    flags.cf = (a != 0);
    flags.of = (a == static_cast<T>(typename std::make_unsigned<T>::type(1) << (sizeof(T) * 8 - 1)));
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_not(T a) noexcept
{
    // NOT does not affect any flags
    return ~a;
}

// Shift operations
template<typename T>
inline T x86_shl(T a, uint8_t count, X86EFlags& flags) noexcept
{
    if (count == 0) return a;
    
    count &= (sizeof(T) * 8 - 1);
    if (count == 0) return a;
    
    using UT = typename std::make_unsigned<T>::type;
    T result = static_cast<T>(static_cast<UT>(a) << count);
    
    flags.cf = (static_cast<UT>(a) >> (sizeof(T) * 8 - count)) & 1;
    if (count == 1) {
        flags.of = ((result < 0) != flags.cf);
    }
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_shr(T a, uint8_t count, X86EFlags& flags) noexcept
{
    if (count == 0) return a;
    
    count &= (sizeof(T) * 8 - 1);
    if (count == 0) return a;
    
    using UT = typename std::make_unsigned<T>::type;
    T result = static_cast<T>(static_cast<UT>(a) >> count);
    
    flags.cf = (static_cast<UT>(a) >> (count - 1)) & 1;
    if (count == 1) {
        flags.of = (a < 0);
    }
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

template<typename T>
inline T x86_sar(T a, uint8_t count, X86EFlags& flags) noexcept
{
    if (count == 0) return a;
    
    count &= (sizeof(T) * 8 - 1);
    if (count == 0) return a;
    
    T result = a >> count;
    
    flags.cf = (a >> (count - 1)) & 1;
    if (count == 1) {
        flags.of = 0;
    }
    flags.zf = (result == 0);
    flags.sf = (result < 0);
    flags.pf = !(__builtin_popcount(static_cast<uint8_t>(result)) & 1);
    
    return result;
}

// Rotate operations
template<typename T>
inline T x86_rol(T a, uint8_t count, X86EFlags& flags) noexcept
{
    constexpr size_t bits = sizeof(T) * 8;
    count &= (bits - 1);
    if (count == 0) return a;
    
    using UT = typename std::make_unsigned<T>::type;
    UT ua = static_cast<UT>(a);
    T result = static_cast<T>((ua << count) | (ua >> (bits - count)));
    
    flags.cf = result & 1;
    if (count == 1) {
        flags.of = ((result < 0) != flags.cf);
    }
    
    return result;
}

template<typename T>
inline T x86_ror(T a, uint8_t count, X86EFlags& flags) noexcept
{
    constexpr size_t bits = sizeof(T) * 8;
    count &= (bits - 1);
    if (count == 0) return a;
    
    using UT = typename std::make_unsigned<T>::type;
    UT ua = static_cast<UT>(a);
    T result = static_cast<T>((ua >> count) | (ua << (bits - count)));
    
    flags.cf = (result < 0);
    if (count == 1) {
        flags.of = ((result < 0) != ((result & (static_cast<T>(1) << (bits - 2))) != 0));
    }
    
    return result;
}

// Rotate through carry
template<typename T>
inline T x86_rcl(T a, uint8_t count, X86EFlags& flags) noexcept
{
    constexpr size_t bits = sizeof(T) * 8;
    count %= (bits + 1);
    if (count == 0) return a;
    
    using UT = typename std::make_unsigned<T>::type;
    UT ua = static_cast<UT>(a);
    UT result = ua;
    uint8_t cf = flags.cf;
    
    for (uint8_t i = 0; i < count; i++) {
        uint8_t new_cf = (result >> (bits - 1)) & 1;
        result = (result << 1) | cf;
        cf = new_cf;
    }
    
    flags.cf = cf;
    if (count == 1) {
        flags.of = ((static_cast<T>(result) < 0) != flags.cf);
    }
    
    return static_cast<T>(result);
}

template<typename T>
inline T x86_rcr(T a, uint8_t count, X86EFlags& flags) noexcept
{
    constexpr size_t bits = sizeof(T) * 8;
    count %= (bits + 1);
    if (count == 0) return a;
    
    using UT = typename std::make_unsigned<T>::type;
    UT ua = static_cast<UT>(a);
    UT result = ua;
    uint8_t cf = flags.cf;
    
    uint8_t old_msb = (result >> (bits - 1)) & 1;
    for (uint8_t i = 0; i < count; i++) {
        uint8_t new_cf = result & 1;
        result = (result >> 1) | (static_cast<UT>(cf) << (bits - 1));
        cf = new_cf;
    }
    
    flags.cf = cf;
    if (count == 1) {
        flags.of = (old_msb != ((result >> (bits - 1)) & 1));
    }
    
    return static_cast<T>(result);
}

// Bit test operations
template<typename T>
inline void x86_bt(T a, T bit, X86EFlags& flags) noexcept
{
    flags.cf = (a >> (bit & (sizeof(T) * 8 - 1))) & 1;
}

template<typename T>
inline T x86_bts(T a, T bit, X86EFlags& flags) noexcept
{
    bit &= (sizeof(T) * 8 - 1);
    flags.cf = (a >> bit) & 1;
    return a | (static_cast<T>(1) << bit);
}

template<typename T>
inline T x86_btr(T a, T bit, X86EFlags& flags) noexcept
{
    bit &= (sizeof(T) * 8 - 1);
    flags.cf = (a >> bit) & 1;
    return a & ~(static_cast<T>(1) << bit);
}

template<typename T>
inline T x86_btc(T a, T bit, X86EFlags& flags) noexcept
{
    bit &= (sizeof(T) * 8 - 1);
    flags.cf = (a >> bit) & 1;
    return a ^ (static_cast<T>(1) << bit);
}

// BSF/BSR - Bit scan forward/reverse
template<typename T>
inline T x86_bsf(T a, X86EFlags& flags) noexcept
{
    if (a == 0) {
        flags.zf = 1;
        return 0; // Undefined, but return 0
    }
    flags.zf = 0;
    return __builtin_ctzll(static_cast<uint64_t>(static_cast<typename std::make_unsigned<T>::type>(a)));
}

template<typename T>
inline T x86_bsr(T a, X86EFlags& flags) noexcept
{
    if (a == 0) {
        flags.zf = 1;
        return 0; // Undefined, but return 0
    }
    flags.zf = 0;
    return (sizeof(T) * 8 - 1) - __builtin_clzll(static_cast<uint64_t>(static_cast<typename std::make_unsigned<T>::type>(a)) << (64 - sizeof(T) * 8));
}

// BSWAP
inline uint32_t x86_bswap32(uint32_t a) noexcept
{
    return __builtin_bswap32(a);
}

inline uint16_t x86_bswap16(uint16_t a) noexcept
{
    return __builtin_bswap16(a);
}

// XCHG
template<typename T>
inline void x86_xchg(T& a, T& b) noexcept
{
    T tmp = a;
    a = b;
    b = tmp;
}

// CMPXCHG
template<typename T>
inline bool x86_cmpxchg(T& dest, T& acc, T src, X86EFlags& flags) noexcept
{
    if (acc == dest) {
        flags.zf = 1;
        dest = src;
        return true;
    } else {
        flags.zf = 0;
        acc = dest;
        return false;
    }
}

// MUL/IMUL helpers
inline void x86_mul8(X86Context& ctx, uint8_t src) noexcept
{
    uint16_t result = static_cast<uint16_t>(X86_REG_AL(ctx)) * static_cast<uint16_t>(src);
    X86_REG_AX(ctx) = result;
    ctx.eflags.cf = ctx.eflags.of = (result > 0xFF);
}

inline void x86_mul16(X86Context& ctx, uint16_t src) noexcept
{
    uint32_t result = static_cast<uint32_t>(X86_REG_AX(ctx)) * static_cast<uint32_t>(src);
    X86_REG_AX(ctx) = static_cast<uint16_t>(result);
    X86_REG_DX(ctx) = static_cast<uint16_t>(result >> 16);
    ctx.eflags.cf = ctx.eflags.of = (result > 0xFFFF);
}

inline void x86_mul32(X86Context& ctx, uint32_t src) noexcept
{
    uint64_t result = static_cast<uint64_t>(X86_REG_EAX(ctx)) * static_cast<uint64_t>(src);
    X86_REG_EAX(ctx) = static_cast<uint32_t>(result);
    X86_REG_EDX(ctx) = static_cast<uint32_t>(result >> 32);
    ctx.eflags.cf = ctx.eflags.of = (result > 0xFFFFFFFF);
}

inline void x86_imul8(X86Context& ctx, int8_t src) noexcept
{
    int16_t result = static_cast<int16_t>(static_cast<int8_t>(X86_REG_AL(ctx))) * static_cast<int16_t>(src);
    X86_REG_AX(ctx) = static_cast<uint16_t>(result);
    ctx.eflags.cf = ctx.eflags.of = (result != static_cast<int8_t>(result));
}

inline void x86_imul16(X86Context& ctx, int16_t src) noexcept
{
    int32_t result = static_cast<int32_t>(static_cast<int16_t>(X86_REG_AX(ctx))) * static_cast<int32_t>(src);
    X86_REG_AX(ctx) = static_cast<uint16_t>(result);
    X86_REG_DX(ctx) = static_cast<uint16_t>(result >> 16);
    ctx.eflags.cf = ctx.eflags.of = (result != static_cast<int16_t>(result));
}

inline void x86_imul32(X86Context& ctx, int32_t src) noexcept
{
    int64_t result = static_cast<int64_t>(static_cast<int32_t>(X86_REG_EAX(ctx))) * static_cast<int64_t>(src);
    X86_REG_EAX(ctx) = static_cast<uint32_t>(result);
    X86_REG_EDX(ctx) = static_cast<uint32_t>(result >> 32);
    ctx.eflags.cf = ctx.eflags.of = (result != static_cast<int32_t>(result));
}

// Two and three operand IMUL
inline int32_t x86_imul32_2op(int32_t a, int32_t b, X86EFlags& flags) noexcept
{
    int64_t result = static_cast<int64_t>(a) * static_cast<int64_t>(b);
    flags.cf = flags.of = (result != static_cast<int32_t>(result));
    return static_cast<int32_t>(result);
}

inline int16_t x86_imul16_2op(int16_t a, int16_t b, X86EFlags& flags) noexcept
{
    int32_t result = static_cast<int32_t>(a) * static_cast<int32_t>(b);
    flags.cf = flags.of = (result != static_cast<int16_t>(result));
    return static_cast<int16_t>(result);
}

// DIV/IDIV helpers
inline void x86_div8(X86Context& ctx, uint8_t src)
{
    if (src == 0) {
        // Division by zero - would trigger exception
        return;
    }
    uint16_t dividend = X86_REG_AX(ctx);
    uint8_t quotient = static_cast<uint8_t>(dividend / src);
    uint8_t remainder = static_cast<uint8_t>(dividend % src);
    X86_REG_AL(ctx) = quotient;
    X86_REG_AH(ctx) = remainder;
}

inline void x86_div16(X86Context& ctx, uint16_t src)
{
    if (src == 0) return;
    uint32_t dividend = (static_cast<uint32_t>(X86_REG_DX(ctx)) << 16) | X86_REG_AX(ctx);
    uint16_t quotient = static_cast<uint16_t>(dividend / src);
    uint16_t remainder = static_cast<uint16_t>(dividend % src);
    X86_REG_AX(ctx) = quotient;
    X86_REG_DX(ctx) = remainder;
}

inline void x86_div32(X86Context& ctx, uint32_t src)
{
    if (src == 0) return;
    uint64_t dividend = (static_cast<uint64_t>(X86_REG_EDX(ctx)) << 32) | X86_REG_EAX(ctx);
    uint32_t quotient = static_cast<uint32_t>(dividend / src);
    uint32_t remainder = static_cast<uint32_t>(dividend % src);
    X86_REG_EAX(ctx) = quotient;
    X86_REG_EDX(ctx) = remainder;
}

inline void x86_idiv8(X86Context& ctx, int8_t src)
{
    if (src == 0) return;
    int16_t dividend = static_cast<int16_t>(X86_REG_AX(ctx));
    int8_t quotient = static_cast<int8_t>(dividend / src);
    int8_t remainder = static_cast<int8_t>(dividend % src);
    X86_REG_AL(ctx) = static_cast<uint8_t>(quotient);
    X86_REG_AH(ctx) = static_cast<uint8_t>(remainder);
}

inline void x86_idiv16(X86Context& ctx, int16_t src)
{
    if (src == 0) return;
    int32_t dividend = static_cast<int32_t>((static_cast<uint32_t>(X86_REG_DX(ctx)) << 16) | X86_REG_AX(ctx));
    int16_t quotient = static_cast<int16_t>(dividend / src);
    int16_t remainder = static_cast<int16_t>(dividend % src);
    X86_REG_AX(ctx) = static_cast<uint16_t>(quotient);
    X86_REG_DX(ctx) = static_cast<uint16_t>(remainder);
}

inline void x86_idiv32(X86Context& ctx, int32_t src)
{
    if (src == 0) return;
    int64_t dividend = static_cast<int64_t>((static_cast<uint64_t>(X86_REG_EDX(ctx)) << 32) | X86_REG_EAX(ctx));
    int32_t quotient = static_cast<int32_t>(dividend / src);
    int32_t remainder = static_cast<int32_t>(dividend % src);
    X86_REG_EAX(ctx) = static_cast<uint32_t>(quotient);
    X86_REG_EDX(ctx) = static_cast<uint32_t>(remainder);
}

// Sign extension helpers
inline void x86_cbw(X86Context& ctx) noexcept
{
    X86_REG_AX(ctx) = static_cast<int16_t>(static_cast<int8_t>(X86_REG_AL(ctx)));
}

inline void x86_cwde(X86Context& ctx) noexcept
{
    X86_REG_EAX(ctx) = static_cast<int32_t>(static_cast<int16_t>(X86_REG_AX(ctx)));
}

inline void x86_cwd(X86Context& ctx) noexcept
{
    X86_REG_DX(ctx) = (static_cast<int16_t>(X86_REG_AX(ctx)) < 0) ? 0xFFFF : 0;
}

inline void x86_cdq(X86Context& ctx) noexcept
{
    X86_REG_EDX(ctx) = (static_cast<int32_t>(X86_REG_EAX(ctx)) < 0) ? 0xFFFFFFFF : 0;
}

// MOVSX/MOVZX helpers
template<typename DT, typename ST>
inline DT x86_movsx(ST src) noexcept
{
    return static_cast<DT>(src);
}

template<typename DT, typename ST>
inline DT x86_movzx(ST src) noexcept
{
    using UST = typename std::make_unsigned<ST>::type;
    return static_cast<DT>(static_cast<UST>(src));
}

// LEA helper (just computes address, no memory access)
inline uint32_t x86_lea(uint32_t base, uint32_t index, uint32_t scale, int32_t disp) noexcept
{
    return base + (index * scale) + disp;
}

// String operation helpers
inline void x86_movsb(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx);
    X86_STORE_U8(X86_REG_EDI(ctx), X86_LOAD_U8(X86_REG_ESI(ctx)));
    X86_REG_ESI(ctx) += dir;
    X86_REG_EDI(ctx) += dir;
}

inline void x86_movsw(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 2;
    X86_STORE_U16(X86_REG_EDI(ctx), X86_LOAD_U16(X86_REG_ESI(ctx)));
    X86_REG_ESI(ctx) += dir;
    X86_REG_EDI(ctx) += dir;
}

inline void x86_movsd(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 4;
    X86_STORE_U32(X86_REG_EDI(ctx), X86_LOAD_U32(X86_REG_ESI(ctx)));
    X86_REG_ESI(ctx) += dir;
    X86_REG_EDI(ctx) += dir;
}

inline void x86_stosb(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx);
    X86_STORE_U8(X86_REG_EDI(ctx), static_cast<uint8_t>(X86_REG_EAX(ctx)));
    X86_REG_EDI(ctx) += dir;
}

inline void x86_stosw(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 2;
    X86_STORE_U16(X86_REG_EDI(ctx), static_cast<uint16_t>(X86_REG_EAX(ctx)));
    X86_REG_EDI(ctx) += dir;
}

inline void x86_stosd(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 4;
    X86_STORE_U32(X86_REG_EDI(ctx), X86_REG_EAX(ctx));
    X86_REG_EDI(ctx) += dir;
}

inline void x86_lodsb(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx);
    X86_REG_AL(ctx) = X86_LOAD_U8(X86_REG_ESI(ctx));
    X86_REG_ESI(ctx) += dir;
}

inline void x86_lodsw(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 2;
    X86_REG_AX(ctx) = X86_LOAD_U16(X86_REG_ESI(ctx));
    X86_REG_ESI(ctx) += dir;
}

inline void x86_lodsd(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 4;
    X86_REG_EAX(ctx) = X86_LOAD_U32(X86_REG_ESI(ctx));
    X86_REG_ESI(ctx) += dir;
}

inline void x86_scasb(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx);
    uint8_t val = X86_LOAD_U8(X86_REG_EDI(ctx));
    x86_sub(static_cast<int8_t>(X86_REG_AL(ctx)), static_cast<int8_t>(val), ctx.eflags);
    X86_REG_EDI(ctx) += dir;
}

inline void x86_scasw(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 2;
    uint16_t val = X86_LOAD_U16(X86_REG_EDI(ctx));
    x86_sub(static_cast<int16_t>(X86_REG_AX(ctx)), static_cast<int16_t>(val), ctx.eflags);
    X86_REG_EDI(ctx) += dir;
}

inline void x86_scasd(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 4;
    uint32_t val = X86_LOAD_U32(X86_REG_EDI(ctx));
    x86_sub(static_cast<int32_t>(X86_REG_EAX(ctx)), static_cast<int32_t>(val), ctx.eflags);
    X86_REG_EDI(ctx) += dir;
}

inline void x86_cmpsb(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx);
    uint8_t src = X86_LOAD_U8(X86_REG_ESI(ctx));
    uint8_t dst = X86_LOAD_U8(X86_REG_EDI(ctx));
    x86_sub(static_cast<int8_t>(src), static_cast<int8_t>(dst), ctx.eflags);
    X86_REG_ESI(ctx) += dir;
    X86_REG_EDI(ctx) += dir;
}

inline void x86_cmpsw(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 2;
    uint16_t src = X86_LOAD_U16(X86_REG_ESI(ctx));
    uint16_t dst = X86_LOAD_U16(X86_REG_EDI(ctx));
    x86_sub(static_cast<int16_t>(src), static_cast<int16_t>(dst), ctx.eflags);
    X86_REG_ESI(ctx) += dir;
    X86_REG_EDI(ctx) += dir;
}

inline void x86_cmpsd(X86Context& ctx, uint8_t* base) noexcept
{
    int dir = X86_STRING_DIRECTION(ctx) * 4;
    uint32_t src = X86_LOAD_U32(X86_REG_ESI(ctx));
    uint32_t dst = X86_LOAD_U32(X86_REG_EDI(ctx));
    x86_sub(static_cast<int32_t>(src), static_cast<int32_t>(dst), ctx.eflags);
    X86_REG_ESI(ctx) += dir;
    X86_REG_EDI(ctx) += dir;
}

// SETCC helpers
#define X86_SETCC(cond) static_cast<uint8_t>((cond) ? 1 : 0)

// CMOV helpers
template<typename T>
inline T x86_cmov(bool cond, T dest, T src) noexcept
{
    return cond ? src : dest;
}

#endif // X86_CONTEXT_H_INCLUDED
