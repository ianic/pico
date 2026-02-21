#ifndef lwip__cc_h
#define lwip__cc_h

#include <stdbool.h>
#include <stdint.h>

typedef unsigned int sys_prot_t;

// required in debug string formating
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "u"
#define X8_F "02x"
#define U8_F "u"
#define S8_F "d"
#define PTR_F "p"

// Platform dependent methods, needs to be implemented for each chip.
extern uint32_t lwip_rand(void);
extern uint32_t lwip_sys_now(void);

// Implemented in network/root.zig
extern void lwip_lock_interrupts(bool *state);
extern void lwip_unlock_interrupts(bool state);
extern void lwip_assert(const char *msg, const char *file, int line);
extern void lwip_diag2(const char *fmt, ...);
extern void lwip_sntp_set_time(uint32_t sec);
extern const char *lwip_sntp_format_time(uint32_t sec);

#define LWIP_PLATFORM_DIAG(x)                                                  \
    do {                                                                       \
        lwip_diag2 x;                                                          \
    } while (0)

#define LWIP_PLATFORM_ASSERT(msg)                                              \
    do {                                                                       \
        lwip_assert((msg), __FILE__, __LINE__);                                \
    } while (0)

#define BYTE_ORDER LITTLE_ENDIAN

#define LWIP_RAND() ((u32_t)lwip_rand())

#define LWIP_NO_STDDEF_H 0
#define LWIP_NO_STDINT_H 0
#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_LIMITS_H 0
#define LWIP_NO_CTYPE_H 1

#define LWIP_UNUSED_ARG(x) (void)x
#define LWIP_PROVIDE_ERRNO 1

// Critical section support:
// https://www.nongnu.org/lwip/2_1_x/group__sys__prot.html
#define SYS_ARCH_DECL_PROTECT(lev) bool lev
#define SYS_ARCH_PROTECT(lev) lwip_lock_interrupts(&lev)
#define SYS_ARCH_UNPROTECT(lev) lwip_unlock_interrupts(lev)

#define SNTP_SET_SYSTEM_TIME(sec) lwip_sntp_set_time(sec)
#define sntp_format_time(sec) lwip_sntp_format_time(sec)

// Rename sys_now to lwip_sys_now
// https://github.com/lwip-tcpip/lwip/blob/6ca936f6b588cee702c638eee75c2436e6cf75de/src/include/lwip/sys.h#L446
#define sys_now lwip_sys_now

// #define LWIP_DEBUG

#endif // lwip__cc_h
