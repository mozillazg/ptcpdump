#ifndef __PTCPDUMP_GOTLS_HELPERS_H__
#define __PTCPDUMP_GOTLS_HELPERS_H__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#if defined(bpf_target_x86)
#define GO_PARAM1(dst, x) BPF_CORE_READ_INTO(dst, (x), ax)
#define GO_PARAM2(dst, x) BPF_CORE_READ_INTO(dst, (x), bx)
#define GO_PARAM3(dst, x) BPF_CORE_READ_INTO(dst, (x), cx)
#define GO_PARAM4(dst, x) BPF_CORE_READ_INTO(dst, (x), di)
#define GO_PARAM5(dst, x) BPF_CORE_READ_INTO(dst, (x), si)
#define GO_PARAM6(dst, x) BPF_CORE_READ_INTO(dst, (x), r8)
#define GO_PARAM7(dst, x) BPF_CORE_READ_INTO(dst, (x), r9)
#define GO_PARAM8(dst, x) BPF_CORE_READ_INTO(dst, (x), r10)
#define GO_PARAM9(dst, x) BPF_CORE_READ_INTO(dst, (x), r11)
#elif defined(bpf_target_arm64)
#define GO_PARAM1(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM1_REG)
#define GO_PARAM2(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM2_REG)
#define GO_PARAM3(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM3_REG)
#define GO_PARAM4(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM4_REG)
#define GO_PARAM5(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM5_REG)
#define GO_PARAM6(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM6_REG)
#define GO_PARAM7(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM7_REG)
#define GO_PARAM8(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM8_REG)
#define GO_PARAM9(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), regs[8])
#elif defined(bpf_target_arm)
#define GO_PARAM1(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM1_REG)
#define GO_PARAM2(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM2_REG)
#define GO_PARAM3(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM3_REG)
#define GO_PARAM4(dst, x) BPF_CORE_READ_INTO(dst, __PT_REGS_CAST(x), __PT_PARM4_REG)
#define GO_PARAM5(dst, x) NULL
#define GO_PARAM6(dst, x) NULL
#define GO_PARAM7(dst, x) NULL
#define GO_PARAM8(dst, x) NULL
#define GO_PARAM9(dst, x) NULL
#endif

static __always_inline void read_go_arg_into(u64 *dst, struct pt_regs *ctx, u8 index) {
    switch (index) {
    case 1:
        GO_PARAM1(dst, ctx);
        break;
    case 2:
        GO_PARAM2(dst, ctx);
        break;
    case 3:
        GO_PARAM3(dst, ctx);
        break;
    case 4:
        GO_PARAM4(dst, ctx);
        break;
    case 5:
        GO_PARAM5(dst, ctx);
        break;
    case 6:
        GO_PARAM6(dst, ctx);
        break;
    case 7:
        GO_PARAM7(dst, ctx);
        break;
    case 8:
        GO_PARAM8(dst, ctx);
        break;
    case 9:
        GO_PARAM9(dst, ctx);
        break;
    }
    return;
}

#endif /* __PTCPDUMP_GOTLS_HELPERS_H__ */
