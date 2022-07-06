/*-
 * Copyright (c) 2022 Julien Cassette <julien.cassette@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_cpu.h"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/bus.h>

#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/md_var.h>

#include <vm/vm.h>

#include <machine/cpufunc.h>

struct cpu_functions cpufuncs;

static void
null_cache_setup(void)
{
	dcache_line_size = 0;
	icache_line_size = 0;
	idcache_line_size = 0;
}

struct cpu_functions null_cpufuncs = {
	.cf_cache_setup			= null_cache_setup,
	.cf_dcache_inv_range   		= (void *)riscv_nullop,
	.cf_dcache_wb_range    		= (void *)riscv_nullop,
	.cf_dcache_wbinv_range 		= (void *)riscv_nullop,
	.cf_icache_sync_range  		= (void *)riscv_nullop,
	.cf_icache_sync_range_checked	= (void *)riscv_nullop,
	.cf_idcache_wbinv_range		= (void *)riscv_nullop,
};

#if defined(CPU_THEAD)
static void
thead_cache_setup(void)
{
	dcache_line_size = 0x40;
	icache_line_size = 0x40;
	idcache_line_size = 0x40;
}

/* Defined in cpufunc_asm_thead.S */
void thead_dcache_inv_range(vm_offset_t, vm_size_t);
void thead_dcache_wb_range(vm_offset_t, vm_size_t);
void thead_dcache_wbinv_range(vm_offset_t, vm_size_t);
void thead_icache_sync_range(vm_offset_t, vm_size_t);
void thead_icache_sync_range_checked(vm_offset_t, vm_size_t);
void thead_idcache_wbinv_range(vm_offset_t, vm_size_t);

struct cpu_functions thead_cpufuncs = {
	.cf_cache_setup			= thead_cache_setup,
	.cf_dcache_inv_range   		= thead_dcache_inv_range,
	.cf_dcache_wb_range    		= thead_dcache_wb_range,
	.cf_dcache_wbinv_range 		= thead_dcache_wbinv_range,
	.cf_icache_sync_range  		= thead_icache_sync_range,
	.cf_icache_sync_range_checked	= thead_icache_sync_range_checked,
	.cf_idcache_wbinv_range		= thead_idcache_wbinv_range,
};
#endif /* CPU_THEAD */

int
set_cpufuncs(void)
{
	switch (mvendorid) {
#if defined(CPU_THEAD)
		case CPU_VENDOR_THEAD:
			cpufuncs = thead_cpufuncs;
			break;
#endif /* CPU_THEAD */
		default:
			cpufuncs = null_cpufuncs;
	}
	return (0);
}

