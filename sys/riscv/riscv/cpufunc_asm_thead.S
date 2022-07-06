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

#include <machine/asm.h>
__FBSDID("$FreeBSD$");

	.text
	.align	2

/*
 * void thead_dcache_inv_range(vm_offset_t, vm_size_t)
 */
ENTRY(thead_dcache_inv_range)
	lw	t0, dcache_line_size	/* get cache line size */
	addi	t1, t0, -1	/* get cache line mask */
	and	t2, a0, t1	/* get offset to cache line */
	sub	a0, a0, t2	/* round down the address */
	add	a1, a1, t2	/* round up the size */
1:
	.long	0x0265000B	/* dcache.iva a0 */
	add	a0, a0, t0	/* increment address */
	sub	a1, a1, t0	/* decrement size */
	bgtz	a1, 1b		/* repeat while size > 0 */

	.long	0x01A0000B	/* sync.i */
	ret
END(thead_dcache_inv_range)

/*
 * void thead_dcache_wb_range(vm_offset_t, vm_size_t)
 */
ENTRY(thead_dcache_wb_range)
	lw	t0, dcache_line_size	/* get cache line size */
	addi	t1, t0, -1	/* get cache line mask */
	and	t2, a0, t1	/* get offset to cache line */
	sub	a0, a0, t2	/* round down the address */
	add	a1, a1, t2	/* round up the size */
1:
	.long	0x0245000B	/* dcache.cva a0 */
	add	a0, a0, t0	/* increment address */
	sub	a1, a1, t0	/* decrement size */
	bgtz	a1, 1b		/* repeat while size > 0 */

	.long	0x01A0000B	/* sync.i */
	ret
END(thead_dcache_wb_range)

/*
 * void thead_dcache_wbinv_range(vm_offset_t, vm_size_t)
 */
ENTRY(thead_dcache_wbinv_range)
	lw	t0, dcache_line_size	/* get cache line size */
	addi	t1, t0, -1	/* get cache line mask */
	and	t2, a0, t1	/* get offset to cache line */
	sub	a0, a0, t2	/* round down the address */
	add	a1, a1, t2	/* round up the size */
1:
	.long	0x0275000B	/* dcache.civa a0 */
	add	a0, a0, t0	/* increment address */
	sub	a1, a1, t0	/* decrement size */
	bgtz	a1, 1b		/* repeat while size > 0 */

	.long	0x01A0000B	/* sync.i */
	ret
END(thead_dcache_wbinv_range)

/*
 * void thead_icache_sync_range(vm_offset_t, vm_size_t)
 */
ENTRY(thead_icache_sync_range)
	/* TODO */
	ret
END(thead_icache_sync_range)

/*
 * void thead_icache_sync_range_checked(vm_offset_t, vm_size_t)
 */
ENTRY(thead_icache_sync_range_checked)
	/* TODO */
	ret
END(thead_icache_sync_range_checked)

/*
 * void thead_idcache_wbinv_range(vm_offset_t, vm_size_t)
 */
ENTRY(thead_idcache_wbinv_range)
	/* TODO */
	ret
END(thead_idcache_wbinv_range)
