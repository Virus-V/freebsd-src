/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * Copyright (c) 2015 Xilinx, Inc.
 * Copyright (c) 2016 Freescale Semiconductor, Inc.
 * Copyright 2016-2022 NXP
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/malloc.h>

#include "dev/rpmsg_lite/rpmsg_compiler.h"
#include "dev/rpmsg_lite/rpmsg_env.h"
#include "dev/rpmsg_lite/virtqueue.h"

#include "dev/rpmsg_lite/rpmsg_lite_bus.h"
#include "sys/systm.h"

MALLOC_DEFINE(M_RPMSG, "rpmsg", "rpmsg-lite environment");

/* Max supported ISR counts */
#define ISR_COUNT (12U)
/*!
 * Structure to keep track of registered ISR's.
 */
struct isr_info {
	void *data;
};
static struct isr_info isr_table[ISR_COUNT];

#if defined(RL_USE_ENVIRONMENT_CONTEXT) && (RL_USE_ENVIRONMENT_CONTEXT == 0)
#error "This RPMsg-Lite port requires RL_USE_ENVIRONMENT_CONTEXT set to 1"
#endif

uint32_t
env_wait_for_link_up(volatile uint32_t *link_state, uint32_t link_id,
    uint32_t timeout_ms)
{
	while (*link_state != 1U) {
	}
	return 1U;
}

void
env_tx_callback(uint32_t link_id)
{
}

int32_t
env_init(void **env_context, void *env_init_data)
{
	// first call
	(void)memset(isr_table, 0, sizeof(isr_table));
	*env_context = env_init_data;
	return 0;
}

void *
env_get_platform_context(void *env_context) {
	return env_context;
}

int32_t
env_deinit(void *env_context)
{
	return 0;
}

/*!
 * env_allocate_memory - implementation
 *
 * @param size
 */
void *
env_allocate_memory(uint32_t size)
{
	return (malloc(size, M_RPMSG, M_WAITOK));
}

/*!
 * env_free_memory - implementation
 *
 * @param ptr
 */
void
env_free_memory(void *ptr)
{
	if (ptr != ((void *)0)) {
		free(ptr, M_RPMSG);
	}
}

void
env_memset(void *ptr, int32_t value, uint32_t size)
{
	(void)memset(ptr, value, size);
}

void
env_memcpy(void *dst, void const *src, uint32_t len)
{
	(void)memcpy(dst, src, len);
}

int32_t
env_strcmp(const char *dst, const char *src)
{
	return (strcmp(dst, src));
}

void
env_strncpy(char *dest, const char *src, uint32_t len)
{
	(void)strncpy(dest, src, len);
}

int32_t
env_strncmp(char *dest, const char *src, uint32_t len)
{
	return (strncmp(dest, src, len));
}

void
env_mb(void)
{
	MEM_BARRIER();
}

void
env_rmb(void)
{
	MEM_BARRIER();
}

void
env_wmb(void)
{
	MEM_BARRIER();
}

uint64_t
env_map_vatopa(void *env, void *address)
{
	struct rpmsg_lite_softc * sc = (struct rpmsg_lite_softc *)env;
	return ((uintptr_t)address - sc->ocram_virt) + sc->ocram_phy;
}

void *
env_map_patova(void *env, uint64_t address)
{
	struct rpmsg_lite_softc * sc = (struct rpmsg_lite_softc *)env;
	return (void *)((address - sc->ocram_phy) + sc->ocram_virt);
}

int32_t
env_create_mutex(void **lock, int32_t count)
{
	*lock = lock;
	return 0;
}

void
env_delete_mutex(void *lock)
{
}

void
env_lock_mutex(void *lock)
{
	/* No mutex needed for RPMsg-Lite in BM environment,
	 * since the API is not shared with ISR context. */
}

void
env_unlock_mutex(void *lock)
{
	/* No mutex needed for RPMsg-Lite in BM environment,
	 * since the API is not shared with ISR context. */
}

void
env_sleep_msec(uint32_t num_msec)
{
	//pause("rpwait", hz); // 1s
	pause("rpwait", (hz / 1000) * num_msec); // 1ms
}

void
env_register_isr(void *env, uint32_t vector_id, void *data)
{
	RL_ASSERT(vector_id < ISR_COUNT);
	if (vector_id < ISR_COUNT) {
		isr_table[vector_id].data = data;
	}
}

void
env_unregister_isr(void *env, uint32_t vector_id)
{
	RL_ASSERT(vector_id < ISR_COUNT);
	if (vector_id < ISR_COUNT) {
		isr_table[vector_id].data = ((void *)0);
	}
}

void
env_enable_interrupt(void *env, uint32_t vector_id)
{
}

void
env_disable_interrupt(void *env, uint32_t vector_id)
{
}

int32_t
env_init_interrupt(void *env, int32_t vq_id, void *isr_data) {
	env_register_isr(env, vq_id, isr_data);
	return 0;
}

int32_t
env_deinit_interrupt(void *env, int32_t vq_id) {
	env_unregister_isr(env, vq_id);
	return 0;
}

void
env_notify(void *env, uint32_t vector)
{
	struct rpmsg_lite_softc * sc = (struct rpmsg_lite_softc *)env;

	// Write IPC0 Base IPC_CPU1_IPC_ISWR
	IPC0_WRITE4(sc, 0, (1 << (IPC_MSG_RPMSG0 + vector + 16)));
}

/*========================================================= */
/* Util data / functions for BM */

void
env_isr(void *env, uint32_t vector)
{
	struct isr_info *info;
	RL_ASSERT(vector < ISR_COUNT);
	if (vector < ISR_COUNT) {
		info = &isr_table[vector];
		virtqueue_notification((struct virtqueue *)info->data);
	}
}
