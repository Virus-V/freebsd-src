/*
 * Copyright (c) 2014, Mentor Graphics Corporation
 * Copyright (c) 2015 Xilinx, Inc.
 * Copyright (c) 2016 Freescale Semiconductor, Inc.
 * Copyright 2016-2022 NXP
 * Copyright 2021 ACRIOS Systems s.r.o.
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

/**************************************************************************
 * FILE NAME
 *
 *       rpmsg_env.h
 *
 * COMPONENT
 *
 *         OpenAMP stack.
 *
 * DESCRIPTION
 *
 *       This file defines abstraction layer for OpenAMP stack. The implementor
 *       must provide definition of all the functions.
 *
 * DATA STRUCTURES
 *
 *        none
 *
 * FUNCTIONS
 *
 *       env_allocate_memory
 *       env_free_memory
 *       env_memset
 *       env_memcpy
 *       env_strncpy
 *       env_print
 *       env_map_vatopa
 *       env_map_patova
 *       env_mb
 *       env_rmb
 *       env_wmb
 *       env_create_mutex
 *       env_delete_mutex
 *       env_lock_mutex
 *       env_unlock_mutex
 *       env_sleep_msec
 *       env_disable_interrupt
 *       env_enable_interrupt
 *       env_create_queue
 *       env_delete_queue
 *       env_put_queue
 *       env_get_queue
 *       env_wait_for_link_up
 *       env_tx_callback
 *       env_notify
 *
 **************************************************************************/
#ifndef RPMSG_ENV_H_
#define RPMSG_ENV_H_

#include <sys/types.h>
#include "dev/rpmsg_lite/rpmsg_default_config.h"
#include "dev/rpmsg_lite/rpmsg_env_specific.h"

/*!
 * env_init
 *
 * Initializes OS/BM environment.
 *
 * @param env_context        Pointer to preallocated environment context data
 * @param env_init_data      Initialization data for the environment layer
 *
 * @returns - execution status
 */
int32_t env_init(void **env_context, void *env_init_data);

/*!
 * env_deinit
 *
 * Uninitializes OS/BM environment.
 *
 * @param env_context   Pointer to environment context data
 *
 * @returns - execution status
 */
int32_t env_deinit(void *env_context);

/*!
 * -------------------------------------------------------------------------
 *
 * Dynamic memory management functions. The parameters
 * are similar to standard c functions.
 *
 *-------------------------------------------------------------------------
 **/

/*!
 * env_allocate_memory
 *
 * Allocates memory with the given size.
 *
 * @param size - size of memory to allocate
 *
 * @return - pointer to allocated memory
 */
void *env_allocate_memory(uint32_t size);

/*!
 * env_free_memory
 *
 * Frees memory pointed by the given parameter.
 *
 * @param ptr - pointer to memory to free
 */
void env_free_memory(void *ptr);

/*!
 * -------------------------------------------------------------------------
 *
 * RTL Functions
 *
 *-------------------------------------------------------------------------
 */

void env_memset(void *ptr, int32_t value, uint32_t size);
void env_memcpy(void *dst, void const *src, uint32_t len);
int32_t env_strcmp(const char *dst, const char *src);
void env_strncpy(char *dest, const char *src, uint32_t len);
int32_t env_strncmp(char *dest, const char *src, uint32_t len);

/* When RPMsg_Lite being used outside of MCUXpresso_SDK use your own env_print
   implemenetation to avoid conflict with Misra 21.6 rule */
#include <sys/systm.h>
#define env_print(...) (void)printf(__VA_ARGS__)

/*!
 *-----------------------------------------------------------------------------
 *
 *  Functions to convert physical address to virtual address and vice versa.
 *
 *-----------------------------------------------------------------------------
 */

/*!
 * env_map_vatopa
 *
 * Converts logical address to physical address
 *
 * @param env       Pointer to environment context data
 * @param address   Pointer to logical address
 *
 * @return  - physical address
 */
uint64_t env_map_vatopa(void *env, void *address);

/*!
 * env_map_patova
 *
 * Converts physical address to logical address
 *
 * @param env_context   Pointer to environment context data
 * @param address       Pointer to physical address
 *
 * @return  - logical address
 *
 */
void *env_map_patova(void *env, uint64_t address);

/*!
 *-----------------------------------------------------------------------------
 *
 *  Abstractions for memory barrier instructions.
 *
 *-----------------------------------------------------------------------------
 */

/*!
 * env_mb
 *
 * Inserts memory barrier.
 */

void env_mb(void);

/*!
 * env_rmb
 *
 * Inserts read memory barrier
 */

void env_rmb(void);

/*!
 * env_wmb
 *
 * Inserts write memory barrier
 */

void env_wmb(void);

/*!
 *-----------------------------------------------------------------------------
 *
 *  Abstractions for OS lock primitives.
 *
 *-----------------------------------------------------------------------------
 */

/*!
 * env_lock_mutex
 *
 * Tries to acquire the lock, if lock is not available then call to
 * this function will suspend.
 *
 * @param lock - mutex to lock
 *
 */

void env_lock_mutex(void *env);

/*!
 * env_unlock_mutex
 *
 * Releases the given lock.
 *
 * @param lock - mutex to unlock
 */

void env_unlock_mutex(void *env);

/*!
 * env_sleep_msec
 *
 * Suspends the calling thread for given time in msecs.
 *
 * @param num_msec -  delay in msecs
 */
void env_sleep_msec(void *env, uint32_t num_msec);

/*!
 * env_get_timestamp
 *
 * Returns a 64 bit time stamp.
 *
 *
 */
uint64_t env_get_timestamp(void);

/*!
 * env_isr
 *
 * Invoke RPMSG/IRQ callback
 *
 * @param env           Pointer to environment context data
 * @param vector        RPMSG IRQ vector ID.
 */
void env_isr(void *env, uint32_t vector);

/*!
 * env_get_platform_context
 *
 * Get the platform layer context from the environment platform context
 *
 * @param env     Pointer to environment context data
 *
 * @return        Pointer to platform context data
 */
void *env_get_platform_context(void *env_context);

/*!
 * env_init_interrupt
 *
 * Initialize the ISR data for given virtqueue interrupt
 *
 * @param env       Pointer to environment context data
 * @param vq_id     Virtqueue ID
 * @param isr_data  Pointer to initial ISR data
 *
 * @return        Execution status, 0 on success
 */
int32_t env_init_interrupt(void *env, int32_t vq_id, void *isr_data);

/*!
 * env_deinit_interrupt
 *
 * Deinitialize the ISR data for given virtqueue interrupt
 *
 * @param env       Pointer to environment context data
 * @param vq_id     Virtqueue ID
 *
 * @return        Execution status, 0 on success
 */
int32_t env_deinit_interrupt(void *env, int32_t vq_id);

/*!
 * env_wait_for_link_up
 *
 * Env. specific implementation of rpmsg_lite_wait_for_link_up function with the usage
 * of RTOS sync. primitives to avoid busy loop. Returns once the link is up.
 *
 * @param link_state  Pointer to the link_state parameter of the rpmsg_lite_instance structure
 * @param link_id     Link ID used to define the rpmsg-lite instance, see rpmsg_platform.h
 * @param timeout_ms  Timeout in ms
 *
 * @return RL_TRUE when link up, RL_FALSE when timeout.
 *
 */
uint32_t env_wait_for_link_up(void *env, volatile uint32_t *link_state, uint32_t link_id, uint32_t timeout_ms);

/*!
 * env_tx_callback
 *
 * Called from rpmsg_lite_tx_callback() to allow unblocking of env_wait_for_link_up()
 *
 * @param link_id     Link ID used to define the rpmsg-lite instance, see rpmsg_platform.h
 */
void env_tx_callback(void *env, uint32_t link_id);

/*!
 * env_notify
 *
 * Called from virtqueue_notify() to notify peer
 *
 * @param env         Pointer to environment context data
 * @param vector      Link ID used to define the rpmsg-lite instance, see rpmsg_platform.h
 */
void env_notify(void *env, uint32_t vector);
#endif /* RPMSG_ENV_H_ */
