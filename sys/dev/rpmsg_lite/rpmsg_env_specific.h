/*
 * Copyright 2021 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef RPMSG_ENV_SPECIFIC_H_
#define RPMSG_ENV_SPECIFIC_H_

#include <sys/types.h>
#include "dev/rpmsg_lite/rpmsg_default_config.h"

/* we have 16K XRAM so we can play a bit with the size here */
#define XRAM_RINGBUF_ADDR 0x22020000
#define XRAM_RINGBUF_SIZE 12*1024

/* timeout to wait for other core to clear a IPC interupt */
#define IPC_TIMEOUT 100

/* IPC_IRQ_INT_SRC_Type is the type of messages we have */
typedef enum {
    IPC_MSG_PING = 0,
    IPC_MSG_PONG ,
    IPC_MSG_RPMSG0 ,
    IPC_MSG_RPMSG1 ,
    IPC_MSG_RPMSG2 ,
    IPC_MSG_RPMSG3 ,
    IPC_MSG_IRQFWD1,
    IPC_MSG_IRQFWD2 ,
    IPC_MSG_IRQFWD3 ,
    IPC_MSG_IRQFWD4 ,
} IPC_MSG_Type;

/**
 *	@brief GLB core ID type definition
 */
typedef enum {
    GLB_CORE_ID_M0,			 /*!< M0 */
    GLB_CORE_ID_D0,			 /*!< D0 */
    GLB_CORE_ID_LP,			 /*!< LP */
    GLB_CORE_ID_MAX,		 /*!< ID max */
    GLB_CORE_ID_INVALID, /*!< ID invalid */
} GLB_CORE_ID_Type;

typedef void(ipcIntCallback)(void *env, uint32_t src);

/*
 * No need to align the VRING as defined in Linux because k32l3a6 is not intended
 * to run the Linux
 */
#ifndef VRING_ALIGN
#define VRING_ALIGN (0x10U)
#endif

/* contains pool of descriptos and two circular buffers */
#ifndef VRING_SIZE
/* set VRING_SIZE based on number of used buffers as calculated in vring_init */
#define VRING_DESC_SIZE (((RL_BUFFER_COUNT * sizeof(struct vring_desc)) + VRING_ALIGN - 1UL) & ~(VRING_ALIGN - 1UL))
#define VRING_AVAIL_SIZE                                                                                            \
    (((sizeof(struct vring_avail) + (RL_BUFFER_COUNT * sizeof(uint16_t)) + sizeof(uint16_t)) + VRING_ALIGN - 1UL) & \
     ~(VRING_ALIGN - 1UL))
#define VRING_USED_SIZE                                                                                     \
    (((sizeof(struct vring_used) + (RL_BUFFER_COUNT * sizeof(struct vring_used_elem)) + sizeof(uint16_t)) + \
      VRING_ALIGN - 1UL) &                                                                                  \
     ~(VRING_ALIGN - 1UL))
#define VRING_SIZE (VRING_DESC_SIZE + VRING_AVAIL_SIZE + VRING_USED_SIZE)
#endif

/* size of shared memory + 2*VRING size */
#define RL_VRING_OVERHEAD (2UL * VRING_SIZE)

#define RL_GET_VQ_ID(link_id, queue_id) (((queue_id)&0x1U) | (((link_id) << 1U) & 0xFFFFFFFEU))
#define RL_GET_LINK_ID(id)              (((id)&0xFFFFFFFEU) >> 1U)
#define RL_GET_Q_ID(id)                 ((id)&0x1U)

#define RL_PLATFORM_BL808_M0_LINK_ID (0U)
#define RL_PLATFORM_HIGHEST_LINK_ID  (0U)

typedef struct
{
    uint32_t src;
    void *data;
    uint32_t len;
} rpmsg_queue_rx_cb_data_t;

#endif /* RPMSG_ENV_SPECIFIC_H_ */
