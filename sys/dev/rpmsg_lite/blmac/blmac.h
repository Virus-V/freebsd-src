/*-
 * Copyright (c) 2023-2024 Neal Rong <virusv@live.com>
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *		notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *		notice, this list of conditions and the following disclaimer in the
 *		documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __BLMAC_H__
#define __BLMAC_H__

#include <sys/types.h>

#define RX_BUFFER_CNT 6
#define RX_BUFFER_LEN 2048

struct rpmsg_lite_softc;

/* mac config  */
#define CONFIG_ERRNO_ARG_INVALID 0
struct blmac_config_desc {
#define CONFIG_ACTION_READ_REG 0
#define CONFIG_ACTION_WRITE_REG 1
#define CONFIG_ACTION_FUNCALL 2
  uint32_t action;
  uint32_t param;
  uint32_t value;
};

/* get blmac version */
int blmac_config_get_version(struct rpmsg_lite_softc *sc,
		uint32_t *blmac_ver, uint32_t *phy_ver1, uint32_t *phy_ver2,
		uint32_t * mac_ver1, uint32_t *mac_ver2);

/* read mac reg */
int blmac_config_reg_rd(struct rpmsg_lite_softc *sc,
		uint32_t addr, uint32_t *reg_val);

/* write mac reg */
int blmac_config_reg_wr(struct rpmsg_lite_softc *sc,
		uint32_t addr, uint32_t reg_val);

int blmac_config_phy_init(struct rpmsg_lite_softc *sc, uint32_t mode);
int blmac_config_phy_set_channel(struct rpmsg_lite_softc *sc, int band,
	int channel, int bandwidth);

#define BLMAC_REG_RD(a,p) !err && (err = blmac_config_reg_rd(sc, (a), (p)))
#define BLMAC_REG_WR(a,v) !err && (err = blmac_config_reg_wr(sc, (a), (v)))
#endif
