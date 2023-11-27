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

#include <sys/cdefs.h>
#include "opt_platform.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>

#include "dev/rpmsg_lite/rpmsg_lite.h"
#include "dev/rpmsg_lite/rpmsg_lite_bus.h"
#include "dev/rpmsg_lite//blmac/blmac.h"

/* do blmac config */
static int
blmac_config(struct rpmsg_lite_softc *sc, struct blmac_config_desc *cfg)
{
	RPMSG_ASSERT_LOCKED(sc);

	while(sc->wifi_config_chan != NULL) {
		msleep(sc->wifi_config_chan, &sc->sc_mtx, PRIBIO, "rpwcfg", hz/10); /* sleep 100ms */
	}

	rpmsg_lite_send(sc->ipc_rpmsg, sc->default_ep, RPMSG_WIFI_CONFIG_EP(sc), (void *)cfg, sizeof(*cfg), RL_BLOCK);

	sc->wifi_config_chan = cfg;
	msleep(cfg, &sc->sc_mtx, PRIBIO, "rpwcfg", 0); /* sleep until event done */

	return 0;
}

int
blmac_config_get_version(struct rpmsg_lite_softc *sc,
		uint32_t *blmac_ver, uint32_t *phy_ver1, uint32_t *phy_ver2,
		uint32_t * mac_ver1, uint32_t *mac_ver2)
{
	int i;
	struct blmac_config_desc cfg;
	uint32_t vers[5];

	/* wifi config */
	cfg.action = CONFIG_ACTION_FUNCALL;
	cfg.param = 0;
	cfg.value = 0;
	blmac_config(sc, &cfg);

	if (cfg.value < 5) {
		/* check blmac version */
		device_printf(sc->dev, "get blmac version failed\n");
		return -1;
	}

	for (i = 0; i < 5; i++) {
		cfg.action = CONFIG_ACTION_READ_REG;
		cfg.param = i;
		cfg.value = 0;
		blmac_config(sc, &cfg);
		vers[i] = cfg.value;
	}

	if (blmac_ver) *blmac_ver = vers[0];
	if (phy_ver1) *phy_ver1 = vers[1];
	if (phy_ver2) *phy_ver2 = vers[2];
	if (mac_ver1) *mac_ver1 = vers[3];
	if (mac_ver2) *mac_ver2 = vers[4];

	return 0;
}

int
blmac_config_reg_rd(struct rpmsg_lite_softc *sc,
		uint32_t addr, uint32_t *reg_val)
{
	struct blmac_config_desc cfg;

	KASSERT(sc != NULL, ("sc is null"));
	KASSERT(reg_val != NULL, ("reg_val is null"));

	/* write addr to gpr[0]*/
	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 0;
	cfg.value = addr;
	blmac_config(sc, &cfg);

	/* do action 2 */
	cfg.action = CONFIG_ACTION_FUNCALL;
	cfg.param = 2;
	cfg.value = 0;
	blmac_config(sc, &cfg);

	if (cfg.value != 1) {
		device_printf(sc->dev, "read mac reg %x failed\n", addr);
		return -1;
	}

	/* reg value from gpr[0] */
	cfg.action = CONFIG_ACTION_READ_REG;
	cfg.param = 0;
	cfg.value = 0;
	blmac_config(sc, &cfg);

	*reg_val = cfg.value;
	return 0;
}

int
blmac_config_reg_wr(struct rpmsg_lite_softc *sc,
		uint32_t addr, uint32_t reg_val)
{
	struct blmac_config_desc cfg;

	KASSERT(sc != NULL, ("sc is null"));
	KASSERT(reg_val != NULL, ("reg_val is null"));

	/* write addr to gpr[0]*/
	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 0;
	cfg.value = addr;
	blmac_config(sc, &cfg);

	/* write value to gpr[1]*/
	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 1;
	cfg.value = reg_val;
	blmac_config(sc, &cfg);

	/* do action 1 */
	cfg.action = CONFIG_ACTION_FUNCALL;
	cfg.param = 1;
	cfg.value = 0;
	blmac_config(sc, &cfg);

	return 0;
}

int
blmac_config_phy_init(struct rpmsg_lite_softc *sc, uint32_t mode)
{
	struct blmac_config_desc cfg;

	KASSERT(sc != NULL, ("sc is null"));

	/* write to gpr */
	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 0;
	cfg.value = mode;
	blmac_config(sc, &cfg);

	/* do action */
	cfg.action = CONFIG_ACTION_FUNCALL;
	cfg.param = 3;
	cfg.value = 0;
	blmac_config(sc, &cfg);

	return 0;
}

int
blmac_config_phy_set_channel(struct rpmsg_lite_softc *sc, int band,
	int channel, int bandwidth)
{
	struct blmac_config_desc cfg;

	KASSERT(sc != NULL, ("sc is null"));

	/* write to gpr */
	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 0;
	cfg.value = band;
	blmac_config(sc, &cfg);

	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 0;
	cfg.value = channel;
	blmac_config(sc, &cfg);

	cfg.action = CONFIG_ACTION_WRITE_REG;
	cfg.param = 0;
	cfg.value = bandwidth;
	blmac_config(sc, &cfg);

	/* do action */
	cfg.action = CONFIG_ACTION_FUNCALL;
	cfg.param = 4;
	cfg.value = 0;
	blmac_config(sc, &cfg);

	return 0;
}
