/*-
 * Copyright (c) 2017-2018 Neal Rong <virusv@live.com>
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

#ifndef _RPMSG_LITE_BUS_H_
#define _RPMSG_LITE_BUS_H_

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
#include <sys/rman.h>
#include <geom/geom_disk.h>

#include <machine/bus.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

#include <dev/rpmsg_lite/rpmsg_lite.h>
#include <dev/rpmsg_lite/rpmsg_ns.h>

#define IPC0_READ4(_sc, _reg) bus_read_4((_sc)->res[2], _reg)
#define IPC0_WRITE4(_sc, _reg, _val) bus_write_4((_sc)->res[2], _reg, _val)

#define IPC2_READ4(_sc, _reg) bus_read_4((_sc)->res[1], _reg)
#define IPC2_WRITE4(_sc, _reg, _val) bus_write_4((_sc)->res[1], _reg, _val)

struct rpmsg_lite_softc {
	device_t		dev;

	struct rpmsg_lite_instance *ipc_rpmsg;
	rpmsg_ns_handle ipc_rpmsg_ns;
	struct proc		*p;

	struct resource		*res[4];
	void			*ih;

	uintptr_t		ocram_virt;
	uintptr_t		ocram_phy;
	size_t			ocram_size;

	struct intr_config_hook config_intrhook;
	struct mtx		sc_mtx;
};

#define RPMSG_LOCK(_sc)		mtx_lock(&(_sc)->sc_mtx)
#define RPMSG_UNLOCK(_sc) mtx_unlock(&(_sc)->sc_mtx)
#define RPMSG_LOCK_INIT(_sc)					\
	mtx_init(&_sc->sc_mtx, device_get_nameunit(_sc->dev), \
			"rpmsg_lite", MTX_DEF)
#define RPMSG_LOCK_DESTROY(_sc) mtx_destroy(&_sc->sc_mtx);
#define RPMSG_ASSERT_LOCKED(_sc)				\
	mtx_assert(&_sc->sc_mtx, MA_OWNED);
#define RPMSG_ASSERT_UNLOCKED(_sc)				\
	mtx_assert(&_sc->sc_mtx, MA_NOTOWNED);

#endif
