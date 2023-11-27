/*-
 * Copyright (c) 2017-2018 Ruslan Bukin <br@bsdpad.com>
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
#include <sys/rman.h>
#include <geom/geom_disk.h>

#include <machine/bus.h>
#include <machine/sbi.h>

#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

#include "dev/rpmsg_lite/rpmsg_lite.h"
#include "dev/rpmsg_lite/rpmsg_lite_bus.h"

#define RPMSG_DEBUG
#undef RPMSG_DEBUG

#ifdef RPMSG_DEBUG
#define dprintf(fmt, ...)  printf(fmt, ##__VA_ARGS__)
#else
#define dprintf(fmt, ...)
#endif

MALLOC_DEFINE(M_RPMSG_BUS, "rlbus", "rpmsg-lite bus");

//#define device_printf(x,f, ...) printf(f, ##__VA_ARGS__)
static struct resource_spec rpmsg_lite_spec[] = {
	{ SYS_RES_MEMORY, 0,	RF_ACTIVE }, /* shared memory */
	{ SYS_RES_MEMORY, 1,	RF_ACTIVE | RF_SHAREABLE }, /* ipc2 C906 */
	{ SYS_RES_MEMORY, 2,	RF_ACTIVE | RF_SHAREABLE }, /* ipc0 E907 */
	{ SYS_RES_IRQ,		0,	RF_ACTIVE | RF_SHAREABLE }, /* irq */
	{ -1, 0, 0}
};

static struct ofw_compat_data compat_data[] = {
	{ "rpmsg-lite",	1},
	{ NULL,			0 },
};

ipcIntCallback *d0IpcIntCbfArra[GLB_CORE_ID_MAX - 1] = { NULL };

static void
ipc_m0_callback(void *env, uint32_t src)
{
	int vector = ffs(src) - 1;
	switch (vector) {
		case IPC_MSG_PING:
			break;
		case IPC_MSG_PONG:
			/* nothing todo */
			break;
		case IPC_MSG_RPMSG0:
		case IPC_MSG_RPMSG1:
		case IPC_MSG_RPMSG2:
		case IPC_MSG_RPMSG3:
			env_isr(env, vector - IPC_MSG_RPMSG0);
			break;
	}
}

static void
rpmsg_lite_intr(void *arg)
{
	struct rpmsg_lite_softc *sc;
	uint32_t irq_state;
	uint32_t tmp;
	uint32_t grp = 0;

	sc = arg;
	/* read irq state */
	irq_state = IPC2_READ4(sc, 0x24);

	for (grp = 0; grp < GLB_CORE_ID_MAX - 1; grp++) {
		tmp = (irq_state >> (16 * grp)) & 0xffff;
		if (tmp != 0) {
			if (d0IpcIntCbfArra[grp] != NULL) {
					d0IpcIntCbfArra[grp](sc, tmp);
			}
		}
	}
	/* clear irq */
	IPC2_WRITE4(sc, 0x28, irq_state);
}

struct rpmsg_ns_task {
	struct rpmsg_lite_softc *sc;
	struct task	ns_task;
	uint32_t new_ept;
	char ept_name[32];
	uint32_t flags;
};

static void process_endpoints(void *arg, int npending);

static void
ipc_rpmsg_ns_callback(uint32_t new_ept, const char *new_ept_name, uint32_t flags, void *priv)
{
	struct rpmsg_lite_softc *sc __unused = priv;
	struct rpmsg_ns_task *ns;

	ns = malloc(sizeof(*ns), M_RPMSG_BUS, M_NOWAIT);
	if (ns == NULL) {
		device_printf(sc->dev, "create ns task failed: %s - endpoint %d - flags %d\n", new_ept_name, new_ept, flags);
		return;
	}

	ns->sc = sc;
	ns->new_ept = new_ept;
	ns->flags = flags;
	strncpy(ns->ept_name, new_ept_name, sizeof(ns->ept_name));

	TASK_INIT(&ns->ns_task, 0, process_endpoints, ns);

	taskqueue_enqueue(sc->rp_tq, &ns->ns_task);
}

static void
process_endpoints(void *arg, int npending)
{
	struct rpmsg_ns_task *ns = arg;
	KASSERT(ns->sc != NULL, "rpmsg sc is null");

	RPMSG_LOCK(ns->sc);

	device_printf(ns->sc->dev, "Endpoint: %s - endpoint %d - flags %d\n", ns->ept_name, ns->new_ept, ns->flags);

	if (strcmp(ns->ept_name, "wifi,blmac") == 0) {
		if (ns->flags == RL_NS_CREATE) {
			ns->sc->wifi_ep = ns->new_ept;
			blmac_init(ns->sc);
		} else {
			device_printf(ns->sc->dev, "unsupport flag: %d\n", ns->flags);
		}
	}
	RPMSG_UNLOCK(ns->sc);

	free(ns, M_RPMSG_BUS);
}

struct rpmsg_rx_task {
	struct rpmsg_lite_softc *sc;
	struct task	ns_task;
};

static int32_t
rpmsg_default_rx_cb(void *payload, uint32_t payload_len, uint32_t src, void *priv)
{
	struct rpmsg_lite_softc *sc __unused = priv;

	RPMSG_LOCK(sc);

	if (src == RPMSG_WIFI_CONFIG_EP(sc)) {
		void *chan;
		if (sc->wifi_config_chan == NULL) {
			device_printf(sc->dev, "wifi config chan is null!\n");
			goto _out;
		}
		if (payload_len != sizeof(*sc->wifi_config_chan)) {
			device_printf(sc->dev, "payload len not equal wifi_config_chan!\n");
			goto _out;
		}
		memcpy(sc->wifi_config_chan, payload, sizeof(*sc->wifi_config_chan));

		chan = sc->wifi_config_chan;
		sc->wifi_config_chan = NULL;

		wakeup(chan);
	} else if (src == RPMSG_WIFI_RX_EP(sc)) {
		if (sc->wifi_rx_cb) {
			sc->wifi_rx_cb(sc, payload, payload_len);
		}
	}

_out:
	RPMSG_UNLOCK(sc);

	return RL_RELEASE;
}

#if 0
static void
rpmsg_lite_task(void *arg)
{
#if 0
	struct rpmsg_lite_softc *sc;
	struct rpmsg_lite_endpoint *rpmsg_ep;
	char buffer[32];
	unsigned int cnt = 0;

	sc = arg;
	rpmsg_ep = rpmsg_lite_create_ept(sc->ipc_rpmsg, 16, rpmsg_bm_rx_cb, sc);
	if (rpmsg_ep == RL_NULL) {
			device_printf(sc->dev, "Failed to create RPMSG endpoint\n");
			goto _errout;
	}
#endif
	for (;;) {
#if 0
		RPMSG_LOCK(sc);
		msleep(sc, &sc->sc_mtx, PRIBIO, "rpmsg", hz); /* sleep 1s */
		snprintf(buffer, sizeof(buffer), "hello, i'm freebsd! cnt:%d", cnt++);
		rpmsg_lite_send(sc->ipc_rpmsg, rpmsg_ep, 17, buffer, strlen(buffer), RL_BLOCK);
		RPMSG_UNLOCK(sc);
#endif
		tsleep(arg, PRIBIO, "rpmsg", hz); /* sleep 1s */
	}

//_errout:
	kproc_exit(0);
}
#endif

static void
rpmsg_lite_delayed_attach(void *arg)
{
	struct rpmsg_lite_softc *sc;
	int ret;

	sc = arg;

	/* Enable IPC ISR */
	IPC2_WRITE4(sc, 0x2c, 0xffffffff);

	// rpmsg init
	sc->ipc_rpmsg = rpmsg_lite_master_init((uintptr_t *)sc->ocram_virt,
			sc->ocram_size, RL_PLATFORM_BL808_M0_LINK_ID, RL_NO_FLAGS, sc);
	if (sc->ipc_rpmsg == RL_NULL) {
		device_printf(sc->dev, "rpmsg-lite create failed\n");
		return;
	}

	device_printf(sc->dev, "rpmsg addr %p, remaining %d, total: %d\n",
			sc->ipc_rpmsg->sh_mem_base,
			sc->ipc_rpmsg->sh_mem_remaining,
			sc->ipc_rpmsg->sh_mem_total);

	device_printf(sc->dev, "Waiting for RPMSG link up\n");
	while (RL_FALSE == rpmsg_lite_is_link_up(sc->ipc_rpmsg)) {
		tsleep(&sc->ipc_rpmsg, PCATCH | PZERO, "rpmsg", hz/2); // 500ms
	}
	device_printf(sc->dev, "RPMSG link up\n");

	sc->ipc_rpmsg_ns = rpmsg_ns_bind(sc->ipc_rpmsg, ipc_rpmsg_ns_callback, sc);
	if (sc->ipc_rpmsg_ns == RL_NULL) {
			device_printf(sc->dev, "Failed to bind RPMSG NS\n");
			goto _errout;
	}
	device_printf(sc->dev, "RPMSG NS binded\r\n");

	sc->default_ep = rpmsg_lite_create_ept(sc->ipc_rpmsg, 16, rpmsg_default_rx_cb, sc);
	if (sc->default_ep == RL_NULL) {
			device_printf(sc->dev, "Failed to create RPMSG endpoint\n");
			goto _errout;
	}

	sc->rp_tq = taskqueue_create("rpmsg_taskq", M_WAITOK | M_ZERO, taskqueue_thread_enqueue, &sc->rp_tq);
	if (sc->rp_tq == NULL) {
			device_printf(sc->dev, "Failed to create RPMSG taskqueue\n");
			goto _errout;
	}
	ret = taskqueue_start_threads(&sc->rp_tq, 1, PI_NET, "rpmsg_lite taskq %p", sc->ipc_rpmsg);
	if (ret != 0) {
			device_printf(sc->dev, "Failed to start taskqueue, errno: %d\n", ret);
			goto _errout;
	}

	if (rpmsg_lite_master_linkup_remote(sc->ipc_rpmsg) != RL_SUCCESS) {
			device_printf(sc->dev, "Failed to kick rpmsg remote\n");
			goto _errout;
	}
	device_printf(sc->dev, "Link-UP e907!\n");

	/* announce freebsd common ep ! e907 will reply all response to this ep */
	if (rpmsg_ns_announce(sc->ipc_rpmsg, sc->default_ep, "freebsd", RL_NS_CREATE) != RL_SUCCESS) {
			device_printf(sc->dev, "Failed to announce RPMSG NS\n");
			goto _errout;
	}

#if 0
	ret = kproc_create(&rpmsg_lite_task, sc, &sc->p, 0, 0, "task: rpmsg");
	if (ret != 0) {
			device_printf(sc->dev, "Failed to create RPMSG task, errno: %d\n", ret);
			goto _errout;
	}
#endif
	return;

_errout:
	rpmsg_lite_deinit(sc->ipc_rpmsg);
	return;
}

static int
rpmsg_lite_probe(device_t dev)
{

	if (!ofw_bus_status_okay(dev)) {
		return (ENXIO);
	}

	if (!ofw_bus_search_compatible(dev, compat_data)->ocd_data) {
		return (ENXIO);
	}

	device_set_desc(dev, "BL808 rpmsg-lite");

	return (0);
}

static int
rpmsg_lite_attach(device_t dev)
{
	struct rpmsg_lite_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	sc->wifi_rx_cb = NULL;

	if (bus_alloc_resources(dev, rpmsg_lite_spec, sc->res)) {
		device_printf(dev, "could not allocate resources\n");
		return (ENXIO);
	}

	sc->ocram_virt = (uintptr_t)rman_get_virtual(sc->res[0]);
	sc->ocram_phy  = (uintptr_t)rman_get_start(sc->res[0]);
	sc->ocram_size = rman_get_size(sc->res[0]);

	device_printf(dev, "ocram_virt:%lx, ocram_phy:%lx, ocram_size:%ld\n",
			sc->ocram_virt, sc->ocram_phy, sc->ocram_size);

	/* Setup interrupt handlers */
	if (bus_setup_intr(sc->dev, sc->res[3], INTR_TYPE_BIO | INTR_MPSAFE,
			NULL, rpmsg_lite_intr, sc, &sc->ih)) {
		device_printf(sc->dev, "Unable to setup intr\n");
		return (ENXIO);
	}

	RPMSG_LOCK_INIT(sc);

	/* register m0 callback */
	d0IpcIntCbfArra[0] = ipc_m0_callback;

	config_intrhook_oneshot(rpmsg_lite_delayed_attach, sc);

	return (0);
}

static int
rpmsg_lite_detach(device_t dev)
{
	return (ENXIO);
}

static device_method_t rpmsg_lite_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		rpmsg_lite_probe),
	DEVMETHOD(device_attach,	rpmsg_lite_attach),
	DEVMETHOD(device_detach,	rpmsg_lite_detach),

	{ 0, 0 }
};

DEFINE_CLASS_0(rpmsg_lite, rpmsg_lite_driver, rpmsg_lite_methods,
		sizeof(struct rpmsg_lite_softc));

DRIVER_MODULE(rpmsg_lite, ofwbus, rpmsg_lite_driver, 0, 0);
