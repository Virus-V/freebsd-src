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
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/rman.h>
#include <sys/taskqueue.h>

#include <machine/bus.h>

#include <sys/socket.h>
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/in_var.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

#include <net80211/ieee80211_var.h>
#include <net80211/ieee80211_regdomain.h>
#include <net80211/ieee80211_radiotap.h>
#include <net80211/ieee80211_ratectl.h>

#include "dev/rpmsg_lite/rpmsg_lite.h"
#include "dev/rpmsg_lite/rpmsg_ns.h"
#include "dev/rpmsg_lite//blmac/blmac.h"

#define IPC0_READ4(_sc, _reg) bus_read_4((_sc)->res[2], _reg)
#define IPC0_WRITE4(_sc, _reg, _val) bus_write_4((_sc)->res[2], _reg, _val)

#define IPC2_READ4(_sc, _reg) bus_read_4((_sc)->res[1], _reg)
#define IPC2_WRITE4(_sc, _reg, _val) bus_write_4((_sc)->res[1], _reg, _val)

/********************** WIFI ************************************************/
/* endpoints */
#define RPMSG_WIFI_CONFIG_EP(sc) ((sc)->wifi_ep)
#define RPMSG_WIFI_RX_EP(sc) ((sc)->wifi_ep + 1)
#define RPMSG_WIFI_TX_BCN_EP(sc) ((sc)->wifi_ep + 2)
#define RPMSG_WIFI_TX_AC0_EP(sc) ((sc)->wifi_ep + 3)
#define RPMSG_WIFI_TX_AC1_EP(sc) ((sc)->wifi_ep + 4)
#define RPMSG_WIFI_TX_AC2_EP(sc) ((sc)->wifi_ep + 5)
#define RPMSG_WIFI_TX_AC3_EP(sc) ((sc)->wifi_ep + 6)

/********************** WIFI ************************************************/

struct rpmsg_lite_softc {
	device_t		dev;
	struct ieee80211com	sc_ic;
	struct mbufq		sc_snd;

	struct rpmsg_lite_instance *ipc_rpmsg;
	struct rpmsg_lite_endpoint *default_ep;
	rpmsg_ns_handle ipc_rpmsg_ns;
	struct taskqueue	*rp_tq;

	struct proc		*p;

	struct resource		*res[4];
	void			*ih;

	uintptr_t		ocram_virt;
	uintptr_t		ocram_phy;
	size_t			ocram_size;

	/* wifi end-points */
	int wifi_ep; /* config ep */
	void (*wifi_rx_cb)(struct rpmsg_lite_softc *, void *, uint32_t);

	struct rtwn_vap		*vaps[1];
	struct ieee80211_node	*node_list[4];

	int			vaps_running;
	int			monvaps_running;

  struct blmac_config_desc *wifi_config_chan;

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

int blmac_init(struct rpmsg_lite_softc *sc);
void rp_blmac_deinit(struct rpmsg_lite_softc *sc);



struct rtwn_vap {
	struct ieee80211vap	vap;
	int			id;
#define RTWN_VAP_ID_INVALID	-1
	int			curr_mode;

	//struct rtwn_tx_buf	bcn_desc;
	struct mbuf		*bcn_mbuf;
	struct timeout_task	tx_beacon_csa;

	struct callout		tsf_sync_adhoc;
	struct task		tsf_sync_adhoc_task;

	const struct ieee80211_key	*keys[IEEE80211_WEP_NKID];

	int			(*newstate)(struct ieee80211vap *,
				    enum ieee80211_state, int);
	void			(*recv_mgmt)(struct ieee80211_node *,
				    struct mbuf *, int,
				    const struct ieee80211_rx_stats *,
				    int, int);
};
#define	RTWN_VAP(vap)		((struct rtwn_vap *)(vap))



#endif
