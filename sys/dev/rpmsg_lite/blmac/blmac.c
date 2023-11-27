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

#include <vm/vm.h>
#include <vm/pmap.h>

#include "dev/rpmsg_lite/rpmsg_lite.h"
#include "dev/rpmsg_lite/rpmsg_lite_bus.h"
#include "dev/rpmsg_lite//blmac/blmac.h"

static uint8_t rx_buffers[RX_BUFFER_CNT][RX_BUFFER_LEN];

static uint8_t (*rx_buffers_nocahce_va)[RX_BUFFER_CNT][RX_BUFFER_LEN];
static uint8_t (*rx_buffers_nocahce_pa)[RX_BUFFER_CNT][RX_BUFFER_LEN];

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define ARRAY_CHECK(ptr,arr) \
  if (ptr) {  \
    int idx __unused = (uintptr_t)(ptr) - ((uintptr_t)&(arr)[0]); \
    KASSERT(idx >= 0 && idx < ARRAY_SIZE(arr), ("over range")); \
    KASSERT((ptr) == ((arr) + idx), ("idx mis-match")); \
  }

/* service messages */
struct rx_buffer_desc {
  uint32_t paddr;
  uint32_t length;
  /* unified buffer */
  uint16_t head, prev, index;
#define HOST_BUFFER_LAST 0x1
  uint16_t flags;
};

/* send buffer to e907 */
static int rx_buffer_release(struct rpmsg_lite_softc *sc, int idx) {
	struct rx_buffer_desc rr;

	KASSERT(idx >= 0 && idx < RX_BUFFER_CNT, ("idx not fit rx_buffers"));

	rr.index = idx;
	rr.paddr = (uint32_t)(uintptr_t)&rx_buffers_nocahce_pa[idx];
	rr.length = RX_BUFFER_LEN;

	rpmsg_lite_send(sc->ipc_rpmsg, sc->default_ep, RPMSG_WIFI_RX_EP(sc), (void *)&rr, sizeof(rr), RL_BLOCK);

	return 0;
}

uint32_t rx_count = 0;
static void mac_rx_callback(struct rpmsg_lite_softc *sc, void *payload, uint32_t payload_len) {
	rx_count ++;
	rpmsg_lite_send(sc->ipc_rpmsg, sc->default_ep, RPMSG_WIFI_RX_EP(sc), payload, payload_len, RL_BLOCK);
	//printf("rx_counter: %d\n", rx_count);
}

static int
blmac_monitor_newstate(struct ieee80211vap *vap, enum ieee80211_state nstate,
	int arg)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct rpmsg_lite_softc *sc = ic->ic_softc;
	struct rtwn_vap *uvp = RTWN_VAP(vap);

	if (vap->iv_state != nstate) {
		IEEE80211_UNLOCK(ic);
		RPMSG_LOCK(sc);

		switch (nstate) {
		case IEEE80211_S_INIT:
			sc->vaps_running--;
			sc->monvaps_running--;

			if (sc->vaps_running == 0) {
				/* Turn link LED off. */
				device_printf(sc->dev, "monitor led off\n");
			}
			break;
		case IEEE80211_S_RUN:
			sc->vaps_running++;
			sc->monvaps_running++;

			if (sc->vaps_running == 1) {
				/* Turn link LED on. */
				device_printf(sc->dev, "monitor led on\n");
			}
			break;
		default:
			/* NOTREACHED */
			break;
		}

		RPMSG_UNLOCK(sc);
		IEEE80211_LOCK(ic);
	}

	return (uvp->newstate(vap, nstate, arg));
}

static void
blmac_update_beacon(struct ieee80211vap *vap, int item)
{
#if 0
	struct ieee80211com *ic = vap->iv_ic;
	struct rtwn_softc *sc = ic->ic_softc;
	struct rtwn_vap *uvp = RTWN_VAP(vap);
	struct ieee80211_beacon_offsets *bo = &vap->iv_bcn_off;
	struct ieee80211_node *ni = vap->iv_bss;
	int mcast = 0;

	RTWN_LOCK(sc);
	if (uvp->bcn_mbuf == NULL) {
		uvp->bcn_mbuf = ieee80211_beacon_alloc(ni);
		if (uvp->bcn_mbuf == NULL) {
			device_printf(sc->sc_dev,
			    "%s: could not allocate beacon frame\n", __func__);
			RTWN_UNLOCK(sc);
			return;
		}
	}

	RTWN_DPRINTF(sc, RTWN_DEBUG_BEACON,
	    "%s: vap id %d, iv_csa_count %d, ic_csa_count %d, item %d\n",
	    __func__, uvp->id, vap->iv_csa_count, ic->ic_csa_count, item);

	switch (item) {
	case IEEE80211_BEACON_CSA:
		if (vap->iv_csa_count != ic->ic_csa_count) {
			/*
			 * XXX two APs with different beacon intervals
			 * are not handled properly.
			 */
			/* XXX check TBTT? */
			taskqueue_enqueue_timeout(taskqueue_thread,
			    &uvp->tx_beacon_csa,
			    msecs_to_ticks(ni->ni_intval));
		}
		break;
	case IEEE80211_BEACON_TIM:
		mcast = 1;	/* XXX */
		break;
	default:
		break;
	}

	setbit(bo->bo_flags, item);

	rtwn_beacon_update_begin(sc, vap);
	RTWN_UNLOCK(sc);

	ieee80211_beacon_update(ni, uvp->bcn_mbuf, mcast);

	/* XXX clear manually */
	clrbit(bo->bo_flags, IEEE80211_BEACON_CSA);

	RTWN_LOCK(sc);
	rtwn_tx_beacon(sc, uvp);
	rtwn_beacon_update_end(sc, vap);
	RTWN_UNLOCK(sc);
#endif
}

static int
blmac_ioctl_reset(struct ieee80211vap *vap, u_long cmd)
{
	int error;

	switch (cmd) {
#ifndef RTWN_WITHOUT_UCODE
	case IEEE80211_IOC_POWERSAVE:
	case IEEE80211_IOC_POWERSAVESLEEP:
#if 0
	{
		struct rtwn_softc *sc = vap->iv_ic->ic_softc;
		struct rtwn_vap *uvp = RTWN_VAP(vap);

		if (vap->iv_opmode == IEEE80211_M_STA && uvp->id == 0) {
			RTWN_LOCK(sc);
			if (sc->sc_flags & RTWN_RUNNING)
				error = rtwn_set_pwrmode(sc, vap, 1);
			else
				error = 0;
			RTWN_UNLOCK(sc);
			if (error != 0)
				error = ENETRESET;
		} else
			error = EOPNOTSUPP;
		break;
	}
#endif
#endif
	case IEEE80211_IOC_SHORTGI:
	case IEEE80211_IOC_RTSTHRESHOLD:
	case IEEE80211_IOC_PROTMODE:
	case IEEE80211_IOC_HTPROTMODE:
	case IEEE80211_IOC_LDPC:
		error = 0;
		break;
	default:
		error = ENETRESET;
		break;
	}

	return (error);
}

static int
blmac_key_alloc(struct ieee80211vap *vap, struct ieee80211_key *k,
    ieee80211_keyix *keyix, ieee80211_keyix *rxkeyix)
{
#if 0
	struct rtwn_softc *sc = vap->iv_ic->ic_softc;
	int i, start;

	if (&vap->iv_nw_keys[0] <= k &&
	    k < &vap->iv_nw_keys[IEEE80211_WEP_NKID]) {
		*keyix = ieee80211_crypto_get_key_wepidx(vap, k);
		if (sc->sc_hwcrypto != RTWN_CRYPTO_FULL)
			k->wk_flags |= IEEE80211_KEY_SWCRYPT;
		else {
			RTWN_LOCK(sc);
			if (isset(sc->keys_bmap, *keyix)) {
				device_printf(sc->sc_dev,
				    "%s: group key slot %d is already used!\n",
				    __func__, *keyix);
				/* XXX recover? */
				RTWN_UNLOCK(sc);
				return (0);
			}

			setbit(sc->keys_bmap, *keyix);
			RTWN_UNLOCK(sc);
		}

		goto end;
	}

	start = sc->cam_entry_limit;
	switch (sc->sc_hwcrypto) {
	case RTWN_CRYPTO_SW:
		k->wk_flags |= IEEE80211_KEY_SWCRYPT;
		*keyix = 0;
		goto end;
	case RTWN_CRYPTO_PAIR:
		/* all slots for pairwise keys. */
		start = 0;
		RTWN_LOCK(sc);
		if (sc->sc_flags & RTWN_FLAG_CAM_FIXED)
			start = 4;
		RTWN_UNLOCK(sc);
		break;
	case RTWN_CRYPTO_FULL:
		/* first 4 - for group keys, others for pairwise. */
		start = 4;
		break;
	default:
		KASSERT(0, ("%s: case %d was not handled!\n",
		    __func__, sc->sc_hwcrypto));
		break;
	}

	RTWN_LOCK(sc);
	for (i = start; i < sc->cam_entry_limit; i++) {
		if (isclr(sc->keys_bmap, i)) {
			setbit(sc->keys_bmap, i);
			*keyix = i;
			break;
		}
	}
	RTWN_UNLOCK(sc);
	if (i == sc->cam_entry_limit) {
		/* XXX check and remove keys with the same MAC address */
		k->wk_flags |= IEEE80211_KEY_SWCRYPT;
		*keyix = 0;
	}

end:
	*rxkeyix = *keyix;
	return (1);
#endif
	return 1;
}

#if 0
static int
rtwn_process_key(struct ieee80211vap *vap, const struct ieee80211_key *k,
    int set)
{
	struct rtwn_softc *sc = vap->iv_ic->ic_softc;

	if (k->wk_flags & IEEE80211_KEY_SWCRYPT) {
		/* Not for us. */
		return (1);
	}

	if (&vap->iv_nw_keys[0] <= k &&
	    k < &vap->iv_nw_keys[IEEE80211_WEP_NKID]) {
		if (sc->sc_hwcrypto == RTWN_CRYPTO_FULL) {
			struct rtwn_vap *rvp = RTWN_VAP(vap);

			RTWN_LOCK(sc);
			rvp->keys[k->wk_keyix] = (set ? k : NULL);
			if ((sc->sc_flags & RTWN_RUNNING) == 0) {
				if (!set)
					clrbit(sc->keys_bmap, k->wk_keyix);
				RTWN_UNLOCK(sc);
				return (1);
			}
			RTWN_UNLOCK(sc);
		}
	}

	return (!rtwn_cmd_sleepable(sc, k, sizeof(*k),
	    set ? rtwn_key_set_cb : rtwn_key_del_cb));
}
#endif

static int
blmac_key_set(struct ieee80211vap *vap, const struct ieee80211_key *k)
{
	//return (rtwn_process_key(vap, k, 1));
	return 0;
}

static int
blmac_key_delete(struct ieee80211vap *vap, const struct ieee80211_key *k)
{
	return 0;
	//return (rtwn_process_key(vap, k, 0));
}

static void
blmac_tx_beacon_csa(void *arg, int npending __unused)
{
	struct ieee80211vap *vap = arg;
	struct ieee80211com *ic = vap->iv_ic;
	struct rtwn_vap *rvp = RTWN_VAP(vap);

	KASSERT (rvp->id == 0 || rvp->id == 1,
	    ("wrong port id %d\n", rvp->id));

	IEEE80211_LOCK(ic);
	if (ic->ic_flags & IEEE80211_F_CSAPENDING) {
		blmac_update_beacon(vap, IEEE80211_BEACON_CSA);
	}
	IEEE80211_UNLOCK(ic);

	(void) rvp;
}

static void
blmac_adhoc_recv_mgmt(struct ieee80211_node *ni, struct mbuf *m, int subtype,
    const struct ieee80211_rx_stats *rxs,
    int rssi, int nf)
{
	struct ieee80211vap *vap = ni->ni_vap;
	//struct rtwn_softc *sc = vap->iv_ic->ic_softc;
	struct rtwn_vap *uvp = RTWN_VAP(vap);
	//uint64_t ni_tstamp, curr_tstamp;

	uvp->recv_mgmt(ni, m, subtype, rxs, rssi, nf);

	if (vap->iv_state == IEEE80211_S_RUN &&
	    (subtype == IEEE80211_FC0_SUBTYPE_BEACON ||
	    subtype == IEEE80211_FC0_SUBTYPE_PROBE_RESP)) {
#if 0
		ni_tstamp = le64toh(ni->ni_tstamp.tsf);
		RTWN_LOCK(sc);
		rtwn_get_tsf(sc, &curr_tstamp, uvp->id);
		RTWN_UNLOCK(sc);

		if (ni_tstamp >= curr_tstamp)
			(void) ieee80211_ibss_merge(ni);
#endif
	}
}

static struct ieee80211vap *
blmac_vap_create(struct ieee80211com *ic, const char name[IFNAMSIZ], int unit,
    enum ieee80211_opmode opmode, int flags,
    const uint8_t bssid[IEEE80211_ADDR_LEN],
    const uint8_t mac[IEEE80211_ADDR_LEN])
{
	struct rpmsg_lite_softc *sc = ic->ic_softc;
	struct rtwn_vap *uvp;
	struct ieee80211vap *vap;
	int id = 1;

	RPMSG_LOCK(sc);
	RPMSG_UNLOCK(sc);

	uvp = malloc(sizeof(struct rtwn_vap), M_80211_VAP, M_WAITOK | M_ZERO);
	uvp->id = id;

	if (id != RTWN_VAP_ID_INVALID) {
		RPMSG_LOCK(sc);
		sc->vaps[id] = uvp;
		RPMSG_UNLOCK(sc);
	}

	vap = &uvp->vap;
	/* enable s/w bmiss handling for sta mode */

	if (ieee80211_vap_setup(ic, vap, name, unit, opmode,
				flags | IEEE80211_CLONE_NOBEACONS, bssid) != 0) {
		/* out of memory */
		free(uvp, M_80211_VAP);

		RPMSG_LOCK(sc);
		sc->vaps[id] = NULL;
		RPMSG_UNLOCK(sc);

		return (NULL);
	}

	//rtwn_beacon_init(sc, &uvp->bcn_desc.txd[0], uvp->id);
	//rtwn_vap_preattach(sc, vap);

	/* override state transition machine */
	uvp->newstate = vap->iv_newstate;

	if (opmode == IEEE80211_M_MONITOR) {
		int err = 0;

		vap->iv_newstate = blmac_monitor_newstate;

		RPMSG_LOCK(sc);
		/* init phy to monitor */
		blmac_config_phy_init(sc, 0);

		/* test: band-2.4G/ch-6/bw-20MHz */
		blmac_config_phy_set_channel(sc, 0, 6, 0);

		/* Rx filter */
    BLMAC_REG_WR(0x24B00060, 0x7fffffde);

		/* set mac to active */
    BLMAC_REG_WR(0x24B00038, 3 << 4);
		RPMSG_UNLOCK(sc);

		if (err != 0) {
			device_printf(sc->dev, "init blmac failed!\n");

			free(uvp, M_80211_VAP);

			RPMSG_LOCK(sc);
			sc->vaps[id] = NULL;
			RPMSG_UNLOCK(sc);

			return (NULL);
		}
	} else {
		printf("should not: %s:%d\n", __func__, __LINE__);
		//vap->iv_newstate = rtwn_newstate;
	}

	vap->iv_update_beacon = blmac_update_beacon;
	vap->iv_reset = blmac_ioctl_reset;
	vap->iv_key_alloc = blmac_key_alloc;
	vap->iv_key_set = blmac_key_set;
	vap->iv_key_delete = blmac_key_delete;
	vap->iv_max_aid = 128;

	/* 802.11n parameters */
	vap->iv_ampdu_density = IEEE80211_HTCAP_MPDUDENSITY_16;
	vap->iv_ampdu_rxmax = IEEE80211_HTCAP_MAXRXAMPDU_64K;

	TIMEOUT_TASK_INIT(taskqueue_thread, &uvp->tx_beacon_csa, 0, blmac_tx_beacon_csa, vap);
	if (opmode == IEEE80211_M_IBSS) {
		uvp->recv_mgmt = vap->iv_recv_mgmt;
		vap->iv_recv_mgmt = blmac_adhoc_recv_mgmt;
#if 0
		TASK_INIT(&uvp->tsf_sync_adhoc_task, 0,
		    rtwn_tsf_sync_adhoc_task, vap);
		callout_init(&uvp->tsf_sync_adhoc, 0);
#endif
	}

	/*
	 * NB: driver can select net80211 RA even when user requests
	 * another mechanism.
	 */
	ieee80211_ratectl_init(vap);

	/* complete setup */
	ieee80211_vap_attach(vap, ieee80211_media_change,
			ieee80211_media_status, mac);

	RPMSG_LOCK(sc);
	//rtwn_set_ic_opmode(sc);
	ic->ic_opmode = IEEE80211_M_MONITOR;
	//rtwn_set_macaddr(sc, vap->iv_myaddr, uvp->id);

	RPMSG_UNLOCK(sc);
	return (vap);
}

#if 0
static void
rtwn_vap_delete(struct ieee80211vap *vap)
{
	struct ieee80211com *ic = vap->iv_ic;
	struct rtwn_softc *sc = ic->ic_softc;
	struct rtwn_vap *uvp = RTWN_VAP(vap);

	/* Put vap into INIT state + stop device if needed. */
	ieee80211_stop(vap);
	ieee80211_draintask(ic, &vap->iv_nstate_task);
	ieee80211_draintask(ic, &ic->ic_parent_task);

	RTWN_LOCK(sc);
	/* Cancel any unfinished Tx. */
	rtwn_reset_lists(sc, vap);
	if (uvp->bcn_mbuf != NULL)
		m_freem(uvp->bcn_mbuf);
	rtwn_vap_decrement_counters(sc, vap->iv_opmode, uvp->id);
	rtwn_set_ic_opmode(sc);
	if (sc->sc_flags & RTWN_RUNNING)
		rtwn_rxfilter_update(sc);
	RTWN_UNLOCK(sc);

	if (vap->iv_opmode == IEEE80211_M_IBSS) {
		ieee80211_draintask(ic, &uvp->tsf_sync_adhoc_task);
		callout_drain(&uvp->tsf_sync_adhoc);
	}

	ieee80211_ratectl_deinit(vap);
	ieee80211_vap_detach(vap);
	free(uvp, M_80211_VAP);
}
#endif

static void
blmac_getradiocaps(struct ieee80211com *ic,
    int maxchans, int *nchans, struct ieee80211_channel chans[])
{
	uint8_t bands[IEEE80211_MODE_BYTES];
	int cbw_flags;

	cbw_flags = (ic->ic_htcaps & IEEE80211_HTCAP_CHWIDTH40) ?
	    NET80211_CBW_FLAG_HT40 : 0;

	memset(bands, 0, sizeof(bands));
	setbit(bands, IEEE80211_MODE_11B);
	setbit(bands, IEEE80211_MODE_11G);
	setbit(bands, IEEE80211_MODE_11NG);
	ieee80211_add_channels_default_2ghz(chans, maxchans, nchans,
	    bands, cbw_flags);
}

int
blmac_init(struct rpmsg_lite_softc *sc)
{
	int i;
	int err = 0;
	vm_offset_t rxbuf_phy_addr;
	struct ieee80211com *ic = &sc->sc_ic;

	uint32_t blmac_ver, phy_ver1, phy_ver2, mac_ver1, mac_ver2;

	RPMSG_ASSERT_LOCKED(sc);

	/* init wifi mac */
	blmac_config_get_version(sc, &blmac_ver, &phy_ver1, &phy_ver2, &mac_ver1, &mac_ver2);
	device_printf(sc->dev, "blmac version:0x%x; phy version:0x%x,0x%x; mac version:0x%x,0x%x.\n",
			blmac_ver, phy_ver1, phy_ver2, mac_ver1, mac_ver2);

	mbufq_init(&sc->sc_snd, ifqmaxlen);

	ic->ic_softc = sc;
	ic->ic_name = device_get_nameunit(sc->dev);
	ic->ic_phytype = IEEE80211_T_OFDM;	/* not only, but not used */
	ic->ic_opmode = IEEE80211_M_STA;	/* default to BSS mode */

	/* set device capabilities */
	ic->ic_caps =
		  IEEE80211_C_STA		/* station mode */
		| IEEE80211_C_MONITOR		/* monitor mode */
		| IEEE80211_C_IBSS		/* adhoc mode */
		| IEEE80211_C_HOSTAP		/* hostap mode */
#if 0	/* TODO: HRPWM register setup */
#ifndef RTWN_WITHOUT_UCODE
		| IEEE80211_C_PMGT		/* Station-side power mgmt */
#endif
#endif
		| IEEE80211_C_SHPREAMBLE	/* short preamble supported */
		| IEEE80211_C_SHSLOT		/* short slot time supported */
#if 0
		| IEEE80211_C_BGSCAN		/* capable of bg scanning */
#endif
		| IEEE80211_C_WPA		/* 802.11i */
		| IEEE80211_C_WME		/* 802.11e */
		| IEEE80211_C_SWAMSDUTX		/* Do software A-MSDU TX */
		| IEEE80211_C_FF		/* Atheros fast-frames */
		;

	 ic->ic_cryptocaps =
		    IEEE80211_CRYPTO_WEP |
		    IEEE80211_CRYPTO_TKIP |
		    IEEE80211_CRYPTO_AES_CCM;

	ic->ic_htcaps =
	      IEEE80211_HTCAP_SHORTGI20		/* short GI in 20MHz */
	    | IEEE80211_HTCAP_MAXAMSDU_3839	/* max A-MSDU length */
	    | IEEE80211_HTCAP_SMPS_OFF		/* SM PS mode disabled */
	    /* s/w capabilities */
	    | IEEE80211_HTC_HT			/* HT operation */
	    | IEEE80211_HTC_AMPDU		/* A-MPDU tx */
	    | IEEE80211_HTC_AMSDU		/* A-MSDU tx */
	    ;

		ic->ic_htcaps |=
		      IEEE80211_HTCAP_CHWIDTH40	/* 40 MHz channel width */
		    | IEEE80211_HTCAP_SHORTGI40	/* short GI in 40MHz */
		    ;

	ic->ic_txstream = 1;
	ic->ic_rxstream = 1;

	blmac_getradiocaps(ic, IEEE80211_CHAN_MAX, &ic->ic_nchans, ic->ic_channels);
	/* XXX TODO: setup regdomain if R92C_CHANNEL_PLAN_BY_HW bit is set. */

	ieee80211_ifattach(ic);

	ic->ic_vap_create = blmac_vap_create;
#if 0
	ic->ic_vap_delete = rtwn_vap_delete;
	ic->ic_raw_xmit = rtwn_raw_xmit;
	ic->ic_scan_start = rtwn_scan_start;
	sc->sc_scan_curchan = ic->ic_scan_curchan;
	ic->ic_scan_curchan = rtwn_scan_curchan;
	ic->ic_scan_end = rtwn_scan_end;
	ic->ic_getradiocaps = rtwn_getradiocaps;
	ic->ic_update_chw = rtwn_update_chw;
	ic->ic_set_channel = rtwn_set_channel;
	ic->ic_transmit = rtwn_transmit;
	ic->ic_parent = rtwn_parent;
	ic->ic_wme.wme_update = rtwn_wme_update;
	ic->ic_updateslot = rtwn_update_slot;
	ic->ic_update_promisc = rtwn_update_promisc;
	ic->ic_update_mcast = rtwn_update_mcast;
	ic->ic_node_alloc = rtwn_node_alloc;
	ic->ic_newassoc = rtwn_newassoc;
	sc->sc_node_free = ic->ic_node_free;
	ic->ic_node_free = rtwn_node_free;

	rtwn_postattach(sc);
	rtwn_radiotap_attach(sc);
#endif

	/* hack: coex */
	uint32_t reg_data = 0;
  BLMAC_REG_WR(0x24B00404, 0x0024f637);

  BLMAC_REG_RD(0x24B00400, &reg_data);
	reg_data |= 0x1;
  BLMAC_REG_WR(0x24B00400, reg_data);

  BLMAC_REG_RD(0x24B00400, &reg_data);
	reg_data &= ~((uint32_t)0x00000001);
  BLMAC_REG_WR(0x24B00400, reg_data);

  BLMAC_REG_WR(0x24B00400, 0x00000068);

  BLMAC_REG_RD(0x24B00400, &reg_data);
	reg_data |= 0x1;
  BLMAC_REG_WR(0x24B00400, reg_data);

  BLMAC_REG_RD(0x24B00400, &reg_data);
	reg_data &= ~((uint32_t)0x00000020);
	reg_data |= (0 << 5);
  BLMAC_REG_WR(0x24B00400, reg_data);

  BLMAC_REG_WR(0x24920004, 0x5010001f);
  BLMAC_REG_WR(0x24b00410, 0x00000001);
  BLMAC_REG_WR(0x24920028, 0x0000000A);

  BLMAC_REG_RD(0x24B00054, &reg_data);
	reg_data |= (1 << 16) | (1 << 1); // rx flow control, err dect
  BLMAC_REG_WR(0x24B00054, reg_data);

	/* max rx length */
  BLMAC_REG_WR(0x24B00150, 2048);

	/* enable mac generic interrupt*/
  BLMAC_REG_WR(0x24B08074, 0x8373f14c);

	/* enable mac rx tx interrupt */
  BLMAC_REG_WR(0x24B08080, 0x800a0000);

  BLMAC_REG_RD(0x24B0004C, &reg_data);
	reg_data |= 0x40007c0; // mac control 1
	reg_data &= ~((uint32_t)0x00000002); // disable ap
	reg_data |= 0x1; // bss type
	reg_data |= 0x1 << 25; // tsf mgt disable
	reg_data |= 0x1 << 12; // reset mib table
  BLMAC_REG_WR(0x24B0004C, reg_data);

  // set tsf
  BLMAC_REG_WR(0x24B080A4, 0);
  BLMAC_REG_WR(0x24B080A8, 0);

	if (err != 0) {
		device_printf(sc->dev, "init blmac failed!\n");
		return -1;
	}

	/* wifi rx init */
	rxbuf_phy_addr = pmap_extract(pmap_kernel(), (uintptr_t)rx_buffers);
	rxbuf_phy_addr = (rxbuf_phy_addr & ~0xF0000000) | 0xD0000000; /* convert to no chache region */

	rx_buffers_nocahce_pa = (void *)rxbuf_phy_addr;
	rx_buffers_nocahce_va = pmap_mapdev(rxbuf_phy_addr, sizeof(rx_buffers));

	for (i = 0; i < RX_BUFFER_CNT; i++) {
		printf("register rx buffer[:%d] to ep:%d\n", i, RPMSG_WIFI_RX_EP(sc));
		rx_buffer_release(sc, i);
	}
	sc->wifi_rx_cb = mac_rx_callback;

	ieee80211_announce(ic);

	return (0);
}

void
rp_blmac_deinit(struct rpmsg_lite_softc *sc)
{
	return;
}
