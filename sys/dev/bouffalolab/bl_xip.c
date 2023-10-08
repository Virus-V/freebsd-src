/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2023 Zhuoran.Rong <zrrong@bouffalolab.org>

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/endian.h>
#include <sys/kernel.h>
#include <sys/kthread.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/resource.h>
#include <sys/rman.h>

#include <geom/geom_disk.h>

#include "opt_platform.h"

#ifdef FDT
#include <dev/fdt/fdt_common.h>
#include <dev/ofw/ofw_bus_subr.h>
#include <dev/ofw/openfirm.h>

static struct ofw_compat_data compat_data[] = {
	{ "bl808,xip",		1 },
	{ NULL,			0 },
};
#endif

#define	BL_XIP_RESSZ		1

struct xip_softc
{
	struct bio_queue_head	bio_queue;
	struct mtx		sc_mtx;
	struct disk		*disk;
	struct proc		*p;
	device_t		dev;
	u_int			taskstate;
	uintptr_t		xipstart;
	size_t		xipsize;
	struct resource *	res[BL_XIP_RESSZ];
};

static struct resource_spec bl_xip_res_spec[] = {
	{ SYS_RES_MEMORY,	0,	RF_ACTIVE },
	{ -1,			0,	0 }
};

#define	TSTATE_STOPPED	0
#define	TSTATE_STOPPING	1
#define	TSTATE_RUNNING	2

#define	BL_XIP_LOCK(_sc)			mtx_lock(&(_sc)->sc_mtx)
#define	BL_XIP_UNLOCK(_sc)		mtx_unlock(&(_sc)->sc_mtx)
#define	BL_XIP_LOCK_INIT(_sc) \
	mtx_init(&_sc->sc_mtx, device_get_nameunit(_sc->dev), \
	    "xip", MTX_DEF)
#define	BL_XIP_LOCK_DESTROY(_sc)		mtx_destroy(&_sc->sc_mtx);
#define	BL_XIP_ASSERT_LOCKED(_sc)	mtx_assert(&_sc->sc_mtx, MA_OWNED);
#define	BL_XIP_ASSERT_UNLOCKED(_sc)	mtx_assert(&_sc->sc_mtx, MA_NOTOWNED);

/* bus entry points */
static device_attach_t bl_xip_attach;
static device_detach_t bl_xip_detach;
static device_probe_t bl_xip_probe;

/* disk routines */
static int bl_xip_close(struct disk *dp);
static int bl_xip_open(struct disk *dp);
static int bl_xip_getattr(struct bio *bp);
static void bl_xip_strategy(struct bio *bp);
static void bl_xip_task(void *arg);

/* helper routines */
static void bl_xip_delayed_attach(void *xsc);

static int
bl_xip_probe(device_t dev)
{
	int rv;

#ifdef FDT
	if (!ofw_bus_status_okay(dev))
		return (ENXIO);

	if (ofw_bus_search_compatible(dev, compat_data)->ocd_data == 0)
		return (ENXIO);

	rv = BUS_PROBE_DEFAULT;
#else
	rv = BUS_PROBE_NOWILDCARD;
#endif

	device_set_desc(dev, "BL808 XIP RootFS");
	return (rv);
}

static int
bl_xip_attach(device_t dev)
{
	struct xip_softc *sc;

	sc = device_get_softc(dev);
	sc->dev = dev;
	BL_XIP_LOCK_INIT(sc);

	if (bus_alloc_resources(dev, bl_xip_res_spec, sc->res) != 0) {
		device_printf(dev, "cannot allocate device resources\n");
		return (ENXIO);
	}

	config_intrhook_oneshot(bl_xip_delayed_attach, sc);
	return (0);
}

static int
bl_xip_detach(device_t dev)
{
	struct xip_softc *sc;
	int err;

	sc = device_get_softc(dev);
	err = 0;

	BL_XIP_LOCK(sc);
	if (sc->taskstate == TSTATE_RUNNING) {
		sc->taskstate = TSTATE_STOPPING;
		wakeup(sc);
		while (err == 0 && sc->taskstate != TSTATE_STOPPED) {
			err = msleep(sc, &sc->sc_mtx, 0, "bl-xip", hz * 3);
			if (err != 0) {
				sc->taskstate = TSTATE_RUNNING;
				device_printf(sc->dev,
				    "Failed to stop queue task\n");
			}
		}
	}
	BL_XIP_UNLOCK(sc);

	if (err == 0 && sc->taskstate == TSTATE_STOPPED) {
		if (sc->disk) {
			disk_destroy(sc->disk);
			bioq_flush(&sc->bio_queue, NULL, ENXIO);
		}
		BL_XIP_LOCK_DESTROY(sc);
	}
	return (err);
}

static void
bl_xip_delayed_attach(void *xsc)
{
	struct xip_softc *sc = xsc;

	sc->xipstart = (uintptr_t)rman_get_virtual(sc->res[0]);
	sc->xipsize = rman_get_size(sc->res[0]);

	sc->disk = disk_alloc();
	sc->disk->d_open = bl_xip_open;
	sc->disk->d_close = bl_xip_close;
	sc->disk->d_strategy = bl_xip_strategy;
	sc->disk->d_getattr = bl_xip_getattr;
	sc->disk->d_name = "BL808/XIP";
	sc->disk->d_drv1 = sc;
	sc->disk->d_flags = DISKFLAG_WRITE_PROTECT;
	sc->disk->d_maxsize = DFLTPHYS;
	sc->disk->d_sectorsize = 4096;
	sc->disk->d_mediasize = sc->xipsize;
	sc->disk->d_unit = device_get_unit(sc->dev);
	disk_create(sc->disk, DISK_VERSION);
	bioq_init(&sc->bio_queue);

	kproc_create(&bl_xip_task, sc, &sc->p, 0, 0, "task: xip bio");
	sc->taskstate = TSTATE_RUNNING;
	device_printf(sc->dev, "%ld KBytes\n", sc->xipsize / 1024);
}

static int
bl_xip_open(struct disk *dp)
{

	return (0);
}

static int
bl_xip_close(struct disk *dp)
{

	return (0);
}

static int
bl_xip_getattr(struct bio *bp)
{
	struct xip_softc *sc;

	/*
	 * This function exists to support geom_flashmap and fdt_slicer.
	 */

	if (bp->bio_disk == NULL || bp->bio_disk->d_drv1 == NULL)
		return (ENXIO);
	if (strcmp(bp->bio_attribute, "SPI::device") != 0)
		return (-1);
	sc = bp->bio_disk->d_drv1;
	if (bp->bio_length != sizeof(sc->dev))
		return (EFAULT);
	bcopy(&sc->dev, bp->bio_data, sizeof(sc->dev));
	return (0);
}

static void
bl_xip_strategy(struct bio *bp)
{
	struct xip_softc *sc;

	sc = (struct xip_softc *)bp->bio_disk->d_drv1;
	BL_XIP_LOCK(sc);
	bioq_disksort(&sc->bio_queue, bp);
	wakeup(sc);
	BL_XIP_UNLOCK(sc);
}

static void
bl_xip_task(void *arg)
{
	struct xip_softc *sc;
	struct bio *bp;
	u_int berr;
	uint8_t *addr;

	sc = (struct xip_softc*)arg;

	for (;;) {
		BL_XIP_LOCK(sc);
		do {
			if (sc->taskstate == TSTATE_STOPPING) {
				sc->taskstate = TSTATE_STOPPED;
				BL_XIP_UNLOCK(sc);
				wakeup(sc);
				kproc_exit(0);
			}
			bp = bioq_takefirst(&sc->bio_queue);
			if (bp == NULL)
				msleep(sc, &sc->sc_mtx, PRIBIO, "bl-xip", 0);
		} while (bp == NULL);
		BL_XIP_UNLOCK(sc);

		berr = 0;

		if (bp->bio_offset > sc->xipsize) {
			printf("bp->bio_offset:%lx out of range\n", bp->bio_offset);
			berr = EINVAL;
			goto out;
		}

		addr = bp->bio_offset + (uint8_t *)sc->xipstart;

		if (bp->bio_cmd == BIO_READ) {
			memcpy(bp->bio_data, (void *)(uintptr_t)addr, bp->bio_bcount);
		} else {
			berr = EIO;
			printf("bl_xip not support write\n");
			goto out;
		}

 out:
		if (berr != 0) {
			bp->bio_flags |= BIO_ERROR;
			bp->bio_error = berr;
		}
		bp->bio_resid = 0;
		biodone(bp);
	}
}

static device_method_t bl_xip_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		bl_xip_probe),
	DEVMETHOD(device_attach,	bl_xip_attach),
	DEVMETHOD(device_detach,	bl_xip_detach),

	DEVMETHOD_END
};

static driver_t bl_xip_driver = {
	"bl_xip",
	bl_xip_methods,
	sizeof(struct xip_softc),
};

DRIVER_MODULE(bl_xip, ofwbus, bl_xip_driver, NULL, NULL);
#ifdef FDT
MODULE_DEPEND(bl_xip, fdt_slicer, 1, 1, 1);
//SPIBUS_FDT_PNP_INFO(compat_data);
#endif
