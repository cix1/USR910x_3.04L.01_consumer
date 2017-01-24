/*
<:copyright-gpl
 Copyright 2002 Broadcom Corp. All Rights Reserved.

 This program is free software; you can distribute it and/or modify it
 under the terms of the GNU General Public License (Version 2) as
 published by the Free Software Foundation.

 This program is distributed in the hope it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 for more details.

 You should have received a copy of the GNU General Public License along
 with this program; if not, write to the Free Software Foundation, Inc.,
 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
:>
*/
/***********************************************************************/
/*                                                                     */
/*   MODULE:  bcmnet.h                                                 */
/*   DATE:    05/16/02                                                 */
/*   PURPOSE: network interface ioctl definition                       */
/*                                                                     */
/***********************************************************************/
#ifndef _IF_NET_H_
#define _IF_NET_H_

#if __cplusplus
extern "C" {
#endif

#define LINKSTATE_DOWN      0
#define LINKSTATE_UP        1
/*
*  Note, we need CHIP_6348 so that user application can also use this.
*/
#if defined(CHIP_6348) || defined(CONFIG_BCM96348)
#define NR_RX_BDS              120 
#else
#define NR_RX_BDS               80
#endif
#define NR_TX_BDS               200
/*---------------------------------------------------------------------*/
/* Ethernet Switch Type                                                */
/*---------------------------------------------------------------------*/
#define ESW_TYPE_UNDEFINED                  0
#define ESW_TYPE_BCM5325M                   1
#define ESW_TYPE_BCM5325E                   2
#define ESW_TYPE_BCM5325F                   3

/*
 * Ioctl definitions.
 */
/* reserved SIOCDEVPRIVATE */
enum {
    SIOCGLINKSTATE = SIOCDEVPRIVATE + 1,
    SIOCSCLEARMIBCNTR,
    SIOCGIFTRANSSTART,
    SIOCMIBINFO,
    SIOCSDUPLEX,	/* 0: auto 1: full 2: half */
    SIOCSSPEED,		/* 0: auto 1: 100mbps 2: 10mbps */
    SIOCCIFSTATS,
    SIOCGENABLEVLAN,
    SIOCGDISABLEVLAN,
    SIOCGQUERYNUMVLANPORTS,
    SIOCGSWITCHTYPE,
    SIOCGQUERYNUMPORTS,
    SIOCGMACTOPORT,
    SIOCGLINKSTATUS,
    SIOCLAST
};

#define SPEED_10MBIT        10000000
#define SPEED_100MBIT       100000000

typedef struct IoctlMibInfo
{
    unsigned long ulIfLastChange;
    unsigned long ulIfSpeed;
} IOCTL_MIB_INFO, *PIOCTL_MIB_INFO;


#if __cplusplus
}
#endif

#endif /* _IF_NET_H_ */
