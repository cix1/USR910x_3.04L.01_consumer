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
/*
 * Interrupt control functions for Broadcom 963xx MIPS boards
 */

#include <asm/atomic.h>

#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/module.h>

#include <asm/irq.h>
#include <asm/mipsregs.h>
#include <asm/addrspace.h>
#include <asm/signal.h>
#include <bcm_map_part.h>
#include <bcm_intr.h>

extern asmlinkage unsigned int do_IRQ(int irq, struct pt_regs *regs);

static void irq_dispatch_int(struct pt_regs *regs)
{
    unsigned int pendingIrqs;
    static unsigned int irqBit;
    static unsigned int isrNumber = 31;

    pendingIrqs = PERF->IrqStatus & PERF->IrqMask;
    if (!pendingIrqs) {
        return;
    }

    while (1) {
	irqBit <<= 1;
	isrNumber++;
	if (isrNumber == 32) {
		isrNumber = 0;
		irqBit = 0x1;
	}
	if (pendingIrqs & irqBit) {
	    	PERF->IrqMask &= ~irqBit; // mask
        	do_IRQ(isrNumber + INTERNAL_ISR_TABLE_OFFSET, regs);
		break;
	}
    }
}

static void irq_dispatch_ext(uint32 irq, struct pt_regs *regs)
{
    if (!(PERF->ExtIrqCfg & (1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_MASK_SHFT)))) {
	printk("**** Ext IRQ mask. Should not dispatch ****\n");
    }
    /* disable and clear interrupt in the controller */
    PERF->ExtIrqCfg |= (1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_CLEAR_SHFT));
    PERF->ExtIrqCfg &= ~(1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_MASK_SHFT));
    do_IRQ(irq, regs);
}

void brcm_irq_dispatch(struct pt_regs *regs)
{
    u32 cause;
    while((cause = (read_c0_cause()& CAUSEF_IP))) {
	if (cause & CAUSEF_IP7)
		do_IRQ(MIPS_TIMER_INT, regs);
	else if (cause & CAUSEF_IP2)
		irq_dispatch_int(regs);
	else if (cause & CAUSEF_IP3)
		irq_dispatch_ext(INTERRUPT_ID_EXTERNAL_0, regs);
	else if (cause & CAUSEF_IP4)
		irq_dispatch_ext(INTERRUPT_ID_EXTERNAL_1, regs);
	else if (cause & CAUSEF_IP5)
		irq_dispatch_ext(INTERRUPT_ID_EXTERNAL_2, regs);
	else if (cause & CAUSEF_IP6)
		irq_dispatch_ext(INTERRUPT_ID_EXTERNAL_3, regs);
	cli();
    }
}


void enable_brcm_irq(unsigned int irq)
{
    unsigned long flags;

    local_irq_save(flags);
    if( irq >= INTERNAL_ISR_TABLE_OFFSET ) {
	PERF->IrqMask |= (1 << (irq - INTERNAL_ISR_TABLE_OFFSET));
    }
    else if (irq >= INTERRUPT_ID_EXTERNAL_0 && irq <= INTERRUPT_ID_EXTERNAL_3) {
    /* enable and clear interrupt in the controller */
	PERF->ExtIrqCfg |= (1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_CLEAR_SHFT));
	PERF->ExtIrqCfg |= (1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_MASK_SHFT));
    }
    local_irq_restore(flags);
}

void disable_brcm_irq(unsigned int irq)
{
    unsigned long flags;

    local_irq_save(flags);
    if( irq >= INTERNAL_ISR_TABLE_OFFSET ) {
	PERF->IrqMask &= ~(1 << (irq - INTERNAL_ISR_TABLE_OFFSET));
    }
    else if (irq >= INTERRUPT_ID_EXTERNAL_0 && irq <= INTERRUPT_ID_EXTERNAL_3) {
    /* disable interrupt in the controller */
	PERF->ExtIrqCfg &= ~(1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_MASK_SHFT));
    }
    local_irq_restore(flags);
}

void ack_brcm_irq(unsigned int irq)
{
    /* Already done in brcm_irq_dispatch */
}

unsigned int startup_brcm_irq(unsigned int irq)
{
    enable_brcm_irq(irq);

    return 0; /* never anything pending */
}

unsigned int startup_brcm_none(unsigned int irq)
{
    return 0;
}

void end_brcm_irq(unsigned int irq)
{
    if (!(irq_desc[irq].status & (IRQ_DISABLED|IRQ_INPROGRESS)))
        enable_brcm_irq(irq);
}

void end_brcm_none(unsigned int irq)
{
}

#define ALLINTS_NOTIMER (IE_IRQ0 | IE_IRQ1 | IE_IRQ2 | IE_IRQ3 | IE_IRQ4)

static void __init brcm_irq_setup(void)
{
	extern asmlinkage void brcmIRQ(void);

	clear_c0_status(ST0_BEV);
    	set_except_vector(0, brcmIRQ);
	change_c0_status(ST0_IM, ALLINTS_NOTIMER);

#ifdef CONFIG_REMOTE_DEBUG
	rs_kgdb_hook(0);
#endif
}

static struct hw_interrupt_type brcm_irq_type = {
    .typename	= "MIPS",
    .startup	= startup_brcm_irq,
    .shutdown	= disable_brcm_irq,
    .enable	= enable_brcm_irq,
    .disable	= disable_brcm_irq,
    .ack	= ack_brcm_irq,
    .end	= end_brcm_irq,
    .set_affinity = NULL
};

static struct hw_interrupt_type brcm_irq_no_end_type = {
    .typename	= "MIPS",
    .startup	= startup_brcm_none,
    .shutdown	= disable_brcm_irq,
    .enable	= enable_brcm_irq,
    .disable	= disable_brcm_irq,
    .ack	= ack_brcm_irq,
    .end	= end_brcm_none,
    .set_affinity = NULL
};

void __init arch_init_irq(void)
{
    int i;

    for (i = 0; i < NR_IRQS; i++) {
        irq_desc[i].status = IRQ_DISABLED;
        irq_desc[i].action = 0;
        irq_desc[i].depth = 1;
        irq_desc[i].handler = &brcm_irq_type;
    }

    brcm_irq_setup();
}

int request_external_irq(unsigned int irq, 
	FN_HANDLER handler,
        unsigned long irqflags, 
        const char * devname,
        void *dev_id)
{
    unsigned long flags;

    local_irq_save(flags);

    PERF->ExtIrqCfg |= (1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_CLEAR_SHFT));      // Clear
    PERF->ExtIrqCfg &= ~(1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_MASK_SHFT));      // Mask
    PERF->ExtIrqCfg &= ~(1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_INSENS_SHFT));    // Edge insesnsitive
    PERF->ExtIrqCfg |= (1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_LEVEL_SHFT));      // Level triggered
    PERF->ExtIrqCfg &= ~(1 << (irq - INTERRUPT_ID_EXTERNAL_0 + EI_SENSE_SHFT));     // Low level

    local_irq_restore(flags);

    return( request_irq(irq, handler, irqflags, devname, dev_id) );
}

unsigned int BcmHalMapInterrupt(FN_HANDLER pfunc, unsigned int param,
    unsigned int interruptId)
{
    int nRet = -1;
    char *devname;

    devname = kmalloc(16, GFP_KERNEL);
    if (devname)
        sprintf( devname, "brcm_%d", interruptId );

    /* Set the IRQ description to not automatically enable the interrupt at
     * the end of an ISR.  The driver that handles the interrupt must
     * explicitly call BcmHalInterruptEnable or enable_brcm_irq.  This behavior
     * is consistent with interrupt handling on VxWorks.
     */
    irq_desc[interruptId].handler = &brcm_irq_no_end_type;

    if( interruptId >= INTERNAL_ISR_TABLE_OFFSET )
    {
        nRet = request_irq( interruptId, pfunc, SA_SAMPLE_RANDOM | SA_INTERRUPT,
                devname, (void *) param );
            
    }
    else if (interruptId >= INTERRUPT_ID_EXTERNAL_0 && interruptId <= INTERRUPT_ID_EXTERNAL_3)
    {
        nRet = request_external_irq( interruptId, pfunc, SA_SAMPLE_RANDOM | SA_INTERRUPT,
            devname, (void *) param );
    }

    return( nRet );
}

/* Debug function. */

void dump_intr_regs(void)
{
    printk("PERF->ExtIrqCfg [%08x]\n", *(&(PERF->ExtIrqCfg)));
} 

EXPORT_SYMBOL(enable_brcm_irq);
EXPORT_SYMBOL(disable_brcm_irq);
EXPORT_SYMBOL(request_external_irq);
EXPORT_SYMBOL(BcmHalMapInterrupt);

