/*
 * probe.c - PCI detection and setup code
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/cpumask.h>
#include <linux/pci-aspm.h>
#include "pci.h"

#define CARDBUS_LATENCY_TIMER	176	/* secondary latency timer */
#define CARDBUS_RESERVE_BUSNR	3

/* Ugh.  Need to stop exporting this to modules. */
LIST_HEAD(pci_root_buses);
EXPORT_SYMBOL(pci_root_buses);


static int find_anything(struct device *dev, void *data)
{
	return 1;
}

/*
 * Some device drivers need know if pci is initiated.
 * Basically, we think pci is not initiated when there
 * is no device to be found on the pci_bus_type.
 */
int no_pci_devices(void)
{
	struct device *dev;
	int no_devices;

	dev = bus_find_device(&pci_bus_type, NULL, NULL, find_anything);
	no_devices = (dev == NULL);
	put_device(dev);
	return no_devices;
}
EXPORT_SYMBOL(no_pci_devices);

/*
 * PCI Bus Class Devices
 */
static ssize_t pci_bus_show_cpuaffinity(struct device *dev,
					int type,
					struct device_attribute *attr,
					char *buf)
{
	int ret;
	const struct cpumask *cpumask;

	cpumask = cpumask_of_pcibus(to_pci_bus(dev));
	ret = type?
		cpulist_scnprintf(buf, PAGE_SIZE-2, cpumask) :
		cpumask_scnprintf(buf, PAGE_SIZE-2, cpumask);
	buf[ret++] = '\n';
	buf[ret] = '\0';
	return ret;
}

static ssize_t inline pci_bus_show_cpumaskaffinity(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return pci_bus_show_cpuaffinity(dev, 0, attr, buf);
}

static ssize_t inline pci_bus_show_cpulistaffinity(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return pci_bus_show_cpuaffinity(dev, 1, attr, buf);
}

DEVICE_ATTR(cpuaffinity,     S_IRUGO, pci_bus_show_cpumaskaffinity, NULL);
DEVICE_ATTR(cpulistaffinity, S_IRUGO, pci_bus_show_cpulistaffinity, NULL);

/*
 * PCI Bus Class
 */
static void release_pcibus_dev(struct device *dev)
{
	struct pci_bus *pci_bus = to_pci_bus(dev);

	if (pci_bus->bridge)
		put_device(pci_bus->bridge);
	pci_bus_remove_resources(pci_bus);
	kfree(pci_bus);
}

static struct class pcibus_class = {
	.name		= "pci_bus",
	.dev_release	= &release_pcibus_dev,
};

static int __init pcibus_class_init(void)
{
	return class_register(&pcibus_class);
}
postcore_initcall(pcibus_class_init);

static u64 pci_size(u64 base, u64 maxbase, u64 mask)
{
	u64 size = mask & maxbase;	/* Find the significant bits */
	if (!size)
		return 0;

	/* Get the lowest of them to find the decode size, and
	   from that the extent.  */
	size = (size & ~(size-1)) - 1;

	/* base == maxbase can be valid only if the BAR has
	   already been programmed with all 1s.  */
	if (base == maxbase && ((base | size) & mask) != mask)
		return 0;

	return size;
}

static inline unsigned long decode_bar(struct pci_dev *dev, u32 bar)
{
	u32 mem_type;
	unsigned long flags;

	if ((bar & PCI_BASE_ADDRESS_SPACE) == PCI_BASE_ADDRESS_SPACE_IO) {
		flags = bar & ~PCI_BASE_ADDRESS_IO_MASK;
		flags |= IORESOURCE_IO;
		return flags;
	}

	flags = bar & ~PCI_BASE_ADDRESS_MEM_MASK;
	flags |= IORESOURCE_MEM;
	if (flags & PCI_BASE_ADDRESS_MEM_PREFETCH)
		flags |= IORESOURCE_PREFETCH;

	mem_type = bar & PCI_BASE_ADDRESS_MEM_TYPE_MASK;
	switch (mem_type) {
	case PCI_BASE_ADDRESS_MEM_TYPE_32:
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_1M:
		dev_info(&dev->dev, "1M mem BAR treated as 32-bit BAR\n");
		break;
	case PCI_BASE_ADDRESS_MEM_TYPE_64:
		flags |= IORESOURCE_MEM_64;
		break;
	default:
		dev_warn(&dev->dev,
			 "mem unknown type %x treated as 32-bit BAR\n",
			 mem_type);
		break;
	}
	return flags;
}

/**
 * pci_read_base - read a PCI BAR
 * @dev: the PCI device
 * @type: type of the BAR
 * @res: resource buffer to be filled in
 * @pos: BAR position in the config space
 *
 * Returns 1 if the BAR is 64-bit, or 0 if 32-bit.
 */
int __pci_read_base(struct pci_dev *dev, enum pci_bar_type type,
			struct resource *res, unsigned int pos)
{
	u32 l, sz, mask;
	u16 orig_cmd;

	mask = type ? ~PCI_ROM_ADDRESS_ENABLE : ~0;

	if (!((struct pci_dev_rh1 *)dev->rh_reserved1)->mmio_always_on) {
		pci_read_config_word(dev, PCI_COMMAND, &orig_cmd);
		pci_write_config_word(dev, PCI_COMMAND,
			orig_cmd & ~(PCI_COMMAND_MEMORY | PCI_COMMAND_IO));
	}

	res->name = pci_name(dev);

	pci_read_config_dword(dev, pos, &l);
	pci_write_config_dword(dev, pos, mask);
	pci_read_config_dword(dev, pos, &sz);
	pci_write_config_dword(dev, pos, l);

	/*
	 * All bits set in sz means the device isn't working properly.
	 * If the BAR isn't implemented, all bits must be 0.  If it's a
	 * memory BAR or a ROM, bit 0 must be clear; if it's an io BAR, bit
	 * 1 must be clear.
	 */
	if (!sz || sz == 0xffffffff)
		goto fail;

	/*
	 * I don't know how l can have all bits set.  Copied from old code.
	 * Maybe it fixes a bug on some ancient platform.
	 */
	if (l == 0xffffffff)
		l = 0;

	if (type == pci_bar_unknown) {
		res->flags = decode_bar(dev, l);
		res->flags |= IORESOURCE_SIZEALIGN;
		if (res->flags & IORESOURCE_IO) {
			l &= PCI_BASE_ADDRESS_IO_MASK;
			mask = PCI_BASE_ADDRESS_IO_MASK & IO_SPACE_LIMIT;
		} else {
			l &= PCI_BASE_ADDRESS_MEM_MASK;
			mask = (u32)PCI_BASE_ADDRESS_MEM_MASK;
		}
	} else {
		res->flags |= (l & IORESOURCE_ROM_ENABLE);
		l &= PCI_ROM_ADDRESS_MASK;
		mask = (u32)PCI_ROM_ADDRESS_MASK;
	}

	if (res->flags & IORESOURCE_MEM_64) {
		u64 l64 = l;
		u64 sz64 = sz;
		u64 mask64 = mask | (u64)~0 << 32;

		pci_read_config_dword(dev, pos + 4, &l);
		pci_write_config_dword(dev, pos + 4, ~0);
		pci_read_config_dword(dev, pos + 4, &sz);
		pci_write_config_dword(dev, pos + 4, l);

		l64 |= ((u64)l << 32);
		sz64 |= ((u64)sz << 32);

		sz64 = pci_size(l64, sz64, mask64);

		if (!sz64)
			goto fail;

		if ((sizeof(resource_size_t) < 8) && (sz64 > 0x100000000ULL)) {
			dev_err(&dev->dev, "reg %x: can't handle 64-bit BAR\n",
				pos);
			goto fail;
		}

		if ((sizeof(resource_size_t) < 8) && l) {
			/* Address above 32-bit boundary; disable the BAR */
			pci_write_config_dword(dev, pos, 0);
			pci_write_config_dword(dev, pos + 4, 0);
			res->start = 0;
			res->end = sz64;
		} else {
			res->start = l64;
			res->end = l64 + sz64;
			dev_printk(KERN_DEBUG, &dev->dev, "reg %x: %pR\n",
				   pos, res);
		}
	} else {
		sz = pci_size(l, sz, mask);

		if (!sz)
			goto fail;

		res->start = l;
		res->end = l + sz;

		dev_printk(KERN_DEBUG, &dev->dev, "reg %x: %pR\n", pos, res);
	}

 out:
	if (!((struct pci_dev_rh1 *)dev->rh_reserved1)->mmio_always_on)
		pci_write_config_word(dev, PCI_COMMAND, orig_cmd);

	return (res->flags & IORESOURCE_MEM_64) ? 1 : 0;
 fail:
	res->flags = 0;
	goto out;
}

static void pci_read_bases(struct pci_dev *dev, unsigned int howmany, int rom)
{
	unsigned int pos, reg;

	for (pos = 0; pos < howmany; pos++) {
		struct resource *res = &dev->resource[pos];
		reg = PCI_BASE_ADDRESS_0 + (pos << 2);
		pos += __pci_read_base(dev, pci_bar_unknown, res, reg);
	}

	if (rom) {
		struct resource *res = &dev->resource[PCI_ROM_RESOURCE];
		dev->rom_base_reg = rom;
		res->flags = IORESOURCE_MEM | IORESOURCE_PREFETCH |
				IORESOURCE_READONLY | IORESOURCE_CACHEABLE |
				IORESOURCE_SIZEALIGN;
		__pci_read_base(dev, pci_bar_mem32, res, rom);
	}
}

static void __devinit pci_read_bridge_io(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	u8 io_base_lo, io_limit_lo;
	unsigned long base, limit;
	struct resource *res;

	res = child->resource[0];
	pci_read_config_byte(dev, PCI_IO_BASE, &io_base_lo);
	pci_read_config_byte(dev, PCI_IO_LIMIT, &io_limit_lo);
	base = (io_base_lo & PCI_IO_RANGE_MASK) << 8;
	limit = (io_limit_lo & PCI_IO_RANGE_MASK) << 8;

	if ((io_base_lo & PCI_IO_RANGE_TYPE_MASK) == PCI_IO_RANGE_TYPE_32) {
		u16 io_base_hi, io_limit_hi;
		pci_read_config_word(dev, PCI_IO_BASE_UPPER16, &io_base_hi);
		pci_read_config_word(dev, PCI_IO_LIMIT_UPPER16, &io_limit_hi);
		base |= (io_base_hi << 16);
		limit |= (io_limit_hi << 16);
	}

	if (base && base <= limit) {
		res->flags = (io_base_lo & PCI_IO_RANGE_TYPE_MASK) | IORESOURCE_IO;
		if (!res->start)
			res->start = base;
		if (!res->end)
			res->end = limit + 0xfff;
		dev_printk(KERN_DEBUG, &dev->dev, "  bridge window %pR\n", res);
	} else {
		dev_printk(KERN_DEBUG, &dev->dev,
			 "  bridge window [io  %#06lx-%#06lx] (disabled)\n",
				 base, limit);
	}
}

static void __devinit pci_read_bridge_mmio(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	u16 mem_base_lo, mem_limit_lo;
	unsigned long base, limit;
	struct resource *res;

	res = child->resource[1];
	pci_read_config_word(dev, PCI_MEMORY_BASE, &mem_base_lo);
	pci_read_config_word(dev, PCI_MEMORY_LIMIT, &mem_limit_lo);
	base = (mem_base_lo & PCI_MEMORY_RANGE_MASK) << 16;
	limit = (mem_limit_lo & PCI_MEMORY_RANGE_MASK) << 16;
	if (base && base <= limit) {
		res->flags = (mem_base_lo & PCI_MEMORY_RANGE_TYPE_MASK) | IORESOURCE_MEM;
		res->start = base;
		res->end = limit + 0xfffff;
		dev_printk(KERN_DEBUG, &dev->dev, "  bridge window %pR\n", res);
	} else {
		dev_printk(KERN_DEBUG, &dev->dev,
			"  bridge window [mem %#010lx-%#010lx] (disabled)\n",
					 base, limit + 0xfffff);
	}
}

static void __devinit pci_read_bridge_mmio_pref(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	u16 mem_base_lo, mem_limit_lo;
	unsigned long base, limit;
	struct resource *res;

	res = child->resource[2];
	pci_read_config_word(dev, PCI_PREF_MEMORY_BASE, &mem_base_lo);
	pci_read_config_word(dev, PCI_PREF_MEMORY_LIMIT, &mem_limit_lo);
	base = (mem_base_lo & PCI_PREF_RANGE_MASK) << 16;
	limit = (mem_limit_lo & PCI_PREF_RANGE_MASK) << 16;

	if ((mem_base_lo & PCI_PREF_RANGE_TYPE_MASK) == PCI_PREF_RANGE_TYPE_64) {
		u32 mem_base_hi, mem_limit_hi;
		pci_read_config_dword(dev, PCI_PREF_BASE_UPPER32, &mem_base_hi);
		pci_read_config_dword(dev, PCI_PREF_LIMIT_UPPER32, &mem_limit_hi);

		/*
		 * Some bridges set the base > limit by default, and some
		 * (broken) BIOSes do not initialize them.  If we find
		 * this, just assume they are not being used.
		 */
		if (mem_base_hi <= mem_limit_hi) {
#if BITS_PER_LONG == 64
			base |= ((long) mem_base_hi) << 32;
			limit |= ((long) mem_limit_hi) << 32;
#else
			if (mem_base_hi || mem_limit_hi) {
				dev_err(&dev->dev, "can't handle 64-bit "
					"address space for bridge\n");
				return;
			}
#endif
		}
	}
	if (base && base <= limit) {
		res->flags = (mem_base_lo & PCI_PREF_RANGE_TYPE_MASK) |
					 IORESOURCE_MEM | IORESOURCE_PREFETCH;
		if (res->flags & PCI_PREF_RANGE_TYPE_64)
			res->flags |= IORESOURCE_MEM_64;
		res->start = base;
		res->end = limit + 0xfffff;
		dev_printk(KERN_DEBUG, &dev->dev, "  bridge window %pR\n", res);
	} else {
		dev_printk(KERN_DEBUG, &dev->dev,
		     "  bridge window [mem %#010lx-%#010lx pref] (disabled)\n",
					 base, limit + 0xfffff);
	}
}

void __devinit pci_read_bridge_bases(struct pci_bus *child)
{
	struct pci_dev *dev = child->self;
	struct resource *res;
	int i;

	if (pci_is_root_bus(child))	/* It's a host bus, nothing to read */
		return;

	dev_info(&dev->dev, "PCI bridge to [bus %02x-%02x]%s\n",
		 child->secondary, child->subordinate,
		 dev->transparent ? " (subtractive decode)" : "");

	pci_bus_remove_resources(child);
	for (i = 0; i < PCI_BRIDGE_RESOURCE_NUM; i++)
		child->resource[i] = &dev->resource[PCI_BRIDGE_RESOURCES+i];

	pci_read_bridge_io(child);
	pci_read_bridge_mmio(child);
	pci_read_bridge_mmio_pref(child);

	if (dev->transparent) {
		pci_bus_for_each_resource(child->parent, res, i) {
			if (res) {
				pci_bus_add_resource(child, res,
						     PCI_SUBTRACTIVE_DECODE);
				dev_printk(KERN_DEBUG, &dev->dev,
					   "  bridge window %pR (subtractive decode)\n",
					   res);
			}
		}
	}
}

static struct pci_bus * pci_alloc_bus(void)
{
	struct pci_bus *b;

	b = kzalloc(sizeof(*b), GFP_KERNEL);
	if (b) {
		INIT_LIST_HEAD(&b->node);
		INIT_LIST_HEAD(&b->children);
		INIT_LIST_HEAD(&b->devices);
		INIT_LIST_HEAD(&b->slots);
		INIT_LIST_HEAD(&b->resources);
	}
	return b;
}

static struct pci_bus *pci_alloc_child_bus(struct pci_bus *parent,
					   struct pci_dev *bridge, int busnr)
{
	struct pci_bus *child;
	int i;

	/*
	 * Allocate a new bus, and inherit stuff from the parent..
	 */
	child = pci_alloc_bus();
	if (!child)
		return NULL;

	child->parent = parent;
	child->ops = parent->ops;
	child->sysdata = parent->sysdata;
	child->bus_flags = parent->bus_flags;

	/* initialize some portions of the bus device, but don't register it
	 * now as the parent is not properly set up yet.  This device will get
	 * registered later in pci_bus_add_devices()
	 */
	child->dev.class = &pcibus_class;
	dev_set_name(&child->dev, "%04x:%02x", pci_domain_nr(child), busnr);

	/*
	 * Set up the primary, secondary and subordinate
	 * bus numbers.
	 */
	child->number = child->secondary = busnr;
	child->primary = parent->secondary;
	child->subordinate = 0xff;

	if (!bridge)
		return child;

	child->self = bridge;
	child->bridge = get_device(&bridge->dev);

	/* Set up default resource pointers and names.. */
	for (i = 0; i < PCI_BRIDGE_RESOURCE_NUM; i++) {
		child->resource[i] = &bridge->resource[PCI_BRIDGE_RESOURCES+i];
		child->resource[i]->name = child->name;
	}
	bridge->subordinate = child;

	return child;
}

struct pci_bus *__ref pci_add_new_bus(struct pci_bus *parent, struct pci_dev *dev, int busnr)
{
	struct pci_bus *child;

	child = pci_alloc_child_bus(parent, dev, busnr);
	if (child) {
		down_write(&pci_bus_sem);
		list_add_tail(&child->node, &parent->children);
		up_write(&pci_bus_sem);
	}
	return child;
}

static void pci_fixup_parent_subordinate_busnr(struct pci_bus *child, int max)
{
	struct pci_bus *parent = child->parent;

	/* Attempts to fix that up are really dangerous unless
	   we're going to re-assign all bus numbers. */
	if (!pcibios_assign_all_busses())
		return;

	while (parent->parent && parent->subordinate < max) {
		parent->subordinate = max;
		pci_write_config_byte(parent->self, PCI_SUBORDINATE_BUS, max);
		parent = parent->parent;
	}
}

/*
 * If it's a bridge, configure it and scan the bus behind it.
 * For CardBus bridges, we don't scan behind as the devices will
 * be handled by the bridge driver itself.
 *
 * We need to process bridges in two passes -- first we scan those
 * already configured by the BIOS and after we are done with all of
 * them, we proceed to assigning numbers to the remaining buses in
 * order to avoid overlaps between old and new bus numbers.
 */
int __devinit pci_scan_bridge(struct pci_bus *bus, struct pci_dev *dev, int max, int pass)
{
	struct pci_bus *child;
	int is_cardbus = (dev->hdr_type == PCI_HEADER_TYPE_CARDBUS);
	u32 buses, i, j = 0;
	u16 bctl;
	u8 primary, secondary, subordinate;
	int broken = 0;

	pci_read_config_dword(dev, PCI_PRIMARY_BUS, &buses);
	primary = buses & 0xFF;
	secondary = (buses >> 8) & 0xFF;
	subordinate = (buses >> 16) & 0xFF;

	dev_dbg(&dev->dev, "scanning [bus %02x-%02x] behind bridge, pass %d\n",
		secondary, subordinate, pass);

	if (!primary && (primary != bus->number) && secondary && subordinate) {
		dev_warn(&dev->dev, "Primary bus is hard wired to 0\n");
		primary = bus->number;
	}

	/* Check if setup is sensible at all */
	if (!pass &&
	    (primary != bus->number || secondary <= bus->number)) {
		dev_dbg(&dev->dev, "bus configuration invalid, reconfiguring\n");
		broken = 1;
	}

	/* Disable MasterAbortMode during probing to avoid reporting
	   of bus errors (in some architectures) */ 
	pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &bctl);
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL,
			      bctl & ~PCI_BRIDGE_CTL_MASTER_ABORT);

	if ((secondary || subordinate) && !pcibios_assign_all_busses() &&
	    !is_cardbus && !broken) {
		unsigned int cmax;
		/*
		 * Bus already configured by firmware, process it in the first
		 * pass and just note the configuration.
		 */
		if (pass)
			goto out;

		/*
		 * If we already got to this bus through a different bridge,
		 * don't re-add it. This can happen with the i450NX chipset.
		 *
		 * However, we continue to descend down the hierarchy and
		 * scan remaining child buses.
		 */
		child = pci_find_bus(pci_domain_nr(bus), secondary);
		if (!child) {
			child = pci_add_new_bus(bus, dev, secondary);
			if (!child)
				goto out;
			child->primary = primary;
			child->subordinate = subordinate;
			child->bridge_ctl = bctl;
		}

		cmax = pci_scan_child_bus(child);
		if (cmax > max)
			max = cmax;
		if (child->subordinate > max)
			max = child->subordinate;
	} else {
		/*
		 * We need to assign a number to this bus which we always
		 * do in the second pass.
		 */
		if (!pass) {
			if (pcibios_assign_all_busses() || broken)
				/* Temporarily disable forwarding of the
				   configuration cycles on all bridges in
				   this bus segment to avoid possible
				   conflicts in the second pass between two
				   bridges programmed with overlapping
				   bus ranges. */
				pci_write_config_dword(dev, PCI_PRIMARY_BUS,
						       buses & ~0xffffff);
			goto out;
		}

		/* Clear errors */
		pci_write_config_word(dev, PCI_STATUS, 0xffff);

		/* Prevent assigning a bus number that already exists.
		 * This can happen when a bridge is hot-plugged */
		if (pci_find_bus(pci_domain_nr(bus), max+1))
			goto out;
		child = pci_add_new_bus(bus, dev, ++max);
		buses = (buses & 0xff000000)
		      | ((unsigned int)(child->primary)     <<  0)
		      | ((unsigned int)(child->secondary)   <<  8)
		      | ((unsigned int)(child->subordinate) << 16);

		/*
		 * yenta.c forces a secondary latency timer of 176.
		 * Copy that behaviour here.
		 */
		if (is_cardbus) {
			buses &= ~0xff000000;
			buses |= CARDBUS_LATENCY_TIMER << 24;
		}
			
		/*
		 * We need to blast all three values with a single write.
		 */
		pci_write_config_dword(dev, PCI_PRIMARY_BUS, buses);

		if (!is_cardbus) {
			child->bridge_ctl = bctl;
			/*
			 * Adjust subordinate busnr in parent buses.
			 * We do this before scanning for children because
			 * some devices may not be detected if the bios
			 * was lazy.
			 */
			pci_fixup_parent_subordinate_busnr(child, max);
			/* Now we can scan all subordinate buses... */
			max = pci_scan_child_bus(child);
			/*
			 * now fix it up again since we have found
			 * the real value of max.
			 */
			pci_fixup_parent_subordinate_busnr(child, max);
		} else {
			/*
			 * For CardBus bridges, we leave 4 bus numbers
			 * as cards with a PCI-to-PCI bridge can be
			 * inserted later.
			 */
			for (i=0; i<CARDBUS_RESERVE_BUSNR; i++) {
				struct pci_bus *parent = bus;
				if (pci_find_bus(pci_domain_nr(bus),
							max+i+1))
					break;
				while (parent->parent) {
					if ((!pcibios_assign_all_busses()) &&
					    (parent->subordinate > max) &&
					    (parent->subordinate <= max+i)) {
						j = 1;
					}
					parent = parent->parent;
				}
				if (j) {
					/*
					 * Often, there are two cardbus bridges
					 * -- try to leave one valid bus number
					 * for each one.
					 */
					i /= 2;
					break;
				}
			}
			max += i;
			pci_fixup_parent_subordinate_busnr(child, max);
		}
		/*
		 * Set the subordinate bus number to its real value.
		 */
		child->subordinate = max;
		pci_write_config_byte(dev, PCI_SUBORDINATE_BUS, max);
	}

	sprintf(child->name,
		(is_cardbus ? "PCI CardBus %04x:%02x" : "PCI Bus %04x:%02x"),
		pci_domain_nr(bus), child->number);

	/* Has only triggered on CardBus, fixup is in yenta_socket */
	while (bus->parent) {
		if ((child->subordinate > bus->subordinate) ||
		    (child->number > bus->subordinate) ||
		    (child->number < bus->number) ||
		    (child->subordinate < bus->number)) {
			dev_info(&child->dev, "[bus %02x-%02x] %s "
				"hidden behind%s bridge %s [bus %02x-%02x]\n",
				child->number, child->subordinate,
				(bus->number > child->subordinate &&
				 bus->subordinate < child->number) ?
					"wholly" : "partially",
				bus->self->transparent ? " transparent" : "",
				dev_name(&bus->dev),
				bus->number, bus->subordinate);
		}
		bus = bus->parent;
	}

out:
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL, bctl);

	return max;
}

/*
 * Read interrupt line and base address registers.
 * The architecture-dependent code can tweak these, of course.
 */
static void pci_read_irq(struct pci_dev *dev)
{
	unsigned char irq;

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &irq);
	dev->pin = irq;
	if (irq)
		pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &irq);
	dev->irq = irq;
}

void set_pcie_port_type(struct pci_dev *pdev)
{
	int pos;
	u16 reg16;

	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (!pos)
		return;
	pdev->is_pcie = 1;
	pdev->pcie_cap = pos;
	pci_read_config_word(pdev, pos + PCI_EXP_FLAGS, &reg16);
	pdev->pcie_type = (reg16 & PCI_EXP_FLAGS_TYPE) >> 4;
	pci_read_config_word(pdev, pos + PCI_EXP_DEVCAP, &reg16);
	rh_set_mpss(pdev, reg16 & PCI_EXP_DEVCAP_PAYLOAD);
}

void set_pcie_hotplug_bridge(struct pci_dev *pdev)
{
	int pos;
	u16 reg16;
	u32 reg32;

	pos = pci_pcie_cap(pdev);
	if (!pos)
		return;
	pci_read_config_word(pdev, pos + PCI_EXP_FLAGS, &reg16);
	if (!(reg16 & PCI_EXP_FLAGS_SLOT))
		return;
	pci_read_config_dword(pdev, pos + PCI_EXP_SLTCAP, &reg32);
	if (reg32 & PCI_EXP_SLTCAP_HPC)
		pdev->is_hotplug_bridge = 1;
}

#define LEGACY_IO_RESOURCE	(IORESOURCE_IO | IORESOURCE_PCI_FIXED)

/**
 * pci_setup_device - fill in class and map information of a device
 * @dev: the device structure to fill
 *
 * Initialize the device structure with information about the device's 
 * vendor,class,memory and IO-space addresses,IRQ lines etc.
 * Called at initialisation of the PCI subsystem and by CardBus services.
 * Returns 0 on success and negative if unknown type of device (not normal,
 * bridge or CardBus).
 */
int pci_setup_device(struct pci_dev *dev)
{
	u32 class;
	u8 hdr_type;
	struct pci_slot *slot;

	if (pci_read_config_byte(dev, PCI_HEADER_TYPE, &hdr_type))
		return -EIO;

	dev->sysdata = dev->bus->sysdata;
	dev->dev.parent = dev->bus->bridge;
	dev->dev.bus = &pci_bus_type;
	dev->hdr_type = hdr_type & 0x7f;
	dev->multifunction = !!(hdr_type & 0x80);
	dev->error_state = pci_channel_io_normal;
	set_pcie_port_type(dev);

	list_for_each_entry(slot, &dev->bus->slots, list)
		if (PCI_SLOT(dev->devfn) == slot->number)
			dev->slot = slot;

	/* Assume 32-bit PCI; let 64-bit PCI cards (which are far rarer)
	   set this higher, assuming the system even supports it.  */
	dev->dma_mask = 0xffffffff;

	dev_set_name(&dev->dev, "%04x:%02x:%02x.%d", pci_domain_nr(dev->bus),
		     dev->bus->number, PCI_SLOT(dev->devfn),
		     PCI_FUNC(dev->devfn));

	pci_read_config_dword(dev, PCI_CLASS_REVISION, &class);
	dev->revision = class & 0xff;
	class >>= 8;				    /* upper 3 bytes */
	dev->class = class;
	class >>= 8;

	dev_dbg(&dev->dev, "found [%04x:%04x] class %06x header type %02x\n",
		 dev->vendor, dev->device, class, dev->hdr_type);

	/* need to have dev->class ready */
	dev->cfg_size = pci_cfg_space_size(dev);

	/* "Unknown power state" */
	dev->current_state = PCI_UNKNOWN;

	/* Early fixups, before probing the BARs */
	pci_fixup_device(pci_fixup_early, dev);
	/* device class may be changed after fixup */
	class = dev->class >> 8;

	switch (dev->hdr_type) {		    /* header type */
	case PCI_HEADER_TYPE_NORMAL:		    /* standard header */
		if (class == PCI_CLASS_BRIDGE_PCI)
			goto bad;
		pci_read_irq(dev);
		pci_read_bases(dev, 6, PCI_ROM_ADDRESS);
		pci_read_config_word(dev, PCI_SUBSYSTEM_VENDOR_ID, &dev->subsystem_vendor);
		pci_read_config_word(dev, PCI_SUBSYSTEM_ID, &dev->subsystem_device);

		/*
		 *	Do the ugly legacy mode stuff here rather than broken chip
		 *	quirk code. Legacy mode ATA controllers have fixed
		 *	addresses. These are not always echoed in BAR0-3, and
		 *	BAR0-3 in a few cases contain junk!
		 */
		if (class == PCI_CLASS_STORAGE_IDE) {
			u8 progif;
			pci_read_config_byte(dev, PCI_CLASS_PROG, &progif);
			if ((progif & 1) == 0) {
				dev->resource[0].start = 0x1F0;
				dev->resource[0].end = 0x1F7;
				dev->resource[0].flags = LEGACY_IO_RESOURCE;
				dev->resource[1].start = 0x3F6;
				dev->resource[1].end = 0x3F6;
				dev->resource[1].flags = LEGACY_IO_RESOURCE;
			}
			if ((progif & 4) == 0) {
				dev->resource[2].start = 0x170;
				dev->resource[2].end = 0x177;
				dev->resource[2].flags = LEGACY_IO_RESOURCE;
				dev->resource[3].start = 0x376;
				dev->resource[3].end = 0x376;
				dev->resource[3].flags = LEGACY_IO_RESOURCE;
			}
		}
		break;

	case PCI_HEADER_TYPE_BRIDGE:		    /* bridge header */
		if (class != PCI_CLASS_BRIDGE_PCI)
			goto bad;
		/* The PCI-to-PCI bridge spec requires that subtractive
		   decoding (i.e. transparent) bridge must have programming
		   interface code of 0x01. */ 
		pci_read_irq(dev);
		dev->transparent = ((dev->class & 0xff) == 1);
		pci_read_bases(dev, 2, PCI_ROM_ADDRESS1);
		set_pcie_hotplug_bridge(dev);
		break;

	case PCI_HEADER_TYPE_CARDBUS:		    /* CardBus bridge header */
		if (class != PCI_CLASS_BRIDGE_CARDBUS)
			goto bad;
		pci_read_irq(dev);
		pci_read_bases(dev, 1, 0);
		pci_read_config_word(dev, PCI_CB_SUBSYSTEM_VENDOR_ID, &dev->subsystem_vendor);
		pci_read_config_word(dev, PCI_CB_SUBSYSTEM_ID, &dev->subsystem_device);
		break;

	default:				    /* unknown header */
		dev_err(&dev->dev, "unknown header type %02x, "
			"ignoring device\n", dev->hdr_type);
		return -EIO;

	bad:
		dev_err(&dev->dev, "ignoring class %02x (doesn't match header "
			"type %02x)\n", class, dev->hdr_type);
		dev->class = PCI_CLASS_NOT_DEFINED;
	}

	/* We found a fine healthy device, go go go... */
	return 0;
}

static void pci_release_capabilities(struct pci_dev *dev)
{
	pci_vpd_release(dev);
	pci_iov_release(dev);
}

/**
 * pci_release_dev - free a pci device structure when all users of it are finished.
 * @dev: device that's been disconnected
 *
 * Will be called only by the device core when all users of this pci device are
 * done.
 */
static void pci_release_dev(struct device *dev)
{
	struct pci_dev *pci_dev;

	pci_dev = to_pci_dev(dev);
	pci_release_capabilities(pci_dev);
	kfree_pci_dev(pci_dev);
}

/**
 * pci_cfg_space_size - get the configuration space size of the PCI device.
 * @dev: PCI device
 *
 * Regular PCI devices have 256 bytes, but PCI-X 2 and PCI Express devices
 * have 4096 bytes.  Even if the device is capable, that doesn't mean we can
 * access it.  Maybe we don't have a way to generate extended config space
 * accesses, or the device is behind a reverse Express bridge.  So we try
 * reading the dword at 0x100 which must either be 0 or a valid extended
 * capability header.
 */
int pci_cfg_space_size_ext(struct pci_dev *dev)
{
	u32 status;
	int pos = PCI_CFG_SPACE_SIZE;

	if (pci_read_config_dword(dev, pos, &status) != PCIBIOS_SUCCESSFUL)
		goto fail;
	if (status == 0xffffffff)
		goto fail;

	return PCI_CFG_SPACE_EXP_SIZE;

 fail:
	return PCI_CFG_SPACE_SIZE;
}

int pci_cfg_space_size(struct pci_dev *dev)
{
	int pos;
	u32 status;
	u16 class;

	class = dev->class >> 8;
	if (class == PCI_CLASS_BRIDGE_HOST)
		return pci_cfg_space_size_ext(dev);

	pos = pci_pcie_cap(dev);
	if (!pos) {
		pos = pci_find_capability(dev, PCI_CAP_ID_PCIX);
		if (!pos)
			goto fail;

		pci_read_config_dword(dev, pos + PCI_X_STATUS, &status);
		if (!(status & (PCI_X_STATUS_266MHZ | PCI_X_STATUS_533MHZ)))
			goto fail;
	}

	return pci_cfg_space_size_ext(dev);

 fail:
	return PCI_CFG_SPACE_SIZE;
}

static void pci_release_bus_bridge_dev(struct device *dev)
{
	kfree(dev);
}

struct pci_dev *alloc_pci_dev(void)
{
	struct pci_dev *dev;

	dev = kzalloc(sizeof(struct pci_dev), GFP_KERNEL);
	if (!dev)
		return NULL;

	dev->rh_reserved1 = kzalloc(sizeof(struct pci_dev_rh1), GFP_KERNEL);
	if (!dev->rh_reserved1) {
		kfree(dev);
		return NULL;
	}

	INIT_LIST_HEAD(&dev->bus_list);

	return dev;
}
EXPORT_SYMBOL(alloc_pci_dev);

void kfree_pci_dev(struct pci_dev *dev)
{
	kfree(dev->rh_reserved1);
	kfree(dev);
}
EXPORT_SYMBOL(kfree_pci_dev);

/*
 * Read the config data for a PCI device, sanity-check it
 * and fill in the dev structure...
 */
static struct pci_dev *pci_scan_device(struct pci_bus *bus, int devfn)
{
	struct pci_dev *dev;
	u32 l;
	int delay = 1;

	if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, &l))
		return NULL;

	/* some broken boards return 0 or ~0 if a slot is empty: */
	if (l == 0xffffffff || l == 0x00000000 ||
	    l == 0x0000ffff || l == 0xffff0000)
		return NULL;

	/* Configuration request Retry Status */
	while (l == 0xffff0001) {
		msleep(delay);
		delay *= 2;
		if (pci_bus_read_config_dword(bus, devfn, PCI_VENDOR_ID, &l))
			return NULL;
		/* Card hasn't responded in 60 seconds?  Must be stuck. */
		if (delay > 60 * 1000) {
			printk(KERN_WARNING "pci %04x:%02x:%02x.%d: not "
					"responding\n", pci_domain_nr(bus),
					bus->number, PCI_SLOT(devfn),
					PCI_FUNC(devfn));
			return NULL;
		}
	}

	dev = alloc_pci_dev();
	if (!dev)
		return NULL;

	dev->bus = bus;
	dev->devfn = devfn;
	dev->vendor = l & 0xffff;
	dev->device = (l >> 16) & 0xffff;

	if (pci_setup_device(dev)) {
		kfree_pci_dev(dev);
		return NULL;
	}

	return dev;
}

static void pci_init_capabilities(struct pci_dev *dev)
{
	/* MSI/MSI-X list */
	pci_msi_init_pci_dev(dev);

	/* Buffers for saving PCIe and PCI-X capabilities */
	pci_allocate_cap_save_buffers(dev);

	/* Power Management */
	pci_pm_init(dev);
	platform_pci_wakeup_init(dev);

	/* Vital Product Data */
	pci_vpd_pci22_init(dev);

	/* Alternative Routing-ID Forwarding */
	pci_enable_ari(dev);

	/* Single Root I/O Virtualization */
	pci_iov_init(dev);

	/* Enable ACS P2P upstream forwarding */
	pci_enable_acs(dev);
}

void pci_device_add(struct pci_dev *dev, struct pci_bus *bus)
{
	device_initialize(&dev->dev);
	dev->dev.release = pci_release_dev;
	pci_dev_get(dev);

	dev->dev.dma_mask = &dev->dma_mask;
	dev->dev.dma_parms = &dev->dma_parms;
	dev->dev.coherent_dma_mask = 0xffffffffull;

	pci_set_dma_max_seg_size(dev, 65536);
	pci_set_dma_seg_boundary(dev, 0xffffffff);

	/* Fix up broken headers */
	pci_fixup_device(pci_fixup_header, dev);

	/* moved out from quirk header fixup code */
	pci_reassigndev_resource_alignment(dev);

	/* Clear the state_saved flag. */
	dev->state_saved = false;

	/* Initialize various capabilities */
	pci_init_capabilities(dev);

	/*
	 * Add the device to our list of discovered devices
	 * and the bus list for fixup functions, etc.
	 */
	down_write(&pci_bus_sem);
	list_add_tail(&dev->bus_list, &bus->devices);
	up_write(&pci_bus_sem);
}

struct pci_dev *__ref pci_scan_single_device(struct pci_bus *bus, int devfn)
{
	struct pci_dev *dev;

	dev = pci_get_slot(bus, devfn);
	if (dev) {
		pci_dev_put(dev);
		return dev;
	}

	dev = pci_scan_device(bus, devfn);
	if (!dev)
		return NULL;

	pci_device_add(dev, bus);

	return dev;
}
EXPORT_SYMBOL(pci_scan_single_device);

/**
 * pci_scan_slot - scan a PCI slot on a bus for devices.
 * @bus: PCI bus to scan
 * @devfn: slot number to scan (must have zero function.)
 *
 * Scan a PCI slot on the specified PCI bus for devices, adding
 * discovered devices to the @bus->devices list.  New devices
 * will not have is_added set.
 *
 * Returns the number of new devices found.
 */
int pci_scan_slot(struct pci_bus *bus, int devfn)
{
	int fn, nr = 0;
	struct pci_dev *dev;

	dev = pci_scan_single_device(bus, devfn);
	if (dev && !dev->is_added)	/* new device? */
		nr++;

	if (dev && dev->multifunction) {
		for (fn = 1; fn < 8; fn++) {
			dev = pci_scan_single_device(bus, devfn + fn);
			if (dev) {
				if (!dev->is_added)
					nr++;
				dev->multifunction = 1;
			}
		}
	}

	/* only one slot has pcie device */
	if (bus->self && nr)
		pcie_aspm_init_link_state(bus->self);

	return nr;
}

static int pcie_find_smpss(struct pci_dev *dev, void *data)
{
	u8 *smpss = data;

	if (!pci_is_pcie(dev))
		return 0;

	/* For PCIE hotplug enabled slots not connected directly to a
	 * PCI-E root port, there can be problems when hotplugging
	 * devices.  This is due to the possibility of hotplugging a
	 * device into the fabric with a smaller MPS that the devices
	 * currently running have configured.  Modifying the MPS on the
	 * running devices could cause a fatal bus error due to an
	 * incoming frame being larger than the newly configured MPS.
	 * To work around this, the MPS for the entire fabric must be
	 * set to the minimum size.  Any devices hotplugged into this
	 * fabric will have the minimum MPS set.  If the PCI hotplug
	 * slot is directly connected to the root port and there are not
	 * other devices on the fabric (which seems to be the most
	 * common case), then this is not an issue and MPS discovery
	 * will occur as normal.
	 */
	if (dev->is_hotplug_bridge && (!list_is_singular(&dev->bus->devices) ||
	     (dev->bus->self &&
	      dev->bus->self->pcie_type != PCI_EXP_TYPE_ROOT_PORT)))
		*smpss = 0;

	if (*smpss > rh_get_mpss(dev))
		*smpss = rh_get_mpss(dev);

	return 0;
}

static void pcie_write_mps(struct pci_dev *dev, int mps)
{
	int rc;

	if (pcie_bus_config == PCIE_BUS_PERFORMANCE) {
		mps = 128 << rh_get_mpss(dev);

		if (dev->pcie_type != PCI_EXP_TYPE_ROOT_PORT && dev->bus->self)
			/* For "Performance", the assumption is made that
			 * downstream communication will never be larger than
			 * the MRRS.  So, the MPS only needs to be configured
			 * for the upstream communication.  This being the case,
			 * walk from the top down and set the MPS of the child
			 * to that of the parent bus.
			 *
			 * Configure the device MPS with the smaller of the
			 * device MPSS or the bridge MPS (which is assumed to be
			 * properly configured at this point to the largest
			 * allowable MPS based on its parent bus).
			 */
			mps = min(mps, pcie_get_mps(dev->bus->self));
	}

	rc = pcie_set_mps(dev, mps);
	if (rc)
		dev_err(&dev->dev, "Failed attempting to set the MPS\n");
}

static void pcie_write_mrrs(struct pci_dev *dev)
{
	int rc, mrrs;

	/* In the "safe" case, do not configure the MRRS.  There appear to be
	 * issues with setting MRRS to 0 on a number of devices.
	 */
	if (pcie_bus_config != PCIE_BUS_PERFORMANCE)
		return;

	/* For Max performance, the MRRS must be set to the largest supported
	 * value.  However, it cannot be configured larger than the MPS the
	 * device or the bus can support.  This should already be properly
	 * configured by a prior call to pcie_write_mps.
	 */
	mrrs = pcie_get_mps(dev);

	/* MRRS is a R/W register.  Invalid values can be written, but a
	 * subsequent read will verify if the value is acceptable or not.
	 * If the MRRS value provided is not acceptable (e.g., too large),
	 * shrink the value until it is acceptable to the HW.
 	 */
	while (mrrs != pcie_get_readrq(dev) && mrrs >= 128) {
		rc = pcie_set_readrq(dev, mrrs);
		if (!rc)
			break;

		dev_warn(&dev->dev, "Failed attempting to set the MRRS\n");
		mrrs /= 2;
	}

	if (mrrs < 128)
		dev_err(&dev->dev, "MRRS was unable to be configured with a "
			"safe value.  If problems are experienced, try running "
			"with pci=pcie_bus_safe.\n");
}

static int pcie_bus_configure_set(struct pci_dev *dev, void *data)
{
	int mps, orig_mps;

	if (!pci_is_pcie(dev))
		return 0;

	mps = 128 << *(u8 *)data;
	orig_mps = pcie_get_mps(dev);

	pcie_write_mps(dev, mps);
	pcie_write_mrrs(dev);

	dev_info(&dev->dev, "PCI-E Max Payload Size set to %4d/%4d (was %4d), "
		 "Max Read Rq %4d\n", pcie_get_mps(dev),
		 128 << rh_get_mpss(dev), orig_mps, pcie_get_readrq(dev));

	return 0;
}

/* pcie_bus_configure_settings requires that pci_walk_bus work in a top-down,
 * parents then children fashion.  If this changes, then this code will not
 * work as designed.
 */
void pcie_bus_configure_settings(struct pci_bus *bus, u8 mpss)
{
	u8 smpss;

	if (!pci_is_pcie(bus->self))
		return;

	if (pcie_bus_config == PCIE_BUS_TUNE_OFF)
		return;

	/* FIXME - Peer to peer DMA is possible, though the endpoint would need
	 * to be aware to the MPS of the destination.  To work around this,
	 * simply force the MPS of the entire system to the smallest possible.
	 */
	if (pcie_bus_config == PCIE_BUS_PEER2PEER)
		smpss = 0;

	if (pcie_bus_config == PCIE_BUS_SAFE) {
		smpss = mpss;

		pcie_find_smpss(bus->self, &smpss);
		pci_walk_bus(bus, pcie_find_smpss, &smpss);
	}

	pcie_bus_configure_set(bus->self, &smpss);
	pci_walk_bus(bus, pcie_bus_configure_set, &smpss);
}

unsigned int __devinit pci_scan_child_bus(struct pci_bus *bus)
{
	unsigned int devfn, pass, max = bus->secondary;
	struct pci_dev *dev;

	dev_dbg(&bus->dev, "scanning bus\n");

	/* Go find them, Rover! */
	for (devfn = 0; devfn < 0x100; devfn += 8)
		pci_scan_slot(bus, devfn);

	/* Reserve buses for SR-IOV capability. */
	max += pci_iov_bus_range(bus);

	/*
	 * After performing arch-dependent fixup of the bus, look behind
	 * all PCI-to-PCI bridges on this bus.
	 */
	if (!bus->is_added) {
		dev_dbg(&bus->dev, "fixups for bus\n");
		pcibios_fixup_bus(bus);
		if (pci_is_root_bus(bus))
			bus->is_added = 1;
	}

	for (pass=0; pass < 2; pass++)
		list_for_each_entry(dev, &bus->devices, bus_list) {
			if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE ||
			    dev->hdr_type == PCI_HEADER_TYPE_CARDBUS)
				max = pci_scan_bridge(bus, dev, max, pass);
		}

	/*
	 * We've scanned the bus and so we know all about what's on
	 * the other side of any bridges that may be on this bus plus
	 * any devices.
	 *
	 * Return how far we've got finding sub-buses.
	 */
	dev_dbg(&bus->dev, "bus scan returning with max=%02x\n", max);
	return max;
}

struct pci_bus * pci_create_bus(struct device *parent,
		int bus, struct pci_ops *ops, void *sysdata)
{
	int error;
	struct pci_bus *b, *b2;
	struct device *dev;

	b = pci_alloc_bus();
	if (!b)
		return NULL;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev){
		kfree(b);
		return NULL;
	}

	b->sysdata = sysdata;
	b->ops = ops;

	b2 = pci_find_bus(pci_domain_nr(b), bus);
	if (b2) {
		/* If we already got to this bus through a different bridge, ignore it */
		dev_dbg(&b2->dev, "bus already known\n");
		goto err_out;
	}

	down_write(&pci_bus_sem);
	list_add_tail(&b->node, &pci_root_buses);
	up_write(&pci_bus_sem);

	dev->parent = parent;
	dev->release = pci_release_bus_bridge_dev;
	dev_set_name(dev, "pci%04x:%02x", pci_domain_nr(b), bus);
	error = device_register(dev);
	if (error)
		goto dev_reg_err;
	b->bridge = get_device(dev);

	if (!parent)
		set_dev_node(b->bridge, pcibus_to_node(b));

	b->dev.class = &pcibus_class;
	b->dev.parent = b->bridge;
	dev_set_name(&b->dev, "%04x:%02x", pci_domain_nr(b), bus);
	error = device_register(&b->dev);
	if (error)
		goto class_dev_reg_err;
	error = device_create_file(&b->dev, &dev_attr_cpuaffinity);
	if (error)
		goto dev_create_file_err;

	/* Create legacy_io and legacy_mem files for this bus */
	pci_create_legacy_files(b);

	b->number = b->secondary = bus;
	b->resource[0] = &ioport_resource;
	b->resource[1] = &iomem_resource;

	return b;

dev_create_file_err:
	device_unregister(&b->dev);
class_dev_reg_err:
	device_unregister(dev);
dev_reg_err:
	down_write(&pci_bus_sem);
	list_del(&b->node);
	up_write(&pci_bus_sem);
err_out:
	kfree(dev);
	kfree(b);
	return NULL;
}

struct pci_bus * __devinit pci_scan_bus_parented(struct device *parent,
		int bus, struct pci_ops *ops, void *sysdata)
{
	struct pci_bus *b;

	b = pci_create_bus(parent, bus, ops, sysdata);
	if (b)
		b->subordinate = pci_scan_child_bus(b);
	return b;
}
EXPORT_SYMBOL(pci_scan_bus_parented);

#ifdef CONFIG_HOTPLUG
/**
 * pci_rescan_bus - scan a PCI bus for devices.
 * @bus: PCI bus to scan
 *
 * Scan a PCI bus and child buses for new devices, adds them,
 * and enables them.
 *
 * Returns the max number of subordinate bus discovered.
 */
unsigned int __ref pci_rescan_bus(struct pci_bus *bus)
{
	unsigned int max;
	struct pci_dev *dev;

	max = pci_scan_child_bus(bus);

	down_read(&pci_bus_sem);
	list_for_each_entry(dev, &bus->devices, bus_list)
		if (dev->hdr_type == PCI_HEADER_TYPE_BRIDGE ||
		    dev->hdr_type == PCI_HEADER_TYPE_CARDBUS)
			if (dev->subordinate)
				pci_bus_size_bridges(dev->subordinate);
	up_read(&pci_bus_sem);

	pci_bus_assign_resources(bus);
	pci_enable_bridges(bus);
	pci_bus_add_devices(bus);

	return max;
}
EXPORT_SYMBOL_GPL(pci_rescan_bus);

EXPORT_SYMBOL(pci_add_new_bus);
EXPORT_SYMBOL(pci_scan_slot);
EXPORT_SYMBOL(pci_scan_bridge);
EXPORT_SYMBOL_GPL(pci_scan_child_bus);
#endif

static int __init pci_sort_bf_cmp(const struct device *d_a, const struct device *d_b)
{
	const struct pci_dev *a = to_pci_dev(d_a);
	const struct pci_dev *b = to_pci_dev(d_b);

	if      (pci_domain_nr(a->bus) < pci_domain_nr(b->bus)) return -1;
	else if (pci_domain_nr(a->bus) > pci_domain_nr(b->bus)) return  1;

	if      (a->bus->number < b->bus->number) return -1;
	else if (a->bus->number > b->bus->number) return  1;

	if      (a->devfn < b->devfn) return -1;
	else if (a->devfn > b->devfn) return  1;

	return 0;
}

void __init pci_sort_breadthfirst(void)
{
	bus_sort_breadthfirst(&pci_bus_type, &pci_sort_bf_cmp);
}