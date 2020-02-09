
// SPDX-License-Identifier: GPL-2.0
/*
 * wslld.c: Works Somewhat Like Loop Device of Linux Kernel
 *
 * Written by Soumendu Sekhar Satapathy, 6th Dec 2019
 * satapathy.soumendu@gmail.com
 * This is a block device driver which has a file as a backing storage.
 * READ/WRITE to this block interface translates into READ/WRITE to the
 * file which is its backing storage.
 *
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* related to file operations  */
#include <linux/errno.h>	/* error codes */
#include <linux/timer.h>
#include <linux/types.h>	/* size_t */
#include <linux/fcntl.h>	
#include <linux/hdreg.h>	
#include <linux/kdev_t.h>
#include <linux/vmalloc.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>	
#include <linux/bio.h>
#include <linux/blk_types.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/backing-dev.h>

#include <linux/mm.h>
#include <linux/swap.h> /* struct reclaim_state */
#include <linux/module.h>
#include <linux/bit_spinlock.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/notifier.h>
#include <linux/seq_file.h>
#include <linux/kasan.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/mempolicy.h>
#include <linux/ctype.h>
#include <linux/debugobjects.h>
#include <linux/kallsyms.h>
#include <linux/memory.h>
#include <linux/math64.h>
#include <linux/fault-inject.h>
#include <linux/stacktrace.h>
#include <linux/prefetch.h>
#include <linux/memcontrol.h>
#include <linux/random.h>

#include <trace/events/kmem.h>


/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */

#define __bio_kmap_atomic(bio, iter)				\
	(kmap_atomic(bio_iter_iovec((bio), (iter)).bv_page) +	\
		bio_iter_iovec((bio), (iter)).bv_offset)

#define __bio_kunmap_atomic(addr)	kunmap_atomic(addr)

#define NO_SECTORS 536870912
#define KERNEL_SECTOR_SIZE 512

static int wslld_major_nr;
/*
 * The internal representation of our wslld device.
 */
struct wslld_dev {
        unsigned long size;             /* wslld_device size in sectors */
	struct file *wslld_backing_file;  /* Device backing storage which is a file */
        spinlock_t lock;                /* For mutual exclusion */
        struct request_queue *queue;    /* The device request queue */
        struct gendisk *gd;             /* The gendisk structure */
};

#define WSLLD_DEV(blk_dev) (blk_dev->bd_disk->private_data)

#if 0
// This is analogous to a DMA operation
static int fw_doing_dma(void *arg)
{
    if(arg)
    	memset((char*)arg, 'c', 100);

    return 0;
}
#endif

static struct wslld_dev* wslld_device = NULL; 

static void wslld_free(struct wslld_dev *dev)
{
	if(dev) {

		if(dev->gd) {
			del_gendisk(dev->gd);
        		put_disk(dev->gd);
		}

		if(dev->queue) {
        		blk_cleanup_queue(dev->queue);
		}

		if (dev->wslld_backing_file)
			filp_close(dev->wslld_backing_file, NULL);

        	kfree(dev);
	}
}

/*
 * Handle an I/O request.
 */

static int wslld_transfer(struct wslld_dev *dev, unsigned
                        long sector, unsigned long nsect,
                        char *buffer, int write)
{
        unsigned long offset = sector * KERNEL_SECTOR_SIZE;
        unsigned long nbytes = nsect * KERNEL_SECTOR_SIZE;
	unsigned long len_r = 0;
	unsigned long len_w = 0;

        if ((offset + nbytes) > dev->size * KERNEL_SECTOR_SIZE) {
                printk (KERN_NOTICE "Beyond-end write (%ld %ld)\n",
                         offset, nbytes);
                return 1;
        }
        dev->wslld_backing_file->f_pos = offset;
        if(write) {
                len_w = kernel_write(dev->wslld_backing_file, buffer, nbytes, &dev->wslld_backing_file->f_pos);
                if (len_w >= 0) {
                }
                else {
                        printk("Unable to write to block device\n");
                        return 1;
                }
        }
        else {
                len_r = kernel_read(dev->wslld_backing_file, buffer, nbytes, &dev->wslld_backing_file->f_pos);
                if (len_r < 0) {
                        printk("Unable to read from block device\n");
                        return 1;
                }
        }

        return 0;
}

static blk_qc_t wslld_make_request(struct request_queue *q, struct bio *bio)
{
        struct wslld_dev *dev = bio->bi_disk->private_data;
        struct bio_vec bvec;
        sector_t sector;
        struct bvec_iter iter;
	int err = 0;

        sector = bio->bi_iter.bi_sector;
        if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
                goto io_error;
	bio_for_each_segment(bvec, bio, iter) {
		char *buffer = __bio_kmap_atomic(bio, iter);
		unsigned len = bvec.bv_len >> SECTOR_SHIFT;

		err = wslld_transfer(dev, sector, len, buffer,
				bio_data_dir(bio) == WRITE);
		sector += len;
		__bio_kunmap_atomic(buffer);
                if (err)
                        goto io_error;
	}

        bio_endio(bio);
        return BLK_QC_T_NONE;

io_error:
        bio_io_error(bio);
        return BLK_QC_T_NONE;
}

/*
 * Open and close.
 */
static int wslld_open(struct block_device *blk_dev, fmode_t mod)
{
	struct wslld_dev *dev = WSLLD_DEV(blk_dev);

	spin_lock(&dev->lock);
	// Open the backing file as block storage if not open
	dev->wslld_backing_file = filp_open("/home/wslld", O_RDWR|O_LARGEFILE|O_CREAT, 0);
	if (IS_ERR(dev->wslld_backing_file)) {
        	printk(KERN_INFO "Unable to open file\n");
        	return PTR_ERR(dev->wslld_backing_file);
    	}
	spin_unlock(&dev->lock);

	return 0;
}

/*
 * The device operations structure.
 */

static struct block_device_operations wslld_ops = {
	.owner           = THIS_MODULE,
	.open 	         = wslld_open,
};

/*
 * And now the modules code and kernel interface.
 */
static int max_part = 0;
static int wslld_major = 0;
module_param(wslld_major, int, 0);
static unsigned int hardsect_size = KERNEL_SECTOR_SIZE;
module_param(hardsect_size, int, 0);
static unsigned long nsectors;
module_param(nsectors, ulong, 0);
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Num Minors");
static unsigned long wslld_size;
module_param(wslld_size, ulong, 0444);
MODULE_PARM_DESC(wslld_size, "Size of each wslld disk in kbytes.");


static struct wslld_dev* wslld_alloc(int i)
{
	/*
	 * Get some memory.
	 */
	struct gendisk *disk;
	struct wslld_dev *dev;
	int which = 0;
	unsigned long no_sectors = NO_SECTORS;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
        if (!dev)
                goto out;

	dev->size = no_sectors;
	wslld_size = dev->size;
	dev->wslld_backing_file = filp_open("/home/wslld", O_RDWR|O_LARGEFILE|O_CREAT, 0);
	if(IS_ERR(dev->wslld_backing_file)) {
		dev->wslld_backing_file = NULL;
		printk(KERN_NOTICE "Unable to Open the file /root/wslld.\n");
		goto out_file_open_err;
	}
	spin_lock_init(&dev->lock);
	
	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!dev->queue) {
		printk(KERN_NOTICE "Failed to allocate queue\n");
		goto out_free_dev;
	}
	blk_queue_make_request(dev->queue, wslld_make_request);
	blk_queue_max_hw_sectors(dev->queue, NO_SECTORS);

	dev->queue->queuedata = dev;
	blk_queue_physical_block_size(dev->queue, 512);
        disk = dev->gd = alloc_disk(max_part);
        if (!disk)
                goto out_free_queue;
        disk->major             = 0;
        disk->first_minor       = max_part;
        disk->fops              = &wslld_ops;
	disk->queue 	        = dev->queue;
        disk->private_data      = dev;
        disk->flags             = GENHD_FL_EXT_DEVT;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "wslld%c", which + '0');
	set_capacity(disk, no_sectors);
        dev->queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

        /* Tell the block layer that this is not a rotational device */

	blk_queue_flag_set(QUEUE_FLAG_NONROT, dev->queue);
        blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, dev->queue);

	return dev;

out_free_queue:
        blk_cleanup_queue(dev->queue);
out_free_dev:
        wslld_free(dev);
out_file_open_err:
	printk(KERN_NOTICE "Unable to Open the file /root/wslld.\n");
out:
	return NULL;

}

static int __init wslld_init(void)
{
        struct wslld_dev *dev;
	int err = 0;
#if 0
	int err1 = 0;
	struct task_struct *t_dma;
#endif

        err = wslld_major_nr = register_blkdev(wslld_major, "wslld");
        if (err <= 0) {
                printk(KERN_WARNING "wslld: unable to get major number\n");
                return -EBUSY;
        }


	dev = wslld_alloc(0);
        if (!dev)
         	goto out_free;

	wslld_device = dev;

	dev->gd->queue = dev->queue;
        add_disk(dev->gd);

#if 0
	// similar to sg buffers getting allocated
        char *ptr = kmalloc(100, GFP_KERNEL);

	// This is where the sg buffers are getting un-mapped
        kfree(ptr);

	// Asynchronous thread is being scheduled, analogous to a DMA operation
	t_dma = kthread_run(fw_doing_dma, (void*)ptr, "thread-1");
        if (IS_ERR(t_dma)) {
        	printk(KERN_INFO "ERROR: Cannot create thread ts1\n");
        	err1 = PTR_ERR(t_dma);
        	t_dma = NULL;
        	goto out_free;
    	}
#endif

        printk("wslld: module loaded\n");
        return 0;

out_free:
        wslld_free(dev);
        unregister_blkdev(wslld_major, "wslld");

        printk("wslld: module NOT loaded !!!\n");
        return -ENOMEM;
}

static void __exit wslld_exit(void)
{
	wslld_free(wslld_device);
	unregister_blkdev(wslld_major_nr, "wslld");
        printk("wslld: module unloaded !!!\n");
}
	
module_init(wslld_init);
module_exit(wslld_exit);

MODULE_ALIAS("wslld");
MODULE_DESCRIPTION("Block device driver with file as its backing storage");
MODULE_AUTHOR("Soumendu Sekhar Satapathy <satapathy.soumendu@gmail.com>");
MODULE_LICENSE("GPL");
