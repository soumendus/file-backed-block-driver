
// SPDX-License-Identifier: GPL-2.0
/*
 * slub_corrupt_inj.c.: SLUB corruption injector
 *
 * Written by Soumendu Sekhar Satapathy, 9th Feb 2020
 * satapathy.soumendu@gmail.com
 * This is a block device driver which is intentionally made buggy to
 * inject SLUB corruption.
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
#include <linux/smp.h>

#include <trace/events/kmem.h>

//#include "scsi.h"
#include <scsi/scsi_dbg.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_driver.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>

//#include "scsi_logging.h"
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>




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

static int slub_corrupt_inj_major_nr;
/*
 * The internal representation of our slub_corrupt_inj device.
 */
struct slub_corrupt_inj_dev {
        unsigned long size;             /* slub_corrupt_inj_device size in sectors */
	struct file *slub_corrupt_inj_backing_file;  /* Device backing storage which is a file */
        spinlock_t lock;                /* For mutual exclusion */
        struct request_queue *queue;    /* The device request queue */
        struct gendisk *gd;             /* The gendisk structure */
};

#define WSLLD_DEV(blk_dev) (blk_dev->bd_disk->private_data)


typedef struct sg_scatter_hold { /* holding area for scsi scatter gather info */
	unsigned short k_use_sg; /* Count of kernel scatter-gather pieces */
	unsigned sglist_len; /* size of malloc'd scatter-gather list ++ */
	unsigned bufflen;	/* Size of (aggregate) data buffer */
	struct page **pages;
	int page_order;
	char dio_in_use;	/* 0->indirect IO (or mmap), 1->dio */
	unsigned char cmd_opcode; /* first byte of command */
} Sg_scatter_hold;

struct sg_device;		/* forward declarations */
struct sg_fd;

typedef struct sg_request {	/* SG_MAX_QUEUE requests outstanding per file */
	struct list_head entry;	/* list entry */
	struct sg_fd *parentfp;	/* NULL -> not in use */
	Sg_scatter_hold data;	/* hold buffer, perhaps scatter list */
	sg_io_hdr_t header;	/* scsi command+info, see <scsi/sg.h> */
	unsigned char sense_b[SCSI_SENSE_BUFFERSIZE];
	char res_used;		/* 1 -> using reserve buffer, 0 -> not ... */
	char orphan;		/* 1 -> drop on sight, 0 -> normal */
	char sg_io_owned;	/* 1 -> packet belongs to SG_IO */
	/* done protected by rq_list_lock */
	char done;		/* 0->before bh, 1->before read, 2->read */
	struct request *rq;
	struct bio *bio;
	struct execute_work ew;
} Sg_request;

struct page *pg;

// This emulates the kernel control path either in process context or kernel thread
// which creates the panic because of the SLUB corruption.
static int panicking_thread(void *arg)
{
#if 0
	Sg_request *srq;
#endif
	struct scatterlist *srq;

#if 0
	srq = kmalloc(sizeof(Sg_request), GFP_KERNEL|GFP_DMA);
#endif
	srq = kmalloc(sizeof(struct scatterlist), GFP_KERNEL|GFP_DMA);
	if (!srq) {
		printk(KERN_WARNING, srq, "%s: kmalloc Sg_request "
			    "failure\n", __func__);
		return ERR_PTR(-ENOMEM);
	}
}

// This is analogous to a DMA operation, writing to the un-mapped sg buffers
static int fw_doing_dma(void *arg)
{
    int this_cpu;
    int err1 = 0;
    struct task_struct *t_dma;

    this_cpu = get_cpu();

    printk(KERN_INFO "fw_doing_dma cpu = %d\n",this_cpu);
    printk(KERN_INFO "I am thread: %s[PID = %d]\n", current->comm, current->pid);

    if(arg)
#if 0
    	memset((char*)arg, 'c', 100);
#endif
    	memset((char*)arg, 'c', sizeof(struct scatterlist));

    put_cpu();

    // This emulates the kernel control path either in process context or kernel thread
    // which creates the panic because of the SLUB corruption.
    t_dma = kthread_run(panicking_thread, NULL, "thread-2");
    if (IS_ERR(t_dma)) {
       	printk(KERN_INFO "ERROR: Cannot create thread t_dma\n");
       	err1 = PTR_ERR(t_dma);
       	t_dma = NULL;
       	return -1;
    }

    return 0;
}

static struct slub_corrupt_inj_dev* slub_corrupt_inj_device = NULL; 

static void slub_corrupt_inj_free(struct slub_corrupt_inj_dev *dev)
{
	if(dev) {

		if(dev->gd) {
			del_gendisk(dev->gd);
        		put_disk(dev->gd);
		}

		if(dev->queue) {
        		blk_cleanup_queue(dev->queue);
		}

		if (dev->slub_corrupt_inj_backing_file)
			filp_close(dev->slub_corrupt_inj_backing_file, NULL);

        	kfree(dev);
	}
}

/*
 * Handle an I/O request.
 */

static int slub_corrupt_inj_transfer(struct slub_corrupt_inj_dev *dev, unsigned
                        long sector, unsigned long nsect,
                        char *buffer, int write)
{
        unsigned long offset = sector * KERNEL_SECTOR_SIZE;
        unsigned long nbytes = nsect * KERNEL_SECTOR_SIZE;
	unsigned long len_r = 0;
	unsigned long len_w = 0;

	struct request *rq;
	struct scatterlist *sg_list;
	struct scsi_cmnd *scsi_cmd;

        if ((offset + nbytes) > dev->size * KERNEL_SECTOR_SIZE) {
                printk (KERN_NOTICE "Beyond-end write (%ld %ld)\n",
                         offset, nbytes);
                return 1;
        }

        dev->slub_corrupt_inj_backing_file->f_pos = offset;
        if(write) {
                len_w = kernel_write(dev->slub_corrupt_inj_backing_file, buffer, nbytes, &dev->slub_corrupt_inj_backing_file->f_pos);
                if (len_w >= 0) {
                }
                else {
                        printk("Unable to write to block device\n");
                        return 1;
                }
        }
        else {
                len_r = kernel_read(dev->slub_corrupt_inj_backing_file, buffer, nbytes, &dev->slub_corrupt_inj_backing_file->f_pos);
                if (len_r < 0) {
                        printk("Unable to read from block device\n");
                        return 1;
                }
        }

        return 0;
}

static blk_qc_t slub_corrupt_inj_make_request(struct request_queue *q, struct bio *bio)
{
        struct slub_corrupt_inj_dev *dev = bio->bi_disk->private_data;
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

		err = slub_corrupt_inj_transfer(dev, sector, len, buffer,
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
static int slub_corrupt_inj_open(struct block_device *blk_dev, fmode_t mod)
{
	struct slub_corrupt_inj_dev *dev = WSLLD_DEV(blk_dev);

	spin_lock(&dev->lock);
	// Open the backing file as block storage if not open
	dev->slub_corrupt_inj_backing_file = filp_open("/home/slub_corrupt_inj", O_RDWR|O_LARGEFILE|O_CREAT, 0);
	if (IS_ERR(dev->slub_corrupt_inj_backing_file)) {
        	printk(KERN_INFO "Unable to open file\n");
        	return PTR_ERR(dev->slub_corrupt_inj_backing_file);
    	}
	spin_unlock(&dev->lock);

	return 0;
}

/*
 * The device operations structure.
 */

static struct block_device_operations slub_corrupt_inj_ops = {
	.owner           = THIS_MODULE,
	.open 	         = slub_corrupt_inj_open,
};

/*
 * And now the modules code and kernel interface.
 */
static int max_part = 0;
static int slub_corrupt_inj_major = 0;
module_param(slub_corrupt_inj_major, int, 0);
static unsigned int hardsect_size = KERNEL_SECTOR_SIZE;
module_param(hardsect_size, int, 0);
static unsigned long nsectors;
module_param(nsectors, ulong, 0);
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Num Minors");
static unsigned long slub_corrupt_inj_size;
module_param(slub_corrupt_inj_size, ulong, 0444);
MODULE_PARM_DESC(slub_corrupt_inj_size, "Size of each slub_corrupt_inj disk in kbytes.");

#if 0
static struct slub_corrupt_inj_dev* slub_corrupt_inj_alloc(int i)
{
	return NULL;
}
#endif

static struct slub_corrupt_inj_dev* slub_corrupt_inj_alloc(int i)
{
	/*
	 * Get some memory.
	 */
	struct gendisk *disk;
	struct slub_corrupt_inj_dev *dev;
	int which = 0;
	unsigned long no_sectors = NO_SECTORS;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
        if (!dev)
                goto out;

	dev->size = no_sectors;
	slub_corrupt_inj_size = dev->size;
	dev->slub_corrupt_inj_backing_file = filp_open("/home/slub_corrupt_inj", O_RDWR|O_LARGEFILE|O_CREAT, 0);
	if(IS_ERR(dev->slub_corrupt_inj_backing_file)) {
		dev->slub_corrupt_inj_backing_file = NULL;
		printk(KERN_NOTICE "Unable to Open the file /root/slub_corrupt_inj.\n");
		goto out_file_open_err;
	}
	spin_lock_init(&dev->lock);
	
	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!dev->queue) {
		printk(KERN_NOTICE "Failed to allocate queue\n");
		goto out_free_dev;
	}
	blk_queue_make_request(dev->queue, slub_corrupt_inj_make_request);
	blk_queue_max_hw_sectors(dev->queue, NO_SECTORS);

	dev->queue->queuedata = dev;
	blk_queue_physical_block_size(dev->queue, 512);
        disk = dev->gd = alloc_disk(max_part);
        if (!disk)
                goto out_free_queue;
        disk->major             = 0;
        disk->first_minor       = max_part;
        disk->fops              = &slub_corrupt_inj_ops;
	disk->queue 	        = dev->queue;
        disk->private_data      = dev;
        disk->flags             = GENHD_FL_EXT_DEVT;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "slub_corrupt_inj%c", which + '0');
	set_capacity(disk, no_sectors);
        dev->queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

        /* Tell the block layer that this is not a rotational device */

	blk_queue_flag_set(QUEUE_FLAG_NONROT, dev->queue);
        blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, dev->queue);


	return dev;

out_free_queue:
        blk_cleanup_queue(dev->queue);
out_free_dev:
        slub_corrupt_inj_free(dev);
out_file_open_err:
	printk(KERN_NOTICE "Unable to Open the file /root/slub_corrupt_inj.\n");
out:
	return NULL;

}

static int __init slub_corrupt_inj_init(void)
{
        struct slub_corrupt_inj_dev *dev;
	int err = 0;

#if 0
	int err1 = 0;
	struct task_struct *t_dma;
	int this_cpu;
#endif
	struct scatterlist *sg_scmd;
	int err1 = 0;
	struct task_struct *t_dma;
	int this_cpu;
	struct scsi_cmnd *scmd;

        err = slub_corrupt_inj_major_nr = register_blkdev(slub_corrupt_inj_major, "slub_corrupt_inj");
        if (err <= 0) {
                printk(KERN_WARNING "slub_corrupt_inj: unable to get major number\n");
                return -EBUSY;
        }


	dev = slub_corrupt_inj_alloc(0);
        if (!dev)
         	goto out_free;

	slub_corrupt_inj_device = dev;

	dev->gd->queue = dev->queue;
        add_disk(dev->gd);


#if 0
	Sg_request *srq;
#endif

	struct scatterlist *srq;

#if 0
	srq = kmalloc(sizeof(Sg_request), GFP_KERNEL|GFP_DMA);
#endif
	srq = kmalloc(sizeof(struct scatterlist), GFP_KERNEL|GFP_DMA);
	if (!srq) {
		printk(KERN_WARNING, srq, "%s: kmalloc Sg list "
			    "failure\n", __func__);
		return ERR_PTR(-ENOMEM);
	}

        kfree(srq);

	// Asynchronous thread is being scheduled, analogous to a DMA operation code path thread
	t_dma = kthread_run(fw_doing_dma, (void*)srq, "thread-1");
        if (IS_ERR(t_dma)) {
        	printk(KERN_INFO "ERROR: Cannot create thread ts1\n");
        	err1 = PTR_ERR(t_dma);
        	t_dma = NULL;
        	goto out_free;
    	}

        printk("slub_corrupt_inj: module loaded\n");
        return 0;

out_free:
        slub_corrupt_inj_free(dev);
        unregister_blkdev(slub_corrupt_inj_major, "slub_corrupt_inj");

        printk("slub_corrupt_inj: module NOT loaded !!!\n");
        return -ENOMEM;
}

static void __exit slub_corrupt_inj_exit(void)
{
	slub_corrupt_inj_free(slub_corrupt_inj_device);
	unregister_blkdev(slub_corrupt_inj_major_nr, "slub_corrupt_inj");
        printk("slub_corrupt_inj: module unloaded !!!\n");
}
	
module_init(slub_corrupt_inj_init);
module_exit(slub_corrupt_inj_exit);

MODULE_ALIAS("slub_corrupt_inj");
MODULE_DESCRIPTION("Buggy Block device driver as a SLUB corruption injector");
MODULE_AUTHOR("Soumendu Sekhar Satapathy <satapathy.soumendu@gmail.com>");
MODULE_LICENSE("GPL");
