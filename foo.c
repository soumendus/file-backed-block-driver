
// SPDX-License-Identifier: GPL-2.0
/*
 * foo.c
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


/*
 * We can tweak our hardware sector size, but the kernel talks to us
 * in terms of small sectors, always.
 */
#define KERNEL_SECTOR_SIZE	512

#define WR true
#define RD false


#define __bio_kmap_atomic(bio, iter)				\
	(kmap_atomic(bio_iter_iovec((bio), (iter)).bv_page) +	\
		bio_iter_iovec((bio), (iter)).bv_offset)

#define __bio_kunmap_atomic(addr)	kunmap_atomic(addr)


/*
 * The internal representation of our foo device.
 */
struct foo_dev {
        unsigned long size;             /* foo_device size in sectors */
	struct file *foo_backing_file;
        spinlock_t lock;                /* For mutual exclusion */
        struct request_queue *queue;    /* The device request queue */
        struct gendisk *gd;             /* The gendisk structure */
};

#define FOO_DEV(blk_dev) (blk_dev->bd_disk->private_data)

static struct foo_dev* foo_device = NULL; 

static void foo_free(struct foo_dev *dev)
{
	if(dev) {

		if(dev->gd) {
			del_gendisk(dev->gd);
        		put_disk(dev->gd);
		}

		if(dev->queue) {
        		blk_cleanup_queue(dev->queue);
		}

		if (dev->foo_backing_file)
			filp_close(dev->foo_backing_file, NULL);

        	kfree(dev);
	}
}

/*
 * Handle an I/O request.
 */

static int foo_transfer(struct foo_dev *dev, unsigned
                        long sector, unsigned long nsect,
                        char *buffer, int write)
{
        unsigned long offset = sector * KERNEL_SECTOR_SIZE;
        unsigned long nbytes = nsect * KERNEL_SECTOR_SIZE;
	unsigned long len_r = 0;
	unsigned long len_w = 0;

        if ((offset + nbytes) > dev->size) {
                printk (KERN_NOTICE "Beyond-end write (%ld %ld)\n",
                         offset, nbytes);
                return 1;
        }
        dev->foo_backing_file->f_pos = offset;
        if(write) {
                len_w = kernel_write(dev->foo_backing_file, buffer, nbytes, &dev->foo_backing_file->f_pos);
                if (len_w >= 0) {
                }
                else {
                        printk("Unable to write to block device\n");
                        return 1;
                }
        }
        else {
                len_r = kernel_read(dev->foo_backing_file, buffer, nbytes, &dev->foo_backing_file->f_pos);
                if (len_r < 0) {
                        printk("Unable to read from block device\n");
                        return 1;
                }
        }

        return 0;
}

static blk_qc_t foo_make_request(struct request_queue *q, struct bio *bio)
{
        struct foo_dev *dev = bio->bi_disk->private_data;
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

		err = foo_transfer(dev, sector, len, buffer,
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
static int foo_open(struct block_device *blk_dev, fmode_t mod)
{
	struct foo_dev *dev = FOO_DEV(blk_dev);

	spin_lock(&dev->lock);
	// Open the backing file as block storage if not open
	dev->foo_backing_file = filp_open("/root/foo", O_RDWR|O_LARGEFILE|O_CREAT, 0);
	if (IS_ERR(dev->foo_backing_file)) {
        	printk(KERN_INFO "Unable to open file\n");
        	return PTR_ERR(dev->foo_backing_file);
    	}
	spin_unlock(&dev->lock);

	return 0;
}

/*
 * The device operations structure.
 */

static struct block_device_operations foo_ops = {
	.owner           = THIS_MODULE,
	.open 	         = foo_open,
};

/*
 * And now the modules code and kernel interface.
 */
#define NO_SECTORS 171798464
#define KERNEL_SECTOR_SIZE 512
static int max_part = 0;
static int foo_major = 0;
module_param(foo_major, int, 0);
static unsigned int hardsect_size = KERNEL_SECTOR_SIZE;
module_param(hardsect_size, int, 0);
static unsigned long nsectors;
module_param(nsectors, ulong, 0);
module_param(max_part, int, 0444);
MODULE_PARM_DESC(max_part, "Num Minors");
static unsigned long foo_size;
module_param(foo_size, ulong, 0444);
MODULE_PARM_DESC(foo_size, "Size of each foo disk in kbytes.");


static struct foo_dev* foo_alloc(int i)
{
	/*
	 * Get some memory.
	 */
	struct gendisk *disk;
	struct foo_dev *dev;
	int which = 0;
	unsigned long no_sectors = NO_SECTORS;
	unsigned int sector_size = KERNEL_SECTOR_SIZE;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
        if (!dev)
                goto out;

	dev->size = no_sectors * sector_size;
	foo_size = dev->size;
	dev->foo_backing_file = filp_open("/root/foo", O_RDWR|O_LARGEFILE|O_CREAT, 0);
	if(IS_ERR(dev->foo_backing_file)) {
		dev->foo_backing_file = NULL;
		printk(KERN_NOTICE "Unable to Open the file /root/foo.\n");
		goto out_file_open_err;
	}
	spin_lock_init(&dev->lock);
	
	dev->queue = blk_alloc_queue(GFP_KERNEL);
	if (!dev->queue) {
		printk(KERN_NOTICE "Failed to allocate queue\n");
		goto out_free_dev;
	}
	blk_queue_make_request(dev->queue, foo_make_request);
	blk_queue_max_hw_sectors(dev->queue, NO_SECTORS);

	/* 
	 * This function is no longer available in Linux 2.6.32.
  	 * A possible replacement is blk_queue_physical_block_size()
	 * blk_queue_hardsect_size(dev->queue, hardsect_size); 
	 */ 

	dev->queue->queuedata = dev;
	blk_queue_physical_block_size(dev->queue, 512);
        disk = dev->gd = alloc_disk(max_part);
        if (!disk)
                goto out_free_queue;
        disk->major             = 0;
        disk->first_minor       = max_part;
        disk->fops              = &foo_ops;
	disk->queue 	        = dev->queue;
        disk->private_data      = dev;
        disk->flags             = GENHD_FL_EXT_DEVT;
	snprintf(dev->gd->disk_name, DISK_NAME_LEN, "foo%c", which + '0');
	set_capacity(disk, no_sectors * sector_size);
        dev->queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

        /* Tell the block layer that this is not a rotational device */

	blk_queue_flag_set(QUEUE_FLAG_NONROT, dev->queue);
        blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, dev->queue);

	return dev;

out_free_queue:
        blk_cleanup_queue(dev->queue);
out_free_dev:
        foo_free(dev);
out_file_open_err:
	printk(KERN_NOTICE "Unable to Open the file /root/foo.\n");
out:
	return NULL;

}

static int __init foo_init(void)
{
        struct foo_dev *dev;
	int f_major = 0;

        f_major = register_blkdev(foo_major, "foo");
        if (f_major <= 0) {
                printk(KERN_WARNING "foo: unable to get major number\n");
                return -EBUSY;
        }


	dev = foo_alloc(0);
        if (!dev)
         	goto out_free;

	foo_device = dev;

	dev->gd->queue = dev->queue;
        add_disk(dev->gd);

        printk("foo: module loaded\n");
        return 0;

out_free:
        foo_free(dev);
        unregister_blkdev(foo_major, "foo");

        printk("foo: module NOT loaded !!!\n");
        return -ENOMEM;
}

static void __exit foo_exit(void)
{
	foo_free(foo_device);
	unregister_blkdev(foo_major, "foo");
}
	
module_init(foo_init);
module_exit(foo_exit);

MODULE_ALIAS("foo");
MODULE_DESCRIPTION("Block device driver with file as its backing storage");
MODULE_AUTHOR("Soumendu Sekhar Satapathy <satapathy.soumendu@gmail.com>");
MODULE_LICENSE("GPL");