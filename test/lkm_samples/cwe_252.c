// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/rwonce.h>

void cwe252_intra_h_lost(void* uptr)
{
  char buf[10];
  long *ret_store = kmalloc(8, GFP_KERNEL);

  WRITE_ONCE(*ret_store, strncpy_from_user(buf, uptr, sizeof(buf))); // CWE_WARNING, 1

  pr_info("Call some func\n");

  WRITE_ONCE(*ret_store, 0); // CWE_WARNING, 2, reason=empty_state

  pr_info("buf: %s\n", buf);
}

static int __init test_init(void)
{
    pr_info("Hello, World\n");

    return 0;
}

static void __exit test_exit(void)
{
    pr_info("Goodbye, World\n");
}

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Valentin Obst");

module_init(test_init);
module_exit(test_exit);
