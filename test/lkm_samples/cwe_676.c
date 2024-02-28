// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

static char *simple_strlen_strcpy(const char *msg)
{
  char *ptr = kmalloc(strlen(msg), __GFP_ZERO);

  if (!ptr)
    return NULL;

  strcpy(ptr, msg);

  return ptr;
}

static int __init test_init(void)
{
    pr_info("Hello, World\n");

    char *msg = (char *)((unsigned long)THIS_MODULE + 0x1337);

    pr_info("%s\n", simple_strlen_strcpy(msg));

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
