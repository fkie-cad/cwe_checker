// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>

static int simple_null_deref(void)
{
    char *ptr = kmalloc(0x42, __GFP_ZERO);

    pr_info("%c\n", *ptr);

    return 42;
}

static int simple_not_null_deref(void)
{
    char *ptr = kmalloc(0x42, __GFP_ZERO);

    if (!ptr)
        return 1337;

    pr_info("%c\n", *ptr);

    return 42;
}

static int __init test_init(void)
{
    pr_info("Hello, World\n");

    simple_not_null_deref();
    simple_null_deref();

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
