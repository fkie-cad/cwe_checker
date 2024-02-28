// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>

const char *long_string = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
char buf[10];

static int simple_sizeof_ptr_02(void)
{
    char *ptr = kmalloc(0x10, __GFP_ZERO);

    strncpy(ptr, long_string, sizeof(ptr));

    return 42;
}

static int simple_sizeof_ptr_01(void)
{
    strncpy(buf, long_string, sizeof(&buf));

    return 42;
}

static int __init test_init(void)
{
    pr_info("Hello, World\n");

    simple_sizeof_ptr_01();
    simple_sizeof_ptr_02();

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
