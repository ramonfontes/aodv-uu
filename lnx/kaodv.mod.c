#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x17300f3a, "module_layout" },
	{ 0x609f1c7e, "synchronize_net" },
	{ 0xe04a6c96, "kmalloc_caches" },
	{ 0xb7700415, "param_ops_int" },
	{ 0x2e5810c6, "__aeabi_unwind_cpp_pr1" },
	{ 0xfa599bb2, "netlink_register_notifier" },
	{ 0xc7a4fbed, "rtnl_lock" },
	{ 0x3b697738, "_raw_read_lock" },
	{ 0x50a95ed9, "dev_get_by_name" },
	{ 0x2124474, "ip_send_check" },
	{ 0xb1ad28e0, "__gnu_mcount_nc" },
	{ 0xdf54a8f7, "netlink_unregister_notifier" },
	{ 0x1be301e0, "skb_set_owner_w" },
	{ 0xe4aabd80, "__icmp_send" },
	{ 0x91715312, "sprintf" },
	{ 0xbc50ca70, "in_dev_finish_destroy" },
	{ 0x526c3a6c, "jiffies" },
	{ 0xe7b238a4, "skb_trim" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x43745509, "param_ops_charp" },
	{ 0x98824feb, "unregister_pernet_subsys" },
	{ 0x7c32d0f0, "printk" },
	{ 0x7d16fb98, "netlink_kernel_release" },
	{ 0x9425caca, "_raw_write_lock" },
	{ 0x707f24a0, "ip_route_me_harder" },
	{ 0xedc06d37, "refcount_dec_and_test_checked" },
	{ 0x5104020c, "nf_register_net_hook" },
	{ 0x392f68e, "nf_unregister_net_hook" },
	{ 0xf0cca357, "skb_copy_expand" },
	{ 0x979005d0, "__alloc_skb" },
	{ 0xd982d50e, "netlink_broadcast" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0xaf6849c5, "kfree_skb" },
	{ 0xb39697ad, "register_pernet_subsys" },
	{ 0x1653b7bf, "netlink_ack" },
	{ 0x96de1846, "kmem_cache_alloc_trace" },
	{ 0xc2c5b2b6, "vsnprintf" },
	{ 0xf6ebc03b, "net_ratelimit" },
	{ 0x1738c19e, "_raw_write_unlock_bh" },
	{ 0x458b382e, "__netlink_kernel_create" },
	{ 0x77f6c690, "_raw_read_lock_bh" },
	{ 0x9acb8066, "_raw_read_unlock_bh" },
	{ 0x37a0cba, "kfree" },
	{ 0x9d669763, "memcpy" },
	{ 0x3e872658, "param_array_ops" },
	{ 0xefb7bccf, "_raw_write_lock_bh" },
	{ 0x8f678b07, "__stack_chk_guard" },
	{ 0x99bb8806, "memmove" },
	{ 0x1ee8d6d4, "refcount_inc_checked" },
	{ 0xcaf077c6, "skb_put" },
	{ 0x9abc3c11, "__nlmsg_put" },
	{ 0x6e720ff2, "rtnl_unlock" },
	{ 0x922245c, "__ip_select_ident" },
	{ 0xf30e7315, "dev_set_mtu" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "AF3BB9514756CA31F355C2D");
