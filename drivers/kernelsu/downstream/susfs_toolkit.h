// SPDX-License-Identifier: GPL-2.0-only
/*
 * SUSFS downstream extension.
 *
 * susfs_handle_sys_prctl() is the real susfs4ksu wire protocol --
 * prctl(KERNEL_SU_OPTION, cmd, arg3, arg4, arg5), arg3 the payload
 * pointer, arg5 a user int* the kernel writes its error/status into.
 * This is what the official ksu_susfs CLI (susfs4ksu's
 * ksu_susfs/jni/main.c, kernel-4.19 branch) actually calls -- matching
 * it means that binary works unmodified against this kernel.
 * KERNEL_SU_OPTION is the same value as KSU_INSTALL_MAGIC1 (0xDEADBEEF);
 * upstream KernelSU and susfs4ksu have always shared that constant.
 */
#pragma once
#ifndef __KSU_H_SUSFS_TOOLKIT
#define __KSU_H_SUSFS_TOOLKIT

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs.h>
#include <linux/susfs_def.h>

#define KERNEL_SU_OPTION KSU_INSTALL_MAGIC1

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
// defined in feature/kernel_umount.c, included later in the unity build.
extern void susfs_try_umount_all(uid_t uid);
#endif

static inline int susfs_handle_sys_prctl(unsigned long option, unsigned long cmd,
					  unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	void __user *payload;
	int error = 0;

	if (option != KERNEL_SU_OPTION)
		return 0;

	// susfs commands are root-only, same gate as toolkit.h's extensions.
	if (!!current_uid().val)
		return 0;

	payload = (void __user *)arg3;

	switch (cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH:
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)payload);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_ADD_SUS_MOUNT:
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)payload);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)payload);
		break;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)payload);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	case CMD_SUSFS_ADD_TRY_UMOUNT:
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)payload);
		break;
	case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS:
		susfs_try_umount_all(current_uid().val);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME:
		error = susfs_set_uname((struct st_susfs_uname __user *)payload);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG:
		// arg3 is the scalar enable value itself here, not a pointer.
		susfs_set_log(!!arg3);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		error = susfs_set_cmdline_or_bootconfig((char __user *)payload);
		break;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)payload);
		break;
#endif
	case CMD_SUSFS_SHOW_VERSION:
		error = copy_to_user(payload, SUSFS_VERSION, strlen(SUSFS_VERSION) + 1);
		break;
	case CMD_SUSFS_SHOW_VARIANT:
		error = copy_to_user(payload, SUSFS_VARIANT, strlen(SUSFS_VARIANT) + 1);
		break;
	case CMD_SUSFS_SHOW_ENABLED_FEATURES: {
		u64 enabled_features = 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
		enabled_features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
		enabled_features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
		enabled_features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
		enabled_features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
		enabled_features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
		enabled_features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
		enabled_features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
		enabled_features |= (1 << 7);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
		enabled_features |= (1 << 8);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
		enabled_features |= (1 << 9);
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
		enabled_features |= (1 << 10);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
		enabled_features |= (1 << 11);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
		enabled_features |= (1 << 12);
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
		enabled_features |= (1 << 14);
#endif
		error = copy_to_user(payload, &enabled_features, sizeof(enabled_features));
		break;
	}
	default:
		// Matches the real v1.5.5 patch: an unmatched cmd leaves arg5
		// untouched (whatever sentinel the caller pre-initialized it
		// to), it does not write a "not supported" code here.
		return 0;
	}

	if (arg5 && copy_to_user((void __user *)arg5, &error, sizeof(error)))
		pr_info("susfs: copy_to_user() of error status failed\n");

	return 0;
}
#else
static inline int susfs_handle_sys_prctl(unsigned long option, unsigned long cmd,
					  unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	return 0;
}
#endif // CONFIG_KSU_SUSFS

#endif // __KSU_H_SUSFS_TOOLKIT
