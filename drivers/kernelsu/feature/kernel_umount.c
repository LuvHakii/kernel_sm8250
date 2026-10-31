static bool ksu_kernel_umount_enabled __read_mostly = true;

static int kernel_umount_feature_get(u64 *value)
{
	*value = ksu_kernel_umount_enabled ? 1 : 0;
	return 0;
}

static int kernel_umount_feature_set(u64 value)
{
	bool enable = value != 0;
	ksu_kernel_umount_enabled = enable;
	pr_info("kernel_umount: set to %d\n", enable);
	return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
	.feature_id = KSU_FEATURE_KERNEL_UMOUNT,
	.name = "kernel_umount",
	.get_handler = kernel_umount_feature_get,
	.set_handler = kernel_umount_feature_set,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
extern int path_umount(struct path *path, int flags);

static inline void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
	int err = path_umount(path, flags);
	if (err)
		pr_info("umount %s failed: %d\n", mnt, err);
}
#else /* we play 'guess if backported' */
static __nocfi inline void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
	extern int path_umount(struct path *path, int flags) __weak;
	int err;
#ifdef MODULE
	assume(!path_umount);
#endif
	if (!path_umount)
		goto syscall;

	err = path_umount(path, flags);
	goto out;

syscall:;
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = (int)ksyscall(umount, (char __user *)mnt, flags);
	set_fs(old_fs);
	path_put(path);  // release caller's ref
out:
	if (err)
		pr_info("umount %s failed: %d\n", mnt, err);
}
#endif

static inline void try_umount(const char *mnt, int flags)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (path.dentry != path.mnt->mnt_root) {
		// it is not root mountpoint, maybe umounted by others already.
		path_put(&path);
		return;
	}

	ksu_umount_mnt(mnt, &path, flags);
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
// fs/susfs.c's provider for its own try_umount list. Called from the same
// setuid-transition context as ksu_handle_umount() below, i.e. already
// running inside the target uid's own mount namespace -- no namespace
// switch needed. `uid` is for logging only, matching susfs's own callers.
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err)
		return;

	if (check_mnt && path.dentry != path.mnt->mnt_root) {
		path_put(&path);
		return;
	}

	pr_info("susfs try_umount: %s for uid: %d\n", mnt, uid);
	ksu_umount_mnt(mnt, &path, flags);
}

// Matches the real susfs4ksu KernelSU patch's susfs_try_umount_all(): the
// user-added LH_TRY_UMOUNT_PATH list (susfs_try_umount) plus the standard
// systemless-mount paths it always sweeps, for both legacy and magic-mount
// KSU layouts. CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS calls this, not bare
// susfs_try_umount(), to match upstream behavior.
extern void susfs_try_umount(uid_t target_uid);
void susfs_try_umount_all(uid_t uid)
{
	susfs_try_umount(uid);
	ksu_try_umount("/system", true, 0, uid);
	ksu_try_umount("/system_ext", true, 0, uid);
	ksu_try_umount("/vendor", true, 0, uid);
	ksu_try_umount("/product", true, 0, uid);
	ksu_try_umount("/odm", true, 0, uid);
	// '/data/adb/modules' is a loop device; we can't tell whether its
	// dev_name is KSU, and it's safe to umount regardless.
	ksu_try_umount("/data/adb/modules", false, MNT_DETACH, uid);
	// For both Legacy KSU and Magic Mount KSU.
	ksu_try_umount("/debug_ramdisk", true, MNT_DETACH, uid);
}
#endif

static inline int ksu_handle_umount(struct cred *new, const struct cred *old)
{
	uid_t new_uid = ksu_get_uid_t(new->uid);
	uid_t old_uid = ksu_get_uid_t(old->uid);

	if (!ksu_kernel_umount_enabled)
		return 0;

	// if there isn't any module mounted, just ignore it!
	if (!ksu_module_mounted)
		return 0;

	// There are 6 scenarios:
	// 1. Normal app: zygote -> appuid
	// 2. Isolated process forked from zygote: zygote -> isolated_process
	// 3. App zygote forked from zygote: zygote -> appuid
	// 4. Webview zygote forked from zygote: zygote -> webview_zygote
	// 5. Isolated process forked from app zygote: appuid -> isolated_process (already handled by 3)
	// 6. Isolated process forked from webview zygote (already handled by 4)
	if (!is_appuid(new_uid) && new_uid != WEBVIEW_ZYGOTE_UID && !is_isolated_process(new_uid))
		return 0;

	if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid))
		return 0;

	// check old process's selinux context, if it is not zygote, ignore it!
	// because some su apps may setuid to untrusted_app but they are in global mount namespace
	// when we umount for such process, that is a disaster!
	// also handle case 4 and 5
	bool is_zygote_child = is_zygote(old);
	if (!is_zygote_child) {
		pr_info("handle umount ignore non zygote child: %d\n", current->pid);
		return 0;
	}
	// umount the target mnt
	pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

	// hostsredirect and getpriority filter tracks this flag
	set_thread_flag(TIF_KSU_UNMOUNTABLE);

	const struct cred *saved = override_creds(ksu_cred);

	struct mount_entry *entry;
	down_read(&mount_list_lock);
	list_for_each_entry (entry, &mount_list, list) {
		pr_info("%s: unmounting: %s flags: 0x%x\n", __func__, entry->umountable, entry->flags);
		try_umount(entry->umountable, entry->flags);
	}
	up_read(&mount_list_lock);

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	susfs_try_umount_all(new_uid);
#endif

	revert_creds(saved);

	return 0;
}

void __init ksu_kernel_umount_init(void)
{
	if (ksu_register_feature_handler(&kernel_umount_handler)) {
		pr_err("Failed to register kernel_umount feature handler\n");
	}
}

void __exit ksu_kernel_umount_exit(void)
{
	ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}
