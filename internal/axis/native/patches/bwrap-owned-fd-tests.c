/* Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0 */

/* Build-only inert tests. The included Bubblewrap main is never called. No
 * namespace, mount, process launch, provider data or caller command is used. */
#include <linux/memfd.h>
int dc_uninvoked_bwrap_main (int argc, char **argv);
#define main dc_uninvoked_bwrap_main
#include "bubblewrap.c"
#undef main

static bool
topology_refuses_nested_bind_mounts_and_malformed_inventory (void)
{
  const char *ordinary = "11 10 0:1 / / rw - ext4 /dev/fixed rw\n";
  const char *nested = "11 10 0:1 / / rw - ext4 /dev/fixed rw\n"
                       "12 11 0:1 /same-inode /grant/nested rw - ext4 /dev/fixed rw\n";
  const char *unrelated_roots = "11 10 0:1 / / rw - ext4 /dev/fixed rw\n"
                                "40 11 0:4 net:[4026532282] /run/netns/x rw - nsfs nsfs rw\n"
                                "41 11 0:1 /path//deleted /unrelated rw - ext4 /dev/fixed rw\n";
  const char *nested_nsfs = "11 10 0:1 / / rw - ext4 /dev/fixed rw\n"
                            "40 11 0:4 net:[4026532282] /grant/netns rw - nsfs nsfs rw\n";
  const char *malformed[] = {
    "11 10 0:1 / / rw - ext4 /dev/fixed rw",
    "11 10 invalid / / rw - ext4 /dev/fixed rw\n",
    "11 10 0:1 / / rw - ext4 /dev/fixed rw extra\n",
    "11 10 0:1 / / rw - ext4 /dev/fixed rw\n11 10 0:1 / /elsewhere rw - ext4 /dev/fixed rw\n",
    "11 10 0:1 / /bad\\999 rw - ext4 /dev/fixed rw\n",
    "11 10 0:1 /bad\\999 / rw - ext4 /dev/fixed rw\n",
    "11 10 0:4 net:[4026532282] relative rw - nsfs nsfs rw\n",
  };
  if (!owned_mountinfo_admits (ordinary, "/grant", 11) ||
      owned_mountinfo_admits (ordinary, "/grant", 99) ||
      owned_mountinfo_admits (nested, "/grant", 11) ||
      !owned_mountinfo_admits (unrelated_roots, "/grant", 11) ||
      owned_mountinfo_admits (nested_nsfs, "/grant", 11))
    return FALSE;
  for (size_t i = 0; i < sizeof (malformed) / sizeof (malformed[0]); i++)
    if (owned_mountinfo_admits (malformed[i], "/grant", 11))
      return FALSE;
  return TRUE;
}

static bool
locator_refuses_deleted_traversal_and_unrepresentable_names (void)
{
  const char *invalid[] = { "relative", "/a//b", "/a/./b", "/a/../b", "/a/",
                            "/a (deleted)", "/(unreachable)/a", "/a\nb" };
  if (!owned_path_valid ("/a/source with spaces", TRUE))
    return FALSE;
  if (owned_reopen_resolve () !=
      (RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_CACHED))
    return FALSE;
  for (size_t i = 0; i < sizeof (invalid) / sizeof (invalid[0]); i++)
    if (owned_path_valid (invalid[i], TRUE))
      return FALSE;
  return TRUE;
}

static bool
cloned_view_uses_reopened_mount_id_and_still_refuses_nested_aliases (void)
{
  /* Pure inventories, not mount/namespace operations. The imported FD may
   * retain old ID99 while its trusted namespace clone has current ID22.
   * Only the reopened current view can describe the tree open_tree will copy.
   * Object/flag identity and trusted clone-only/idmap provenance are separate
   * mandatory predicates; this parser test does not fabricate that proof. */
  const char *current = "11 10 0:1 / / rw - ext4 /dev/fixed rw\n"
                         "22 11 0:1 /same-object /grant rw - ext4 /dev/fixed rw\n";
  const char *nested = "11 10 0:1 / / rw - ext4 /dev/fixed rw\n"
                        "22 11 0:1 /same-object /grant rw - ext4 /dev/fixed rw\n"
                        "23 22 0:1 /same-object /grant/nested rw - ext4 /dev/fixed rw\n";
  return !owned_mountinfo_admits (current, "/grant", 99) &&
         owned_mountinfo_admits (current, "/grant", 22) &&
         !owned_mountinfo_admits (current, "/grant", 0) &&
         !owned_mountinfo_admits (nested, "/grant", 22) &&
         !owned_preserves_flags (ST_RDONLY | ST_NOEXEC, ST_RDONLY);
}

static bool
immutable_copy_preserves_seals_size_and_every_byte (void)
{
  cleanup_fd int source = -1;
  cleanup_fd int directory = -1;
  cleanup_fd int target = -1;
  unsigned char bytes[32771], copied[32771];
  struct stat expected;
  char path[] = "/tmp/dc-axis-inert-copy-XXXXXX";
  int seals = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE;
  for (size_t i = 0; i < sizeof (bytes); i++)
    bytes[i] = i % 251;
  source = syscall (SYS_memfd_create, "dc-axis-inert-not-an-executable", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (source < 0 || write (source, bytes, sizeof (bytes)) != (ssize_t) sizeof (bytes) ||
      fstat (source, &expected) != 0 || owned_image_sealed (source, &expected) ||
      fcntl (source, F_ADD_SEALS, seals) != 0 || !owned_image_sealed (source, &expected) ||
      mkdtemp (path) == NULL)
    return FALSE;
  directory = open (path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (directory < 0)
    return FALSE;
  target = openat (directory, "inert-bytes", O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (target < 0)
    return FALSE;
  owned_copy_image (source, target, &expected);
  if (pread (target, copied, sizeof (copied), 0) != (ssize_t) sizeof (copied) ||
      memcmp (bytes, copied, sizeof (bytes)) != 0 || !owned_image_sealed (source, &expected))
    return FALSE;
  expected.st_ino++;
  if (owned_image_sealed (source, &expected))
    return FALSE;
  /* Remove only this exact newly created inert fixture, without recursion. */
  if (unlinkat (directory, "inert-bytes", 0) != 0 || rmdir (path) != 0)
    return FALSE;
  return TRUE;
}

static bool
readonly_root_is_nonrecursive_and_source_noexec_is_preserved (void)
{
  return owned_root_attribute_flags () == AT_EMPTY_PATH &&
         (owned_root_attribute_flags () & AT_RECURSIVE) == 0 &&
         owned_root_attribute_set () == (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV) &&
         owned_source_attribute_set (FALSE, ST_RDONLY | ST_NOEXEC) ==
           (MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV) &&
         owned_source_attribute_set (FALSE, 0) == (MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV) &&
         !owned_preserves_flags (ST_RDONLY | ST_NOEXEC, ST_RDONLY) &&
         owned_preserves_flags (ST_RDONLY, ST_RDONLY | ST_NOEXEC);
}

int
main (int argc, char **argv)
{
  (void) argv;
  if (argc != 1)
    return 1;
#define RUN_TEST(name) do { if (!(name ())) return 1; puts (#name); } while (0)
  RUN_TEST (topology_refuses_nested_bind_mounts_and_malformed_inventory);
  RUN_TEST (locator_refuses_deleted_traversal_and_unrepresentable_names);
  RUN_TEST (cloned_view_uses_reopened_mount_id_and_still_refuses_nested_aliases);
  RUN_TEST (immutable_copy_preserves_seals_size_and_every_byte);
  RUN_TEST (readonly_root_is_nonrecursive_and_source_noexec_is_preserved);
#undef RUN_TEST
  puts ("PASS 5 inert owned-FD tests; no namespace, mount or workload execution");
  return 0;
}
