//! Whether a filesystem entry can be walked out of, and the one platform
//! difference that decides it.
//!
//! Every "this path must stay inside this directory" check in this workspace
//! asks the same question — is this entry a link? — and on Windows there are two
//! answers, not one.
//!
//! `std::fs::FileType::is_symlink()` is true only for
//! `IO_REPARSE_TAG_SYMLINK`. A **directory junction**
//! (`IO_REPARSE_TAG_MOUNT_POINT`, what `mklink /J`, `git`, `npm`, and `cargo`
//! create) reports `is_symlink() == false` and `is_dir() == true`. So a check
//! written on Linux against `is_symlink()` is a *no-op* on Windows for the link
//! type Windows users and tooling actually create, and it fails open: the walk
//! continues straight out of the directory it was told to stay inside.
//!
//! The difference is not academic. A junction needs no privilege, so the
//! "requires Developer Mode or `SeCreateSymbolicLinkPrivilege`" argument that
//! makes a symlink rare does not apply, and a build context or a `cp`
//! destination reached through one is exactly the escape those checks exist to
//! prevent.
//!
//! So the single test is [`FILE_ATTRIBUTE_REPARSE_POINT`], which covers a
//! symlink, a junction, and a mount point alike.

use std::fs::Metadata;

/// Whether the entry is a link of any kind, and so must not be walked through.
///
/// This is the containment question. `false` means the entry is an ordinary
/// file or directory on this filesystem.
#[must_use]
pub fn is_link_or_reparse_point(metadata: &Metadata) -> bool {
    #[cfg(unix)]
    {
        metadata.file_type().is_symlink()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        // `FILE_ATTRIBUTE_REPARSE_POINT`. `MetadataExt::file_attributes` is the
        // `dwFileAttributes` field of the same `FILE_BASIC_INFORMATION`/`BY_HANDLE_FILE_INFORMATION`
        // the rest of the link check reads, so this is not a second source of
        // truth about the entry.
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(any(unix, windows)))]
    {
        metadata.file_type().is_symlink()
    }
}

/// Convenience form of [`is_link_or_reparse_point`] for a path that may not
/// exist. A path that cannot be stat'd is not a link.
///
/// Use `symlink_metadata`, so the question is asked about the entry itself and
/// not about whatever it points at. Asking about the target is the mistake that
/// makes a link invisible.
#[must_use]
pub fn path_is_link_or_reparse_point(path: &std::path::Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| is_link_or_reparse_point(&metadata))
}

#[cfg(test)]
mod tests {
    use super::{is_link_or_reparse_point, path_is_link_or_reparse_point};

    #[test]
    fn an_ordinary_directory_is_not_a_link() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let metadata = std::fs::symlink_metadata(directory.path()).expect("metadata");
        assert!(
            !is_link_or_reparse_point(&metadata),
            "a plain directory must not read as a link"
        );
    }

    #[test]
    fn an_ordinary_file_is_not_a_link() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("file");
        std::fs::write(&path, b"contents").expect("write");
        let metadata = std::fs::symlink_metadata(&path).expect("metadata");
        assert!(!is_link_or_reparse_point(&metadata));
        assert!(!path_is_link_or_reparse_point(&path));
    }

    #[test]
    fn a_path_that_does_not_exist_is_not_a_link() {
        let directory = tempfile::tempdir().expect("temporary directory");
        assert!(!path_is_link_or_reparse_point(
            &directory.path().join("absent")
        ));
    }

    /// The check has to see a link of the kind the host actually creates.
    ///
    /// On Unix that is a symbolic link. On Windows this is where the defect
    /// lived: a *junction* is the link Windows tooling creates without a
    /// privilege, and `FileType::is_symlink()` answers `false` for it. Creating
    /// one needs no elevation — `mklink /J` — so the test can make one without
    /// Developer Mode and then assert the check sees it, which is precisely what
    /// the old `is_symlink()` check could not do.
    #[test]
    fn a_link_of_the_kind_this_host_creates_is_seen() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target");
        std::fs::create_dir_all(&target).expect("link target");
        let link = directory.path().join("link");

        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).expect("symbolic link");
        #[cfg(windows)]
        {
            let status = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&link)
                .arg(&target)
                .status()
                .expect("mklink");
            assert!(
                status.success(),
                "mklink /J failed; junctions need no privilege"
            );
        }

        assert!(
            path_is_link_or_reparse_point(&link),
            "a link must be visible to the containment check"
        );
        // And the entry it points at is an ordinary directory, which is exactly
        // why `is_dir()` on the link's target is not a sufficient test.
        assert!(std::fs::metadata(&link).expect("target metadata").is_dir());
    }
}
