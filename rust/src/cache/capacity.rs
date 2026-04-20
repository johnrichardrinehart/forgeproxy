use std::path::Path;

use anyhow::{Context, Result};

pub(crate) fn filesystem_capacity_bytes(path: &Path) -> Result<u64> {
    statvfs_capacity_bytes(path)
}

pub(crate) fn budget_bytes_for_path(path: &Path, max_percent: f64) -> Result<u64> {
    let capacity = filesystem_capacity_bytes(path)?;
    Ok(percent_of_bytes(capacity, max_percent))
}

pub(crate) fn nested_budget_bytes_for_path(
    path: &Path,
    parent_percent: f64,
    child_percent: f64,
) -> Result<u64> {
    let parent_budget = budget_bytes_for_path(path, parent_percent)?;
    Ok(percent_of_bytes(parent_budget, child_percent))
}

pub(crate) fn percent_of_bytes(bytes: u64, percent: f64) -> u64 {
    ((bytes as f64 * percent) as u64).max(1)
}

#[cfg(unix)]
fn statvfs_capacity_bytes(path: &Path) -> Result<u64> {
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::unix::ffi::OsStrExt;

    let path_bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(path_bytes)
        .with_context(|| format!("filesystem path contains NUL byte: {}", path.display()))?;
    let mut stat = MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("statvfs {}", path.display()));
    }

    let stat = unsafe { stat.assume_init() };
    let blocks = stat.f_blocks as u128;
    let fragment_size = stat.f_frsize as u128;
    let capacity = blocks.saturating_mul(fragment_size);
    Ok(capacity.min(u64::MAX as u128) as u64)
}

#[cfg(not(unix))]
fn statvfs_capacity_bytes(path: &Path) -> Result<u64> {
    anyhow::bail!(
        "filesystem capacity detection is not supported on this platform: {}",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::percent_of_bytes;

    #[test]
    fn percent_budget_has_one_byte_floor() {
        assert_eq!(percent_of_bytes(0, 0.50), 1);
        assert_eq!(percent_of_bytes(10, 0.50), 5);
    }
}
