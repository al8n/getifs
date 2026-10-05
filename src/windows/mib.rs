//! Ownership of, and row access to, the variable-length tables that the IP
//! Helper `Get*Table*` functions allocate.

use std::io;

use windows_sys::Win32::{
  Foundation::{ERROR_NOT_FOUND, ERROR_NOT_SUPPORTED, NO_ERROR},
  NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, GetIpForwardTable2, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2,
    MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW,
    MIB_UNICASTIPADDRESS_TABLE,
  },
};

/// A table that IP Helper returns as a `NumEntries` count followed by a
/// `Table` array. The SDK declares that array with one element, but the API
/// allocates `NumEntries` rows after it.
///
/// # Safety
///
/// Implementations must read both fields through the raw `table` pointer
/// without creating a reference. A reference to the declared one-element
/// array, or to the whole struct, limits the row pointer's provenance to a
/// single row, so reading any later row would be undefined behavior.
pub(super) unsafe trait MibTable {
  type Row;

  /// # Safety
  ///
  /// `table` must point to a live table returned by IP Helper.
  unsafe fn num_entries(table: *const Self) -> usize;

  /// # Safety
  ///
  /// `table` must point to a live table returned by IP Helper.
  unsafe fn first_row(table: *const Self) -> *const Self::Row;
}

macro_rules! mib_table {
  ($($table:ty => $row:ty),+ $(,)?) => {$(
    // SAFETY: both fields are read through raw place projections.
    unsafe impl MibTable for $table {
      type Row = $row;

      #[inline]
      unsafe fn num_entries(table: *const Self) -> usize {
        // SAFETY: the caller guarantees that `table` is live.
        unsafe { core::ptr::addr_of!((*table).NumEntries).read() as usize }
      }

      #[inline]
      unsafe fn first_row(table: *const Self) -> *const $row {
        // SAFETY: the caller guarantees that `table` is live. `addr_of!`
        // keeps the provenance of the whole allocation.
        unsafe { core::ptr::addr_of!((*table).Table).cast::<$row>() }
      }
    }
  )+};
}

mib_table! {
  MIB_IF_TABLE2 => MIB_IF_ROW2,
  MIB_IPFORWARD_TABLE2 => MIB_IPFORWARD_ROW2,
  MIB_IPINTERFACE_TABLE => MIB_IPINTERFACE_ROW,
  MIB_UNICASTIPADDRESS_TABLE => MIB_UNICASTIPADDRESS_ROW,
}

/// A table allocated by an IP Helper getter and released with
/// `FreeMibTable` when dropped.
pub(super) struct OwnedMibTable<T: MibTable> {
  ptr: *mut T,
}

impl<T: MibTable> OwnedMibTable<T> {
  /// Calls an IP Helper table getter. Returns the table on `NO_ERROR` and the
  /// getter's status otherwise.
  ///
  /// Any pointer the getter stores is owned and freed, whatever the status.
  /// Windows is expected to leave the out-pointer null on failure, but Wine
  /// allocates the table before it reports a per-family error. A failed fetch
  /// exposes no rows, because that table's contents are not guaranteed to be
  /// initialized.
  ///
  /// # Safety
  ///
  /// `get` must behave like an IP Helper table getter: it either leaves the
  /// out-pointer null or stores a table of `T` that the caller owns and
  /// releases with `FreeMibTable`. When it returns `NO_ERROR`, a stored table
  /// must have `NumEntries` initialized and that many initialized rows.
  pub(super) unsafe fn fetch(get: impl FnOnce(*mut *mut T) -> u32) -> Result<Self, u32> {
    let mut ptr = core::ptr::null_mut();
    let status = get(&mut ptr);
    let table = Self { ptr };
    if status == NO_ERROR {
      Ok(table)
    } else {
      // Dropping `table` frees whatever the getter stored.
      Err(status)
    }
  }

  /// Returns the table's rows.
  pub(super) fn rows(&self) -> &[T::Row] {
    // SAFETY: a non-null `ptr` comes from a successful fetch, is owned by
    // `self`, and stays live for the returned borrow.
    unsafe { rows_of(self.ptr) }
  }
}

impl<T: MibTable> Drop for OwnedMibTable<T> {
  fn drop(&mut self) {
    if !self.ptr.is_null() {
      // SAFETY: `ptr` came from an IP Helper getter, and `self` is its only
      // owner (the type is neither `Clone` nor `Copy`), so it is freed
      // exactly once.
      unsafe { FreeMibTable(self.ptr.cast()) };
    }
  }
}

/// # Safety
///
/// `table` must be null or point to a live table of `T` whose `NumEntries`
/// rows are initialized and outlive `'a`.
unsafe fn rows_of<'a, T: MibTable>(table: *const T) -> &'a [T::Row] {
  if table.is_null() {
    return &[];
  }
  // SAFETY: guaranteed by the caller. The row pointer carries the provenance
  // of the whole allocation; see `MibTable`.
  unsafe { core::slice::from_raw_parts(T::first_row(table), T::num_entries(table)) }
}

/// Fetches the MIB-II table containing administrative interface state.
///
/// The returned status is the Win32 error code itself; `GetIfTable2` does not
/// report failures through the thread's last-error slot.
pub(super) fn interface_table() -> io::Result<OwnedMibTable<MIB_IF_TABLE2>> {
  // SAFETY: `GetIfTable2` allocates a `MIB_IF_TABLE2` that must be released
  // with `FreeMibTable`, exactly matching `OwnedMibTable::fetch`'s contract.
  unsafe { OwnedMibTable::fetch(|table| GetIfTable2(table)) }
    .map_err(|status| io::Error::from_raw_os_error(status as i32))
}

/// Fetches the forwarding table for one address family.
///
/// Returns `Ok(None)` when that family has no table: `ERROR_NOT_FOUND` means
/// the stack is present but has no routes, and `ERROR_NOT_SUPPORTED` means
/// the stack for that family is not installed. This lets a union query return
/// whichever family is populated on a single-stack host. Any other failure
/// keeps its status code, so a failed table call is never mistaken for an
/// empty one. The status the getter returns is the Win32 error code itself;
/// these IP Helper calls do not reliably set the thread's last error, so
/// `io::Error::last_os_error()` must not be used in its place.
pub(super) fn forward_table(
  family: u16,
) -> io::Result<Option<OwnedMibTable<MIB_IPFORWARD_TABLE2>>> {
  // SAFETY: `GetIpForwardTable2` is an IP Helper table getter.
  match unsafe { OwnedMibTable::fetch(|table| GetIpForwardTable2(family, table)) } {
    Ok(table) => Ok(Some(table)),
    Err(status) => empty_family(status).map(|()| None),
  }
}

#[inline]
fn empty_family(status: u32) -> io::Result<()> {
  match status {
    ERROR_NOT_FOUND | ERROR_NOT_SUPPORTED => Ok(()),
    status => Err(io::Error::from_raw_os_error(status as i32)),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use core::mem::offset_of;
  use windows_sys::Win32::NetworkManagement::Ndis::NET_IF_ADMIN_STATUS_UP;

  /// The layout IP Helper allocates for a three-row forwarding table.
  #[repr(C)]
  struct Fixture {
    num_entries: u32,
    rows: [MIB_IPFORWARD_ROW2; 3],
  }

  const _: () = {
    assert!(offset_of!(Fixture, num_entries) == offset_of!(MIB_IPFORWARD_TABLE2, NumEntries));
    assert!(offset_of!(Fixture, rows) == offset_of!(MIB_IPFORWARD_TABLE2, Table));
  };

  /// The layout IP Helper allocates for a three-row interface table.
  #[repr(C)]
  struct InterfaceFixture {
    num_entries: u32,
    rows: [MIB_IF_ROW2; 3],
  }

  const _: () = {
    assert!(offset_of!(InterfaceFixture, num_entries) == offset_of!(MIB_IF_TABLE2, NumEntries));
    assert!(offset_of!(InterfaceFixture, rows) == offset_of!(MIB_IF_TABLE2, Table));
  };

  #[test]
  fn rows_cover_every_entry_not_only_the_declared_one() {
    let mut fixture = Fixture {
      num_entries: 3,
      rows: [MIB_IPFORWARD_ROW2::default(); 3],
    };
    for (i, row) in fixture.rows.iter_mut().enumerate() {
      row.InterfaceIndex = 10 + i as u32;
    }

    let table = core::ptr::addr_of!(fixture).cast::<MIB_IPFORWARD_TABLE2>();
    // SAFETY: `Fixture` has the table's layout with three initialized rows,
    // and it outlives `rows`.
    let rows = unsafe { rows_of(table) };
    let indices: Vec<u32> = rows.iter().map(|row| row.InterfaceIndex).collect();
    assert_eq!(indices, [10, 11, 12]);
  }

  #[test]
  fn interface_rows_cover_the_whole_allocation() {
    let mut fixture = InterfaceFixture {
      num_entries: 3,
      rows: [MIB_IF_ROW2::default(); 3],
    };
    for (i, row) in fixture.rows.iter_mut().enumerate() {
      row.InterfaceIndex = 20 + i as u32;
      row.AdminStatus = if i == 1 {
        NET_IF_ADMIN_STATUS_UP
      } else {
        i as i32
      };
    }

    let table = core::ptr::addr_of!(fixture).cast::<MIB_IF_TABLE2>();
    // SAFETY: `InterfaceFixture` has the SDK table layout with three
    // initialized rows, and it outlives the returned slice.
    let rows = unsafe { rows_of(table) };
    let metadata: Vec<_> = rows
      .iter()
      .map(|row| (row.InterfaceIndex, row.AdminStatus))
      .collect();
    assert_eq!(metadata, [(20, 0), (21, NET_IF_ADMIN_STATUS_UP), (22, 2),]);
  }

  #[test]
  fn null_table_has_no_rows() {
    // SAFETY: a null table is allowed.
    let rows = unsafe { rows_of::<MIB_IPFORWARD_TABLE2>(core::ptr::null()) };
    assert!(rows.is_empty());
  }

  #[test]
  fn failed_fetch_returns_the_status_and_no_table() {
    // SAFETY: the stand-in getter never stores a pointer.
    let result = unsafe { OwnedMibTable::<MIB_IPFORWARD_TABLE2>::fetch(|_| ERROR_NOT_FOUND) };
    assert_eq!(result.err(), Some(ERROR_NOT_FOUND));
  }

  #[test]
  fn missing_family_is_empty_and_other_statuses_are_errors() {
    assert!(empty_family(ERROR_NOT_FOUND).is_ok());
    assert!(empty_family(ERROR_NOT_SUPPORTED).is_ok());
    assert_eq!(empty_family(8).unwrap_err().raw_os_error(), Some(8));
  }
}
