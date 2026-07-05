#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub(crate) type BackendContext = linux::Context;
#[cfg(target_os = "windows")]
pub(crate) type BackendContext = windows::Context;
