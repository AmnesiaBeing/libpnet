// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(all(
    feature = "bpf",
    any(
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "macos",
        target_os = "ios",
        target_os = "windows"
    )
))]
pub mod bpf;

#[cfg(all(feature = "linux_dll", any(target_os = "linux", target_os = "android")))]
pub mod linux;

#[cfg(all(feature = "winpcap", target_os = "windows"))]
pub mod winpcap;
