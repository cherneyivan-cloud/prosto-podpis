//! Небольшие Win32-хелперы: тёмный заголовок, поиск окна, ресайз без рамки.
//!
//! На не-Windows всё превращается в no-op.

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicIsize, Ordering};

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[link(name = "user32")]
    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn EnumWindows(cb: extern "system" fn(*mut c_void, isize) -> i32, lparam: isize) -> i32;
        fn GetWindowThreadProcessId(hwnd: *mut c_void, pid: *mut u32) -> u32;
        fn IsWindowVisible(hwnd: *mut c_void) -> i32;
        fn GetCursorPos(point: *mut Point) -> i32;
        fn GetWindowRect(hwnd: *mut c_void, rect: *mut Rect) -> i32;
        fn GetAsyncKeyState(vk: i32) -> i16;
        fn SetWindowPos(
            hwnd: *mut c_void,
            after: *mut c_void,
            x: i32,
            y: i32,
            cx: i32,
            cy: i32,
            flags: u32,
        ) -> i32;
    }

    #[link(name = "dwmapi")]
    extern "system" {
        fn DwmSetWindowAttribute(
            hwnd: *mut c_void,
            attr: u32,
            pv: *const c_void,
            cb: u32,
        ) -> i32;
    }

    const SWP_NOZORDER: u32 = 0x0004;
    const SWP_NOACTIVATE: u32 = 0x0010;

    static FOUND: AtomicIsize = AtomicIsize::new(0);
    static HANDLE: AtomicIsize = AtomicIsize::new(0);

    extern "system" fn enum_cb(hwnd: *mut c_void, lparam: isize) -> i32 {
        let target = lparam as u32;
        let mut pid = 0u32;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut pid);
            if pid == target && IsWindowVisible(hwnd) == 1 {
                FOUND.store(hwnd as isize, Ordering::SeqCst);
                return 0;
            }
        }
        1
    }

    pub fn set_handle(hwnd: isize) {
        HANDLE.store(hwnd, Ordering::SeqCst);
    }

    pub fn handle() -> Option<*mut c_void> {
        let cached = HANDLE.load(Ordering::SeqCst);
        if cached != 0 {
            return Some(cached as *mut c_void);
        }

        let pid = unsafe { GetCurrentProcessId() };
        unsafe {
            EnumWindows(enum_cb, pid as isize);
        }
        let hwnd = FOUND.swap(0, Ordering::SeqCst) as *mut c_void;
        if hwnd.is_null() {
            return None;
        }
        HANDLE.store(hwnd as isize, Ordering::SeqCst);
        Some(hwnd)
    }

    pub fn cursor_pos() -> Option<(i32, i32)> {
        let mut p = Point { x: 0, y: 0 };
        if unsafe { GetCursorPos(&mut p) } != 0 {
            Some((p.x, p.y))
        } else {
            None
        }
    }

    /// Зажаты ли Ctrl (0x11) и A (0x41) сейчас.
    pub fn ctrl_a_down() -> bool {
        let ctrl = unsafe { GetAsyncKeyState(0x11) } < 0;
        let a = unsafe { GetAsyncKeyState(0x41) } < 0;
        ctrl && a
    }

    pub fn window_rect() -> Option<(i32, i32, i32, i32)> {
        let hwnd = handle()?;
        let mut r = Rect {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        if unsafe { GetWindowRect(hwnd, &mut r) } != 0 {
            Some((r.left, r.top, r.right - r.left, r.bottom - r.top))
        } else {
            None
        }
    }

    pub fn set_window_rect(x: i32, y: i32, w: i32, h: i32) {
        if let Some(hwnd) = handle() {
            unsafe {
                SetWindowPos(
                    hwnd,
                    std::ptr::null_mut(),
                    x,
                    y,
                    w,
                    h,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
            }
        }
    }

    pub fn enable_dark_titlebar() -> bool {
        let Some(hwnd) = handle() else {
            return false;
        };
        // DWMWA_USE_IMMERSIVE_DARK_MODE: 20 в Windows 11, 19 в Windows 10.
        let dark: u32 = 1;
        // COLORREF = 0x00BBGGRR: фон заголовка #232530, рамка #2B2D38.
        let caption: u32 = 0x0030_2523;
        let border: u32 = 0x0038_2D2B;
        unsafe {
            DwmSetWindowAttribute(hwnd, 20, &dark as *const _ as *const c_void, 4);
            DwmSetWindowAttribute(hwnd, 19, &dark as *const _ as *const c_void, 4);
            DwmSetWindowAttribute(hwnd, 35, &caption as *const _ as *const c_void, 4);
            DwmSetWindowAttribute(hwnd, 34, &border as *const _ as *const c_void, 4);
            // DWMWA_WINDOW_CORNER_PREFERENCE = DWMWCP_ROUND (Windows 11).
            let round: u32 = 2;
            DwmSetWindowAttribute(hwnd, 33, &round as *const _ as *const c_void, 4);
        }
        true
    }
}

#[cfg(windows)]
pub use imp::*;

#[cfg(not(windows))]
pub fn set_handle(_hwnd: isize) {}

#[cfg(not(windows))]
pub fn enable_dark_titlebar() -> bool {
    true
}

#[cfg(not(windows))]
pub fn cursor_pos() -> Option<(i32, i32)> {
    None
}

#[cfg(not(windows))]
pub fn ctrl_a_down() -> bool {
    false
}

#[cfg(not(windows))]
pub fn window_rect() -> Option<(i32, i32, i32, i32)> {
    None
}

#[cfg(not(windows))]
pub fn set_window_rect(_x: i32, _y: i32, _w: i32, _h: i32) {}
