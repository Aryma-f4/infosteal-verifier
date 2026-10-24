//! Native macOS desktop GUI (Cocoa / AppKit) via direct Objective-C runtime FFI.
//!
//! No browser, no WebView, no HTML, no third-party crates — only `AppKit.framework`,
//! `Foundation.framework`, `CoreGraphics.framework` and `libobjc`.
//!
//! Layout mirrors the original WPF `MainView.xaml`: Resources/Settings card on the left,
//! Statistic + LiveChart card on the right, Dark Aqua theme (#1C1C1C / #262628 / #12eb90).

use std::fs;
use std::process::Command;
use std::ptr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use crate::{format_hms, start_workers, EngineState, ProxyType};

#[link(name = "objc", kind = "dylib")]
#[link(name = "Foundation", kind = "framework")]
#[link(name = "AppKit", kind = "framework")]
#[link(name = "CoreGraphics", kind = "framework")]
extern "C" {
    fn objc_getClass(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    fn sel_registerName(name: *const std::ffi::c_char) -> *mut std::ffi::c_void;
    fn objc_allocateClassPair(
        superclass: *mut std::ffi::c_void,
        name: *const std::ffi::c_char,
        extra_bytes: usize,
    ) -> *mut std::ffi::c_void;
    fn objc_registerClassPair(cls: *mut std::ffi::c_void);
    fn class_addMethod(
        cls: *mut std::ffi::c_void,
        name: *mut std::ffi::c_void,
        imp: *const std::ffi::c_void,
        types: *const std::ffi::c_char,
    ) -> bool;
    fn objc_msgSend();
}

use std::ffi::{c_char, c_void, CStr, CString};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NSPoint {
    pub x: f64,
    pub y: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NSSize {
    pub width: f64,
    pub height: f64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NSRect {
    pub origin: NSPoint,
    pub size: NSSize,
}

impl NSRect {
    fn new(x: f64, y: f64, w: f64, h: f64) -> Self {
        NSRect {
            origin: NSPoint { x, y },
            size: NSSize {
                width: w,
                height: h,
            },
        }
    }
}

unsafe fn cls(name: &str) -> *mut c_void {
    let c = CString::new(name).unwrap();
    objc_getClass(c.as_ptr())
}

unsafe fn sel(name: &str) -> *mut c_void {
    let c = CString::new(name).unwrap();
    sel_registerName(c.as_ptr())
}

unsafe fn nsstring(s: &str) -> *mut c_void {
    let c = CString::new(s).unwrap_or_else(|_| CString::new("").unwrap());
    let f: extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> *mut c_void =
        std::mem::transmute(objc_msgSend as *const ());
    f(cls("NSString"), sel("stringWithUTF8String:"), c.as_ptr())
}

unsafe fn from_nsstring(ns: *mut c_void) -> String {
    if ns.is_null() {
        return String::new();
    }
    let f: extern "C" fn(*mut c_void, *mut c_void) -> *const c_char =
        std::mem::transmute(objc_msgSend as *const ());
    let ptr = f(ns, sel("UTF8String"));
    if ptr.is_null() {
        String::new()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

unsafe fn nscolor_rgba(r: f64, g: f64, b: f64, a: f64) -> *mut c_void {
    let f: extern "C" fn(*mut c_void, *mut c_void, f64, f64, f64, f64) -> *mut c_void =
        std::mem::transmute(objc_msgSend as *const ());
    f(
        cls("NSColor"),
        sel("colorWithSRGBRed:green:blue:alpha:"),
        r,
        g,
        b,
        a,
    )
}

unsafe fn msg0_id(obj: *mut c_void, s: &str) -> *mut c_void {
    let f: extern "C" fn(*mut c_void, *mut c_void) -> *mut c_void =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s))
}

unsafe fn msg0_void(obj: *mut c_void, s: &str) {
    let f: extern "C" fn(*mut c_void, *mut c_void) = std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s));
}

unsafe fn msg1_void_id(obj: *mut c_void, s: &str, a: *mut c_void) {
    let f: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s), a);
}

unsafe fn msg1_void_bool(obj: *mut c_void, s: &str, a: bool) {
    let f: extern "C" fn(*mut c_void, *mut c_void, bool) =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s), a);
}

unsafe fn msg1_void_isize(obj: *mut c_void, s: &str, a: isize) {
    let f: extern "C" fn(*mut c_void, *mut c_void, isize) =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s), a);
}

unsafe fn msg1_void_f64(obj: *mut c_void, s: &str, a: f64) {
    let f: extern "C" fn(*mut c_void, *mut c_void, f64) =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s), a);
}

unsafe fn msg0_isize(obj: *mut c_void, s: &str) -> isize {
    let f: extern "C" fn(*mut c_void, *mut c_void) -> isize =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel(s))
}

unsafe fn init_frame(obj: *mut c_void, rect: NSRect) -> *mut c_void {
    let f: extern "C" fn(*mut c_void, *mut c_void, NSRect) -> *mut c_void =
        std::mem::transmute(objc_msgSend as *const ());
    f(obj, sel("initWithFrame:"), rect)
}

unsafe fn make_label(
    rect: NSRect,
    text: &str,
    size: f64,
    bold: bool,
    color: *mut c_void,
    align: isize,
) -> *mut c_void {
    let lbl = init_frame(msg0_id(cls("NSTextField"), "alloc"), rect);
    msg1_void_id(lbl, "setStringValue:", nsstring(text));
    msg1_void_bool(lbl, "setBezeled:", false);
    msg1_void_bool(lbl, "setDrawsBackground:", false);
    msg1_void_bool(lbl, "setEditable:", false);
    msg1_void_bool(lbl, "setSelectable:", false);
    msg1_void_id(lbl, "setTextColor:", color);
    msg1_void_isize(lbl, "setAlignment:", align);
    let font_sel = if bold {
        "boldSystemFontOfSize:"
    } else {
        "systemFontOfSize:"
    };
    let f_font: extern "C" fn(*mut c_void, *mut c_void, f64) -> *mut c_void =
        std::mem::transmute(objc_msgSend as *const ());
    let font = f_font(cls("NSFont"), sel(font_sel), size);
    msg1_void_id(lbl, "setFont:", font);
    lbl
}

unsafe fn make_button(
    rect: NSRect,
    title: &str,
    target: *mut c_void,
    action: &str,
) -> *mut c_void {
    let btn = init_frame(msg0_id(cls("NSButton"), "alloc"), rect);
    msg1_void_id(btn, "setTitle:", nsstring(title));
    msg1_void_isize(btn, "setBezelStyle:", 1); // NSBezelStyleRounded
    msg1_void_id(btn, "setTarget:", target);
    msg1_void_id(btn, "setAction:", sel(action));
    btn
}

struct GuiHandles {
    state: Arc<EngineState>,
    btn_accounts: usize,
    btn_proxies: usize,
    txt_threads: usize,
    txt_proxy_url: usize,
    btn_start: usize,
    lbl_valid: usize,
    lbl_invalid: usize,
    lbl_errors: usize,
    lbl_elapsed: usize,
    lbl_apm: usize,
    lbl_eta: usize,
    lbl_progress: usize,
    chart_view: usize,
}

static GUI_HANDLES: OnceLock<Mutex<GuiHandles>> = OnceLock::new();

extern "C" fn on_load_accounts(_this: *mut c_void, _cmd: *mut c_void, _sender: *mut c_void) {
    unsafe {
        let panel = msg0_id(cls("NSOpenPanel"), "openPanel");
        msg1_void_bool(panel, "setCanChooseFiles:", true);
        msg1_void_bool(panel, "setCanChooseDirectories:", false);
        msg1_void_bool(panel, "setAllowsMultipleSelection:", false);
        msg1_void_id(panel, "setTitle:", nsstring("Load accounts"));
        if msg0_isize(panel, "runModal") == 1 {
            let url = msg0_id(panel, "URL");
            let path_str = from_nsstring(msg0_id(url, "path"));
            // A dump can be hundreds of megabytes: load it on a worker thread
            // so the window keeps painting and the counter keeps ticking up.
            let state = match GUI_HANDLES.get() {
                Some(lock) => Arc::clone(&lock.lock().unwrap().state),
                None => return,
            };
            thread::spawn(move || {
                if let Err(e) = state.load_accounts_from_path(std::path::Path::new(&path_str)) {
                    let msg = format!("Failed to read accounts file: {}", e);
                    let alert = msg0_id(cls("NSAlert"), "alloc");
                    init_frame(alert, NSRect::new(0.0, 0.0, 1.0, 1.0));
                    msg1_void_id(alert, "setMessageText:", nsstring(&msg));
                    msg0_void(alert, "runModal");
                }
            });
        }
    }
    refresh_gui();
}

extern "C" fn on_load_proxies(_this: *mut c_void, _cmd: *mut c_void, _sender: *mut c_void) {
    unsafe {
        let panel = msg0_id(cls("NSOpenPanel"), "openPanel");
        msg1_void_bool(panel, "setCanChooseFiles:", true);
        msg1_void_bool(panel, "setCanChooseDirectories:", false);
        msg1_void_bool(panel, "setAllowsMultipleSelection:", false);
        msg1_void_id(panel, "setTitle:", nsstring("Load proxies"));
        if msg0_isize(panel, "runModal") == 1 {
            let url = msg0_id(panel, "URL");
            let path_str = from_nsstring(msg0_id(url, "path"));
            if let Ok(content) = fs::read_to_string(&path_str) {
                if let Some(lock) = GUI_HANDLES.get() {
                    let h = lock.lock().unwrap();
                    h.state.load_proxies_from_str(&content);
                }
            }
        }
    }
    refresh_gui();
}

extern "C" fn on_proxy_type_changed(_this: *mut c_void, _cmd: *mut c_void, sender: *mut c_void) {
    unsafe {
        let idx = msg0_isize(sender, "selectedSegment");
        if let Some(lock) = GUI_HANDLES.get() {
            let h = lock.lock().unwrap();
            let pt = match idx {
                1 => ProxyType::Socks4,
                2 => ProxyType::Socks5,
                _ => ProxyType::Http,
            };
            *h.state.proxy_type.lock().unwrap() = pt;
        }
    }
}

extern "C" fn on_start_stop(_this: *mut c_void, _cmd: *mut c_void, _sender: *mut c_void) {
    if let Some(lock) = GUI_HANDLES.get() {
        let st = {
            let h = lock.lock().unwrap();
            unsafe {
                let th_str = from_nsstring(msg0_id(h.txt_threads as *mut c_void, "stringValue"));
                if let Ok(n) = th_str.trim().parse::<usize>() {
                    h.state.threads_count.store(n.clamp(1, 500), Ordering::SeqCst);
                }
                let pu_str = from_nsstring(msg0_id(h.txt_proxy_url as *mut c_void, "stringValue"));
                *h.state.proxy_url.lock().unwrap() = pu_str;
            }
            Arc::clone(&h.state)
        };
        if st.running.load(Ordering::SeqCst) {
            st.stopping.store(true, Ordering::SeqCst);
        } else {
            start_workers(st);
        }
    }
    refresh_gui();
}

extern "C" fn on_open_folder(_this: *mut c_void, _cmd: *mut c_void, _sender: *mut c_void) {
    if let Some(lock) = GUI_HANDLES.get() {
        let dir = lock.lock().unwrap().state.results_dir.lock().unwrap().clone();
        let _ = fs::create_dir_all(&dir);
        let _ = Command::new("/usr/bin/open").arg(dir).spawn();
    }
}

extern "C" fn on_timer_tick(_this: *mut c_void, _cmd: *mut c_void, _timer: *mut c_void) {
    refresh_gui();
}

extern "C" fn app_should_terminate(
    _this: *mut c_void,
    _cmd: *mut c_void,
    _sender: *mut c_void,
) -> bool {
    true
}

extern "C" fn draw_card_rect(this: *mut c_void, _cmd: *mut c_void, _dirty: NSRect) {
    unsafe {
        let f_bounds: extern "C" fn(*mut c_void, *mut c_void) -> NSRect =
            std::mem::transmute(objc_msgSend as *const ());
        let bounds = f_bounds(this, sel("bounds"));

        let f_path: extern "C" fn(*mut c_void, *mut c_void, NSRect, f64, f64) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let path = f_path(
            cls("NSBezierPath"),
            sel("bezierPathWithRoundedRect:xRadius:yRadius:"),
            bounds,
            5.0,
            5.0,
        );
        msg0_void(nscolor_rgba(0.149, 0.149, 0.157, 1.0), "setFill"); // #262628
        msg0_void(path, "fill");
        msg0_void(nscolor_rgba(0.243, 0.243, 0.243, 1.0), "setStroke"); // #3e3e3e
        msg0_void(path, "stroke");
    }
}

extern "C" fn draw_chart_rect(this: *mut c_void, _cmd: *mut c_void, _dirty: NSRect) {
    unsafe {
        let f_bounds: extern "C" fn(*mut c_void, *mut c_void) -> NSRect =
            std::mem::transmute(objc_msgSend as *const ());
        let b = f_bounds(this, sel("bounds"));

        let chart_rect = NSRect::new(0.0, 28.0, b.size.width, b.size.height - 28.0);
        let prog_rect = NSRect::new(0.0, 0.0, b.size.width, 22.0);

        let f_rpath: extern "C" fn(*mut c_void, *mut c_void, NSRect, f64, f64) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let c_bg = f_rpath(
            cls("NSBezierPath"),
            sel("bezierPathWithRoundedRect:xRadius:yRadius:"),
            chart_rect,
            4.0,
            4.0,
        );
        msg0_void(nscolor_rgba(0.11, 0.11, 0.12, 1.0), "setFill");
        msg0_void(c_bg, "fill");
        msg0_void(nscolor_rgba(0.243, 0.243, 0.243, 1.0), "setStroke");
        msg0_void(c_bg, "stroke");

        let (series, progress) = if let Some(lock) = GUI_HANDLES.get() {
            let h = lock.lock().unwrap();
            let s = h.state.speed_history.lock().unwrap().clone();
            let tot = h.state.total_accounts.load(Ordering::SeqCst);
            let chk = h.state.checked.load(Ordering::SeqCst);
            let p = if tot > 0 {
                (chk as f64 / tot as f64).clamp(0.0, 1.0)
            } else {
                0.0
            };
            (s, p)
        } else {
            (vec![0; 30], 0.0)
        };

        if series.len() > 1 {
            let max_v = (*series.iter().max().unwrap_or(&10)).max(10) as f64;
            let f_move: extern "C" fn(*mut c_void, *mut c_void, NSPoint) =
                std::mem::transmute(objc_msgSend as *const ());
            let f_line: extern "C" fn(*mut c_void, *mut c_void, NSPoint) =
                std::mem::transmute(objc_msgSend as *const ());

            let fill_path = msg0_id(cls("NSBezierPath"), "bezierPath");
            let stroke_path = msg0_id(cls("NSBezierPath"), "bezierPath");
            msg1_void_f64(stroke_path, "setLineWidth:", 2.0);

            f_move(
                fill_path,
                sel("moveToPoint:"),
                NSPoint {
                    x: chart_rect.origin.x + 2.0,
                    y: chart_rect.origin.y + 2.0,
                },
            );

            for (i, &val) in series.iter().enumerate() {
                let x = chart_rect.origin.x
                    + 2.0
                    + (i as f64 / (series.len() - 1) as f64) * (chart_rect.size.width - 4.0);
                let y = chart_rect.origin.y
                    + 4.0
                    + (val as f64 / max_v) * (chart_rect.size.height - 28.0);
                let pt = NSPoint { x, y };
                f_line(fill_path, sel("lineToPoint:"), pt);
                if i == 0 {
                    f_move(stroke_path, sel("moveToPoint:"), pt);
                } else {
                    f_line(stroke_path, sel("lineToPoint:"), pt);
                }
            }
            f_line(
                fill_path,
                sel("lineToPoint:"),
                NSPoint {
                    x: chart_rect.origin.x + chart_rect.size.width - 2.0,
                    y: chart_rect.origin.y + 2.0,
                },
            );
            msg0_void(fill_path, "closePath");

            msg0_void(nscolor_rgba(0.071, 0.922, 0.565, 0.22), "setFill"); // #12eb90 fill
            msg0_void(fill_path, "fill");
            msg0_void(nscolor_rgba(0.071, 0.922, 0.565, 1.0), "setStroke"); // #12eb90 line
            msg0_void(stroke_path, "stroke");
        }

        let p_bg = f_rpath(
            cls("NSBezierPath"),
            sel("bezierPathWithRoundedRect:xRadius:yRadius:"),
            prog_rect,
            4.0,
            4.0,
        );
        msg0_void(nscolor_rgba(0.10, 0.10, 0.11, 1.0), "setFill");
        msg0_void(p_bg, "fill");

        if progress > 0.0 {
            let fill_w = (prog_rect.size.width * progress).max(4.0);
            let p_fill = f_rpath(
                cls("NSBezierPath"),
                sel("bezierPathWithRoundedRect:xRadius:yRadius:"),
                NSRect::new(0.0, 0.0, fill_w, prog_rect.size.height),
                4.0,
                4.0,
            );
            msg0_void(nscolor_rgba(0.071, 0.922, 0.565, 0.40), "setFill");
            msg0_void(p_fill, "fill");
        }
        msg0_void(nscolor_rgba(0.243, 0.243, 0.243, 1.0), "setStroke");
        msg0_void(p_bg, "stroke");
    }
}

fn refresh_gui() {
    if let Some(lock) = GUI_HANDLES.get() {
        let h = lock.lock().unwrap();
        let st = &h.state;
        let rem_accs = st.accounts.lock().unwrap().len();
        let loaded = st.total_accounts.load(Ordering::SeqCst);
        let prx_cnt = st.proxies.lock().unwrap().len();
        let valid = st.valid.load(Ordering::SeqCst);
        let invalid = st.invalid.load(Ordering::SeqCst);
        let errors = st.errors.load(Ordering::SeqCst);
        let checked = st.checked.load(Ordering::SeqCst);
        let total = st.total_accounts.load(Ordering::SeqCst);
        let running = st.running.load(Ordering::SeqCst);
        let stopping = st.stopping.load(Ordering::SeqCst);
        let cur_threads = st.current_threads.load(Ordering::SeqCst);

        let elapsed_secs = if running {
            st.started_at
                .lock()
                .unwrap()
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0)
        } else {
            0
        };
        let apm = if elapsed_secs > 0 {
            ((checked as f64 / elapsed_secs as f64) * 60.0).round() as u64
        } else {
            0
        };
        let eta_secs = if apm > 0 && rem_accs > 0 {
            ((rem_accs as f64 / (apm as f64 / 60.0)).round()) as u64
        } else {
            0
        };
        let pct = if total > 0 {
            ((checked as f64 / total as f64) * 100.0).round() as usize
        } else {
            0
        };

        unsafe {
            msg1_void_id(
                h.btn_accounts as *mut c_void,
                "setTitle:",
                nsstring(&format!("Accounts | {}", loaded)),
            );
            msg1_void_id(
                h.btn_proxies as *mut c_void,
                "setTitle:",
                nsstring(&format!("Proxies | {}", prx_cnt)),
            );
            msg1_void_id(
                h.lbl_valid as *mut c_void,
                "setStringValue:",
                nsstring(&valid.to_string()),
            );
            msg1_void_id(
                h.lbl_invalid as *mut c_void,
                "setStringValue:",
                nsstring(&invalid.to_string()),
            );
            msg1_void_id(
                h.lbl_errors as *mut c_void,
                "setStringValue:",
                nsstring(&errors.to_string()),
            );
            msg1_void_id(
                h.lbl_elapsed as *mut c_void,
                "setStringValue:",
                nsstring(&format_hms(elapsed_secs)),
            );
            msg1_void_id(
                h.lbl_apm as *mut c_void,
                "setStringValue:",
                nsstring(&format!("accs/min: {}", apm)),
            );
            msg1_void_id(
                h.lbl_eta as *mut c_void,
                "setStringValue:",
                nsstring(&format_hms(eta_secs)),
            );
            msg1_void_id(
                h.lbl_progress as *mut c_void,
                "setStringValue:",
                nsstring(&format!("{}% - {}/{}", pct, checked, rem_accs)),
            );

            let btn_title = if stopping {
                format!("Stopping... [{}]", cur_threads)
            } else if running {
                "Stop".to_string()
            } else {
                "Start".to_string()
            };
            msg1_void_id(h.btn_start as *mut c_void, "setTitle:", nsstring(&btn_title));
            msg1_void_bool(h.chart_view as *mut c_void, "setNeedsDisplay:", true);
        }
    }
}

pub fn run(state: Arc<EngineState>, preload: Option<String>) {
    unsafe {
        let app = msg0_id(cls("NSApplication"), "sharedApplication");
        msg1_void_isize(app, "setActivationPolicy:", 0); // NSApplicationActivationPolicyRegular

        // Dark Aqua theme (#1C1C1C / #262628)
        let f_app_named: extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> *mut c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let dark_app = f_app_named(
            cls("NSAppearance"),
            sel("appearanceNamed:"),
            nsstring("NSAppearanceNameDarkAqua"),
        );
        if !dark_app.is_null() {
            msg1_void_id(app, "setAppearance:", dark_app);
        }

        // ---- Register controller class ----
        let ns_object = cls("NSObject");
        let ctrl_cls =
            objc_allocateClassPair(ns_object, b"AdminPanelController\0".as_ptr() as *const c_char, 0);
        class_addMethod(
            ctrl_cls,
            sel("onLoadAccounts:"),
            on_load_accounts as *const c_void,
            b"v@:@\0".as_ptr() as *const c_char,
        );
        class_addMethod(
            ctrl_cls,
            sel("onLoadProxies:"),
            on_load_proxies as *const c_void,
            b"v@:@\0".as_ptr() as *const c_char,
        );
        class_addMethod(
            ctrl_cls,
            sel("onProxyTypeChanged:"),
            on_proxy_type_changed as *const c_void,
            b"v@:@\0".as_ptr() as *const c_char,
        );
        class_addMethod(
            ctrl_cls,
            sel("onStartStop:"),
            on_start_stop as *const c_void,
            b"v@:@\0".as_ptr() as *const c_char,
        );
        class_addMethod(
            ctrl_cls,
            sel("onOpenFolder:"),
            on_open_folder as *const c_void,
            b"v@:@\0".as_ptr() as *const c_char,
        );
        class_addMethod(
            ctrl_cls,
            sel("onTimerTick:"),
            on_timer_tick as *const c_void,
            b"v@:@\0".as_ptr() as *const c_char,
        );
        class_addMethod(
            ctrl_cls,
            sel("applicationShouldTerminateAfterLastWindowClosed:"),
            app_should_terminate as *const c_void,
            b"B@:@\0".as_ptr() as *const c_char,
        );
        objc_registerClassPair(ctrl_cls);
        let controller = msg0_id(msg0_id(ctrl_cls, "alloc"), "init");
        msg1_void_id(app, "setDelegate:", controller);

        // ---- Register custom NSView subclasses ----
        let ns_view = cls("NSView");
        let card_cls =
            objc_allocateClassPair(ns_view, b"AdminPanelCardView\0".as_ptr() as *const c_char, 0);
        class_addMethod(
            card_cls,
            sel("drawRect:"),
            draw_card_rect as *const c_void,
            b"v@:{CGRect={CGPoint=dd}{CGSize=dd}}\0".as_ptr() as *const c_char,
        );
        objc_registerClassPair(card_cls);

        let chart_cls =
            objc_allocateClassPair(ns_view, b"AdminPanelChartView\0".as_ptr() as *const c_char, 0);
        class_addMethod(
            chart_cls,
            sel("drawRect:"),
            draw_chart_rect as *const c_void,
            b"v@:{CGRect={CGPoint=dd}{CGSize=dd}}\0".as_ptr() as *const c_char,
        );
        objc_registerClassPair(chart_cls);

        // ---- Main window ----
        let win_rect = NSRect::new(0.0, 0.0, 530.0, 268.0);
        let style_mask: usize = (1 << 0) | (1 << 1) | (1 << 2); // Titled | Closable | Miniaturizable
        let f_win_init: extern "C" fn(
            *mut c_void,
            *mut c_void,
            NSRect,
            usize,
            usize,
            bool,
        ) -> *mut c_void = std::mem::transmute(objc_msgSend as *const ());
        let window = f_win_init(
            msg0_id(cls("NSWindow"), "alloc"),
            sel("initWithContentRect:styleMask:backing:defer:"),
            win_rect,
            style_mask,
            2, // NSBackingStoreBuffered
            false,
        );
        msg1_void_id(window, "setTitle:", nsstring("Admin Panel"));
        msg1_void_id(
            window,
            "setBackgroundColor:",
            nscolor_rgba(0.11, 0.11, 0.11, 1.0), // #1C1C1C
        );
        msg0_void(window, "center");

        let content_view = msg0_id(window, "contentView");
        let white = nscolor_rgba(0.92, 0.92, 0.92, 1.0);
        let muted = nscolor_rgba(0.65, 0.65, 0.68, 1.0);
        let mint_green = nscolor_rgba(0.071, 0.922, 0.565, 1.0); // #12eb90

        // ---------------- Left card: Resources & Settings ----------------
        let left_card = init_frame(msg0_id(card_cls, "alloc"), NSRect::new(12.0, 12.0, 235.0, 244.0));
        msg1_void_id(content_view, "addSubview:", left_card);

        let lbl_res = make_label(
            NSRect::new(12.0, 214.0, 200.0, 20.0),
            "Resources",
            13.0,
            true,
            white,
            0,
        );
        msg1_void_id(left_card, "addSubview:", lbl_res);

        let btn_accounts = make_button(
            NSRect::new(10.0, 180.0, 215.0, 28.0),
            "Accounts | 0",
            controller,
            "onLoadAccounts:",
        );
        msg1_void_id(left_card, "addSubview:", btn_accounts);

        let btn_proxies = make_button(
            NSRect::new(10.0, 150.0, 215.0, 28.0),
            "Proxies | 0",
            controller,
            "onLoadProxies:",
        );
        msg1_void_id(left_card, "addSubview:", btn_proxies);

        let lbl_settings = make_label(
            NSRect::new(12.0, 126.0, 211.0, 18.0),
            "───  Settings  ───",
            11.0,
            false,
            muted,
            1, // Center
        );
        msg1_void_id(left_card, "addSubview:", lbl_settings);

        let seg_proxy = init_frame(
            msg0_id(cls("NSSegmentedControl"), "alloc"),
            NSRect::new(10.0, 98.0, 215.0, 24.0),
        );
        msg1_void_isize(seg_proxy, "setSegmentCount:", 3);
        let f_seg_lbl: extern "C" fn(*mut c_void, *mut c_void, *mut c_void, isize) =
            std::mem::transmute(objc_msgSend as *const ());
        f_seg_lbl(seg_proxy, sel("setLabel:forSegment:"), nsstring("HTTP"), 0);
        f_seg_lbl(seg_proxy, sel("setLabel:forSegment:"), nsstring("Socks4"), 1);
        f_seg_lbl(seg_proxy, sel("setLabel:forSegment:"), nsstring("Socks5"), 2);
        msg1_void_isize(seg_proxy, "setSelectedSegment:", 0);
        msg1_void_id(seg_proxy, "setTarget:", controller);
        msg1_void_id(seg_proxy, "setAction:", sel("onProxyTypeChanged:"));
        msg1_void_id(left_card, "addSubview:", seg_proxy);

        let lbl_threads = make_label(
            NSRect::new(12.0, 70.0, 115.0, 18.0),
            "Count of threads:",
            12.0,
            false,
            white,
            0,
        );
        msg1_void_id(left_card, "addSubview:", lbl_threads);

        let txt_threads = init_frame(
            msg0_id(cls("NSTextField"), "alloc"),
            NSRect::new(135.0, 68.0, 88.0, 22.0),
        );
        msg1_void_id(txt_threads, "setStringValue:", nsstring("150"));
        msg1_void_id(left_card, "addSubview:", txt_threads);

        let txt_proxy_url = init_frame(
            msg0_id(cls("NSTextField"), "alloc"),
            NSRect::new(12.0, 40.0, 211.0, 22.0),
        );
        msg1_void_id(
            txt_proxy_url,
            "setPlaceholderString:",
            nsstring("Address for proxy"),
        );
        msg1_void_id(left_card, "addSubview:", txt_proxy_url);

        let btn_start = make_button(
            NSRect::new(10.0, 8.0, 215.0, 28.0),
            "Start",
            controller,
            "onStartStop:",
        );
        msg1_void_id(btn_start, "setBezelColor:", mint_green);
        msg1_void_id(left_card, "addSubview:", btn_start);

        // ---------------- Right card: Statistic & LiveChart ----------------
        let right_card = init_frame(msg0_id(card_cls, "alloc"), NSRect::new(257.0, 12.0, 261.0, 244.0));
        msg1_void_id(content_view, "addSubview:", right_card);

        let lbl_stat = make_label(
            NSRect::new(12.0, 214.0, 150.0, 20.0),
            "Statistic",
            13.0,
            true,
            white,
            0,
        );
        msg1_void_id(right_card, "addSubview:", lbl_stat);

        let btn_folder = make_button(
            NSRect::new(182.0, 212.0, 70.0, 24.0),
            "Results",
            controller,
            "onOpenFolder:",
        );
        msg1_void_id(right_card, "addSubview:", btn_folder);

        let lbl_v_title = make_label(
            NSRect::new(12.0, 186.0, 130.0, 18.0),
            "Count of valid:",
            12.0,
            false,
            white,
            0,
        );
        let lbl_valid = make_label(
            NSRect::new(145.0, 186.0, 104.0, 18.0),
            "0",
            12.0,
            true,
            mint_green,
            2, // Right
        );
        msg1_void_id(right_card, "addSubview:", lbl_v_title);
        msg1_void_id(right_card, "addSubview:", lbl_valid);

        let lbl_i_title = make_label(
            NSRect::new(12.0, 166.0, 130.0, 18.0),
            "Count of invalid:",
            12.0,
            false,
            white,
            0,
        );
        let lbl_invalid = make_label(
            NSRect::new(145.0, 166.0, 104.0, 18.0),
            "0",
            12.0,
            true,
            white,
            2,
        );
        msg1_void_id(right_card, "addSubview:", lbl_i_title);
        msg1_void_id(right_card, "addSubview:", lbl_invalid);

        let lbl_e_title = make_label(
            NSRect::new(12.0, 146.0, 130.0, 18.0),
            "Count of errors:",
            12.0,
            false,
            white,
            0,
        );
        let lbl_errors = make_label(
            NSRect::new(145.0, 146.0, 104.0, 18.0),
            "0",
            12.0,
            true,
            white,
            2,
        );
        msg1_void_id(right_card, "addSubview:", lbl_e_title);
        msg1_void_id(right_card, "addSubview:", lbl_errors);

        let chart_view = init_frame(
            msg0_id(chart_cls, "alloc"),
            NSRect::new(12.0, 10.0, 237.0, 130.0),
        );
        msg1_void_id(right_card, "addSubview:", chart_view);

        let lbl_elapsed = make_label(
            NSRect::new(6.0, 108.0, 70.0, 16.0),
            "00:00:00",
            11.0,
            false,
            muted,
            0,
        );
        let lbl_apm = make_label(
            NSRect::new(68.0, 108.0, 100.0, 16.0),
            "accs/min: 0",
            11.0,
            false,
            muted,
            1,
        );
        let lbl_eta = make_label(
            NSRect::new(160.0, 108.0, 70.0, 16.0),
            "00:00:00",
            11.0,
            false,
            muted,
            2,
        );
        let lbl_progress = make_label(
            NSRect::new(4.0, 3.0, 229.0, 16.0),
            "0% - 0/0",
            11.0,
            true,
            white,
            1,
        );
        msg1_void_id(chart_view, "addSubview:", lbl_elapsed);
        msg1_void_id(chart_view, "addSubview:", lbl_apm);
        msg1_void_id(chart_view, "addSubview:", lbl_eta);
        msg1_void_id(chart_view, "addSubview:", lbl_progress);

        let _ = GUI_HANDLES.set(Mutex::new(GuiHandles {
            state: Arc::clone(&state),
            btn_accounts: btn_accounts as usize,
            btn_proxies: btn_proxies as usize,
            txt_threads: txt_threads as usize,
            txt_proxy_url: txt_proxy_url as usize,
            btn_start: btn_start as usize,
            lbl_valid: lbl_valid as usize,
            lbl_invalid: lbl_invalid as usize,
            lbl_errors: lbl_errors as usize,
            lbl_elapsed: lbl_elapsed as usize,
            lbl_apm: lbl_apm as usize,
            lbl_eta: lbl_eta as usize,
            lbl_progress: lbl_progress as usize,
            chart_view: chart_view as usize,
        }));

        // 250 ms UI refresh timer
        let f_timer: extern "C" fn(
            *mut c_void,
            *mut c_void,
            f64,
            *mut c_void,
            *mut c_void,
            *mut c_void,
            bool,
        ) -> *mut c_void = std::mem::transmute(objc_msgSend as *const ());
        f_timer(
            cls("NSTimer"),
            sel("scheduledTimerWithTimeInterval:target:selector:userInfo:repeats:"),
            0.25,
            controller,
            sel("onTimerTick:"),
            ptr::null_mut(),
            true,
        );

        msg1_void_id(window, "makeKeyAndOrderFront:", ptr::null_mut());
        msg1_void_bool(app, "activateIgnoringOtherApps:", true);

        // Optionally preload an account list so the window opens with the
        // dump already counted (the load runs on a worker thread).
        if let Some(path) = preload {
            let st = Arc::clone(&state);
            thread::spawn(move || {
                let _ = st.load_accounts_from_path(std::path::Path::new(&path));
            });
        }

        msg0_void(app, "run");
    }
}
