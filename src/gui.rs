//! Tray + egui popover UI.
//!
//! Build with `--features gui` for a plain window (all platforms).
//! Build with `--features gui-tray` for system tray + window (Windows/macOS;
//!   Linux additionally needs `sudo apt install libgtk-3-dev`).
//!
//! Architecture:
//!   main thread  → eframe event loop (required on macOS)
//!   bg threads   → tokio multi-thread runtime
//!   shared state → Arc<Stats>, Arc<AtomicBool> proxy_running
//!   control      → Mutex<Option<watch::Sender<bool>>> to stop/restart

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, FontId, RichText, TextStyle, Ui};

use crate::config::Config;
use crate::pool::WsPool;
use crate::stats::{human_bytes, Stats};
use crate::websocket;

// ── Colour palette ────────────────────────────────────────────────────────────

const BLUE: Color32 = Color32::from_rgb(51, 144, 236);
const GREEN: Color32 = Color32::from_rgb(39, 185, 111);
const RED: Color32 = Color32::from_rgb(230, 74, 74);
const GREY: Color32 = Color32::from_rgb(150, 157, 166);

// ── Proxy controller ──────────────────────────────────────────────────────────

pub struct Controller {
    rt: tokio::runtime::Handle,
    stop_tx: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
    pub running: Arc<AtomicBool>,
}

impl Controller {
    pub fn start(&self, config: Arc<Config>, stats: Arc<Stats>) {
        let tls = match websocket::build_tls_config(config.skip_tls_verify) {
            Ok(t) => Arc::new(t),
            Err(e) => {
                tracing::error!("TLS config failed: {}", e);
                return;
            }
        };
        let pool = Arc::new(WsPool::new());
        let (tx, rx) = tokio::sync::watch::channel(false);
        *self.stop_tx.lock().unwrap() = Some(tx);
        self.running.store(true, Relaxed);

        let running = Arc::clone(&self.running);
        self.rt.spawn(async move {
            pool.warmup(&config, Arc::clone(&tls)).await;
            let _ = crate::proxy::run(config, stats, tls, pool, rx).await;
            running.store(false, Relaxed);
        });
    }

    pub fn stop(&self) {
        if let Some(tx) = self.stop_tx.lock().unwrap().take() {
            let _ = tx.send(true);
        }
    }

    /// Stop current instance, then start a new one after a short pause.
    pub fn restart(self: &Arc<Self>, config: Arc<Config>, stats: Arc<Stats>) {
        self.stop();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(350)).await;
            this.start(config, stats);
        });
    }
}

// ── Tray abstraction (conditionally compiled) ─────────────────────────────────

#[cfg(feature = "gui-tray")]
mod tray {
    use tray_icon::{
        menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
        TrayIconBuilder, TrayIconEvent,
    };

    pub use tray_icon::menu::MenuId;

    pub struct Tray {
        _icon: tray_icon::TrayIcon,
        pub ids: Ids,
    }

    pub struct Ids {
        pub toggle: MenuId,
        pub restart: MenuId,
        pub open_tg: MenuId,
        pub quit: MenuId,
    }

    impl Tray {
        pub fn new() -> Self {
            let toggle = MenuItem::new("Show / Hide", true, None);
            let restart = MenuItem::new("Restart proxy", true, None);
            let open_tg = MenuItem::new("Open in Telegram…", true, None);
            let quit = MenuItem::new("Exit", true, None);

            let ids = Ids {
                toggle: toggle.id().clone(),
                restart: restart.id().clone(),
                open_tg: open_tg.id().clone(),
                quit: quit.id().clone(),
            };

            let menu = Menu::new();
            menu.append(&toggle).ok();
            menu.append(&PredefinedMenuItem::separator()).ok();
            menu.append(&restart).ok();
            menu.append(&open_tg).ok();
            menu.append(&PredefinedMenuItem::separator()).ok();
            menu.append(&quit).ok();

            let icon = make_icon(true);
            let _icon = TrayIconBuilder::new()
                .with_icon(icon)
                .with_tooltip("tg-proxy")
                .with_menu(Box::new(menu))
                .build()
                .expect("Failed to create system tray icon");

            Self { _icon, ids }
        }

        pub fn set_running(&self, running: bool) {
            let _ = self._icon.set_icon(Some(make_icon(running)));
            let tip = if running { "tg-proxy — running" } else { "tg-proxy — stopped" };
            let _ = self._icon.set_tooltip(Some(tip));
        }

        /// Poll all pending tray + menu events; returns a list of action tags.
        pub fn poll_events(&self) -> Vec<TrayAction> {
            let mut actions = Vec::new();
            while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
                if matches!(
                    ev,
                    TrayIconEvent::DoubleClick { .. } | TrayIconEvent::Click { .. }
                ) {
                    actions.push(TrayAction::ShowWindow);
                }
            }
            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                let id = &ev.id;
                if id == &self.ids.toggle {
                    actions.push(TrayAction::ShowWindow);
                } else if id == &self.ids.restart {
                    actions.push(TrayAction::Restart);
                } else if id == &self.ids.open_tg {
                    actions.push(TrayAction::OpenTg);
                } else if id == &self.ids.quit {
                    actions.push(TrayAction::Quit);
                }
            }
            actions
        }
    }

    pub enum TrayAction {
        ShowWindow,
        Restart,
        OpenTg,
        Quit,
    }

    fn make_icon(running: bool) -> tray_icon::Icon {
        let color: [u8; 4] = if running {
            [51, 144, 236, 255]
        } else {
            [120, 120, 120, 255]
        };
        let size = 32u32;
        let mut data = vec![0u8; (size * size * 4) as usize];
        let (cx, cy, r) = (size as i32 / 2, size as i32 / 2, size as i32 / 2 - 1);
        for y in 0..size as i32 {
            for x in 0..size as i32 {
                if (x - cx) * (x - cx) + (y - cy) * (y - cy) <= r * r {
                    let i = ((y as u32 * size + x as u32) * 4) as usize;
                    data[i..i + 4].copy_from_slice(&color);
                }
            }
        }
        tray_icon::Icon::from_rgba(data, size, size).expect("icon")
    }
}

// ── Cached stats ──────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
struct Cached {
    total: u64,
    ws: u64,
    tcp: u64,
    pool_hits: u64,
    pool_total: u64,
    bytes_up: u64,
    bytes_down: u64,
    errors: u64,
}
impl Cached {
    fn from(s: &Stats) -> Self {
        let hits = s.pool_hits.load(Relaxed);
        Self {
            total: s.total.load(Relaxed),
            ws: s.ws.load(Relaxed),
            tcp: s.tcp_fallback.load(Relaxed),
            pool_hits: hits,
            pool_total: hits + s.pool_misses.load(Relaxed),
            bytes_up: s.bytes_up.load(Relaxed),
            bytes_down: s.bytes_down.load(Relaxed),
            errors: s.ws_errors.load(Relaxed),
        }
    }
}

// ── egui App ──────────────────────────────────────────────────────────────────

pub struct TgProxyApp {
    stats: Arc<Stats>,
    ctrl: Arc<Controller>,
    config: Arc<Config>,

    #[cfg(feature = "gui-tray")]
    tray: tray::Tray,

    // form state
    host_str: String,
    port_str: String,
    dc_text: String,
    form_err: Option<String>,

    // live
    cached: Cached,
    last_refresh: Instant,
    status: Option<(String, bool, Instant)>, // (text, is_error, when)
}

impl TgProxyApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        config: Arc<Config>,
        stats: Arc<Stats>,
        ctrl: Arc<Controller>,
    ) -> Self {
        setup_visuals(&cc.egui_ctx);

        let dc_text = {
            let mut pairs: Vec<_> = config.dc_ips.iter().collect();
            pairs.sort_by_key(|&(dc, _)| *dc);
            pairs
                .iter()
                .map(|(dc, ip)| format!("{}:{}", dc, ip))
                .collect::<Vec<_>>()
                .join("\n")
        };

        Self {
            host_str: config.host.clone(),
            port_str: config.port.to_string(),
            dc_text,
            form_err: None,
            stats,
            ctrl,
            config,
            #[cfg(feature = "gui-tray")]
            tray: tray::Tray::new(),
            cached: Cached::default(),
            last_refresh: Instant::now() - Duration::from_secs(5),
            status: None,
        }
    }

    fn running(&self) -> bool {
        self.ctrl.running.load(Relaxed)
    }

    fn tg_url(&self) -> String {
        format!(
            "tg://socks?server={}&port={}",
            self.config.host, self.config.port
        )
    }

    fn set_status(&mut self, msg: impl Into<String>, err: bool) {
        self.status = Some((msg.into(), err, Instant::now()));
    }

    fn parse_form(&self) -> Result<Arc<Config>, String> {
        let host = self.host_str.trim().to_string();
        if std::net::IpAddr::from_str(&host).is_err() {
            return Err(format!("Invalid host IP: {:?}", host));
        }
        let port: u16 = self
            .port_str
            .trim()
            .parse()
            .map_err(|_| "Port must be 1–65535".to_string())?;
        if port == 0 {
            return Err("Port must be 1–65535".to_string());
        }
        let mut dc_ips: HashMap<u8, Ipv4Addr> = HashMap::new();
        for line in self.dc_text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (ds, is) = line
                .split_once(':')
                .ok_or_else(|| format!("Bad DC:IP {:?}", line))?;
            let dc: u8 = ds
                .trim()
                .parse()
                .map_err(|_| format!("Bad DC {:?}", ds))?;
            if !(1..=5).contains(&dc) {
                return Err(format!("DC must be 1–5, got {}", dc));
            }
            let ip =
                Ipv4Addr::from_str(is.trim()).map_err(|_| format!("Bad IP {:?}", is))?;
            dc_ips.insert(dc, ip);
        }
        if dc_ips.is_empty() {
            return Err("At least one DC:IP required".to_string());
        }
        Ok(Arc::new(Config {
            host,
            port,
            dc_ips,
            ..(*self.config).clone()
        }))
    }

    // ── draw ──────────────────────────────────────────────────────────────────

    fn draw(&mut self, ui: &mut Ui, ctx: &egui::Context) {
        ui.add_space(4.0);

        // ─ Header ─────────────────────────────────────────────────────────────
        ui.horizontal(|ui| {
            let running = self.running();
            ui.label(
                RichText::new(if running { "●" } else { "○" })
                    .size(18.0)
                    .color(if running { GREEN } else { GREY }),
            );
            ui.add_space(4.0);
            ui.label(RichText::new("tg-proxy").font(FontId::proportional(18.0)).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{}:{}", self.config.host, self.config.port))
                        .small()
                        .color(GREY),
                );
            });
        });
        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);

        // ─ Stats ──────────────────────────────────────────────────────────────
        let s = &self.cached;
        egui::Grid::new("stats_grid")
            .num_columns(2)
            .spacing([16.0, 4.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Connections").small().color(GREY));
                ui.label(format!(
                    "{}   WS {}   TCP {}   Err {}",
                    s.total, s.ws, s.tcp, s.errors
                ));
                ui.end_row();

                ui.label(RichText::new("Pool").small().color(GREY));
                if s.pool_total > 0 {
                    ui.label(format!(
                        "{}/{} hits ({:.0}%)",
                        s.pool_hits,
                        s.pool_total,
                        s.pool_hits as f64 / s.pool_total as f64 * 100.0,
                    ));
                } else {
                    ui.label("—");
                }
                ui.end_row();

                ui.label(RichText::new("Traffic").small().color(GREY));
                ui.label(format!(
                    "↑ {}   ↓ {}",
                    human_bytes(s.bytes_up),
                    human_bytes(s.bytes_down)
                ));
                ui.end_row();
            });

        ui.add_space(4.0);
        ui.separator();
        ui.add_space(2.0);

        // ─ Settings collapsible ───────────────────────────────────────────────
        egui::CollapsingHeader::new(RichText::new("⚙  Settings").small())
            .id_salt("settings")
            .show(ui, |ui| {
                egui::Grid::new("cfg_grid")
                    .num_columns(2)
                    .spacing([8.0, 6.0])
                    .show(ui, |ui| {
                        ui.label("Host");
                        ui.text_edit_singleline(&mut self.host_str);
                        ui.end_row();
                        ui.label("Port");
                        ui.text_edit_singleline(&mut self.port_str);
                        ui.end_row();
                    });
                ui.label(RichText::new("DC → IP  (one per line, format  DC:IP)").small().color(GREY));
                ui.add(
                    egui::TextEdit::multiline(&mut self.dc_text)
                        .font(TextStyle::Monospace)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY),
                );
                if let Some(err) = &self.form_err.clone() {
                    ui.colored_label(RED, err);
                }
                ui.add_space(4.0);
                if ui
                    .add(egui::Button::new(RichText::new("Apply & Restart").color(Color32::WHITE)).fill(BLUE))
                    .clicked()
                {
                    match self.parse_form() {
                        Ok(new_cfg) => {
                            self.form_err = None;
                            let stats = Arc::clone(&self.stats);
                            self.ctrl.restart(Arc::clone(&new_cfg), stats);
                            self.config = new_cfg;
                            self.set_status("Restarting…", false);
                        }
                        Err(e) => self.form_err = Some(e),
                    }
                }
            });

        ui.add_space(4.0);
        ui.separator();
        ui.add_space(4.0);

        // ─ Action buttons ─────────────────────────────────────────────────────
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(egui::Button::new(RichText::new("Open in Telegram").color(Color32::WHITE)).fill(BLUE))
                .on_hover_text(self.tg_url())
                .clicked()
            {
                let url = self.tg_url();
                if open::that(&url).is_ok() {
                    self.set_status("Opened in Telegram", false);
                } else {
                    self.set_status(format!("Copy link manually: {}", url), true);
                }
            }

            let running = self.running();
            if running {
                if ui.button("Stop").clicked() {
                    self.ctrl.stop();
                    self.set_status("Stopped", false);
                }
            } else if ui
                .add(egui::Button::new(RichText::new("Start").color(Color32::WHITE)).fill(GREEN))
                .clicked()
            {
                self.ctrl.start(Arc::clone(&self.config), Arc::clone(&self.stats));
                self.set_status("Starting…", false);
            }

            if ui.button("Restart").clicked() {
                self.ctrl.restart(Arc::clone(&self.config), Arc::clone(&self.stats));
                self.set_status("Restarting…", false);
            }

            // "Hide to tray" only makes sense when tray feature is active
            #[cfg(feature = "gui-tray")]
            if ui.button("Hide to tray").clicked() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        });

        // ─ Status message ─────────────────────────────────────────────────────
        if let Some((msg, is_err, when)) = self.status.clone() {
            if when.elapsed() < Duration::from_secs(4) {
                ui.add_space(4.0);
                ui.colored_label(if is_err { RED } else { GREEN }, &msg);
            } else {
                self.status = None;
            }
        }

        ui.add_space(4.0);

        // suppress unused warning when tray feature is off
        let _ = ctx;
    }
}

impl eframe::App for TgProxyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ─ Tray events (only when gui-tray is enabled) ─
        #[cfg(feature = "gui-tray")]
        {
            for action in self.tray.poll_events() {
                use tray::TrayAction::*;
                match action {
                    ShowWindow => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    Restart => {
                        let cfg = Arc::clone(&self.config);
                        let stats = Arc::clone(&self.stats);
                        self.ctrl.restart(cfg, stats);
                    }
                    OpenTg => {
                        open::that(self.tg_url()).ok();
                    }
                    Quit => {
                        self.ctrl.stop();
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
            // Update tray icon colour to reflect running state
            self.tray.set_running(self.running());
        }

        // ─ Intercept window-close → hide to tray (or just quit if no tray) ─
        if ctx.input(|i| i.viewport().close_requested()) {
            #[cfg(feature = "gui-tray")]
            {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
            // Without tray the close button just closes normally (no cancel).
        }

        // ─ Refresh stats ~1×/s ─
        if self.last_refresh.elapsed() > Duration::from_secs(1) {
            self.cached = Cached::from(&self.stats);
            self.last_refresh = Instant::now();
        }
        ctx.request_repaint_after(Duration::from_millis(500));

        // ─ Render ─
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| {
                self.draw(ui, ctx);
            });
        });
    }
}

// ── Visuals ───────────────────────────────────────────────────────────────────

fn setup_visuals(ctx: &egui::Context) {
    let mut v = egui::Visuals::light();
    let r = egui::CornerRadius::same(6);
    v.window_corner_radius = egui::CornerRadius::same(8);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;
    v.selection.bg_fill = BLUE;
    ctx.set_visuals(v);

    let mut style = (*ctx.style()).clone();
    style.spacing.button_padding = egui::vec2(10.0, 5.0);
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    ctx.set_style(style);
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Launch the GUI.  Blocks the calling thread (must be the main thread on macOS).
pub fn run_gui(config: Arc<Config>, stats: Arc<Stats>) -> anyhow::Result<()> {
    // Tokio runtime lives on background threads; main thread → eframe.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("tg-proxy-worker")
        .build()?;
    let handle = rt.handle().clone();

    // Park the runtime on its own thread so it stays alive.
    std::thread::Builder::new()
        .name("tokio-rt".into())
        .spawn(move || rt.block_on(std::future::pending::<()>()))
        .expect("failed to spawn tokio thread");

    let ctrl = Arc::new(Controller {
        rt: handle,
        stop_tx: Mutex::new(None),
        running: Arc::new(AtomicBool::new(false)),
    });
    ctrl.start(Arc::clone(&config), Arc::clone(&stats));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("tg-proxy")
            .with_inner_size([430.0, 370.0])
            .with_min_inner_size([360.0, 300.0])
            .with_resizable(true),
        ..Default::default()
    };

    eframe::run_native(
        "tg-proxy",
        options,
        Box::new(move |cc| {
            Ok(Box::new(TgProxyApp::new(
                cc,
                Arc::clone(&config),
                Arc::clone(&stats),
                ctrl,
            )))
        }),
    )
    .map_err(|e| anyhow::anyhow!("eframe: {}", e))
}
