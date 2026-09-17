//! Full-screen management of the current Sync Chain identity. Secrets never enter argv/history.
use crate::{
    app,
    service::{self, Action, TemporaryAgent},
    update,
};
use anyhow::{Context, Result, ensure};
use crossterm::{
    event::{
        self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Position, Rect},
    style::{Color, Style},
    widgets::{Block, List, ListState, Paragraph, Wrap},
};
use serde_json::Value;
use std::{
    io,
    path::Path,
    time::{Duration, Instant},
};
use wayfinder_core::{
    identity::{self, Role},
    protocol::Operation,
};
use zeroize::Zeroizing;

const SECTIONS: [&str; 7] = [
    "Overview",
    "Devices",
    "MCP Grants",
    "Browser pairing",
    "Gateway",
    "Agent",
    "Updates",
];
type Screen = Terminal<CrosstermBackend<io::Stdout>>;
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            io::stdout(),
            event::DisableMouseCapture,
            event::DisableBracketedPaste,
            LeaveAlternateScreen,
            crossterm::cursor::Show
        );
    }
}
fn safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}
fn value(v: &Value) -> String {
    match v {
        Value::String(s) => safe(s),
        Value::Array(a) => a.iter().map(value).collect::<Vec<_>>().join(", "),
        Value::Object(o) => o
            .iter()
            .map(|(k, v)| format!("{}: {}", k.replace('_', " "), value(v)))
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Null => "—".into(),
        _ => v.to_string(),
    }
}
fn details(v: &Value) -> String {
    value(v)
}
#[derive(Clone)]
enum Task {
    RevokeDevice(String),
    RevokeGrant(String),
    Pending(String),
    Approve(String, String),
    Gateway(String),
    Service(Action),
    Install,
    Enroll {
        name: String,
        gateway: String,
        admin: bool,
    },
}
enum Mode {
    Browse,
    Input(&'static str),
    Confirm(Task, String),
    Phrase(Task, bool),
}
// Targets are rebuilt from the rendered rectangles, including ListState's viewport.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hit {
    Section(usize),
    Row(usize),
    Key(KeyCode),
    List,
    Content,
}
#[derive(Default)]
struct Hits {
    regions: Vec<(Rect, Hit)>,
}
impl Hits {
    fn at(&self, mouse: MouseEvent) -> Option<Hit> {
        self.regions
            .iter()
            .rev()
            .find(|(rect, _)| rect.contains(Position::new(mouse.column, mouse.row)))
            .map(|(_, hit)| *hit)
    }
}

struct Ui {
    section: usize,
    rows: Vec<Value>,
    selected: ListState,
    focus: bool,
    status: Value,
    enrolled: bool,
    message: String,
    mode: Mode,
    input: Zeroizing<String>,
    update: Option<update::State>,
    owned: bool,
    scroll: u16,
    quit: bool,
    hits: Hits,
    busy: Option<bool>,
}
impl Ui {
    fn new() -> Self {
        Self {
            section: 0,
            rows: vec![],
            selected: ListState::default().with_selected(Some(0)),
            focus: false,
            status: Value::Null,
            enrolled: false,
            message: "Remote execution uses this OS account's permissions.".into(),
            mode: Mode::Browse,
            input: Zeroizing::new(String::new()),
            update: None,
            owned: false,
            scroll: 0,
            quit: false,
            hits: Hits::default(),
            busy: None,
        }
    }
    fn section(&mut self, section: usize) -> bool {
        self.focus = false;
        if self.section == section {
            return false;
        }
        self.section = section;
        self.scroll = 0;
        self.rows.clear();
        self.selected = ListState::default().with_selected(Some(0));
        true
    }
    fn select(&mut self, index: usize) {
        self.focus = true;
        let index = index.min(self.rows.len().saturating_sub(1));
        if self.selected.selected() != Some(index) {
            self.scroll = 0;
        }
        self.selected.select(Some(index));
    }
    fn mouse(&mut self, mouse: MouseEvent, fetch: &mut bool) -> Option<KeyCode> {
        let hit = self.hits.at(mouse)?;
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => match hit {
                Hit::Section(section) => {
                    *fetch |= self.section(section);
                    None
                }
                Hit::Row(index) => {
                    self.select(index);
                    None
                }
                Hit::Key(key) => Some(key),
                _ => None,
            },
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                let down = mouse.kind == MouseEventKind::ScrollDown;
                match hit {
                    Hit::List | Hit::Row(_) => {
                        let old = self.selected.selected().unwrap_or(0);
                        self.select(if down {
                            old.saturating_add(1)
                        } else {
                            old.saturating_sub(1)
                        });
                    }
                    Hit::Content => {
                        self.scroll = if down {
                            self.scroll.saturating_add(3)
                        } else {
                            self.scroll.saturating_sub(3)
                        }
                    }
                    _ => {}
                }
                None
            }
            _ => None,
        }
    }
    fn buttons(&mut self, f: &mut ratatui::Frame, area: Rect, buttons: &[(&str, KeyCode, bool)]) {
        // One row per action keeps even long labels usable in narrow terminals.
        for (row, (label, key, enabled)) in buttons.iter().enumerate() {
            if row >= usize::from(area.height) {
                break;
            }
            let rect = Rect::new(
                area.x,
                area.y + row as u16,
                area.width.min((label.len() + 4) as u16),
                1,
            );
            let enabled =
                *enabled && (self.busy.is_none() || (*key == KeyCode::Char('q') && !self.quit));
            f.render_widget(
                Paragraph::new(format!("[ {label} ]")).style(Style::default().fg(if enabled {
                    Color::Cyan
                } else {
                    Color::DarkGray
                })),
                rect,
            );
            if enabled {
                self.hits.regions.push((rect, Hit::Key(*key)));
            }
        }
    }
    fn refresh(&mut self, data: &Path, owned: bool) {
        self.enrolled = data.join("installation.json").exists();
        self.owned = owned;
        match app::status(data) {
            Ok(s) => self.status = s,
            Err(e) if self.enrolled => self.message = format!("Identity/status unavailable: {e:#}"),
            _ => {}
        }
    }
    fn prompt(&mut self, label: &'static str) {
        self.input = Zeroizing::new(String::new());
        self.scroll = 0;
        self.mode = Mode::Input(label);
    }
    fn confirm(&mut self, task: Task, text: String) {
        self.input = Zeroizing::new(String::new());
        self.scroll = 0;
        self.mode = Mode::Confirm(task, text);
    }
    fn draw(&mut self, terminal: &mut Screen) -> Result<()> {
        terminal.draw(|f| self.render(f))?;
        Ok(())
    }

    fn render(&mut self, f: &mut ratatui::Frame) {
        self.hits.regions.clear();
        let width = usize::from(f.area().width.saturating_sub(2).max(1));
        let notice_lines: usize = self
            .message
            .lines()
            .map(|line| line.chars().count().div_ceil(width).max(1))
            .sum();
        let area = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length((notice_lines + 3).clamp(4, 8) as u16),
            Constraint::Length(2),
        ])
        .split(f.area());
        let online = self.status["online"] == true;
        let running = self.status["agent_running"] == true;
        f.render_widget(
            Paragraph::new(format!(
                " WAYFINDER  {}    •    {}    •    Gateway {}",
                update::CURRENT,
                if !self.enrolled {
                    "Not enrolled"
                } else if running {
                    "Agent running"
                } else {
                    "Agent stopped"
                },
                if online { "● online" } else { "○ offline" }
            ))
            .style(Style::default().fg(Color::Cyan))
            .block(Block::bordered()),
            area[0],
        );
        let body = Layout::horizontal([Constraint::Length(22), Constraint::Min(10)]).split(area[1]);
        let names: Vec<&str> = if self.enrolled {
            SECTIONS.to_vec()
        } else {
            vec!["Create Sync Chain", "Join Sync Chain"]
        };
        let mut sections = ListState::default().with_selected(Some(self.section));
        let section_count = names.len();
        f.render_stateful_widget(
            List::new(names)
                .block(Block::bordered().title(" Sections "))
                .highlight_symbol("› ")
                .highlight_style(Style::default().fg(if self.focus {
                    Color::Gray
                } else {
                    Color::Cyan
                })),
            body[0],
            &mut sections,
        );
        let inner = Block::bordered().inner(body[0]);
        for row in 0..usize::from(inner.height).min(section_count.saturating_sub(sections.offset()))
        {
            self.hits.regions.push((
                Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
                Hit::Section(sections.offset() + row),
            ));
        }
        let actions = if !self.enrolled {
            vec![(
                if self.section == 0 {
                    "Create Sync Chain"
                } else {
                    "Join Sync Chain"
                },
                KeyCode::Enter,
                true,
            )]
        } else {
            match self.section {
                1 | 2 => vec![(
                    "Revoke selected (D)",
                    KeyCode::Char('d'),
                    !self.rows.is_empty(),
                )],
                3 => vec![("Look up pairing code (Enter)", KeyCode::Enter, true)],
                4 => vec![("Change gateway (Enter)", KeyCode::Enter, true)],
                5 => vec![
                    ("Start (S)", KeyCode::Char('s'), true),
                    ("Stop (X)", KeyCode::Char('x'), true),
                    ("Restart (T)", KeyCode::Char('t'), true),
                    ("Install automatic startup (I)", KeyCode::Char('i'), true),
                    ("Uninstall automatic startup (U)", KeyCode::Char('u'), true),
                ],
                6 => vec![
                    ("Check for updates (C)", KeyCode::Char('c'), true),
                    (
                        "Install update (I)",
                        KeyCode::Char('i'),
                        self.update.as_ref().is_some_and(|s| s.available()),
                    ),
                ],
                _ => vec![],
            }
        };
        let right =
            Layout::vertical([Constraint::Min(3), Constraint::Length(actions.len() as u16)])
                .split(body[1]);
        self.buttons(f, right[1], &actions);
        let content = if !self.enrolled {
            "Welcome to Wayfinder\n\nCreate a Sync Chain or join with your recovery phrase.\nUse a private, unrecorded terminal. Recovery words are never saved or copied.\n\nEnter to begin. Joining defaults to the member role.".into()
        } else {
            match self.section {
                0 => format!("Device       {}\nRole         {}\nDevice ID    {}\nSync Chain   {}\nGateway      {}\nObserved     {}\n\n{}\n\n{}", value(&self.status["name"]), value(&self.status["role"]), value(&self.status["device_id"]), value(&self.status["chain_id"]), value(&self.status["gateway"]), self.status["observed"].as_u64().map(|t|format!("{} seconds ago",wayfinder_core::now().saturating_sub(t))).unwrap_or("Not yet observed".into()), if self.owned {"Temporary agent • stops when this TUI exits"} else {"Attached agent • this TUI does not own it"}, self.update.as_ref().map(|s|s.message()).unwrap_or("Checking updates…".into())),
                3 => "Approve a browser pairing request\n\nEnter the pairing code from your browser. Review the client, redirect URI and exact requested scopes before approving.\n\nClient names are self-reported. exec permits shell commands with each agent's OS privileges.\n\nEnter: look up code".into(),
                4 => format!("Current gateway\n{}\n\nChanging gateway registers this identity at the new gateway. Revocations and MCP grants are gateway-local; a fresh gateway has neither.\n\nAn independently running agent must be stopped explicitly first.\n\nEnter: change gateway", value(&self.status["gateway"])),
                5 => format!("{}\nAutomatic startup installed: {}\n\nService changes apply only to the current OS user.\nStopping may interrupt active commands.", if self.owned {"Temporary agent owned by this TUI"} else {"External agents remain running on TUI exit"}, value(&self.status["service_installed"])),
                6 => format!("{}\n\nSource/package-manager installs retain their existing update owner.", self.update.as_ref().map(|s|s.message()).unwrap_or("Checking updates…".into())), _ => String::new() }
        };
        if self.enrolled && matches!(self.section, 1 | 2) {
            let panes = Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)])
                .split(right[0]);
            let rows: Vec<String> = self
                .rows
                .iter()
                .map(|r| {
                    format!(
                        "{}  {}  {}",
                        if r["online"] == true || r["active"] == true {
                            "●"
                        } else {
                            "○"
                        },
                        value(
                            r.get("name")
                                .or_else(|| r.get("client_name"))
                                .unwrap_or(&r["id"])
                        )
                        .replace('\n', " "),
                        if r["revoked"] == true || r["revoked"].is_u64() {
                            "REVOKED"
                        } else {
                            ""
                        }
                    )
                })
                .collect();
            f.render_stateful_widget(
                List::new(rows)
                    .block(Block::bordered().title(format!(
                        " {} • Tab focus • D revoke ",
                        SECTIONS[self.section]
                    )))
                    .highlight_symbol("› ")
                    .highlight_style(Style::default().fg(if self.focus {
                        Color::Cyan
                    } else {
                        Color::White
                    })),
                panes[0],
                &mut self.selected,
            );
            self.hits.regions.push((panes[0], Hit::List));
            let inner = Block::bordered().inner(panes[0]);
            for row in 0..usize::from(inner.height)
                .min(self.rows.len().saturating_sub(self.selected.offset()))
            {
                self.hits.regions.push((
                    Rect::new(inner.x, inner.y + row as u16, inner.width, 1),
                    Hit::Row(self.selected.offset() + row),
                ));
            }
            self.hits.regions.push((panes[1], Hit::Content));
            f.render_widget(
                Paragraph::new(
                    self.rows
                        .get(self.selected.selected().unwrap_or(0))
                        .map(details)
                        .unwrap_or("No entries loaded. R refreshes.".into()),
                )
                .wrap(Wrap { trim: false })
                .scroll((self.scroll, 0))
                .block(Block::bordered().title(" Details ")),
                panes[1],
            );
        } else {
            self.hits.regions.push((right[0], Hit::Content));
            f.render_widget(
                Paragraph::new(safe(&content))
                    .wrap(Wrap { trim: false })
                    .scroll((self.scroll, 0))
                    .block(Block::bordered().title(" Details ")),
                right[0],
            );
        }
        // The create screen contains recovery words: wipe temporary formatting buffers too.
        let prompt = Zeroizing::new(match &self.mode {
            Mode::Browse => safe(&self.message),
            Mode::Input(label) => format!(
                "{label}\n{}\nEnter continues • Esc cancels",
                self.input.as_str()
            ),
            Mode::Confirm(_, text) => format!(
                "{}\nType yes, then Enter to confirm • Esc cancels\n{}",
                safe(text),
                self.input.as_str()
            ),
            Mode::Phrase(_, create) => {
                if *create {
                    format!(
                        "Store these 24 recovery words securely offline. Anyone with them can enroll administrators.\n{}\nPress Enter after storing them to continue to explicit confirmation. Esc cancels.",
                        self.input.as_str()
                    )
                } else {
                    "24 recovery words (hidden)\nInput is hidden, including its length. Enter joins • Esc cancels".into()
                }
            }
        });
        if matches!(self.mode, Mode::Browse) {
            f.render_widget(
                Paragraph::new(prompt.as_str())
                    .wrap(Wrap { trim: false })
                    .block(Block::bordered().title(" Action / notice "))
                    .style(Style::default().fg(Color::Yellow)),
                area[2],
            );
        } else {
            let modal = ratatui::layout::Rect::new(
                area[1].x,
                area[1].y,
                area[1].width,
                area[1].height + area[2].height,
            );
            self.hits.regions.clear();
            self.hits.regions.push((modal, Hit::Content));
            f.render_widget(ratatui::widgets::Clear, modal);
            let parts = Layout::vertical([Constraint::Min(1), Constraint::Length(2)]).split(modal);
            let label = match self.mode {
                Mode::Confirm(..) => "Confirm",
                Mode::Phrase(_, false) => "Join",
                Mode::Phrase(_, true) => "I've stored it",
                _ => "Continue",
            };
            self.buttons(
                f,
                parts[1],
                &[
                    (label, KeyCode::Enter, true),
                    ("Cancel", KeyCode::Esc, true),
                ],
            );
            let modal_text =
                Zeroizing::new(format!("{}\n\n{}", prompt.as_str(), safe(&self.message)));
            f.render_widget(
                Paragraph::new(modal_text.as_str())
                    .wrap(Wrap { trim: false })
                    .scroll((self.scroll, 0))
                    .block(Block::bordered().title(" Action • PgUp/PgDn scroll • Esc cancel "))
                    .style(Style::default().fg(Color::Yellow)),
                parts[0],
            );
        }
        if self.busy.is_some() {
            self.hits
                .regions
                .retain(|(_, hit)| matches!(hit, Hit::Content));
        }
        let footer = Layout::horizontal([
            Constraint::Length(15),
            Constraint::Length(12),
            Constraint::Min(0),
        ])
        .split(area[3]);
        if matches!(self.mode, Mode::Browse) {
            self.buttons(f, footer[0], &[("Refresh (R)", KeyCode::Char('r'), true)]);
            self.buttons(f, footer[1], &[("Quit (Q)", KeyCode::Char('q'), true)]);
        }
        if self.busy == Some(true) {
            f.render_widget(
                Paragraph::new("[ Cancel ]").style(Style::default().fg(Color::Cyan)),
                footer[0],
            );
            self.hits.regions.push((
                Rect::new(footer[0].x, footer[0].y, footer[0].width.min(10), 1),
                Hit::Key(KeyCode::Esc),
            ));
        }
        f.render_widget(Paragraph::new("Click sections, rows & actions • Wheel scroll\n↑↓ Navigate • Tab Focus • Enter Select • PgUp/PgDn • Esc • Ctrl-C"), footer[2]);
    }
}

async fn remote(data: &Path, op: Operation) -> Result<Value> {
    let i = app::load(data)?;
    tokio::time::timeout(Duration::from_secs(12), wayfinder_agent::operation(&i, op))
        .await
        .context("Gateway timed out; refresh before retrying an action")?
}
async fn stop_owned(owned: &mut Option<TemporaryAgent>) -> Result<bool> {
    if let Some(agent) = owned.take() {
        agent.stop().await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
fn start_if_needed(data: &Path, owned: &mut Option<TemporaryAgent>) -> Result<()> {
    if owned.is_none() && data.join("installation.json").exists() && !service::agent_running(data)?
    {
        *owned = Some(TemporaryAgent::start(data)?);
    }
    Ok(())
}

pub async fn run(data: &Path) -> Result<()> {
    let _restore = Restore;
    terminal::enable_raw_mode()?;
    crossterm::execute!(
        io::stdout(),
        EnterAlternateScreen,
        event::EnableBracketedPaste,
        event::EnableMouseCapture
    )?;
    let mut screen = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut owned = None;
    let result = session(data, &mut screen, &mut owned).await;
    let stopped = stop_owned(&mut owned).await;
    result.and(stopped.map(|_| ()))
}

// Keep servicing the terminal during actions. Mutations finish before quitting so ownership
// and on-disk identity cannot be left half-transitioned by cancellation.
async fn busy<T>(
    ui: &mut Ui,
    screen: &mut Screen,
    cancellable: bool,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<(T, bool)> {
    ui.busy = Some(cancellable);
    ui.draw(screen)?;
    let result = busy_loop(ui, screen, cancellable, future).await;
    ui.busy = None;
    result
}
async fn busy_loop<T>(
    ui: &mut Ui,
    screen: &mut Screen,
    cancellable: bool,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<(T, bool)> {
    tokio::pin!(future);
    let mut quit = false;
    loop {
        tokio::select! {
            result = &mut future => return result.map(|v|(v,quit)),
            _ = app::stop_signal() => { quit = true; ui.quit = true; },
            _ = tokio::time::sleep(Duration::from_millis(50)) => {
                if event::poll(Duration::from_millis(1))? {
                    let key = match event::read()? {
                        Event::Key(k) if k.kind == KeyEventKind::Press => {
                            if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) { quit = true; ui.quit = true; }
                            Some(k.code)
                        }
                        Event::Mouse(m) => ui.mouse(m, &mut false),
                        _ => None,
                    };
                    if matches!(key, Some(KeyCode::Char('q' | 'Q'))) { quit = true; ui.quit = true; }
                    if cancellable && key == Some(KeyCode::Esc) { anyhow::bail!("Lookup canceled"); }
                    if key == Some(KeyCode::PageDown) { ui.scroll = ui.scroll.saturating_add(5); }
                    if key == Some(KeyCode::PageUp) { ui.scroll = ui.scroll.saturating_sub(5); }
                }
                if cancellable && quit { anyhow::bail!("Lookup canceled"); }
                if quit { ui.message = "Finishing the current action before safely exiting…".into(); }
                ui.draw(screen)?;
            }
        }
    }
}
async fn perform(
    data: &Path,
    task: Task,
    phrase: Zeroizing<String>,
    owned: &mut Option<TemporaryAgent>,
) -> Result<String> {
    match task {
        Task::RevokeDevice(id) => {
            remote(data, Operation::RevokeDevice { device_id: id }).await?;
        }
        Task::RevokeGrant(id) => {
            remote(data, Operation::RevokeGrant { grant_id: id }).await?;
        }
        Task::Approve(code, hash) => {
            remote(
                data,
                Operation::Approve {
                    code,
                    request_hash: hash,
                },
            )
            .await?;
            return Ok("Approved. Refresh the browser authorization page.".into());
        }
        Task::Gateway(url) => {
            identity::validate_gateway(&url)?;
            let restart = stop_owned(owned).await?;
            let result = async {
                let _lock = wayfinder_core::lock_dir(data)
                    .context("Stop the independently running agent before changing gateway")?;
                let mut i = app::load(data)?;
                i.gateway = url;
                tokio::time::timeout(Duration::from_secs(12), wayfinder_agent::register(&i))
                    .await??;
                wayfinder_core::atomic_write(&data.join("installation.json"), &i)
            }
            .await;
            if restart {
                *owned = Some(TemporaryAgent::start(data)?);
            }
            result?;
        }
        Task::Service(action) => match action {
            Action::Start if !service::installed(data)? => {
                ensure!(
                    !service::agent_running(data)?,
                    "An agent already owns this directory"
                );
                *owned = Some(TemporaryAgent::start(data)?);
            }
            Action::Stop if owned.is_some() => {
                stop_owned(owned).await?;
            }
            Action::Restart if owned.is_some() && !service::installed(data)? => {
                stop_owned(owned).await?;
                *owned = Some(TemporaryAgent::start(data)?);
            }
            _ => {
                let stopped_temporary =
                    if matches!(action, Action::Install | Action::Start | Action::Restart) {
                        stop_owned(owned).await?
                    } else {
                        false
                    };
                let path = data.to_owned();
                let result =
                    tokio::task::spawn_blocking(move || service::manage_quiet(&path, action))
                        .await
                        .context("Managed service action task failed")
                        .and_then(|result| result);
                if let Err(error) = result {
                    if stopped_temporary {
                        let recovery: Result<()> = async {
                            if matches!(action, Action::Start | Action::Restart) {
                                // A failed native command may still have queued startup/retries.
                                // Quiesce it before taking the directory lock back.
                                let path = data.to_owned();
                                tokio::task::spawn_blocking(move || {
                                    service::manage_quiet(&path, Action::Stop)
                                })
                                .await
                                .context("Managed service recovery stop task failed")??;
                                service::wait_stopped(data).await?;
                            }
                            if !service::agent_running(data)? {
                                *owned = Some(TemporaryAgent::start(data)?);
                            }
                            Ok(())
                        }
                        .await;
                        if let Err(recovery) = recovery {
                            return Err(error.context(format!(
                                "Temporary agent recovery also failed: {recovery:#}"
                            )));
                        }
                    }
                    return Err(error);
                }
            }
        },
        Task::Install => {
            update::ensure_owned()?;
            let restart = stop_owned(owned).await?;
            let result = update::install_quiet(data).await;
            if restart {
                start_if_needed(data, owned)?;
            }
            result?;
            return Ok("Updated. Quit and reopen Wayfinder to use the new version.".into());
        }
        Task::Enroll {
            name,
            gateway,
            admin,
        } => {
            let result = async {
                let _lock = wayfinder_core::lock_dir(data)?;
                ensure!(
                    !data.join("installation.json").exists(),
                    "An installation already exists"
                );
                tokio::time::timeout(
                    Duration::from_secs(12),
                    app::enroll(
                        data,
                        phrase.trim(),
                        name,
                        gateway,
                        if admin { Role::Admin } else { Role::Member },
                    ),
                )
                .await
                .context(
                    "Registration timed out; any saved identity will reconnect automatically",
                )?
            }
            .await;
            drop(phrase);
            start_if_needed(data, owned)?;
            result?;
        }
        Task::Pending(_) => unreachable!(),
    }
    Ok("Action completed. R refreshes the current view.".into())
}

async fn session(
    data: &Path,
    screen: &mut Screen,
    owned: &mut Option<TemporaryAgent>,
) -> Result<()> {
    let mut ui = Ui::new();
    if let Err(e) = start_if_needed(data, owned) {
        ui.message = format!("Agent startup: {e:#}");
    }
    ui.refresh(data, owned.is_some());
    let path = data.to_owned();
    let mut check = tokio::task::JoinSet::new();
    check.spawn(async move { update::check(&path, false).await });
    let mut lists: tokio::task::JoinSet<(usize, Result<Value>)> = tokio::task::JoinSet::new();
    let mut refresh = Instant::now();
    let mut fetch = false;
    let mut name = String::new();
    let mut gateway = String::new();
    let mut saved_phrase = Zeroizing::new(String::new());
    loop {
        if refresh.elapsed() >= Duration::from_secs(2) {
            ui.refresh(data, owned.is_some());
            refresh = Instant::now();
        }
        if let Some(result) = check.try_join_next() {
            match result {
                Ok(Ok(state)) => ui.update = Some(state),
                _ => ui.message = "Update check unavailable; agent operation unaffected.".into(),
            }
        }
        if let Some(result) = lists.try_join_next() {
            match result {
                Ok((section, Ok(v))) if section == ui.section => {
                    let selected_id = ui
                        .rows
                        .get(ui.selected.selected().unwrap_or(0))
                        .map(|r| r["id"].clone());
                    ui.rows = v
                        .as_array()
                        .context("Gateway returned an invalid list")?
                        .clone();
                    let pos = selected_id
                        .and_then(|id| ui.rows.iter().position(|r| r["id"] == id))
                        .unwrap_or(
                            ui.selected
                                .selected()
                                .unwrap_or(0)
                                .min(ui.rows.len().saturating_sub(1)),
                        );
                    ui.selected.select(Some(pos));
                    ui.message = format!(
                        "{} entries • Tab focuses list • D revokes selected entry",
                        ui.rows.len()
                    );
                }
                Ok((section, Err(e))) if section == ui.section => {
                    ui.message = format!("Gateway: {e:#}")
                }
                _ => {}
            }
        }
        if fetch && ui.enrolled && matches!(ui.section, 1 | 2) {
            lists.abort_all();
            let path = data.to_owned();
            let section = ui.section;
            lists.spawn(async move {
                (
                    section,
                    remote(
                        &path,
                        if section == 1 {
                            Operation::Devices
                        } else {
                            Operation::Grants
                        },
                    )
                    .await,
                )
            });
            ui.message = "Loading from gateway… (navigation remains available)".into();
        }
        fetch = false;
        ui.draw(screen)?;
        if !event::poll(Duration::from_millis(1))? {
            tokio::select! { _ = app::stop_signal() => break, _ = tokio::time::sleep(Duration::from_millis(50)) => {} }
            continue;
        }
        tokio::task::yield_now().await;
        let ev = event::read()?;
        let mut key = match ev {
            Event::Key(k) if k.kind == KeyEventKind::Press => {
                if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                    break;
                }
                k.code
            }
            Event::Mouse(mouse) => {
                // A resize can precede its queued event: redraw before interpreting coordinates.
                ui.draw(screen)?;
                match ui.mouse(mouse, &mut fetch) {
                    Some(key) => key,
                    None => continue,
                }
            }
            Event::Paste(mut text) => {
                if matches!(ui.mode, Mode::Input(_) | Mode::Phrase(_, false)) {
                    for c in text.chars().filter(|c| !c.is_control()) {
                        if ui.input.len() + c.len_utf8() <= 1024 {
                            ui.input.push(c);
                        }
                    }
                }
                zeroize::Zeroize::zeroize(&mut text);
                continue;
            }
            _ => continue,
        };
        if matches!(key, KeyCode::PageUp | KeyCode::PageDown) {
            ui.scroll = if key == KeyCode::PageDown {
                ui.scroll.saturating_add(5)
            } else {
                ui.scroll.saturating_sub(5)
            };
            continue;
        }
        if matches!(ui.mode, Mode::Browse)
            && let KeyCode::Char(c) = key
        {
            key = KeyCode::Char(c.to_ascii_lowercase());
        }
        let mut task = None;
        if key == KeyCode::Esc {
            ui.mode = Mode::Browse;
            ui.input = Zeroizing::new(String::new());
            saved_phrase = Zeroizing::new(String::new());
            continue;
        }
        match &ui.mode {
            Mode::Browse => match key {
                KeyCode::Char('q') => break,
                KeyCode::Tab | KeyCode::Left | KeyCode::Right => ui.focus = !ui.focus,
                KeyCode::Up | KeyCode::Down => {
                    let down = key == KeyCode::Down;
                    if ui.focus && matches!(ui.section, 1 | 2) && ui.enrolled {
                        let old = ui.selected.selected().unwrap_or(0);
                        ui.select(if down {
                            old.saturating_add(1)
                        } else {
                            old.saturating_sub(1)
                        });
                    } else {
                        let section = if down {
                            (ui.section + 1).min(if ui.enrolled { 6 } else { 1 })
                        } else {
                            ui.section.saturating_sub(1)
                        };
                        fetch |= ui.section(section);
                    }
                }
                KeyCode::Char('r') => {
                    ui.refresh(data, owned.is_some());
                    fetch = true;
                }
                KeyCode::Enter if ui.enrolled && matches!(ui.section, 1 | 2) => ui.focus = true,
                KeyCode::Enter if !ui.enrolled => ui.prompt("Device name"),
                KeyCode::Enter if ui.section == 3 => ui.prompt("Pairing code from your browser"),
                KeyCode::Enter if ui.section == 4 => ui.prompt("New gateway URL"),
                KeyCode::Char('d') if matches!(ui.section, 1 | 2) => {
                    if let Some(row) = ui.rows.get(ui.selected.selected().unwrap_or(0))
                        && let Some(id) = row["id"].as_str()
                    {
                        ui.confirm(
                            if ui.section == 1 {
                                Task::RevokeDevice(id.into())
                            } else {
                                Task::RevokeGrant(id.into())
                            },
                            format!(
                                "Permanently revoke {}? Active access may be interrupted.",
                                id
                            ),
                        );
                    }
                }
                KeyCode::Char(c) if ui.section == 5 => {
                    let action = match c {
                        's' => Some(Action::Start),
                        'x' => Some(Action::Stop),
                        't' => Some(Action::Restart),
                        'i' => Some(Action::Install),
                        'u' => Some(Action::Uninstall),
                        _ => None,
                    };
                    if let Some(action) = action {
                        ui.confirm(Task::Service(action), match action {
                            Action::Start => "Start the agent for this OS user?",
                            Action::Stop => "Stop the agent? Active commands may be interrupted.",
                            Action::Restart => "Restart the agent? Active commands may be interrupted.",
                            Action::Install => "Enable automatic startup for this OS user? The temporary agent will stop; active commands may be interrupted.",
                            Action::Uninstall => "Disable automatic startup and stop the managed agent? Active commands may be interrupted.",
                            Action::Status => unreachable!(),
                        }.into());
                    }
                }
                KeyCode::Char('c') if ui.section == 6 && check.is_empty() => {
                    let path = data.to_owned();
                    check.spawn(async move { update::check(&path, true).await });
                    ui.message = "Checking release channel…".into();
                }
                KeyCode::Char('i') if ui.section == 6 => {
                    if ui.update.as_ref().is_some_and(|s| s.available()) {
                        ui.confirm(Task::Install,"Install update? Active commands may be interrupted. Reopen Wayfinder afterward.".into());
                    } else {
                        ui.message = "No available update. C checks the release channel.".into();
                    }
                }
                _ => {}
            },
            Mode::Input(label) if key == KeyCode::Enter => {
                let text = ui.input.trim().to_owned();
                match *label {
                    "Device name" => match wayfinder_core::valid_name(&text) {
                        Ok(()) => {
                            name = text;
                            ui.prompt("Enrollment gateway URL (empty uses default)");
                        }
                        Err(e) => ui.message = e.to_string(),
                    },
                    "Enrollment gateway URL (empty uses default)" => {
                        gateway = if text.is_empty() {
                            identity::DEFAULT_GATEWAY.into()
                        } else {
                            text
                        };
                        if let Err(e) = identity::validate_gateway(&gateway) {
                            ui.message = e.to_string();
                        } else if ui.section == 1 {
                            ui.prompt("Role: member (default) or admin");
                        } else {
                            use rand::RngCore;
                            let mut entropy = Zeroizing::new([0u8; 32]);
                            rand::rngs::OsRng.fill_bytes(entropy.as_mut());
                            let mnemonic = bip39::Mnemonic::from_entropy(entropy.as_ref())?;
                            ui.input = Zeroizing::new(mnemonic.to_string());
                            ui.mode = Mode::Phrase(
                                Task::Enroll {
                                    name: name.clone(),
                                    gateway: gateway.clone(),
                                    admin: true,
                                },
                                true,
                            );
                        }
                    }
                    "Role: member (default) or admin" => {
                        if text.is_empty() || text == "member" || text == "admin" {
                            ui.input = Zeroizing::new(String::with_capacity(4096));
                            ui.mode = Mode::Phrase(
                                Task::Enroll {
                                    name: name.clone(),
                                    gateway: gateway.clone(),
                                    admin: text == "admin",
                                },
                                false,
                            );
                        } else {
                            ui.message = "Choose member or admin.".into();
                        }
                    }
                    "Pairing code from your browser" => {
                        task = Some(Task::Pending(text.to_uppercase()))
                    }
                    "New gateway URL" => {
                        if let Err(e) = identity::validate_gateway(&text) {
                            ui.message = e.to_string();
                        } else {
                            ui.confirm(Task::Gateway(text.clone()),format!("Move to {text}? Revocations and MCP grants are gateway-local. Temporary agent will restart; active commands may be interrupted."));
                        }
                    }
                    _ => {}
                }
            }
            Mode::Phrase(t, create) if key == KeyCode::Enter => {
                let t = t.clone();
                saved_phrase = std::mem::replace(&mut ui.input, Zeroizing::new(String::new()));
                if *create {
                    ui.confirm(t,"Have you stored the recovery phrase securely offline? It will not be shown again.".into());
                } else {
                    task = Some(t);
                }
            }
            Mode::Confirm(t, _) if key == KeyCode::Enter => {
                if ui.input.as_str() == "yes" {
                    task = Some(t.clone());
                } else {
                    ui.message = "Explicit confirmation requires typing yes.".into();
                }
            }
            Mode::Input(_) | Mode::Confirm(_, _) | Mode::Phrase(_, false) => match key {
                KeyCode::Backspace => {
                    ui.input.pop();
                }
                KeyCode::Char(c) if !c.is_control() && ui.input.len() + c.len_utf8() <= 1024 => {
                    ui.input.push(c)
                }
                _ => {}
            },
            _ => {}
        }
        if let Some(task) = task {
            ui.mode = Mode::Browse;
            ui.input = Zeroizing::new(String::new());
            ui.message = "Working…".into();
            let result = if let Task::Pending(code) = task {
                match busy(
                    &mut ui,
                    screen,
                    true,
                    remote(data, Operation::Pending { code: code.clone() }),
                )
                .await
                {
                    Ok((v, quit)) => {
                        if quit {
                            break;
                        }
                        let approval: wayfinder_core::oauth::Approval =
                            serde_json::from_value(v.clone())?;
                        let hash = wayfinder_core::digest(&serde_json::to_vec(&approval)?);
                        ui.confirm(Task::Approve(code, hash), format!("Gateway: {}\nSync Chain: {}\nClient is self-reported. exec allows shell commands as the agent OS user.\n{}", value(&ui.status["gateway"]), value(&ui.status["chain_id"]), details(&v)));
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            } else {
                let phrase = std::mem::replace(&mut saved_phrase, Zeroizing::new(String::new()));
                match busy(&mut ui, screen, false, perform(data, task, phrase, owned)).await {
                    Ok((message, quit)) => {
                        ui.message = message;
                        if quit {
                            break;
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            };
            if let Err(e) = result {
                ui.message = format!("Action failed: {e:#}");
            }
            if ui.quit {
                break;
            }
            ui.refresh(data, owned.is_some());
            if ui.enrolled && ui.section > 6 {
                ui.section = 0;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn mouse_at(rect: Rect, kind: MouseEventKind) -> MouseEvent {
        MouseEvent {
            kind,
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn mouse_targets_follow_viewport_resize_and_modal_exclusivity() {
        let mut ui = Ui::new();
        ui.enrolled = true;
        ui.section = 1;
        ui.rows = (0..40)
            .map(|i| serde_json::json!({"id":i.to_string(),"name":format!("Device {i}")}))
            .collect();
        ui.select(30);
        let mut terminal = Terminal::new(TestBackend::new(90, 25)).unwrap();
        terminal.draw(|f| ui.render(f)).unwrap();
        let (rect, hit) = *ui
            .hits
            .regions
            .iter()
            .find(|(_, hit)| matches!(hit, Hit::Row(_)))
            .unwrap();
        let Hit::Row(index) = hit else { unreachable!() };
        assert!(index > 0);
        let mut fetch = false;
        ui.mouse(
            mouse_at(rect, MouseEventKind::Down(MouseButton::Left)),
            &mut fetch,
        );
        assert_eq!(ui.selected.selected(), Some(index));
        ui.mouse(mouse_at(rect, MouseEventKind::ScrollDown), &mut fetch);
        assert_eq!(ui.selected.selected(), Some(index + 1));
        assert_eq!(ui.scroll, 0);
        let details = ui
            .hits
            .regions
            .iter()
            .find(|(_, hit)| *hit == Hit::Content)
            .unwrap()
            .0;
        ui.mouse(mouse_at(details, MouseEventKind::ScrollDown), &mut fetch);
        assert_eq!(ui.scroll, 3);
        assert_eq!(ui.selected.selected(), Some(index + 1));
        ui.confirm(Task::RevokeDevice("test".into()), "Revoke?".into());
        terminal.backend_mut().resize(60, 18);
        terminal.draw(|f| ui.render(f)).unwrap();
        assert!(ui.hits.regions.iter().all(|(rect, hit)| rect.right() <= 60
            && rect.bottom() <= 18
            && !matches!(hit, Hit::Section(_) | Hit::Row(_) | Hit::List)));
        let confirm = ui
            .hits
            .regions
            .iter()
            .find(|(_, hit)| *hit == Hit::Key(KeyCode::Enter))
            .unwrap()
            .0;
        assert_eq!(
            ui.mouse(
                mouse_at(confirm, MouseEventKind::Drag(MouseButton::Left)),
                &mut fetch
            ),
            None
        );
        assert_eq!(
            ui.mouse(
                mouse_at(confirm, MouseEventKind::Down(MouseButton::Right)),
                &mut fetch
            ),
            None
        );
        assert_eq!(
            ui.mouse(
                mouse_at(confirm, MouseEventKind::Down(MouseButton::Left)),
                &mut fetch
            ),
            Some(KeyCode::Enter)
        );
        assert!(ui.input.is_empty());
        assert!(matches!(ui.mode, Mode::Confirm(..)));
        ui.mode = Mode::Browse;
        ui.busy = Some(false);
        terminal.draw(|f| ui.render(f)).unwrap();
        assert!(
            ui.hits
                .regions
                .iter()
                .all(|(_, hit)| matches!(hit, Hit::Content | Hit::Key(KeyCode::Char('q'))))
        );
        ui.busy = Some(true);
        terminal.draw(|f| ui.render(f)).unwrap();
        assert!(
            ui.hits
                .regions
                .iter()
                .any(|(_, hit)| *hit == Hit::Key(KeyCode::Esc))
        );
    }

    #[test]
    fn hidden_phrase_never_enters_terminal_frames() {
        let mut ui = Ui::new();
        ui.mode = Mode::Phrase(
            Task::Enroll {
                name: "test".into(),
                gateway: identity::DEFAULT_GATEWAY.into(),
                admin: false,
            },
            false,
        );
        ui.input = Zeroizing::new("sensitive recovery input".into());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        for _ in 0..3 {
            terminal.draw(|f| ui.render(f)).unwrap();
            let text: String = terminal
                .backend()
                .buffer()
                .content
                .iter()
                .map(|c| c.symbol())
                .collect();
            assert!(text.contains("24 recovery words (hidden)"));
            assert!(!text.contains("sensitive"));
            assert!(!text.contains("recovery input"));
        }
    }

    #[test]
    fn drawing_and_scrolling_preserve_selection_and_confirmation() {
        let mut ui = Ui::new();
        ui.enrolled = true;
        ui.section = 1;
        ui.rows = vec![
            serde_json::json!({"id":"one","name":"First"}),
            serde_json::json!({"id":"two","name":"Second"}),
        ];
        ui.selected.select(Some(1));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|f| ui.render(f)).unwrap();
        assert_eq!(ui.selected.selected(), Some(1));
        ui.confirm(
            Task::RevokeDevice("two".into()),
            "Permanently revoke two?".into(),
        );
        assert!(ui.input.is_empty());
        ui.input.push_str("ye");
        ui.scroll = 3;
        terminal.draw(|f| ui.render(f)).unwrap();
        assert_eq!(ui.input.as_str(), "ye");
        assert_eq!(ui.selected.selected(), Some(1));
    }
}
