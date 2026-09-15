//! A terminal client of the private control API. Lifecycle is managed by the caller.
use anyhow::Result;
use base64::{Engine, engine::general_purpose::STANDARD};
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use std::io::Write;
use std::time::{Duration, Instant};
use wayfinder_api::{Client, Operation};
enum Mode {
    Browse,
    Create,
    Join,
    ConfirmJoin(String),
    Remove(String),
}
struct Restore;
impl Drop for Restore {
    fn drop(&mut self) {
        let _ = crossterm::execute!(std::io::stdout(), event::DisableBracketedPaste);
        ratatui::restore();
    }
}
fn safe(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect()
}
pub async fn run(client: Client, stops_daemon_on_exit: bool) -> Result<()> {
    let mut status = client.status().await?;
    let mut terminal = ratatui::try_init()?;
    let _restore = Restore;
    crossterm::execute!(std::io::stdout(), event::EnableBracketedPaste)?;
    let mut invitation = String::new();
    let mut selected = ListState::default().with_selected(Some(0));
    let mut mode = Mode::Browse;
    let mut input = String::new();
    let mut message = String::from(if stops_daemon_on_exit {
        "Select a node for details. Q closes this TUI and stops its daemon."
    } else {
        "Select a node for details. Q closes this TUI; the daemon keeps running."
    });
    let mut applications = false;
    let mut service_text = String::new();
    let mut refreshed = Instant::now();
    'ui: loop {
        terminal.draw(|f|{
 let areas=Layout::vertical([Constraint::Length(3),Constraint::Min(4),Constraint::Length(4),Constraint::Length(8),Constraint::Length(2)]).split(f.area());
 let title=format!("Wayfinder     Network: {}\n{}",status.network_name.as_deref().unwrap_or("Standalone"),status.network_id.as_deref().unwrap_or("Create a network with N or join with J"));
 f.render_widget(Paragraph::new(title).block(Block::bordered()),areas[0]);
 let rows:Vec<ListItem>=status.nodes.iter().map(|n|ListItem::new(format!("{} {:<20} {:<15} {}",if n.reachable{"●"}else{"○"},safe(&n.name),if n.local{"This machine"}else{""},if n.reachable{"Reachable"}else{"Offline / unknown"}))).collect();
 if applications {
 f.render_widget(Paragraph::new(service_text.clone()).wrap(Wrap{trim:false}).block(Block::bordered().title("Applications / Services")),areas[1]);
 } else {
 f.render_stateful_widget(List::new(rows).block(Block::bordered().title("Nodes")).highlight_style(Style::default().fg(Color::Cyan)).highlight_symbol("› "),areas[1],&mut selected);
 }
 let reachable=status.nodes.iter().filter(|n|!n.local&&n.reachable).count();let peers=status.nodes.iter().filter(|n|!n.local).count();
 f.render_widget(Paragraph::new(format!("MCP  {}  {}\nPeers  {}  {reachable} / {peers} reachable{}",status.mcp_listen,if status.mcp_enabled {"Listening / bearer required"} else {"Disabled"},status.peer_listen,if status.conflict{"   MEMBERSHIP CONFLICT — peer execution blocked"}else{""})).block(Block::bordered().title("Connections")),areas[2]);
 let text=match &mode{Mode::Browse=>safe(&message),Mode::Create=>format!("Create network — enter a name, then Enter. Esc cancels.\n{input}"),Mode::Join=>format!("Paste invitation, then Enter to authenticate the inviter. Esc cancels.\n{input}"),Mode::ConfirmJoin(_)=>format!("{}\nJoin this network? Y confirms; Esc cancels.",safe(&message)),Mode::Remove(id)=>format!("Remove node {id}?\nThis revokes peer access after membership propagates. Y confirms; Esc cancels.")};
 f.render_widget(Paragraph::new(text).wrap(Wrap{trim:false}).block(Block::bordered().title("Network administration")),areas[3]);
 f.render_widget(Paragraph::new("↑↓ Select  Enter Details  A Add  R Remove  N Create  J Join  S Settings  V Services
C Copy invite (OSC 52)  Q Quit"),areas[4]);
 })?;
        if event::poll(Duration::from_millis(100))? {
            let ev = event::read()?;
            let key = match ev {
                Event::Key(k) if k.kind == KeyEventKind::Press => {
                    if k.code == KeyCode::Char('c')
                        && k.modifiers.contains(event::KeyModifiers::CONTROL)
                    {
                        break 'ui;
                    }
                    Some(k.code)
                }
                Event::Paste(text) => {
                    if matches!(mode, Mode::Join | Mode::Create) {
                        input.extend(
                            text.chars()
                                .filter(|c| !c.is_control())
                                .take(8192 - input.len().min(8192)),
                        );
                    }
                    None
                }
                _ => None,
            };
            if let Some(key) = key {
                let mut action = None;
                match &mode {
                    Mode::Browse => match key {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') if !invitation.is_empty() => {
                            print!("\x1b]52;c;{}\x07", STANDARD.encode(&invitation));
                            std::io::stdout().flush()?;
                            message="Invitation sent to terminal clipboard (OSC 52); paste it on the joining node. It expires after 10 minutes and works once.".into();
                        }
                        KeyCode::Down => {
                            selected.select(Some(
                                (selected.selected().unwrap_or(0) + 1)
                                    .min(status.nodes.len().saturating_sub(1)),
                            ));
                        }
                        KeyCode::Up => {
                            selected
                                .select(Some(selected.selected().unwrap_or(0).saturating_sub(1)));
                        }
                        KeyCode::Char('n') => {
                            mode = Mode::Create;
                            input.clear();
                        }
                        KeyCode::Char('j') => {
                            mode = Mode::Join;
                            input.clear();
                        }
                        KeyCode::Char('a') => action = Some(Operation::Invite { ttl: None }),
                        KeyCode::Enter => {
                            if let Some(n) = status.nodes.get(selected.selected().unwrap_or(0)) {
                                action = Some(Operation::Details { id: n.id.clone() });
                            }
                        }
                        KeyCode::Char('r') => {
                            if let Some(n) = status.nodes.get(selected.selected().unwrap_or(0)) {
                                if n.local {
                                    message =
                                        "Remove this node from another network member.".into();
                                } else {
                                    mode = Mode::Remove(n.id.clone());
                                }
                            }
                        }
                        KeyCode::Char('v') => {
                            applications = !applications;
                            if applications {
                                action = Some(Operation::Applications);
                            }
                        }
                        KeyCode::Char('s') => {
                            message = format!(
                                "Node: {}\nAdvertised peer endpoint: {}\nMembership revision: {}\nMCP authentication enabled; credentials are never shown here. Listener settings live in config.json; changing them requires a daemon restart. Linked descriptors are immutable.",
                                status.node.id, status.node.endpoint, status.revision
                            );
                        }
                        _ => {}
                    },
                    Mode::Create | Mode::Join => match key {
                        KeyCode::Esc => {
                            mode = Mode::Browse;
                            input.clear();
                        }
                        KeyCode::Backspace => {
                            input.pop();
                        }
                        KeyCode::Char(c) => {
                            if !c.is_control() && input.len() < 8192 {
                                input.push(c);
                            }
                        }
                        KeyCode::Enter => {
                            action = Some(if matches!(mode, Mode::Create) {
                                Operation::Create {
                                    name: input.clone(),
                                }
                            } else {
                                Operation::Preview {
                                    invitation: input.clone(),
                                }
                            });
                        }
                        _ => {}
                    },
                    Mode::ConfirmJoin(invitation) => match key {
                        KeyCode::Char('y') => {
                            action = Some(Operation::Join {
                                invitation: invitation.clone(),
                            })
                        }
                        KeyCode::Esc => mode = Mode::Browse,
                        _ => {}
                    },
                    Mode::Remove(id) => match key {
                        KeyCode::Char('y') => {
                            action = Some(Operation::Remove {
                                id: id.clone(),
                                confirm: true,
                            })
                        }
                        KeyCode::Esc => mode = Mode::Browse,
                        _ => {}
                    },
                }
                if let Some(op) = action {
                    let is_applications = matches!(op, Operation::Applications);
                    let preview = matches!(op, Operation::Preview { .. });
                    match client.call(op).await {
                        Ok(value) => {
                            if let Some(i) = value.get("invitation").and_then(|v| v.as_str()) {
                                invitation = i.to_owned();
                            }
                            message = serde_json::to_string_pretty(&value)?;
                            if is_applications {
                                service_text = serde_json::to_string_pretty(&value["active"])?;
                                message = "Live application registrations (read only). Applications register automatically. V returns to nodes.".into();
                            }
                            mode = if preview {
                                Mode::ConfirmJoin(input.clone())
                            } else {
                                input.clear();
                                Mode::Browse
                            };
                        }
                        Err(e) => {
                            message = e.to_string();
                            mode = Mode::Browse;
                            input.clear();
                        }
                    }
                    refreshed = Instant::now() - Duration::from_secs(3);
                }
            }
        }
        if refreshed.elapsed() >= Duration::from_secs(2) {
            match client.status().await {
                Ok(s) => {
                    status = s;
                    selected.select(Some(
                        selected
                            .selected()
                            .unwrap_or(0)
                            .min(status.nodes.len().saturating_sub(1)),
                    ));
                }
                Err(e) => message = format!("Daemon unavailable: {e}"),
            };
            refreshed = Instant::now();
        }
    }
    Ok(())
}
