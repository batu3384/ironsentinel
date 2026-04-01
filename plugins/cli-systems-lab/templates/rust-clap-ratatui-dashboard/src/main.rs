use std::error::Error;
use std::io::{self, stdout, IsTerminal};

use clap::{Parser, Subcommand};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;

#[derive(Parser)]
#[command(name = "__APP_SLUG__", about = "__APP_TITLE__ CLI starter")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Dashboard,
}

struct App {
    selected: usize,
    items: Vec<&'static str>,
}

impl App {
    fn new() -> Self {
        Self {
            selected: 0,
            items: vec![
                "Review the active workspace",
                "Validate local dependencies",
                "Start the first scan",
            ],
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    match cli.command {
        Command::Dashboard => run_dashboard(),
    }
}

fn run_dashboard() -> Result<(), Box<dyn Error>> {
    if std::env::var("NO_COLOR").is_ok() || !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        print_plain();
        return Ok(());
    }

    enable_raw_mode()?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen)?;
    let backend = ratatui::backend::CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();

    let result = run_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn Error>> {
    loop {
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(5), Constraint::Length(3)])
                .split(frame.area());

            let header = Paragraph::new("__APP_TITLE__ operator cockpit")
                .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .block(Block::default().borders(Borders::ALL).title("Header"));
            frame.render_widget(header, areas[0]);

            let items: Vec<ListItem> = app
                .items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let prefix = if index == app.selected { "> " } else { "  " };
                    let style = if index == app.selected {
                        Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    ListItem::new(Line::from(vec![Span::styled(format!("{prefix}{item}"), style)]))
                })
                .collect();

            let list = List::new(items).block(Block::default().borders(Borders::ALL).title("Actions"));
            frame.render_widget(list, areas[1]);

            let footer = Paragraph::new("q quit | j/k move | plain fallback outside TTY")
                .block(Block::default().borders(Borders::ALL).title("Keys"));
            frame.render_widget(footer, areas[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            match key.code {
                KeyCode::Char('q') => return Ok(()),
                KeyCode::Char('j') | KeyCode::Down => {
                    if app.selected + 1 < app.items.len() {
                        app.selected += 1;
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if app.selected > 0 {
                        app.selected -= 1;
                    }
                }
                _ => {}
            }
        }
    }
}

fn print_plain() {
    println!("__APP_TITLE__ dashboard");
    println!("1. Review the active workspace");
    println!("2. Validate local dependencies");
    println!("3. Start the first scan");
}
