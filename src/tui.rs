use crate::cve::CveMatchResult;
use crossterm::event::{
    self,
    Event,
    KeyCode,
    KeyEventKind,
};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode,
    enable_raw_mode,
    EnterAlternateScreen,
    LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{
    Constraint,
    Layout,
};
use ratatui::style::{
    Color,
    Modifier,
    Style,
};
use ratatui::text::Span;
use ratatui::widgets::{
    Block,
    Borders,
    Cell,
    Paragraph,
    Row,
    Table,
    TableState,
};
use ratatui::Terminal;
use std::io::{
    self,
    Stdout,
};

type TuiTerminal = Terminal<CrosstermBackend<Stdout>>;

fn severity_style(severity: &str) -> Style {
    match severity {
        "CRITICAL" => Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD),
        "HIGH" => Style::default().fg(Color::Red),
        "MEDIUM" => Style::default().fg(Color::Yellow),
        "LOW" => Style::default().fg(Color::Green),
        _ => Style::default().fg(Color::DarkGray),
    }
}

fn style_row<'a>(r: &'a CveMatchResult) -> Row<'a> {
    let date_str = r.published_date.trim_matches('"');
    let date_short = date_str.get(..10).unwrap_or(date_str);
    let sev_style = severity_style(&r.severity);
    Row::new(vec![
        Cell::from(Span::styled(&r.id, Style::default().fg(Color::Cyan))),
        Cell::from(date_short),
        Cell::from(Span::styled(&r.severity, sev_style)),
        Cell::from(r.problem_type.as_str()),
        Cell::from(r.description.as_str()),
    ])
}

fn header_row<'a>() -> Row<'a> {
    let header_style = Style::default()
        .fg(Color::White)
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    Row::new(vec![
        Cell::from("ID"),
        Cell::from("Date"),
        Cell::from("Severity"),
        Cell::from("Problem Type"),
        Cell::from("Description"),
    ])
    .style(header_style)
    .height(1)
}

pub fn run_tui(results: &[CveMatchResult]) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut state = TableState::default();
    if !results.is_empty() {
        state.select(Some(0));
    }

    let outcome = run_app(&mut terminal, results, &mut state);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    outcome
}

fn run_app(
    terminal: &mut TuiTerminal,
    results: &[CveMatchResult],
    state: &mut TableState,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| {
            let area = f.area();
            let chunks = Layout::vertical([
                Constraint::Length(1),
                Constraint::Min(1),
                Constraint::Length(1),
            ])
            .split(area);

            let title = Paragraph::new("CVE Match Results")
                .style(
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                )
                .alignment(ratatui::layout::Alignment::Center);
            f.render_widget(title, chunks[0]);

            let selected_style = Style::default().fg(Color::Black).bg(Color::LightBlue);

            let rows: Vec<Row> = results.iter().map(style_row).collect();
            let widths = [
                Constraint::Length(22),
                Constraint::Length(12),
                Constraint::Length(10),
                Constraint::Length(20),
                Constraint::Min(20),
            ];

            let table = Table::new(rows, widths)
                .header(header_row())
                .block(Block::default().borders(Borders::ALL).title(" Results "))
                .row_highlight_style(selected_style)
                .highlight_symbol(">> ");

            f.render_stateful_widget(table, chunks[1], state);

            let status = format!(
                "Row {}/{}  |  j/k: scroll  |  q: quit",
                state.selected().map_or(0, |i| i + 1),
                results.len()
            );
            let status_bar = Paragraph::new(status).style(Style::default().fg(Color::Green));
            f.render_widget(status_bar, chunks[2]);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Down | KeyCode::Char('j') => {
                        let i = state
                            .selected()
                            .map_or(0, |i| (i + 1).min(results.len().saturating_sub(1)));
                        state.select(Some(i));
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        let i = state.selected().map_or(0, |i| i.saturating_sub(1));
                        state.select(Some(i));
                    }
                    KeyCode::Home | KeyCode::Char('g') => state.select(Some(0)),
                    KeyCode::End | KeyCode::Char('G') => {
                        state.select(Some(results.len().saturating_sub(1)));
                    }
                    _ => {}
                }
            }
        }
    }
}
