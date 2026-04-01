package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

type setupModel struct {
	cursor int
	width  int
	steps  []string
	done   bool
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86"))
	focusStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	bodyStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

func main() {
	root := &cobra.Command{
		Use:   "__APP_SLUG__",
		Short: "__APP_TITLE__ CLI starter",
	}

	root.AddCommand(&cobra.Command{
		Use:   "setup",
		Short: "Open the onboarding surface",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !isInteractive(cmd.OutOrStdout(), os.Stdin) || os.Getenv("NO_COLOR") != "" {
				renderPlain(cmd.OutOrStdout())
				return nil
			}

			model := setupModel{
				steps: []string{
					"Pick the active workspace",
					"Validate local dependencies",
					"Create the first project profile",
				},
			}

			program := tea.NewProgram(model, tea.WithAltScreen())
			_, err := program.Run()
			return err
		},
	})

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func isInteractive(out io.Writer, in *os.File) bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	info, err := in.Stat()
	if err != nil {
		return false
	}
	_, outIsFile := out.(*os.File)
	return (info.Mode()&os.ModeCharDevice) != 0 && outIsFile
}

func renderPlain(w io.Writer) {
	fmt.Fprintln(w, "__APP_TITLE__ setup")
	fmt.Fprintln(w, "1. Pick the active workspace")
	fmt.Fprintln(w, "2. Validate local dependencies")
	fmt.Fprintln(w, "3. Create the first project profile")
}

func (m setupModel) Init() tea.Cmd {
	return nil
}

func (m setupModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.steps)-1 {
				m.cursor++
			}
		case "enter":
			if m.cursor == len(m.steps)-1 {
				m.done = true
				return m, tea.Quit
			}
			m.cursor++
		}
	}

	return m, nil
}

func (m setupModel) View() string {
	if m.done {
		return titleStyle.Render("__APP_TITLE__ ready") + "\n\n" +
			bodyStyle.Render("Next command: __APP_SLUG__ setup --help") + "\n"
	}

	var lines []string
	lines = append(lines, titleStyle.Render("__APP_TITLE__ onboarding"))
	lines = append(lines, mutedStyle.Render("Use j/k or arrows, Enter to continue, q to quit."))
	lines = append(lines, "")

	for i, step := range m.steps {
		prefix := "  "
		style := bodyStyle
		if i == m.cursor {
			prefix = "> "
			style = focusStyle
		}
		lines = append(lines, style.Render(prefix+step))
	}

	lines = append(lines, "")
	lines = append(lines, mutedStyle.Render(narrowHint(m.width)))
	return strings.Join(lines, "\n")
}

func narrowHint(width int) string {
	if width > 0 && width < 90 {
		return "Narrow mode: keep the primary action visible and remove decorative chrome first."
	}
	return "Primary action stays visible; plain fallback is available outside interactive terminals."
}
