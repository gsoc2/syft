package ui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"

	"github.com/anchore/bubbly/bubbles/taskprogress"
	"github.com/anchore/bubbly/bubbles/tree"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/event/monitor"
	syftEventParsers "github.com/anchore/syft/syft/event/parsers"
)

type taskModelFactory func(title taskprogress.Title, opts ...taskprogress.Option) taskprogress.Model

var _ tea.Model = (*catalogerTaskState)(nil)

type catalogerTaskState struct {
	model        tree.Model
	modelFactory taskModelFactory
}

func newCatalogerTaskState(f taskModelFactory) *catalogerTaskState {
	t := tree.NewModel()
	t.Padding = "   "
	t.RootsWithoutPrefix = true
	return &catalogerTaskState{
		modelFactory: f,
		model:        t,
	}
}

func (cts catalogerTaskState) Init() tea.Cmd {
	return cts.model.Init()
}

func (cts *catalogerTaskState) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return cts.model.Update(msg)
}

func (cts catalogerTaskState) View() string {
	return cts.model.View()
}

func (cts *catalogerTaskState) onCatalogerTaskStarted(info monitor.GenericTask, prog progress.StagedProgressable) tea.Cmd {
	if info.ID == "" {
		// ID is optional from the consumer perspective, but required internally
		info.ID = uuid.Must(uuid.NewRandom()).String()
	}

	var cmd tea.Cmd

	if !info.Hidden {
		tsk := cts.modelFactory(
			taskprogress.Title{
				Default: info.Title.Default,
				Running: info.Title.WhileRunning,
				Success: info.Title.OnSuccess,
			},
			taskprogress.WithStagedProgressable(prog),
		)

		if info.Context != "" {
			tsk.Context = []string{info.Context}
		}

		// TODO: this isn't ideal since the model stays around after it is no longer needed, but it works for now
		tsk.HideOnSuccess = info.HideOnSuccess
		tsk.HideStageOnSuccess = info.HideStageOnSuccess
		tsk.HideProgressOnSuccess = true

		if info.ParentID != "" {
			tsk.TitleStyle = lipgloss.NewStyle()
			// TODO: this is a hack to get the spinner to not show up, but ideally the component would support making the spinner optional
			// tsk.Spinner.Spinner.Frames = []string{" "}
		}

		cmd = tea.Batch(cmd, tsk.Init())

		if err := cts.model.Add(info.ParentID, info.ID, tsk); err != nil {
			log.WithFields("error", err).Error("unable to add cataloger task to tree model")
		}
	}

	return cmd
}

func (m *Handler) handleCatalogerTaskStarted(e partybus.Event) ([]tea.Model, tea.Cmd) {
	mon, info, err := syftEventParsers.ParseCatalogerTaskStarted(e)
	if err != nil {
		log.WithFields("error", err).Warn("unable to parse event")
		return nil, nil
	}

	var models []tea.Model
	if m.catalogerTasks == nil {
		m.catalogerTasks = newCatalogerTaskState(m.newTaskProgress)
		models = append(models, m.catalogerTasks)
	}

	cmd := m.catalogerTasks.onCatalogerTaskStarted(*info, mon)

	return models, cmd
}
