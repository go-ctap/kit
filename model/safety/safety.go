package safety

type Severity string

const SeverityInfo Severity = "info"
const SeverityWarning Severity = "warning"
const SeverityDestructive Severity = "destructive"

type Warning struct {
	Severity Severity `json:"severity"`
	Code     string   `json:"code"`
	Message  string   `json:"message"`
}

type PreviewMode string

const (
	PreviewModeDryRun  PreviewMode = "dry-run"
	PreviewModeExecute PreviewMode = "execute"
)
