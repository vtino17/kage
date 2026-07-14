package model

type Patch struct {
	FilePath    string `json:"file_path"`
	Original    string `json:"original"`
	Replacement string `json:"replacement"`
	FindingID   string `json:"finding_id"`
}

type FixProposal struct {
	Findings []Finding `json:"findings"`
	Patches  []Patch   `json:"patches"`
	Summary  string    `json:"summary"`
}

type PRRequest struct {
	Owner  string `json:"owner"`
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	Head   string `json:"head"`
	Base   string `json:"base"`
}
