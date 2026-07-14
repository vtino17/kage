package scanner

import "github.com/vtino17/kage/internal/model"

type Result struct {
	ScannerName string
	Findings    []model.Finding
	Error       error
}

type Scanner interface {
	Name() string
	Scan(targetPath string) (*Result, error)
}
