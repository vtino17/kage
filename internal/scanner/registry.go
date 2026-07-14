package scanner

import (
	"sync"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

type Registry struct {
	scanners []Scanner
}

func NewRegistry() *Registry {
	return &Registry{scanners: make([]Scanner, 0)}
}

func (r *Registry) Register(s Scanner) {
	r.scanners = append(r.scanners, s)
}

func (r *Registry) Names() []string {
	names := make([]string, len(r.scanners))
	for i, s := range r.scanners {
		names[i] = s.Name()
	}
	return names
}

func (r *Registry) RunAll(targetPath string) ([]Result, []string) {
	var (
		mu      sync.Mutex
		results []Result
		errors  []string
		g       errgroup.Group
	)

	for _, s := range r.scanners {
		s := s
		g.Go(func() error {
			log.Info().Str("scanner", s.Name()).Msg("scanning")
			result, err := s.Scan(targetPath)
			mu.Lock()
			if err != nil {
				errors = append(errors, s.Name()+": "+err.Error())
			} else {
				results = append(results, *result)
			}
			mu.Unlock()
			return nil
		})
	}

	_ = g.Wait()
	return results, errors
}
