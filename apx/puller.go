package apxapp

import "go.uber.org/zap"

// puller is a stub; Task 6 replaces it with the real config puller.
type puller struct{ started bool }

func newPuller(cfg PullerConfig, st *SharedState, log *zap.Logger) (*puller, error) {
	return &puller{}, nil
}
func (p *puller) start()        { p.started = true }
func (p *puller) stop()         { p.started = false }
func (p *puller) running() bool { return p != nil && p.started }
