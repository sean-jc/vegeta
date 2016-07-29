package vegeta

import (
	"sync"
	"time"
)

// Pummel reads its Targets from the passed Targeter and hits them for a total
// number of attacks, or until Stop is called.  Results are put into the returned
// channel as soon as they arrive.
func (a *Attacker) Pummel(tr Targeter, hits uint64) <-chan *Result {
	var workers sync.WaitGroup
	results := make(chan *Result)

	// Ignore the remainder if hits is not a multiple of workers.
	for i := uint64(0); i < a.workers; i++ {
		go a.pummel(tr, &workers, hits/a.workers, results)
	}

	// We don't need to listen to the stop channel as we can simply wait for the
	// workers to finish as Pummel doesn't need to do any worker adjustment.
	go func() {
		defer close(results)
		workers.Wait()
	}()

	return results
}

func (a *Attacker) pummel(tr Targeter, workers *sync.WaitGroup, hits uint64, results chan<- *Result) {
	workers.Add(1)
	defer workers.Done()
	for i := uint64(0); i < hits; i++ {
		results <- a.hit(tr, time.Now())
	}
}
