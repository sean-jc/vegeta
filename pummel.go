package main

import (
	"errors"
	"flag"

	vegeta "github.com/tsenart/vegeta/lib"
)

func pummelCmd() command {
	fs := flag.NewFlagSet("vegeta pummel", flag.ExitOnError)
	opts := &pummelOpts{}

	fs.Uint64Var(&opts.hits, "hits", 100, "Total number of requests")
	opts.common.addFlags(fs)

	return command{fs, func(args []string) error {
		fs.Parse(args)
		return pummel(opts)
	}}
}

var (
	errZeroHits = errors.New("hits must be bigger than zero")
)

// pummelOpts aggregates the pummel function command options
type pummelOpts struct {
	common commonOpts
	hits   uint64
}

// pummel validates the pummel arguments and invokes fight to begin
// pummeling the target
func pummel(opts *pummelOpts) (err error) {
	if opts.hits == 0 {
		return errZeroHits
	}

	f := func(a *vegeta.Attacker, tr vegeta.Targeter) <-chan *vegeta.Result {
		return a.Pummel(tr, opts.hits)
	}
	return fight(&opts.common, f)
}
