package main

import (
	"errors"
	"flag"
	"time"

	vegeta "github.com/tsenart/vegeta/lib"
)

func attackCmd() command {
	fs := flag.NewFlagSet("vegeta attack", flag.ExitOnError)
	opts := &attackOpts{}

	opts.common.addFlags(fs)
	fs.DurationVar(&opts.duration, "duration", 0, "Duration of the test [0 = forever]")
	fs.Uint64Var(&opts.rate, "rate", 50, "Requests per second")

	return command{fs, func(args []string) error {
		fs.Parse(args)
		return attack(opts)
	}}
}

var (
	errZeroRate = errors.New("rate must be bigger than zero")
)

// attackOpts aggregates the attack function command options
type attackOpts struct {
	common   commonOpts
	duration time.Duration
	rate     uint64
}

// attack validates the attack arguments and invokes fight to
// launch the attack
func attack(opts *attackOpts) (err error) {
	if opts.rate == 0 {
		return errZeroRate
	}

	f := func(a *vegeta.Attacker, tr vegeta.Targeter) <-chan *vegeta.Result {
		return a.Attack(tr, opts.rate, opts.duration)
	}
	return fight(&opts.common, f)
}
