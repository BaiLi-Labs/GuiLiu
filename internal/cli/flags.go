package cli

import (
	"flag"
	"io"
	"strconv"
	"time"
)

// flagDef is the machine-readable description emitted by `query --describe`.
// The same registration call records the definition, so help output and the
// skill reference do not drift from the flags the binary actually accepts.
type flagDef struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Default string `json:"default,omitempty"`
	Usage   string `json:"usage"`
}

type flagSet struct {
	*flag.FlagSet
	defs []flagDef
}

func newFlagSet(name string, out io.Writer) *flagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(out)
	return &flagSet{FlagSet: fs}
}

func (f *flagSet) note(name, typ, def, usage string) {
	f.defs = append(f.defs, flagDef{Name: name, Type: typ, Default: def, Usage: usage})
}

func (f *flagSet) String(p *string, name, def, usage string) {
	f.FlagSet.StringVar(p, name, def, usage)
	f.note(name, "string", def, usage)
}

func (f *flagSet) Int(p *int, name string, def int, usage string) {
	f.FlagSet.IntVar(p, name, def, usage)
	f.note(name, "int", strconv.Itoa(def), usage)
}

func (f *flagSet) Int64(p *int64, name string, def int64, usage string) {
	f.FlagSet.Int64Var(p, name, def, usage)
	f.note(name, "int64", strconv.FormatInt(def, 10), usage)
}

func (f *flagSet) Bool(p *bool, name string, def bool, usage string) {
	f.FlagSet.BoolVar(p, name, def, usage)
	if def {
		f.note(name, "bool", "true", usage)
		return
	}
	f.note(name, "bool", "", usage)
}

func (f *flagSet) Duration(p *time.Duration, name string, def time.Duration, usage string) {
	f.FlagSet.DurationVar(p, name, def, usage)
	f.note(name, "duration", def.String(), usage)
}

func (f *flagSet) Changed(name string) bool {
	changed := false
	f.FlagSet.Visit(func(fl *flag.Flag) {
		if fl.Name == name {
			changed = true
		}
	})
	return changed
}
