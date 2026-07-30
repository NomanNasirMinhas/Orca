// Command orca is the unified AD attack-path mapping tool. This build ships the
// analysis pipeline and operator UI over an ingest/JSON dataset; network
// collectors (LDAP/ADCS) plug into the same ingest schema.
//
// Authorized red-team use only. Orca maps and advises; it does not execute
// exploits, and it keeps a hash-chained deconfliction log of its own activity.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"orca/internal/analysis"
	"orca/internal/api"
	"orca/internal/collect"
	ldapcoll "orca/internal/collect/ldap"
	"orca/internal/collect/transport"
	"orca/internal/graph"
	"orca/internal/importer"
	"orca/internal/ingest"
	"orca/internal/model"
	"orca/internal/opsec"
)

// stringSlice is a repeatable string flag (e.g. --seed A --seed B).
type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// newFlagSet returns a subcommand flag set that prints usage to stderr on error.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.SetOutput(os.Stderr)
	return fs
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "import":
		cmdImport(os.Args[2:])
	case "collect":
		cmdCollect(os.Args[2:])
	case "analyze":
		cmdAnalyze(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "profiles":
		cmdProfiles()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `orca — unified AD attack-path mapping (authorized red-team use only)

USAGE:
  orca import   [--bloodhound <zip|dir|json>]... [--ldapsearch <ldif>]...
                [--ldapdomaindump <json|dir>]... [--certipy <json>]...
                [--seed <SID>]... [--no-implicit] --out <dataset.json>
  orca collect  --dc <host> --domain <fqdn> --user <name> (--password <pw> | --nt-hash <hex>)
                [--ldaps] [--insecure] [--profile stealth|balanced|fast]
                [--seed <SID>]... --out <dataset.json>
  orca analyze  --data <dataset.json> [--objective practical|balanced|fastest|quietest|reliable]
  orca serve    --data <dataset.json> [--addr 127.0.0.1:8666] [--profile stealth|balanced|fast]
                [--seeds <sid1,sid2>] [--objective practical|balanced|fastest|quietest|reliable]
                [--deconflict-log <path>]
  orca profiles

`+"`import`"+` fuses output from BloodHound (SharpHound JSON/zip), ldapsearch (LDIF),
ldapdomaindump (domain_*.json), and Certipy (find -json) into one dataset.
`+"`collect`"+` authenticates to a DC over LDAP/LDAPS. Both write a dataset that
`+"`analyze`"+` and `+"`serve`"+` consume.
`)
}

func cmdProfiles() {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PROFILE\tDELAY\tMAX-NOISE\tMUTATE\tADWS\tHONEYTOKEN-AVOID")
	for _, name := range []string{"stealth", "balanced", "fast"} {
		p := opsec.Get(name)
		fmt.Fprintf(tw, "%s\t%v–%v\t%d\t%v\t%v\t%v\n",
			p.Name, p.MinDelay, p.MaxDelay, p.MaxNoise, p.MutateFilters, p.PreferADWS, p.AvoidHoneytokens)
	}
	tw.Flush()
}

func cmdImport(args []string) {
	fs := newFlagSet("import")
	var bh, ldif, ldd, certipy, seeds stringSlice
	fs.Var(&bh, "bloodhound", "BloodHound export (.zip, dir, or .json); repeatable")
	fs.Var(&ldif, "ldapsearch", "ldapsearch LDIF file; repeatable")
	fs.Var(&ldd, "ldapdomaindump", "ldapdomaindump JSON (domain_*.json file or dir); repeatable")
	fs.Var(&certipy, "certipy", "certipy find -json output; repeatable")
	fs.Var(&seeds, "seed", "foothold SID you control (repeatable)")
	noImplicit := fs.Bool("no-implicit", false, "do not add implicit Authenticated Users/Everyone/Domain Users memberships")
	out := fs.String("out", "", "output dataset JSON path")
	fs.Parse(args)

	if *out == "" {
		die("import: --out is required")
	}
	if len(bh)+len(ldif)+len(ldd)+len(certipy) == 0 {
		die("import: provide at least one of --bloodhound/--ldapsearch/--ldapdomaindump/--certipy")
	}

	var nodes []model.Node
	var facts []model.Fact
	absorb := func(src string, n []model.Node, f []model.Fact, err error) {
		if err != nil {
			die("import " + src + ": " + err.Error())
		}
		nodes = append(nodes, n...)
		facts = append(facts, f...)
		fmt.Printf("  %-12s +%d nodes, +%d facts\n", src, len(n), len(f))
	}

	// SID-based sources first, so Certipy names can resolve against them.
	for _, p := range bh {
		n, f, err := importer.ImportBloodHound(p)
		absorb("bloodhound", n, f, err)
	}
	for _, p := range ldif {
		fh, err := os.Open(p)
		if err != nil {
			die("import ldapsearch: " + err.Error())
		}
		n, f, err := importer.ImportLDIF(fh)
		fh.Close()
		absorb("ldapsearch", n, f, err)
	}
	for _, p := range ldd {
		n, f, err := importer.ImportLDAPDomainDump(p)
		absorb("ldapdomaindump", n, f, err)
	}
	// Certipy resolves principal names against everything gathered so far.
	resolver := importer.BuildResolver(nodes)
	for _, p := range certipy {
		fh, err := os.Open(p)
		if err != nil {
			die("import certipy: " + err.Error())
		}
		n, f, err := importer.ImportCertipy(fh, resolver)
		fh.Close()
		absorb("certipy", n, f, err)
	}

	if !*noImplicit {
		nodes, facts = importer.EnrichImplicitMembership(nodes, facts)
	}

	g := graph.New()
	for _, n := range nodes {
		g.AddNode(n)
	}
	for _, f := range facts {
		g.AddFact(f)
	}
	n, f := g.Stats()
	fmt.Printf("Merged dataset: %d nodes, %d facts. Foothold: %v\n", n, f, []string(seeds))
	if err := ingest.WriteFile(*out, ingest.Export(g, seeds)); err != nil {
		die("import: write output: " + err.Error())
	}
	fmt.Printf("Wrote %s. Next: orca serve --data %s\n", *out, *out)
}

func cmdCollect(args []string) {
	fs := newFlagSet("collect")
	dc := fs.String("dc", "", "domain controller host/IP")
	domain := fs.String("domain", "", "domain FQDN (e.g. corp.local)")
	user := fs.String("user", "", "username")
	password := fs.String("password", "", "password")
	ntHash := fs.String("nt-hash", "", "NT hash for pass-the-hash (hex)")
	ldaps := fs.Bool("ldaps", false, "use LDAPS (port 636)")
	insecure := fs.Bool("insecure", false, "skip TLS verification (lab use)")
	profile := fs.String("profile", "balanced", "OPSEC profile: stealth|balanced|fast")
	out := fs.String("out", "", "output dataset JSON path")
	operator := fs.String("operator", "operator", "operator id for the deconfliction log")
	logPath := fs.String("deconflict-log", "", "optional path to append the deconfliction log")
	var seeds stringSlice
	fs.Var(&seeds, "seed", "foothold SID you control (repeatable)")
	fs.Parse(args)

	if *dc == "" || *domain == "" || *user == "" || *out == "" {
		die("collect: --dc, --domain, --user and --out are required")
	}
	if *password == "" && *ntHash == "" {
		die("collect: provide --password or --nt-hash")
	}

	prof := opsec.Get(*profile)
	dlog := opsec.NewDeconflictLog(*logPath, *operator, *profile)
	dlog.Record("session.start", *dc, "orca collect")

	fmt.Printf("Connecting to %s (%s) as %s [profile=%s]...\n", *dc, *domain, *user, *profile)
	sess, err := transport.DialLDAP(transport.LDAPConfig{
		Host: *dc, Domain: *domain, Username: *user, Password: *password,
		NTHash: *ntHash, UseTLS: *ldaps, Insecure: *insecure,
	})
	if err != nil {
		die("collect: " + err.Error())
	}
	defer sess.Close()

	g := graph.New()
	runner := collect.Runner{Profile: prof, Log: dlog}
	res := runner.Run(context.Background(), sess, g, []collect.Collector{
		&ldapcoll.Collector{Profile: prof},
	})
	for name, e := range res.Errors {
		fmt.Fprintf(os.Stderr, "  collector %s: %v\n", name, e)
	}

	n, f := g.Stats()
	fmt.Printf("Collected %d nodes, %d facts (ran: %v, skipped: %v)\n", n, f, res.Ran, res.Skipped)
	if err := ingest.WriteFile(*out, ingest.Export(g, seeds)); err != nil {
		die("collect: write output: " + err.Error())
	}
	fmt.Printf("Wrote dataset to %s. Next: orca serve --data %s\n", *out, *out)
}

func cmdAnalyze(args []string) {
	fs := newFlagSet("analyze")
	data := fs.String("data", "", "path to collector-output dataset JSON")
	objective := fs.String("objective", "practical", "practical|balanced|fastest|quietest|reliable")
	fs.Parse(args)
	if *data == "" {
		die("analyze: --data is required")
	}

	g, seeds, err := ingest.LoadFile(*data)
	if err != nil {
		die("ingest: " + err.Error())
	}
	n, f := g.Stats()
	fmt.Printf("Loaded %d nodes, %d facts. Foothold: %v\n\n", n, f, seeds)

	eng := analysis.New()
	sol := eng.Solve(g.Facts(), seeds, analysis.Objective(*objective))
	sol.SetNames(g.Names())
	names := g.Names()
	nm := func(sid string) string {
		if x, ok := names[sid]; ok {
			return x
		}
		return sid
	}

	findings := sol.Findings()
	if len(findings) == 0 {
		fmt.Println("No exploitable paths to high-value targets found.")
		return
	}
	fmt.Printf("Found %d exploitable path(s) [objective=%s], most-exploitable first:\n", len(findings), *objective)
	for i, p := range findings {
		fmt.Printf("\n[%d] ⇒ %s  (cost %.2f, %d steps)\n", i+1, nm(p.Goal.A), p.TotalCost, len(p.Steps))
		for j, st := range p.Steps {
			esc := ""
			if st.ESC != "" {
				esc = " [" + st.ESC + "]"
			}
			edge := nm(st.Head.A)
			if st.Head.B != "" {
				edge += " → " + nm(st.Head.B)
			}
			fmt.Printf("   %d. %s%s\n      %s\n", j+1, st.Technique, esc, edge)
			if st.Command != "" {
				fmt.Printf("      $ %s\n", st.Command)
			}
		}
	}
}

func cmdServe(args []string) {
	fs := newFlagSet("serve")
	data := fs.String("data", "", "path to collector-output dataset JSON")
	addr := fs.String("addr", "127.0.0.1:8666", "listen address (localhost only recommended)")
	profile := fs.String("profile", "balanced", "OPSEC profile: stealth|balanced|fast")
	operator := fs.String("operator", "operator", "operator id for the deconfliction log")
	logPath := fs.String("deconflict-log", "", "optional path to append the deconfliction log")
	seedsFlag := fs.String("seeds", "", "comma-separated initial foothold SIDs (default: none; foothold is managed from the UI)")
	fs.Parse(args)
	if *data == "" {
		die("serve: --data is required")
	}

	// The dataset's own seeds are ignored: a fresh engagement starts with zero
	// foothold and the operator adds compromised accounts/machines from the UI.
	// --seeds pre-populates the foothold for scripted/headless runs.
	g, _, err := ingest.LoadFile(*data)
	if err != nil {
		die("ingest: " + err.Error())
	}
	var initSeeds []string
	if *seedsFlag != "" {
		initSeeds = strings.Split(*seedsFlag, ",")
	}
	dlog := opsec.NewDeconflictLog(*logPath, *operator, *profile)
	dlog.Record("session.start", *addr, "orca serve")

	srv := api.New(g, initSeeds, dlog)
	n, f := g.Stats()
	fmt.Printf("Orca serving %d nodes / %d facts on http://%s  (profile=%s)\n", n, f, *addr, *profile)
	fmt.Println("Open the address in your browser. Ctrl-C to stop.")
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		die("serve: " + err.Error())
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "orca: "+msg)
	os.Exit(1)
}
