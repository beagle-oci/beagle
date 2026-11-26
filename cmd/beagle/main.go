// Command beagle is a k9s-style terminal UI for OCI registries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/beagle-oci/beagle/internal/harbor"
	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/ui"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

const usage = `beagle - sniff around OCI registries

Usage:
  beagle [flags] <registry>[/<repository>[:<tag>|@<digest>]]

On Harbor, beagle lists projects via the Harbor API (no admin rights needed).

Examples:
  beagle ghcr.io/oras-project/oras
  beagle localhost:5050
  beagle --insecure harbor.example.com/library/nginx:1.27

Flags:
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "beagle:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("beagle", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	plainHTTP := fs.Bool("plain-http", false, "use HTTP instead of HTTPS (default for localhost)")
	forceHTTPS := fs.Bool("https", false, "force HTTPS, even for localhost")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	noHarbor := fs.Bool("no-harbor", false, "do not use the Harbor API, even if the registry is Harbor")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Println("beagle", version)
		return nil
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("expected exactly one registry argument")
	}

	host, repo, ref := parseTarget(fs.Arg(0))
	plain := *plainHTTP || (oci.IsLoopbackHost(host) && !*forceHTTPS)

	client, err := oci.New(host, oci.Options{
		PlainHTTP: plain,
		Insecure:  *insecure,
		UserAgent: "beagle/" + version,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		if oci.IsUnauthorized(err) {
			return fmt.Errorf("%s requires authentication, run 'docker login %s' (or 'oras login') first: %w", host, host, err)
		}
		return fmt.Errorf("cannot reach registry %s: %w", host, err)
	}

	var hc *harbor.Client
	if !*noHarbor {
		hc = detectHarbor(ctx, client)
	}

	app := ui.New(ui.Options{Client: client, Harbor: hc, Version: version, Repository: repo, Reference: ref})
	_, err = tea.NewProgram(app, tea.WithAltScreen()).Run()
	return err
}

// detectHarbor returns a Harbor API client if the registry is Harbor, and
// nil otherwise. Detection problems are not fatal: beagle then falls back to
// the catalog API.
func detectHarbor(ctx context.Context, client *oci.Client) *harbor.Client {
	cred := func(ctx context.Context) (string, string, error) {
		c, err := client.Credential(ctx)
		return c.Username, c.Password, err
	}
	hc, err := harbor.Detect(ctx, client.BaseURL(), client.HTTPClient(), cred)
	if err != nil {
		return nil
	}
	hc.UserAgent = "beagle/" + version
	return hc
}

// parseTarget splits "host/repo:tag" into its parts. The repository and
// reference are optional.
func parseTarget(s string) (host, repo, ref string) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	host, rest, _ := strings.Cut(s, "/")
	if rest == "" {
		return host, "", ""
	}
	if i := strings.Index(rest, "@"); i >= 0 {
		return host, rest[:i], rest[i+1:]
	}
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "/") {
		return host, rest[:i], rest[i+1:]
	}
	return host, rest, ""
}
