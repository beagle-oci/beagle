// Command beagle is a k9s-style terminal UI for OCI registries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/beagle-oci/beagle/internal/dockerhub"
	"github.com/beagle-oci/beagle/internal/harbor"
	"github.com/beagle-oci/beagle/internal/meta"
	"github.com/beagle-oci/beagle/internal/oci"
	"github.com/beagle-oci/beagle/internal/sigverify"
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
	opts, err := setup(os.Args[1:], os.Stdout, os.Stderr)
	if errors.Is(err, errDone) {
		return
	}
	if err == nil {
		_, err = tea.NewProgram(ui.New(opts), tea.WithAltScreen()).Run()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "beagle:", err)
		os.Exit(1)
	}
}

// errDone tells main that setup already handled the invocation (--help,
// --version) and there is nothing to start.
var errDone = errors.New("done")

// setup parses the arguments, connects to the registry and returns the UI
// options. It does everything except starting the TUI, so it can be tested.
func setup(args []string, stdout, stderr io.Writer) (ui.Options, error) {
	fs := flag.NewFlagSet("beagle", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	plainHTTP := fs.Bool("plain-http", false, "use HTTP instead of HTTPS (default for localhost)")
	forceHTTPS := fs.Bool("https", false, "force HTTPS, even for localhost")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	noHarbor := fs.Bool("no-harbor", false, "do not use the Harbor API, even if the registry is Harbor")
	noVerify := fs.Bool("no-verify", false, "do not verify cosign signatures")
	sigstoreRoot := fs.String("sigstore-root", "", "verify against this `trusted_root.json` instead of the Sigstore public-good instance")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ui.Options{}, errDone
		}
		return ui.Options{}, err
	}
	if *showVersion {
		fmt.Fprintln(stdout, "beagle", version)
		return ui.Options{}, errDone
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return ui.Options{}, errors.New("expected exactly one registry argument")
	}

	verifier, err := newVerifier(*noVerify, *sigstoreRoot)
	if err != nil {
		return ui.Options{}, err
	}

	host, repo, ref := parseTarget(fs.Arg(0))
	plain := *plainHTTP || (oci.IsLoopbackHost(host) && !*forceHTTPS)

	client, err := oci.New(host, oci.Options{
		PlainHTTP: plain,
		Insecure:  *insecure,
		UserAgent: "beagle/" + version,
	})
	if err != nil {
		return ui.Options{}, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		if oci.IsUnauthorized(err) {
			return ui.Options{}, fmt.Errorf("%s requires authentication, run 'docker login %s' (or 'oras login') first: %w", host, host, err)
		}
		return ui.Options{}, fmt.Errorf("cannot reach registry %s: %w", host, err)
	}

	var hc *harbor.Client
	if !*noHarbor {
		hc = detectHarbor(ctx, client)
	}

	return ui.Options{
		Client:     client,
		Harbor:     hc,
		Metadata:   selectProvider(client, hc),
		Verifier:   verifier,
		Version:    version,
		Repository: repo,
		Reference:  ref,
	}, nil
}

// newVerifier sets up cosign signature verification: against the Sigstore
// public-good instance by default, a trusted_root.json if given, or not at
// all.
func newVerifier(disabled bool, trustedRoot string) (*sigverify.Verifier, error) {
	switch {
	case disabled && trustedRoot != "":
		return nil, errors.New("--no-verify and --sigstore-root exclude each other")
	case disabled:
		return nil, nil
	case trustedRoot != "":
		return sigverify.NewFromFile(trustedRoot)
	}
	return sigverify.NewPublicGood(), nil
}

// selectProvider picks the vendor API that adds push/pull times and scan
// results to the tag list, or nil for registries without one.
func selectProvider(client *oci.Client, hc *harbor.Client) meta.Provider {
	switch {
	case hc != nil:
		return hc
	case client.Host() == "docker.io":
		hub := dockerhub.New(client.HTTPClient())
		hub.UserAgent = "beagle/" + version
		return hub
	}
	return nil
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
