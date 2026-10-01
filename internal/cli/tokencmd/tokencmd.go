// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

// Package tokencmd implements "portholed token create|list|revoke". The commands operate directly on the
// server's SQLite database, which is safe while the server runs (DESIGN.md §3.3).
package tokencmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/config"
	"github.com/eto-a/porthole/internal/store"
)

const (
	// opTimeout bounds one command's database work.
	opTimeout = 30 * time.Second

	// maxExpiresDays keeps now+expires far from time overflow.
	maxExpiresDays = 36500

	// liveSessionGrace is how long the server may take to close sessions of a revoked token (DESIGN.md §3.3).
	liveSessionGrace = "~30 seconds"

	timeLayout = "2006-01-02 15:04"
)

// New returns the "token" command. load is called lazily, only when a subcommand runs.
func New(load func() (*config.Config, error)) *cobra.Command {
	return newCmd(load, time.Now)
}

// env is what the subcommands share.
type env struct {
	load func() (*config.Config, error)
	now  func() time.Time
}

// open loads the configuration and opens the store.
func (e *env) open(cmd *cobra.Command) (*config.Config, *store.SQLite, context.Context, context.CancelFunc, error) {
	cfg, err := e.load()
	if err != nil {
		return nil, nil, nil, nil, exitcode.ConfigError(fmt.Errorf("load config: %w", err))
	}
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, opTimeout)
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		cancel()
		return nil, nil, nil, nil, fmt.Errorf("open database: %w", err)
	}
	return cfg, st, ctx, cancel, nil
}

func newCmd(load func() (*config.Config, error), now func() time.Time) *cobra.Command {
	e := &env{load: load, now: now}
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Manage client tokens",
		Long: "Manage client tokens. The commands work directly on the server's database, so they can be used\n" +
			"while the server is running.",
	}
	cmd.AddCommand(e.createCmd(), e.listCmd(), e.revokeCmd())
	return cmd
}

// parseExpires parses an expiry duration: "" and "0" mean never (returns 0); otherwise a count of days with
// suffix "d" (30d, 1.5d) or anything time.ParseDuration accepts (720h). Negative values are rejected.
func parseExpires(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseFloat(days, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, fmt.Errorf("invalid duration %q: want e.g. 30d, 720h or 0", s)
		}
		if n < 0 {
			return 0, fmt.Errorf("invalid duration %q: must not be negative", s)
		}
		if n > maxExpiresDays {
			return 0, fmt.Errorf("invalid duration %q: more than %d days", s, maxExpiresDays)
		}
		d := time.Duration(n * float64(24*time.Hour))
		if d <= 0 {
			return 0, fmt.Errorf("invalid duration %q: too small", s)
		}
		return d, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: want e.g. 30d, 720h or 0", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("invalid duration %q: must not be negative", s)
	}
	if d > maxExpiresDays*24*time.Hour {
		return 0, fmt.Errorf("invalid duration %q: more than %d days", s, maxExpiresDays)
	}
	return d, nil
}

// validateScopes checks and de-duplicates scopes, keeping the order.
func validateScopes(in []string) ([]string, error) {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if !auth.ValidScope(s) {
			return nil, fmt.Errorf("invalid --scopes: unknown scope %q (known: %s)", s, strings.Join(auth.DefaultScopes, ", "))
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("invalid --scopes: at least one scope is required")
	}
	return out, nil
}

// loginURL is the server URL for the "porthole login" hint: server_url when set, else derived from the public settings.
func loginURL(cfg *config.Config) string {
	if u := cfg.ClientURL(); u != "" {
		return u
	}
	scheme := cfg.PublicScheme
	if scheme == "" {
		scheme = "https"
	}
	host := cfg.Domain
	if host == "" {
		host = "<domain>"
	}
	u := scheme + "://" + host
	if cfg.PublicPort != 0 {
		u += ":" + strconv.Itoa(cfg.PublicPort)
	}
	return u
}

func (e *env) createCmd() *cobra.Command {
	var (
		name       string
		expires    string
		scopes     []string
		maxTunnels int
	)
	cmd := &cobra.Command{
		Use:   "create --name <name>",
		Short: "Create a client token (shown once)",
		Long: "Create a client token. The token is the client's identity: its name becomes the client name\n" +
			"in tunnel URLs. The secret is printed once and cannot be shown again.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !auth.ValidName(name) {
				return exitcode.UsageError(fmt.Errorf("invalid --name %q: want 1-32 characters of a-z, 0-9 and '-', not starting or ending with '-'", name))
			}
			sc, err := validateScopes(scopes)
			if err != nil {
				return exitcode.UsageError(err)
			}
			d, err := parseExpires(expires)
			if err != nil {
				return exitcode.UsageError(fmt.Errorf("invalid --expires: %w", err))
			}
			if maxTunnels < 0 {
				return exitcode.UsageError(fmt.Errorf("invalid --max-tunnels %d: must not be negative", maxTunnels))
			}

			cfg, st, ctx, cancel, err := e.open(cmd)
			if err != nil {
				return err
			}
			defer cancel()
			defer st.Close()

			tok, err := auth.Generate()
			if err != nil {
				return fmt.Errorf("generate token: %w", err)
			}
			now := e.now()
			rec := &store.Token{
				ID:         tok.ID,
				Name:       name,
				SecretHash: tok.Hash(),
				Last4:      tok.Last4(),
				Scopes:     sc,
				MaxTunnels: maxTunnels,
				CreatedAt:  now,
			}
			if d > 0 {
				exp := now.Add(d)
				rec.ExpiresAt = &exp
			}
			if err := st.CreateToken(ctx, rec); err != nil {
				if errors.Is(err, store.ErrNameTaken) {
					return fmt.Errorf("token name %q is already used by an active token (revoke it first): %w", name, err)
				}
				return fmt.Errorf("create token: %w", err)
			}

			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				return jsonout.Write(out, createdJSON{
					ID:         tok.ID,
					Name:       name,
					Token:      tok.String(),
					Last4:      tok.Last4(),
					Scopes:     sc,
					MaxTunnels: maxTunnels,
					CreatedAt:  now.UTC(),
					ExpiresAt:  utcPtr(rec.ExpiresAt),
					ServerURL:  loginURL(cfg),
					Login:      fmt.Sprintf("porthole login %s %s", loginURL(cfg), tok.String()),
				})
			}
			fmt.Fprintf(out, "Created token %q (id %s, scopes %s, expires %s).\n\n",
				name, tok.ID, strings.Join(sc, ","), formatExpires(rec.ExpiresAt))
			fmt.Fprintf(out, "    %s\n\n", tok.String())
			fmt.Fprintln(out, "Save this token now: it is shown only once and cannot be recovered.")
			fmt.Fprintln(out, "Log in with:")
			fmt.Fprintf(out, "    porthole login %s %s\n", loginURL(cfg), tok.String())
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "client name, becomes part of tunnel URLs (required)")
	f.StringVar(&expires, "expires", "0", "token lifetime: 30d, 720h or 0 for no expiry")
	f.StringSliceVar(&scopes, "scopes", slices.Clone(auth.DefaultScopes), "comma-separated scopes")
	f.IntVar(&maxTunnels, "max-tunnels", 0, "maximum simultaneous tunnels (0 = server default)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func formatExpires(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(timeLayout) + " UTC"
}

func formatTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format(timeLayout)
}

// status is active, expired or revoked.
func status(t *store.Token, now time.Time) string {
	switch err := t.Usable(now); {
	case errors.Is(err, store.ErrRevoked):
		return "revoked"
	case errors.Is(err, store.ErrExpired):
		return "expired"
	default:
		return "active"
	}
}

// tokenJSON is the --json form of a token: never contains the hash or the secret.
type tokenJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Last4      string     `json:"last4"`
	Scopes     []string   `json:"scopes"`
	MaxTunnels int        `json:"max_tunnels"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	Status     string     `json:"status"`
}

// createdJSON is the --json output of `token create`. It is the only place that ever shows the secret: "token" is the
// full token and "login" the command that stores it on a client.
type createdJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Token      string     `json:"token"`
	Last4      string     `json:"last4"`
	Scopes     []string   `json:"scopes"`
	MaxTunnels int        `json:"max_tunnels"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	ServerURL  string     `json:"server_url"`
	Login      string     `json:"login"`
}

// revokedJSON is the --json output of `token revoke`.
type revokedJSON struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Revoked        bool   `json:"revoked"`
	AlreadyRevoked bool   `json:"already_revoked"`
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func (e *env) listCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List client tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, st, ctx, cancel, err := e.open(cmd)
			if err != nil {
				return err
			}
			defer cancel()
			defer st.Close()

			toks, err := st.ListTokens(ctx)
			if err != nil {
				return fmt.Errorf("list tokens: %w", err)
			}
			now := e.now()
			shown := toks[:0:0]
			for _, t := range toks {
				if all || t.RevokedAt == nil {
					shown = append(shown, t)
				}
			}
			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				return writeJSON(out, shown, now)
			}
			return writeTable(out, shown, now)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include revoked tokens")
	return cmd
}

func writeJSON(w io.Writer, toks []*store.Token, now time.Time) error {
	arr := make([]tokenJSON, 0, len(toks))
	for _, t := range toks {
		scopes := t.Scopes
		if scopes == nil {
			scopes = []string{}
		}
		arr = append(arr, tokenJSON{
			ID:         t.ID,
			Name:       t.Name,
			Last4:      t.Last4,
			Scopes:     scopes,
			MaxTunnels: t.MaxTunnels,
			CreatedAt:  t.CreatedAt.UTC(),
			ExpiresAt:  utcPtr(t.ExpiresAt),
			RevokedAt:  utcPtr(t.RevokedAt),
			LastUsedAt: utcPtr(t.LastUsedAt),
			Status:     status(t, now),
		})
	}
	return jsonout.Write(w, arr)
}

func writeTable(w io.Writer, toks []*store.Token, now time.Time) error {
	if len(toks) == 0 {
		_, err := fmt.Fprintln(w, "No tokens.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSECRET\tSCOPES\tCREATED\tEXPIRES\tLAST USED\tSTATUS")
	for _, t := range toks {
		created := t.CreatedAt
		fmt.Fprintf(tw, "%s\t%s\t…%s\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Name, t.Last4, strings.Join(t.Scopes, ","),
			formatTime(&created), formatTime(t.ExpiresAt), formatTime(t.LastUsedAt), status(t, now))
	}
	return tw.Flush()
}

func (e *env) revokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id|name>",
		Short: "Revoke a token",
		Long: "Revoke a token by id or by name. Live sessions using it are closed by the server within " +
			liveSessionGrace + ".",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, st, ctx, cancel, err := e.open(cmd)
			if err != nil {
				return err
			}
			defer cancel()
			defer st.Close()

			// Resolve like the store does (id first, then active name) so the message can name the token.
			target, err := resolve(ctx, st, args[0])
			if err != nil {
				return err
			}
			if err := st.RevokeToken(ctx, target.ID, e.now()); err != nil {
				return fmt.Errorf("revoke token: %w", err)
			}
			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				return jsonout.Write(out, revokedJSON{
					ID: target.ID, Name: target.Name, Revoked: true, AlreadyRevoked: target.RevokedAt != nil,
				})
			}
			if target.RevokedAt != nil {
				fmt.Fprintf(out, "Token %q (id %s) was already revoked.\n", target.Name, target.ID)
				return nil
			}
			fmt.Fprintf(out, "Revoked token %q (id %s). Live sessions will be closed by the server within %s.\n",
				target.Name, target.ID, liveSessionGrace)
			return nil
		},
	}
}

func resolve(ctx context.Context, st *store.SQLite, idOrName string) (*store.Token, error) {
	t, err := st.GetToken(ctx, idOrName)
	if err == nil {
		return t, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("look up token: %w", err)
	}
	toks, err := st.ListTokens(ctx)
	if err != nil {
		return nil, fmt.Errorf("look up token: %w", err)
	}
	for _, t := range toks {
		if t.Name == idOrName && t.RevokedAt == nil {
			return t, nil
		}
	}
	return nil, fmt.Errorf("no active token with id or name %q: %w", idOrName, store.ErrNotFound)
}
