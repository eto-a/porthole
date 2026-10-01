// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package clientcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/eto-a/porthole/internal/auth"
	"github.com/eto-a/porthole/internal/cli/exitcode"
	"github.com/eto-a/porthole/internal/cli/jsonout"
	"github.com/eto-a/porthole/internal/client"
	"github.com/eto-a/porthole/internal/proto"
)

const (
	joinTimeout     = 30 * time.Second
	maxJoinResponse = 16 << 10
)

// joinResult is the --json output of `porthole join`. It never contains the token.
type joinResult struct {
	Joined     bool   `json:"joined"`
	ClientName string `json:"client_name"`
	Server     string `json:"server"`
	Config     string `json:"config"` // path of the file the credentials were written to
}

func (a *app) newJoinCmd() *cobra.Command {
	var server string
	cmd := &cobra.Command{
		Use:   "join <link|code>",
		Short: "Enrol this machine with a one-time join link",
		Long: "Redeem a one-time join link (https://<server>/j/pj_...) or code (pj_...) that a server operator created,\n" +
			"and store the server URL and the new token in the client config file (mode 0600), like `porthole login`.\n" +
			"A join link works once and expires after a short time (15 minutes by default).\n" +
			"With a bare code, the server comes from --server, $" + envServer + " or the config file.",
		Example: "  porthole join https://tun.example.com/j/pj_3kq9w2m1z8xa_...",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path, err := a.path()
			if err != nil {
				return err
			}
			if server == "" {
				server = a.d.getenv(envServer)
			}
			if server == "" {
				if fc, err := loadConfig(path); err == nil {
					server = fc.Server
				}
			}
			base, code, err := parseJoinTarget(args[0], server)
			if err != nil {
				return usageErr(err)
			}
			parent := cmd.Context()
			if parent == nil {
				parent = context.Background()
			}
			ctx, cancel := context.WithTimeout(parent, joinTimeout)
			defer cancel()
			res, err := redeemJoin(ctx, base, code)
			if err != nil {
				return err
			}
			if _, err := auth.Parse(res.Token); err != nil || !auth.ValidName(res.ClientName) {
				return errors.New("the server returned an invalid join response")
			}
			if err := saveConfig(path, fileConfig{Server: base, Token: res.Token}); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonout.Enabled(cmd) {
				return jsonout.Write(out, joinResult{Joined: true, ClientName: res.ClientName, Server: base, Config: path})
			}
			fmt.Fprintf(out, "joined as %s\nSaved credentials for %s to %s\n", res.ClientName, base, path)
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "server URL, needed when giving a bare code (default: $"+envServer+", then the config file)")
	return cmd
}

// parseJoinTarget splits what the user gave into the server base URL and the join code. A link carries both; a bare
// code needs the server from fallback.
func parseJoinTarget(arg, fallback string) (base, code string, err error) {
	arg = strings.TrimSpace(arg)
	if !strings.Contains(arg, "://") {
		if _, err := auth.ParseJoin(arg); err != nil {
			return "", "", errors.New("invalid join code: expected pj_<id>_<secret> or a link ending in /j/pj_<id>_<secret>")
		}
		if fallback == "" {
			return "", "", errors.New("a bare join code needs the server: give --server, set $" + envServer + ", or use the full link")
		}
		base = strings.TrimRight(strings.TrimSpace(fallback), "/")
		if _, err := client.ConnectURL(base); err != nil {
			return "", "", err
		}
		return base, arg, nil
	}
	u, err := url.Parse(arg)
	if err != nil || u.Host == "" {
		return "", "", errors.New("invalid join link: expected https://<server>/j/pj_<id>_<secret>")
	}
	i := strings.LastIndex(u.Path, proto.JoinPagePrefix)
	if i < 0 {
		return "", "", errors.New("invalid join link: the path must end in /j/pj_<id>_<secret>")
	}
	code = u.Path[i+len(proto.JoinPagePrefix):]
	if _, err := auth.ParseJoin(code); err != nil {
		return "", "", errors.New("invalid join link: the code after /j/ is malformed")
	}
	base = u.Scheme + "://" + u.Host + u.Path[:i]
	if _, err := client.ConnectURL(base); err != nil {
		return "", "", err
	}
	return base, code, nil
}

// redeemError is a refusal by the server, with the stable error code.
type redeemError struct {
	status int
	code   string
	msg    string
}

func (e *redeemError) Error() string {
	return fmt.Sprintf("the server refused the join link: %s (%s)", e.msg, e.code)
}

// redeemJoin posts the code to base and returns the server's answer. Redirects are not followed: a POST that is
// redirected would lose its body, and a plain-http base must not be silently upgraded either.
func redeemJoin(ctx context.Context, base, code string) (proto.JoinResponse, error) {
	var zero proto.JoinResponse
	body, err := json.Marshal(proto.JoinRequest{Code: code})
	if err != nil {
		return zero, fmt.Errorf("encode join request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+proto.JoinPath, bytes.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("join: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{
		Timeout:       joinTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Do(req)
	if err != nil {
		return zero, &exitcode.Error{Code: exitcode.Connect, Err: fmt.Errorf("cannot reach the server at %s: %w", base, err)}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJoinResponse))
	if err != nil {
		return zero, &exitcode.Error{Code: exitcode.Connect, Err: fmt.Errorf("read the server's answer: %w", err)}
	}
	if resp.StatusCode != http.StatusOK {
		var eb struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		if json.Unmarshal(data, &eb) != nil || eb.Error.Code == "" {
			return zero, &exitcode.Error{Code: exitcode.Connect, Err: fmt.Errorf("unexpected answer from %s: HTTP %d (is this a porthole server?)", base, resp.StatusCode)}
		}
		re := &redeemError{status: resp.StatusCode, code: eb.Error.Code, msg: eb.Error.Message}
		status := exitcode.Auth
		if eb.Error.Code == proto.CodeNameTaken {
			status = exitcode.Rejected
		}
		return zero, &exitcode.Error{Code: status, Err: re}
	}
	var out proto.JoinResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return zero, fmt.Errorf("decode the server's answer: %w", err)
	}
	return out, nil
}
