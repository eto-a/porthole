// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package adminapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	clientTimeout    = 15 * time.Second
	maxResponseBytes = 4 << 20
)

// SocketClient calls the admin API over the unix socket (no token needed).
type SocketClient struct {
	hc *http.Client
}

// NewSocketClient returns a SocketClient that talks to the admin socket at path.
func NewSocketClient(path string) *SocketClient {
	return &SocketClient{hc: &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}}
}

// Status calls GET status.
func (c *SocketClient) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.get(ctx, "/status", &s)
	return s, err
}

// Error is an error response of the API.
type Error struct {
	HTTPStatus int
	Code       string
	Message    string
}

func (e *Error) Error() string {
	return fmt.Sprintf("admin api: %s: %s (HTTP %d)", e.Code, e.Message, e.HTTPStatus)
}

func (c *SocketClient) get(ctx context.Context, path string, out any) error {
	// The host is a placeholder: the dialer ignores it and connects to the socket.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://porthole-admin"+Prefix+path, nil)
	if err != nil {
		return fmt.Errorf("admin api: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("admin api: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("admin api: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var eb ErrorBody
		if json.Unmarshal(body, &eb) != nil || eb.Error.Code == "" {
			return &Error{HTTPStatus: resp.StatusCode, Code: "http_error", Message: http.StatusText(resp.StatusCode)}
		}
		return &Error{HTTPStatus: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("admin api: decode response: %w", err)
	}
	return nil
}
