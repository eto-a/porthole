// Copyright 2026 The porthole Authors
// SPDX-License-Identifier: Apache-2.0

package proto

// JoinPath is the HTTP endpoint on the control host where a machine redeems a one-time join code (ADR 0005).
const JoinPath = "/_porthole/v1/join"

// JoinPagePrefix starts the human-facing join link, <server_url>/j/<code>; GET returns instructions and never
// redeems the code.
const JoinPagePrefix = "/j/"

// Error codes of a failed join request (HTTP 4xx, body {"error":{"code":"...","message":"..."}}).
const (
	CodeInvalidJoinCode = "invalid_code"      // malformed, unknown or wrong secret
	CodeJoinUsed        = "join_code_used"    // already redeemed
	CodeJoinExpired     = "join_code_expired" // past its expiry
	CodeJoinRevoked     = "join_code_revoked" // revoked by the operator
	CodeRateLimited     = "rate_limited"      // too many failed attempts from this address
)

// JoinRequest is the body of POST JoinPath.
type JoinRequest struct {
	Code string `json:"code"`
}

// JoinResponse is the answer to a redeemed code. Token is the permanent client token, shown only here.
type JoinResponse struct {
	ServerURL  string `json:"server_url"`
	ClientName string `json:"client_name"`
	Token      string `json:"token"`
}
