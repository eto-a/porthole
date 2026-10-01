# Contributing to porthole

Thank you for your interest. This document describes how to build the project, what a good change looks like and how
changes are accepted. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

Security vulnerabilities must not go through public issues or pull requests: see [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a small fix, open an issue first so we can agree on the approach.
- Read [DESIGN.md](DESIGN.md) (what we build and why) and, if you touch the wire format,
  [docs/protocol.md](docs/protocol.md).

## Building and testing

You need Go 1.27 or newer (see `go.mod`). `make` and [golangci-lint](https://golangci-lint.run) v2 are used for the
convenience targets; on Windows use Git Bash or WSL for `make`.

```console
$ go build ./cmd/...        # build both binaries
$ make build                # static, stripped binaries with a version, in ./bin
$ make lint test            # lint and run the tests (what CI runs, minus the OS matrix)
$ make test-race            # tests with the race detector
$ make vuln                 # govulncheck
$ make fuzz                 # short fuzzing run of the parsers
```

## Requirements for a change

- **Tests.** New behavior needs tests; a bug fix needs a test that fails without the fix. Network code is tested
  against real sockets. Tests must pass with `-race -shuffle=on` and must not leak goroutines.
- **Formatting and lint.** Code is formatted with `gofumpt` and `goimports` (local prefix
  `github.com/eto-a/porthole`) and passes `golangci-lint run` with the repository's `.golangci.yml`. Do not add
  `//nolint` without a specific linter name and a reason.
- **Go style.** Wrap errors with `%w`; use `log/slog` for logging and never log tokens; pass `context.Context` as the
  first argument of blocking functions; put timeouts and size limits on everything that touches the network; avoid
  global state.
- **Commits.** One logical change per commit. Use [Conventional Commits](https://www.conventionalcommits.org/) with
  the package as scope, imperative mood: `fix(server): reject duplicate tunnel names`,
  `feat(client): add --remote-port`, `docs: clarify certbot example`. Types used for the changelog: `feat`, `fix`,
  `perf`, `docs`, `refactor`, `test`, `build`, `ci`, `chore`. Explain the why in the body when it is not obvious.
- **Dependencies.** Keep them few. A new dependency needs a justification in the pull request, and its license must be
  compatible with Apache-2.0.
- **Licenses of copied code.** Do not copy code from projects under AGPL or proprietary licenses. Code from
  Apache-2.0, MIT or BSD projects may be included only with its copyright notice preserved and its source stated in
  the pull request.
- **Docs.** Update the README, `docs/` and the example configuration when behavior or options change.

## Architecture decisions and protocol changes

- A change that affects the architecture (transport, storage, authentication model, public behavior) needs an
  Architecture Decision Record in [docs/adr/](docs/adr/), written in the
  [MADR](https://adr.github.io/madr/) format and numbered sequentially (`0002-short-title.md`). Propose it in the
  same pull request as the change, or before it.
- Changes to the wire protocol are made in [docs/protocol.md](docs/protocol.md) first. Adding optional fields or
  message types is compatible; anything else requires bumping `protocol_version` and keeping support for the
  previous version as described in that document.

## Developer Certificate of Origin (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org) instead of a contributor
license agreement. By signing off a commit you certify that you wrote the change or otherwise have the right to submit
it under the project's license (Apache-2.0), as stated in the DCO 1.1:

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I have the right to submit it under the open source
> license indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best of my knowledge, is covered under an appropriate
> open source license and I have the right under that license to submit that work with modifications, whether created
> in whole or in part by me, under the same open source license (unless I am permitted to submit under a different
> license), as indicated in the file; or
>
> (c) The contribution was provided directly to me by some other person who certified (a), (b) or (c) and I have not
> modified it.
>
> (d) I understand and agree that this project and the contribution are public and that a record of the contribution
> (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be
> redistributed consistent with this project or the open source license(s) involved.

Add a `Signed-off-by` line to every commit with your real name and e-mail address by using `git commit -s`:

```
Signed-off-by: Jane Developer <jane@example.com>
```

To add the sign-off to existing commits: `git rebase --signoff main` (or `git commit --amend -s` for the last one).

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change following the requirements above and run `make lint test`.
3. Open a pull request and fill in the template. CI (tests on Linux, macOS and Windows, lint, `govulncheck`, fuzz
   smoke tests and workflow lint) must pass.
4. A maintainer reviews the change. Expect requests for changes; we squash or rebase when merging.

## Reporting bugs and requesting features

Use the issue templates. For bugs include the versions of `portholed` and `porthole` (`portholed version`,
`porthole version`), your operating system, how you run the server (TLS directly or behind a reverse proxy) and
logs with tokens removed.
