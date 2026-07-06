# Contributing to culler

Contributions are welcome. Please read this before opening a PR.

## Development Setup

```sh
git clone https://github.com/sumeetghimire/culler
cd culler
go mod download
go test ./...
```

## Running Tests

```sh
go test -race ./...
go test -cover ./internal/...
```

## Submitting Changes

1. Fork the repo and create a feature branch.
2. Write tests for new behaviour (table-driven preferred).
3. Run `golangci-lint run` and fix any issues.
4. Open a PR against `main` with a clear description.

## Adding a New Parser

1. Create `internal/parsers/<scanner>.go` implementing `Parse(io.Reader) ([]model.Finding, error)`.
2. Add a detection case in `internal/parsers/detect.go`.
3. Add a realistic fixture in `testdata/<scanner>.json`.
4. Write table-driven tests in `internal/parsers/<scanner>_test.go`.

## Reporting Security Issues

See [SECURITY.md](SECURITY.md).
