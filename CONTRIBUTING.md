# Contributing to KAGE

## Getting Started

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit your changes (`git commit -m "feat: add amazing feature"`)
4. Push to the branch (`git push origin feat/amazing-feature`)
5. Open a Pull Request

## Development Setup

```bash
go mod download
go test ./... -race -count=1
```

## Code Style

- Run `go vet ./...` before committing
- Run `gofmt -s` on all Go files
- Keep test coverage above 70%

## Pull Request Guidelines

- One feature per PR
- Include tests for new functionality
- Update documentation if needed
- Keep the changelog updated

## Security Issues

Report security vulnerabilities to the maintainers directly. Do not open public issues for security bugs.
