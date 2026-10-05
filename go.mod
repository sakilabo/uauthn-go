module github.com/sakilabo/uauthn-go

go 1.26.0

// The passwd and session formats of these versions are not supported from v0.4.0.
retract [v0.1.0, v0.3.1]

require (
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
)
