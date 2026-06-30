module example.com/sample

go 1.21

require github.com/google/uuid v1.6.0

require (
	github.com/spf13/cobra v1.8.0
	golang.org/x/sync v0.7.0 // indirect
)

replace github.com/spf13/cobra => ../local-cobra
