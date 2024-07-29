package main

import (
	"bytes"
	"os"

	"ec.mleku.dev/v2/lol"
)

type (
	B = []byte
	S = string
	E = error
)

var (
	log, chk, errorf = lol.New(os.Stderr)
	equals           = bytes.Equal
)
