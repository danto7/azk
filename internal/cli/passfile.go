package cli

import (
	"bytes"
	"fmt"
	"os"
)

func readPassphraseFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("passphrase file: %w", err)
	}
	return bytes.TrimRight(b, "\r\n"), nil
}
