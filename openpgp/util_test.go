package openpgp

import (
	"code.google.com/p/go.crypto/openpgp/armor"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func MustInput(t *testing.T, name string) *os.File {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("Cannot locate unit test data files")
	}
	path := filepath.Join(filepath.Dir(thisFile), "testdata", name)
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("Cannot open unit test data file", path, ":", err)
	}
	return f
}

func MustInputAscKeys(t *testing.T, name string) (result []*Pubkey) {
	f := MustInput(t, name)
	defer f.Close()
	block, err := armor.Decode(f)
	if err != nil {
		t.Fatal(err)
	}
	for keyRead := range ReadKeys(block.Body) {
		if keyRead.Error != nil {
			t.Fatal(keyRead.Error)
		}
		result = append(result, keyRead.Pubkey)
	}
	return
}

func MustInputAscKey(t *testing.T, name string) *Pubkey {
	keys := MustInputAscKeys(t, name)
	if len(keys) != 1 {
		t.Fatal("Expected only one key, got", len(keys))
	}
	return keys[0]
}
