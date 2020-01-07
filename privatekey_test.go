package rsautils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveAndLoad(t *testing.T) {
	dir := os.TempDir()
	fp := filepath.Join(dir, "rsautils_test.pem")
	defer os.Remove(fp)
	key1, err := GenerateAndSavePrivateKey(256, fp)
	if err != nil {
		t.Fatalf("GenerateAndSavePrivateKey error: %v", err)
	}
	key2, err := LoadPrivateKey(fp)
	if err != nil {
		t.Fatalf("LoadPrivateKey from %q error: %v", fp, err)
	}
	if key1.N.Cmp(key2.N) != 0 {
		t.Error("N is different")
	}

	if key1.E != key2.E {
		t.Error("E is different")
	}
}

func TestNEBase64(t *testing.T) {
	key, err := LoadPrivateKey("./testdata/test1.pem")
	if err != nil {
		t.Fatalf("LoadPrivateKey error: %v", err)
	}

	n, e, err := NEBase64(key)
	if err != nil {
		t.Fatalf("NEBase64 error: %v", err)
	}

	if n != "xFeZxNf8WB5kJknpbSmj1qtDPjtgQp4p29AZEsNOcWk" {
		t.Errorf("invalid N %q", n)
	}
	if e != "AQAB" {
		t.Errorf("invalid E %q", e)
	}
}
