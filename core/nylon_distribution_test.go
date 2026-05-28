package core

import (
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
)

func TestCentralConfigBytesDefaultsToPlaintext(t *testing.T) {
	old := PersistEncryptedCentral
	PersistEncryptedCentral = "false"
	t.Cleanup(func() { PersistEncryptedCentral = old })

	cfg := &state.CentralCfg{
		Routers: []state.RouterCfg{{NodeCfg: state.NodeCfg{Id: "alice"}}},
	}
	bundle := []byte("encrypted bundle")
	data, err := centralConfigBytes(cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == string(bundle) {
		t.Fatal("expected plaintext yaml, got encrypted bundle")
	}

	var parsed state.CentralCfg
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Routers[0].Id != "alice" {
		t.Fatalf("expected alice, got %s", parsed.Routers[0].Id)
	}
}

func TestCentralConfigBytesCanPersistEncrypted(t *testing.T) {
	old := PersistEncryptedCentral
	PersistEncryptedCentral = "true"
	t.Cleanup(func() { PersistEncryptedCentral = old })

	cfg := &state.CentralCfg{
		Routers: []state.RouterCfg{{NodeCfg: state.NodeCfg{Id: "alice"}}},
	}
	bundle := []byte("encrypted bundle")
	data, err := centralConfigBytes(cfg, bundle)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(bundle) {
		t.Fatal("expected encrypted bundle")
	}
}
