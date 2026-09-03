package crypto

import "testing"

func TestBcrypt(t *testing.T) {
	hasher := Bcrypt{Cost: 4}
	hash, err := hasher.Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !hasher.Compare(hash, "correct horse") {
		t.Fatal("valid password rejected")
	}
	if hasher.Compare(hash, "wrong") {
		t.Fatal("wrong password accepted")
	}
}
