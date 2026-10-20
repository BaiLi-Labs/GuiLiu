package password

import "testing"

func TestHashAndVerify(t *testing.T) {
	hash, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := Verify("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("verify correct = %v, %v", ok, err)
	}
	ok, err = Verify("wrong password", hash)
	if err != nil || ok {
		t.Fatalf("verify wrong = %v, %v", ok, err)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, encoded := range []string{
		"",
		"plaintext",
		"$argon2id$v=19$m=65536,t=3,p=2$notbase64$notbase64",
		"$argon2id$v=19$m=99999999,t=3,p=2$c2FsdA$a2V5",
	} {
		if ok, err := Verify("x", encoded); err == nil || ok {
			t.Fatalf("expected error for %q, got ok=%v err=%v", encoded, ok, err)
		}
	}
}

func TestHashIsSalted(t *testing.T) {
	a, _ := Hash("same password")
	b, _ := Hash("same password")
	if a == b {
		t.Fatal("expected different salts")
	}
}
