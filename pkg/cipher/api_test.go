// Copyright (C) 2026  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cipher

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/enfein/mieru/v3/apis/constant"
)

func TestUserHintOperationsAllocateNoHeap(t *testing.T) {
	user := []byte("allocation-free-user")
	key := make([]byte, DefaultKeyLen)
	c, err := newXChaCha20Poly1305BlockCipher(key)
	if err != nil {
		t.Fatalf("newXChaCha20Poly1305BlockCipher() failed: %v", err)
	}
	c.SetBlockContext(BlockContext{UserName: string(user)})
	var baseNonce [DefaultNonceSize]byte
	nonce := c.addUserHintToNonce(baseNonce[:])
	if !CheckUserFromHint(user, nonce) {
		t.Fatal("generated user hint did not match")
	}

	if allocs := testing.AllocsPerRun(1000, func() {
		if !CheckUserFromHint(user, nonce) {
			panic("user hint did not match")
		}
	}); allocs != 0 {
		t.Fatalf("CheckUserFromHint() allocations = %v, want 0", allocs)
	}

	if allocs := testing.AllocsPerRun(1000, func() {
		localNonce := baseNonce
		c.addUserHintToNonce(localNonce[:])
	}); allocs != 0 {
		t.Fatalf("addUserHintToNonce() allocations = %v, want 0", allocs)
	}
}

func TestUserHintOperationsPanicForLongUserName(t *testing.T) {
	user := strings.Repeat("x", constant.MaxUserNameLen+1)
	var nonce [DefaultNonceSize]byte
	tests := []struct {
		name string
		fn   func()
	}{
		{
			name: "CheckUserFromHint",
			fn: func() {
				CheckUserFromHint([]byte(user), nonce[:])
			},
		},
		{
			name: "addUserHintToNonce",
			fn: func() {
				c := &aeadBlockCipher{ctx: BlockContext{UserName: user}}
				c.addUserHintToNonce(nonce[:])
			},
		},
		{
			name: "CheckUserFromHintV3",
			fn: func() {
				CheckUserFromHintV3(HintPepper(user, "password"), []byte(user), nonce[:])
			},
		},
		{
			name: "CheckUserFromHintV3 empty pepper",
			fn: func() {
				CheckUserFromHintV3(nil, []byte("user"), nonce[:])
			},
		},
		{
			name: "CheckUserFromHintV3 empty user",
			fn: func() {
				CheckUserFromHintV3([]byte("pepper"), nil, nonce[:])
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("operation did not panic")
				}
			}()
			test.fn()
		})
	}
}

func TestHintPepper(t *testing.T) {
	const user = "pepper-user"
	const password = "pepper-password"
	pepper := HintPepper(user, password)
	if len(pepper) != HintPepperLen {
		t.Fatalf("HintPepper() length = %d, want %d", len(pepper), HintPepperLen)
	}
	if got := HintPepper(user, password); !bytes.Equal(got, pepper) {
		t.Errorf("HintPepper() is not deterministic: %x then %x", pepper, got)
	}

	// A pepper must change with the credential and with the user name, so that
	// a hint cannot be computed or verified without the shared credential.
	for _, test := range []struct {
		name     string
		user     string
		password string
	}{
		{name: "other password", user: user, password: "other-password"},
		{name: "other user", user: "other-user", password: password},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HintPepper(test.user, test.password); bytes.Equal(got, pepper) {
				t.Errorf("HintPepper(%q, %q) = %x, want a different pepper", test.user, test.password, got)
			}
		})
	}

	// A missing user name or credential selects the legacy hint of protocol v2.
	for _, test := range []struct {
		name     string
		user     string
		password string
	}{
		{name: "empty user", user: "", password: password},
		{name: "empty password", user: user, password: ""},
		{name: "both empty", user: "", password: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := HintPepper(test.user, test.password); got != nil {
				t.Errorf("HintPepper(%q, %q) = %x, want nil", test.user, test.password, got)
			}
		})
	}
}

func TestKeyedUserHint(t *testing.T) {
	const user = "keyed-hint-user"
	const password = "keyed-hint-password"
	userBytes := []byte(user)
	pepper := HintPepper(user, password)
	c, err := newXChaCha20Poly1305BlockCipher(make([]byte, DefaultKeyLen))
	if err != nil {
		t.Fatalf("newXChaCha20Poly1305BlockCipher() failed: %v", err)
	}

	var baseNonce [DefaultNonceSize]byte
	for i := range baseNonce {
		baseNonce[i] = byte(i)
	}

	// The keyed hint has the same position and the same length as the legacy
	// hint: only the last NonceSuffixLenForUserHint bytes of the nonce change.
	c.SetBlockContext(BlockContext{UserName: user, Pepper: pepper})
	keyed := c.addUserHintToNonce(append([]byte(nil), baseNonce[:]...))
	if len(keyed) != DefaultNonceSize {
		t.Fatalf("nonce length = %d, want %d", len(keyed), DefaultNonceSize)
	}
	prefixLen := len(baseNonce) - NonceSuffixLenForUserHint
	if !bytes.Equal(keyed[:prefixLen], baseNonce[:prefixLen]) {
		t.Errorf("addUserHintToNonce() changed the nonce in front of the hint: %x, want %x", keyed[:prefixLen], baseNonce[:prefixLen])
	}
	if bytes.Equal(keyed, baseNonce[:]) {
		t.Error("addUserHintToNonce() did not write a keyed hint")
	}
	if !CheckUserFromHintV3(pepper, userBytes, keyed) {
		t.Errorf("CheckUserFromHintV3() did not match the keyed hint %x that was written", keyed[prefixLen:])
	}
	if CheckUserFromHint(userBytes, keyed) {
		t.Error("CheckUserFromHint() matched a keyed hint")
	}
	// The same nonce must always carry the same keyed hint.
	if again := c.addUserHintToNonce(append([]byte(nil), baseNonce[:]...)); !bytes.Equal(again, keyed) {
		t.Errorf("keyed hint of a fixed nonce = %x, want %x", again, keyed)
	}

	// The legacy hint of the same user and the same nonce is a different value
	// and still matches the legacy check.
	c.SetBlockContext(BlockContext{UserName: user})
	legacy := c.addUserHintToNonce(append([]byte(nil), baseNonce[:]...))
	if !CheckUserFromHint(userBytes, legacy) {
		t.Errorf("CheckUserFromHint() did not match the legacy hint %x that was written", legacy[prefixLen:])
	}
	if bytes.Equal(legacy, keyed) {
		t.Error("the keyed hint equals the legacy hint of the same user and nonce")
	}

	// Only the credential of that user yields a matching keyed hint.
	for _, test := range []struct {
		name   string
		pepper []byte
		user   []byte
	}{
		{name: "other password", pepper: HintPepper(user, "other-password"), user: userBytes},
		{name: "other user", pepper: pepper, user: []byte("other-user")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if CheckUserFromHintV3(test.pepper, test.user, keyed) {
				t.Errorf("CheckUserFromHintV3(%q) matched the keyed hint of %q", test.user, user)
			}
		})
	}

	// Both derivation paths must stay heap allocation free.
	c.SetBlockContext(BlockContext{UserName: user, Pepper: pepper})
	if allocs := testing.AllocsPerRun(1000, func() {
		localNonce := baseNonce
		c.addUserHintToNonce(localNonce[:])
	}); allocs != 0 {
		t.Fatalf("addUserHintToNonce() with a pepper allocations = %v, want 0", allocs)
	}
	if allocs := testing.AllocsPerRun(1000, func() {
		if !CheckUserFromHintV3(pepper, userBytes, keyed) {
			panic("keyed user hint did not match")
		}
	}); allocs != 0 {
		t.Fatalf("CheckUserFromHintV3() allocations = %v, want 0", allocs)
	}
}

func TestConcurrentStatelessTrialsReturnIndependentCiphers(t *testing.T) {
	password := HashPassword([]byte(t.Name()), []byte("parallel-user"))
	block, err := BlockCipherFromPassword(SuiteXChaCha20Poly1305, password, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	plaintext := []byte("parallel plaintext")
	ciphertext := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
	if err := block.Encrypt(ciphertext[:0], plaintext); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	decryptor, err := NewStatelessDecryptor([]Suite{SuiteXChaCha20Poly1305}, password)
	if err != nil {
		t.Fatalf("NewStatelessDecryptor() failed: %v", err)
	}

	const trials = 64
	var wg sync.WaitGroup
	errCh := make(chan error, trials)
	for i := range trials {
		wg.Add(1)
		go func() {
			defer wg.Done()
			winner, _, err := decryptor.TryDecrypt(ciphertext, nil)
			if err != nil {
				errCh <- err
				return
			}
			if got := winner.BlockContext().UserName; got != "" {
				errCh <- fmt.Errorf("trial %d inherited context %q", i, got)
				return
			}
			want := fmt.Sprintf("trial-%d", i)
			winner.SetBlockContext(BlockContext{UserName: want})
			if got := winner.BlockContext().UserName; got != want {
				errCh <- fmt.Errorf("trial %d context = %q, want %q", i, got, want)
				return
			}
			nonce := make([]byte, DefaultNonceSize)
			nonce[len(nonce)-1] = byte(i)
			sealed := make([]byte, len(plaintext)+winner.Overhead())
			if err := winner.EncryptWithNonce(sealed[:0], nonce, plaintext); err != nil {
				errCh <- fmt.Errorf("trial %d EncryptWithNonce() failed: %w", i, err)
				return
			}
			opened, err := winner.DecryptWithNonce(sealed, nonce)
			if err != nil {
				errCh <- fmt.Errorf("trial %d DecryptWithNonce() failed: %w", i, err)
				return
			}
			if !bytes.Equal(opened, plaintext) {
				errCh <- fmt.Errorf("trial %d direct plaintext = %q, want %q", i, opened, plaintext)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	templates, err := getBlockCipherList(string(password), SuiteXChaCha20Poly1305, true, KeyIterV3)
	if err != nil {
		t.Fatalf("getBlockCipherList() failed: %v", err)
	}
	for i, template := range templates {
		if got := template.BlockContext().UserName; got != "" {
			t.Fatalf("cached template %d context = %q after concurrent trials, want empty", i, got)
		}
	}
}

func TestConcurrentStatelessDecryptor(t *testing.T) {
	password := HashPassword([]byte(t.Name()), []byte("parallel-prepared-user"))
	block, err := BlockCipherFromPassword(SuiteXChaCha20Poly1305, password, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	plaintext := []byte("parallel prepared plaintext")
	ciphertext := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
	if err := block.Encrypt(ciphertext[:0], plaintext); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	decryptor, err := NewStatelessDecryptor(nil, password)
	if err != nil {
		t.Fatalf("NewStatelessDecryptor() failed: %v", err)
	}

	const trials = 64
	var wg sync.WaitGroup
	errCh := make(chan error, trials)
	for i := range trials {
		wg.Add(1)
		go func() {
			defer wg.Done()
			winner, got, err := decryptor.TryDecrypt(ciphertext, make([]byte, 0, len(plaintext)))
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, plaintext) {
				errCh <- fmt.Errorf("trial %d plaintext = %q, want %q", i, got, plaintext)
				return
			}
			want := fmt.Sprintf("prepared-trial-%d", i)
			winner.SetBlockContext(BlockContext{UserName: want})
			if got := winner.BlockContext().UserName; got != want {
				errCh <- fmt.Errorf("trial %d context = %q, want %q", i, got, want)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	entry := decryptor.ciphers.Load()
	if entry == nil {
		t.Fatal("prepared decryptor did not retain trial material")
	}
	for i, list := range entry.lists {
		for j, template := range list {
			if got := template.BlockContext().UserName; got != "" {
				t.Fatalf("cached template %d/%d context = %q after concurrent trials, want empty", i, j, got)
			}
		}
	}
}

// BenchmarkStatelessDecryptor measures the cost of the server side discovery
// trial decrypt: one password, one cipher suite, three time slots.
func BenchmarkStatelessDecryptor(b *testing.B) {
	password := HashPassword([]byte("benchmark-password"), []byte("benchmark-user"))
	data := make([]byte, 1500)
	if _, err := crand.Read(data); err != nil {
		b.Fatalf("failed to generate data: %v", err)
	}
	block, err := BlockCipherFromPassword(SuiteXChaCha20Poly1305, password, true)
	if err != nil {
		b.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	ciphertext := make([]byte, block.NonceSize()+len(data)+block.Overhead())
	if err := block.Encrypt(ciphertext[:0], data); err != nil {
		b.Fatalf("Encrypt() failed: %v", err)
	}
	decryptor, err := NewStatelessDecryptor([]Suite{SuiteXChaCha20Poly1305}, password)
	if err != nil {
		b.Fatalf("NewStatelessDecryptor() failed: %v", err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		winner, plaintext, err := decryptor.TryDecrypt(ciphertext, nil)
		if err != nil || winner == nil || len(plaintext) != len(data) {
			b.Fatalf("TryDecrypt() = (block nil=%t, plaintext bytes=%d, %v)", winner == nil, len(plaintext), err)
		}
	}
}

func BenchmarkCheckUserFromHint(b *testing.B) {
	user := []byte("benchmark-user")
	key := make([]byte, 32)
	if _, err := crand.Read(key); err != nil {
		b.Fatalf("fail to generate key: %v", err)
	}
	c, err := newXChaCha20Poly1305BlockCipher(key)
	if err != nil {
		b.Fatalf("newXChaCha20Poly1305BlockCipher() failed: %v", err)
	}
	c.SetBlockContext(BlockContext{UserName: string(user)})
	nonce, err := c.newNonce()
	if err != nil {
		b.Fatalf("newNonce() failed: %v", err)
	}
	nonce = c.addUserHintToNonce(nonce)

	b.ReportAllocs()
	for b.Loop() {
		if !CheckUserFromHint(user, nonce) {
			b.Fatal("user hint did not match")
		}
	}
}
