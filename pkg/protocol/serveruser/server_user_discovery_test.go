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

package serveruser

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"google.golang.org/protobuf/proto"
)

type discoveryTransport struct {
	name     string
	discover func(map[string]*appctlpb.User, bool, []byte) ([]byte, string, error)
}

var discoveryTransports = []discoveryTransport{
	{
		name: "CurrentGeneration",
		discover: func(users map[string]*appctlpb.User, hintMandatory bool, encryptedMeta []byte) ([]byte, string, error) {
			registry := &Registry{}
			registry.SetUsers(users)
			registry.SetHintMandatory(hintMandatory)
			block, decryptedMeta, _, err := registry.Discover(encryptedMeta, Source{}, true)
			if err != nil {
				return nil, "", err
			}
			return decryptedMeta, block.BlockContext().UserName, nil
		},
	},
	{
		name: "SnapshotGeneration",
		discover: func(users map[string]*appctlpb.User, hintMandatory bool, encryptedMeta []byte) ([]byte, string, error) {
			registry := &Registry{}
			registry.SetUsers(users)
			registry.SetHintMandatory(hintMandatory)
			block, decryptedMeta, _, err := registry.Discover(encryptedMeta, Source{}, false)
			if err != nil {
				return nil, "", err
			}
			return decryptedMeta, block.BlockContext().UserName, nil
		},
	},
}

func testPublisher(users map[string]*appctlpb.User, hintMandatory bool) (*atomic.Pointer[state], *atomic.Bool) {
	publisher := &atomic.Pointer[state]{}
	publisher.Store(buildState(users, cipher.AllSuites()))
	mandatory := &atomic.Bool{}
	mandatory.Store(hintMandatory)
	return publisher, mandatory
}

// TestUserDiscoveryRequiresAuthentication records the authentication invariant:
// a nonce hint proposes an identity (user name), but it cannot select that identity
// unless the associated credential can decrypt the metadata.
func TestUserDiscoveryRequiresAuthentication(t *testing.T) {
	const userName = "hinted-user"
	registeredCredential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, registeredCredential))
	unknownCredential := cipher.HashPassword([]byte("not-the-registered-password"), []byte(userName))
	plaintext := newDummyMetadata()
	// The packet carries the hint of the registered user, which a client that
	// does not hold the credential of that user could not produce, and it is
	// protected by another credential, so only the AEAD trial can reject it.
	encryptedMetadataWithHint := encryptMetadataWithContext(t, unknownCredential, cipher.BlockContext{
		UserName: userName,
		Pepper:   cipher.HintPepper(userName, string(registeredCredential)),
	}, plaintext)

	for _, transport := range discoveryTransports {
		for _, hintMandatory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/MandatoryHint_%t", transport.name, hintMandatory), func(t *testing.T) {
				decryptedMetadata, matchedUser, err := transport.discover(users, hintMandatory, encryptedMetadataWithHint)
				if err == nil {
					t.Fatalf("discovery succeeded as user %q without authenticated decryption", matchedUser)
				}
				if decryptedMetadata != nil || matchedUser != "" {
					t.Fatalf("discovery returned unexpected result (metadata=%x, user=%q)", decryptedMetadata, matchedUser)
				}
			})
		}
	}
}

// TestUserDiscoveryMandatoryHint records that a mandatory hint cannot be
// bypassed. With optional hints, the same authenticated message must fall
// back safely. Hash collision are optimization misses and must preserve
// this full fallback.
func TestUserDiscoveryMandatoryHint(t *testing.T) {
	const userName = "fallback-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	plaintext := newDummyMetadata()
	encryptedMetadataNoHint := encryptDiscoveryMetadata(t, credential, "", users, false, plaintext)

	for _, transport := range discoveryTransports {
		t.Run(transport.name+"/OptionalHintFallsBack", func(t *testing.T) {
			decryptedMetadata, matchedUser, err := transport.discover(users, false, encryptedMetadataNoHint)
			if err != nil {
				t.Fatalf("optional-hint discovery failed: %v", err)
			}
			if !bytes.Equal(decryptedMetadata, plaintext) || matchedUser != userName {
				t.Fatalf("discovery = (%x, %q), want (%x, %q)", decryptedMetadata, matchedUser, plaintext, userName)
			}
		})
		t.Run(transport.name+"/MandatoryHintRejectsFallback", func(t *testing.T) {
			decryptedMetadata, matchedUser, err := transport.discover(users, true, encryptedMetadataNoHint)
			if err == nil {
				t.Fatalf("mandatory-hint discovery selected user %q without a usable hint", matchedUser)
			}
			if decryptedMetadata != nil || matchedUser != "" {
				t.Fatalf("discovery returned unexpected result (metadata=%x, user=%q)", decryptedMetadata, matchedUser)
			}
		})
	}
}

// TestUserDiscoveryHintPrecedence records selected identity semantics
// when credentials are shared. Even if a nonmatching user somehow has
// the same credential as the hinted user, the hinted user must
// retain precedence.
func TestUserDiscoveryHintPrecedence(t *testing.T) {
	const (
		hintedUser      = "hinted-user"
		nonmatchingUser = "cached-nonmatching-user"
	)
	sharedCredential := cipher.HashPassword([]byte(t.Name()), []byte("shared-credential"))
	users := userMap(
		makeTestUser(nonmatchingUser, sharedCredential),
		makeTestUser(hintedUser, sharedCredential),
	)
	plaintext := newDummyMetadata()
	encryptedMetadata := encryptDiscoveryMetadata(t, sharedCredential, hintedUser, users, true, plaintext)

	for _, transport := range discoveryTransports {
		for _, hintMandatory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/MandatoryHint_%t", transport.name, hintMandatory), func(t *testing.T) {
				decryptedMetadata, matchedUser, err := transport.discover(users, hintMandatory, encryptedMetadata)
				if err != nil {
					t.Fatalf("discovery failed: %v", err)
				}
				if !bytes.Equal(decryptedMetadata, plaintext) || matchedUser != hintedUser {
					t.Fatalf("discovery = (%x, %q), want (%x, %q)", decryptedMetadata, matchedUser, plaintext, hintedUser)
				}
			})
		}
	}
}

func TestDiscoveryWarmCachedHintMatch(t *testing.T) {
	const target = "warm-target"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(
		makeTestUser("registry-user-a", cipher.HashPassword([]byte("a"), []byte("registry-user-a"))),
		makeTestUser("registry-user-b", cipher.HashPassword([]byte("b"), []byte("registry-user-b"))),
		makeTestUser(target, credential),
	)
	publisher, mandatory := testPublisher(users, false)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(301), valid: true}
	state.cache.recordAuthenticated(source.key, testUserID(t, state, target), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptDiscoveryMetadata(t, credential, target, users, true, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, target, matchCachedHint, 1)
}

func TestDiscoveryOptionalCachedFallback(t *testing.T) {
	const target = "cached-fallback"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(makeTestUser(target, credential))
	publisher, mandatory := testPublisher(users, false)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(302), valid: true}
	state.cache.recordAuthenticated(source.key, testUserID(t, state, target), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptDiscoveryMetadata(t, credential, "", users, false, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, target, matchCachedFallback, 1)
}

func TestDiscoveryRegistryHintPrecedesCachedSharedCredential(t *testing.T) {
	const (
		cached = "cached-nonmatching"
		hinted = "hinted-registry-user"
	)
	credential := cipher.HashPassword([]byte(t.Name()), []byte("shared"))
	users := userMap(makeTestUser(cached, credential), makeTestUser(hinted, credential))
	publisher, mandatory := testPublisher(users, false)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(303), valid: true}
	state.cache.recordAuthenticated(source.key, testUserID(t, state, cached), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptDiscoveryMetadata(t, credential, hinted, users, true, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, hinted, matchRegistryHint, 1)
}

func TestDiscoveryMandatoryHintRejectsCachedFallback(t *testing.T) {
	const target = "cached-but-not-hinted"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(makeTestUser(target, credential))
	publisher, _ := testPublisher(users, true)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(304), valid: true}
	state.cache.recordAuthenticated(source.key, testUserID(t, state, target), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptDiscoveryMetadata(t, credential, "unregistered-hint", users, false, newDummyMetadata())

	result := tryState(state, encrypted, source, true)
	if result.block != nil || result.attempts != 0 {
		t.Fatalf("mandatory discovery = (block nil=%t, attempts=%d), want rejection without cached fallback", result.block == nil, result.attempts)
	}
}

func TestDiscoveryCacheMissPreservesRegistryFallback(t *testing.T) {
	const target = "z-registry-fallback"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(
		makeTestUser("a-wrong-user", cipher.HashPassword([]byte("wrong"), []byte("a-wrong-user"))),
		makeTestUser(target, credential),
	)
	publisher, mandatory := testPublisher(users, false)
	source := Source{key: sourceUserCacheTestKey(305), valid: true}
	encrypted := encryptDiscoveryMetadata(t, credential, "", users, false, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, target, matchRegistryFallback, 2)
}

func TestDiscoveryMultipleCachedUsers(t *testing.T) {
	const (
		first  = "first-cached-user"
		target = "second-cached-user"
	)
	firstCredential := cipher.HashPassword([]byte("first"), []byte(first))
	targetCredential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(makeTestUser(first, firstCredential), makeTestUser(target, targetCredential))
	publisher, mandatory := testPublisher(users, false)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(306), valid: true}
	state.cache.recordAuthenticated(source.key, testUserID(t, state, first), cipher.SuiteXChaCha20Poly1305)
	state.cache.recordAuthenticated(source.key, testUserID(t, state, target), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptDiscoveryMetadata(t, targetCredential, "", users, false, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, target, matchCachedFallback, 2)
}

func TestDiscoverySkipsInvalidCachedID(t *testing.T) {
	const target = "valid-cached-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(makeTestUser(target, credential))
	publisher, mandatory := testPublisher(users, false)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(307), valid: true}
	state.cache.recordAuthenticated(source.key, uint32(len(state.users)+100), cipher.SuiteXChaCha20Poly1305)
	state.cache.recordAuthenticated(source.key, testUserID(t, state, target), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptDiscoveryMetadata(t, credential, "", users, false, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, target, matchCachedFallback, 1)
}

// TestDiscoveryDoesNotRetryCachedCandidate checks that a cached candidate whose
// trial decryption failed is not tried a second time in the optional fallback
// phase: the packet carries the hint of the cached user, which is what puts it
// in the cached hint phase, while only the later registry scan authenticates the
// real user.
func TestDiscoveryDoesNotRetryCachedCandidate(t *testing.T) {
	const (
		cachedWrong = "a-cached-wrong"
		target      = "z-correct-user"
	)
	wrongCredential := cipher.HashPassword([]byte("wrong"), []byte(cachedWrong))
	targetCredential := cipher.HashPassword([]byte(t.Name()), []byte(target))
	users := userMap(makeTestUser(cachedWrong, wrongCredential), makeTestUser(target, targetCredential))
	publisher, mandatory := testPublisher(users, false)
	state := publisher.Load()
	source := Source{key: sourceUserCacheTestKey(308), valid: true}
	state.cache.recordAuthenticated(source.key, testUserID(t, state, cachedWrong), cipher.SuiteXChaCha20Poly1305)
	encrypted := encryptMetadataWithContext(t, targetCredential, cipher.BlockContext{
		UserName: cachedWrong,
		Pepper:   cipher.HintPepper(cachedWrong, string(wrongCredential)),
	}, newDummyMetadata())

	result, err := discoverUser(publisher, mandatory, encrypted, source, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	assertDiscovery(t, result, target, matchRegistryFallback, 2)
}

func TestDiscoverySharedCredentialContextsAreIndependent(t *testing.T) {
	const (
		userA = "shared-user-a"
		userB = "shared-user-b"
	)
	credential := cipher.HashPassword([]byte(t.Name()), []byte("shared"))
	users := userMap(makeTestUser(userA, credential), makeTestUser(userB, credential))
	publisher, mandatory := testPublisher(users, true)
	encrypted := map[string][]byte{
		userA: encryptDiscoveryMetadata(t, credential, userA, users, true, newDummyMetadata()),
		userB: encryptDiscoveryMetadata(t, credential, userB, users, true, newDummyMetadata()),
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 32; i++ {
		want := userA
		if i%2 != 0 {
			want = userB
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := discoverUser(publisher, mandatory, encrypted[want], Source{}, false, nil)
			if err != nil {
				errCh <- err
				return
			}
			result.block.SetBlockContext(result.userContext)
			if got := result.block.BlockContext().UserName; got != want {
				errCh <- fmt.Errorf("matched context = %q, want %q", got, want)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// encryptMetadataWithContext protects metadata as a client that uses the given
// block context, so a test can choose the user hint variant of its client.
func encryptMetadataWithContext(tb testing.TB, credential []byte, ctx cipher.BlockContext, plaintext []byte) []byte {
	tb.Helper()
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
	if err != nil {
		tb.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	block.SetBlockContext(ctx)
	encryptedMeta := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
	if err := block.Encrypt(encryptedMeta[:0], plaintext); err != nil {
		tb.Fatalf("Encrypt() failed: %v", err)
	}
	return encryptedMeta
}

// encryptMetadataWithHint retries the randomized nonce until the hint of the
// produced metadata matches the requested hint relationship with the compiled
// users. The hint is computed from the random bytes in front of it, so a single
// attempt is normally enough; retrying removes the unlikely case of a hint that
// does not match the user whose name the client claims.
func encryptMetadataWithHint(tb testing.TB, credential []byte, ctx cipher.BlockContext, compiled *state, wantMatch bool, plaintext []byte) []byte {
	tb.Helper()
	for range 10 {
		encrypted := encryptMetadataWithContext(tb, credential, ctx, plaintext)
		matches := false
		for i := range compiled.users {
			if compiled.users[i].hintMatches(encrypted[:cipher.DefaultNonceSize]) {
				matches = true
			}
		}
		if matches == wantMatch {
			return encrypted
		}
	}
	tb.Fatalf("failed to build metadata whose user hint matches is %t", wantMatch)
	return nil
}

// TestUserDiscoveryAcceptsKeyedHint records that the user a client claims is
// found when the hint of the client is the keyed hint of that user, which
// requires the credential shared by the client and the server.
func TestUserDiscoveryAcceptsKeyedHint(t *testing.T) {
	const userName = "keyed-hint-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	plaintext := newDummyMetadata()

	state := buildState(users, cipher.AllSuites())
	if len(state.users) != 1 {
		t.Fatalf("compiled user count = %d, want 1", len(state.users))
	}
	pepper := state.users[0].pepper
	if want := cipher.HintPepper(userName, string(credential)); !bytes.Equal(pepper, want) {
		t.Errorf("compiled pepper = %x, want %x", pepper, want)
	}

	ctx := cipher.BlockContext{UserName: userName, Pepper: pepper}
	encrypted := encryptMetadataWithHint(t, credential, ctx, state, true, plaintext)
	for _, transport := range discoveryTransports {
		for _, hintMandatory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/MandatoryHint_%t", transport.name, hintMandatory), func(t *testing.T) {
				decryptedMeta, matchedUser, err := transport.discover(users, hintMandatory, encrypted)
				if err != nil {
					t.Fatalf("discovery failed: %v", err)
				}
				if !bytes.Equal(decryptedMeta, plaintext) {
					t.Errorf("decrypted metadata = %x, want %x", decryptedMeta, plaintext)
				}
				if matchedUser != userName {
					t.Errorf("discovered user = %q, want %q", matchedUser, userName)
				}
			})
		}
	}

	// A hint built from another credential must not select this user, so
	// with mandatory hints the trial decryption is never reached. The metadata
	// itself is protected by the credential of the user, so optional hints fall
	// back to the registry scan and still find the user: a hint is a filter of
	// candidate users, never an access control decision.
	mismatchedCtx := cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, "another-password")}
	mismatched := encryptMetadataWithHint(t, credential, mismatchedCtx, state, false, plaintext)
	for _, transport := range discoveryTransports {
		t.Run(fmt.Sprintf("%s/mismatched-hint", transport.name), func(t *testing.T) {
			if _, _, err := transport.discover(users, true, mismatched); err == nil {
				t.Error("discovery succeeded with mandatory hints and a hint of another credential")
			}
			decryptedMeta, matchedUser, err := transport.discover(users, false, mismatched)
			if err != nil {
				t.Fatalf("discovery with optional hints failed: %v", err)
			}
			if matchedUser != userName || !bytes.Equal(decryptedMeta, plaintext) {
				t.Errorf("discovery with optional hints = (metadata %x, user %q), want (%x, %q)", decryptedMeta, matchedUser, plaintext, userName)
			}
		})
	}
}

// TestServerResponseCarriesUserHint records that the handshake response the
// server protects with the cipher of a discovered user carries the hint of that
// user. Nothing verifies a hint on a response, a client ignores it, so this is
// only about not leaking the user name: the hint is derived from the credential
// of the user, so an observer of a response cannot test whether a guessed name
// is registered.
func TestServerResponseCarriesUserHint(t *testing.T) {
	const userName = "keyed-response-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	plaintext := newDummyMetadata()

	state := buildState(users, cipher.AllSuites())
	if len(state.users) != 1 {
		t.Fatalf("compiled user count = %d, want 1", len(state.users))
	}
	pepper := state.users[0].pepper

	publisher, mandatory := testPublisher(users, false)
	request := encryptMetadataWithHint(t, credential, cipher.BlockContext{UserName: userName, Pepper: pepper}, state, true, plaintext)
	result, err := discoverUser(publisher, mandatory, request, Source{}, false, nil)
	if err != nil {
		t.Fatalf("discoverUser() failed: %v", err)
	}
	// Discover() applies the context of the discovered user to the cipher it
	// returns; the handshake response is protected with that cipher.
	result.block.SetBlockContext(result.userContext)
	if got := result.block.BlockContext().Pepper; !bytes.Equal(got, pepper) {
		t.Errorf("response cipher pepper = %x, want %x", got, pepper)
	}

	response := []byte("handshake response")
	encrypted := make([]byte, result.block.NonceSize()+len(response)+result.block.Overhead())
	if err := result.block.Encrypt(encrypted[:0], response); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	nonce := encrypted[:cipher.DefaultNonceSize]
	if !cipher.CheckUserFromHintV3(pepper, []byte(userName), nonce) {
		t.Fatal("the response nonce does not carry the user hint of the user")
	}
}

// assertDiscovery verifies the discovered identity, the number of cipher
// trials and the candidate phase of tryState that produced the match.
// wantOrigin is asserted through discoveryResult.origin, which exists only so
// tests can observe the phase order.
func assertDiscovery(t *testing.T, result discoveryResult, wantUser string, wantOrigin matchOrigin, wantAttempts int) {
	t.Helper()
	if result.block == nil || !bytes.Equal(result.decryptedMetadata, newDummyMetadata()) {
		t.Fatalf("discovery returned block nil=%t, metadata=%x", result.block == nil, result.decryptedMetadata)
	}
	if result.userID == 0 || result.userContext.UserName != wantUser || result.policy.name != wantUser {
		t.Fatalf("discovery identity = (ID %d, context %q, policy %q), want %q", result.userID, result.userContext.UserName, result.policy.name, wantUser)
	}
	if result.origin != wantOrigin || result.attempts != wantAttempts {
		t.Fatalf("discovery path = (origin %d, attempts %d), want (%d, %d)", result.origin, result.attempts, wantOrigin, wantAttempts)
	}
	if result.generation == nil {
		t.Fatal("discovery did not return its user generation")
	}
}

func testUserID(t *testing.T, state *state, name string) uint32 {
	t.Helper()
	for i := range state.users {
		if state.users[i].name == name {
			return state.users[i].id
		}
	}
	t.Fatalf("compiled user %q not found", name)
	return 0
}

func makeTestUser(name string, credential []byte) *appctlpb.User {
	return &appctlpb.User{
		Name:           proto.String(name),
		HashedPassword: proto.String(hex.EncodeToString(credential)),
	}
}

func userMap(users ...*appctlpb.User) map[string]*appctlpb.User {
	result := make(map[string]*appctlpb.User, len(users))
	for _, user := range users {
		result[user.GetName()] = user
	}
	return result
}

func newDummyMetadata() []byte {
	metadata := make([]byte, metadataLength)
	for i := range metadata {
		metadata[i] = byte(i)
	}
	return metadata
}

// encryptDiscoveryMetadata retries the randomized nonce until it has exactly
// the requested hint relationship with the registered users: wantHint selects
// metadata whose hint matches hintUser and no other user, and !wantHint selects
// metadata whose hint matches no user. The hint of the client is derived from
// the credential the caller passes, so a client that does not hold the
// credential of hintUser cannot produce metadata whose hint matches that user.
// The probability of an accidental hint collision is very low so we don't need
// to retry a lot.
func encryptDiscoveryMetadata(tb testing.TB, credential []byte, hintUser string, users map[string]*appctlpb.User, wantHint bool, plaintext []byte) []byte {
	tb.Helper()
	compiled := buildState(users, cipher.AllSuites())
	pepper := cipher.HintPepper(hintUser, string(credential))
	for range 10 {
		block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
		if err != nil {
			tb.Fatalf("BlockCipherFromPassword() failed: %v", err)
		}
		block.SetBlockContext(cipher.BlockContext{UserName: hintUser, Pepper: pepper})
		encryptedMeta := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
		if err := block.Encrypt(encryptedMeta[:0], plaintext); err != nil {
			tb.Fatalf("Encrypt() failed: %v", err)
		}

		matches := 0
		matchedUser := ""
		for i := range compiled.users {
			if compiled.users[i].hintMatches(encryptedMeta[:cipher.DefaultNonceSize]) {
				matches++
				matchedUser = compiled.users[i].name
			}
		}
		if wantHint && matches == 1 && matchedUser == hintUser {
			return encryptedMeta
		}
		if !wantHint && matches == 0 {
			return encryptedMeta
		}
	}
	tb.Fatalf("failed to generate metadata with requested hint relationship after multiple attempts")
	return nil
}
