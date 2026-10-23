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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/Acheirial/shadowlemon/v3/apis/constant"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
)

// metadataLength is the fixed plaintext size of the ShadowLemon protocol
// metadata.
// We don't use the definition in protocol package, because protocol depends on
// this package.
const metadataLength = 32

// user is the immutable authentication record used by server side user discovery.
// IDs are dense within one generation and start at 1. ID 0 is reserved for an
// empty source-user cache slot.
type user struct {
	id         uint32
	name       string
	credential [sha256.Size]byte
	// pepper is the keyed user hint pepper of this user, precomputed from the
	// name and the credential by HintPepper. It is immutable after
	// publication, so the hint of an incoming packet can be checked without
	// deriving it again.
	pepper []byte
	// suites is the cipher suite order that discovery tries for this user: the
	// suites the server allows first, followed by the remaining supported
	// suites. It also gates the single suite decryptor built from a cached
	// hint, so a hint for a suite outside the allowed set stays usable.
	suites []cipher.Suite
	// decryptor is the stateless decryptor of this user, built over every suite
	// in suites and the credential of the user. The block it returns is the
	// block that authenticated the request, and it is the block used to protect
	// the handshake response.
	decryptor *cipher.StatelessDecryptor
	policy    Policy

	// suiteMu guards the single suite decryptor built on demand. The source
	// user cache records the cipher suite that authenticated a user, so the
	// next discovery of the same user can try that suite before the others.
	// A failed trial falls back to decryptor, so a wrong hint only costs one
	// extra AEAD attempt.
	suiteMu        sync.Mutex
	preferredSuite cipher.Suite
	preferred      *cipher.StatelessDecryptor
}

// Policy contains the value-based user settings retained after
// authentication.
type Policy struct {
	name string
}

// Name returns the authenticated user name.
func (p Policy) Name() string { return p.name }

// state is immutable after publication, except for its explicitly
// concurrent cache. A cache belongs to exactly one state generation.
type state struct {
	users []user
	cache *sourceUserCache
	// failCache remembers recent (source, hint) discovery failures of this
	// generation. It is retired together with cache when a new generation is
	// published, so a user added by a reload is immediately discoverable.
	failCache *sourceFailCache
}

// Registry owns the current server users and their source decryption cache.
// Its zero value is ready to use.
type Registry struct {
	users         atomic.Pointer[state]
	hintMandatory atomic.Bool

	// allowedSuites is the cipher suite set the server accepts for the data
	// plane of a session. A nil value means all the supported cipher suites.
	//
	// The set restricts the negotiation only. User discovery still decrypts
	// the envelope of an open session request with every supported cipher
	// suite, because that envelope is protected by the first suite of the
	// client preference list, which the client picks before it can know the
	// allowed set.
	allowedSuites atomic.Pointer[[]cipher.Suite]

	// lastUsers retains the user map of the last SetUsers call, so that
	// SetAllowedCipherSuites can rebuild the discovery material of the users.
	lastUsers atomic.Pointer[map[string]*appctlpb.User]
}

// Source identifies an optional source-user cache lookup.
// A zero value disables the cache without changing authentication fallback.
type Source struct {
	key   [16]byte
	valid bool
}

// matchOrigin identifies the candidate phase of tryState that matched. It is
// recorded only so tests can observe the phase order; identity resolution,
// caching and authentication don't depend on this value.
type matchOrigin uint8

const (
	matchCachedHint matchOrigin = iota
	matchRegistryHint
	matchCachedFallback
	matchRegistryFallback
)

// discoveryResult contains only the matched identity and immutable
// policy needed after discovery. generation is retained only while the caller
// validates and commits initial authentication; established connections and
// sessions must not retain it. origin records which candidate phase of
// tryState matched; it is for test observation of the phase order only and
// is never read by production code.
type discoveryResult struct {
	block             cipher.BlockCipher
	decryptedMetadata []byte
	userID            uint32
	userContext       cipher.BlockContext
	suite             cipher.Suite
	policy            Policy
	origin            matchOrigin
	generation        *state
	attempts          int
}

// Authentication is retained only while a newly authenticated
// segment is structurally validated and dispatched. In particular, generation
// must not be retained by an established underlay or session.
type Authentication struct {
	userID     uint32
	policy     Policy
	suite      cipher.Suite
	generation *state
	source     Source
}

func (r discoveryResult) authentication(source Source) Authentication {
	return Authentication{
		userID:     r.userID,
		policy:     r.policy,
		suite:      r.suite,
		generation: r.generation,
		source:     source,
	}
}

func (a *Authentication) valid() bool {
	return a != nil && a.userID != 0 && a.generation != nil
}

// Valid reports whether this value holds a pending authentication.
func (a *Authentication) Valid() bool { return a.valid() }

// Policy returns the immutable policy of the authenticated user.
func (a Authentication) Policy() Policy { return a.policy }

// recordAuthenticated records only into the generation used for discovery.
// A concurrent reload may already have retired that generation's cache, in
// which case the update is intentionally a no-op.
func (a *Authentication) recordAuthenticated() {
	if !a.valid() {
		return
	}
	generation := a.generation
	a.generation = nil
	if a.source.valid && generation.cache != nil {
		generation.cache.recordAuthenticated(a.source.key, a.userID, a.suite)
	}
}

// Record stores the authenticated source-to-user association. It is a no-op
// when the source is unavailable or the user generation has been retired.
func (a *Authentication) Record() { a.recordAuthenticated() }

// sourceUserCache owns an atomically detachable table. Cache lookup and update
// operations load table once; retirement prevents later operations from
// starting while allowing an operation that already loaded the table to finish.
type sourceUserCache struct {
	table       atomic.Pointer[sourceUserCacheTable]
	tick        sourceUserCacheTickFunc
	bucketLocks [sourceUserCacheLockStripes]sync.Mutex
}

const (
	sourceUserCacheBucketCount = 4096
	sourceUserCacheWays        = 4
	sourceUserCacheUsers       = 16
	sourceUserCacheLockStripes = 256
)

type sourceUserCacheTable struct {
	buckets [sourceUserCacheBucketCount]sourceUserCacheBucket
}

type sourceUserCacheBucket struct {
	ways [sourceUserCacheWays]atomic.Pointer[sourceUserCacheEntry]
}

type sourceUserCacheEntry struct {
	key        [16]byte
	lastActive atomic.Uint32
	users      [sourceUserCacheUsers]atomic.Uint64
	// suites stores the cipher suite that authenticated the user of the same
	// slot the last time. It is a non-authenticating hint that changes the
	// trial order only.
	suites [sourceUserCacheUsers]atomic.Uint32
}

func newSourceUserCache() *sourceUserCache {
	return newSourceUserCacheWithTick(sourceUserCacheCurrentTick)
}

func (c *sourceUserCache) loadTable() *sourceUserCacheTable {
	if c == nil {
		return nil
	}
	return c.table.Load()
}

func (c *sourceUserCache) retire() {
	if c != nil {
		c.table.Swap(nil)
	}
}

// SetUsers compiles and atomically publishes a new server user generation.
func (r *Registry) SetUsers(users map[string]*appctlpb.User) {
	retained := make(map[string]*appctlpb.User, len(users))
	for name, user := range users {
		retained[name] = user
	}
	r.lastUsers.Store(&retained)
	state := buildState(users, r.AllowedCipherSuites())
	old := r.users.Swap(state)
	if old != nil {
		old.cache.retire()
		old.failCache.retire()
	}
}

// SetAllowedCipherSuites sets the cipher suite set that the server allows for
// the data plane of new sessions. Duplicates and unknown suites are dropped,
// and an empty list allows all the supported cipher suites.
//
// The set restricts the negotiated suite only: the discovery material of the
// users is rebuilt so that the allowed suites are tried first, but it still
// covers every supported suite, because a client protects its handshake
// request with a suite of its own preference list.
//
// The discovery material of the users is rebuilt, so this method is meant to
// be called on configuration reload.
func (r *Registry) SetAllowedCipherSuites(suites []cipher.Suite) {
	normalized := normalizeAllowedSuites(suites)
	r.allowedSuites.Store(&normalized)
	if users := r.lastUsers.Load(); users != nil {
		r.SetUsers(*users)
	}
}

// AllowedCipherSuites returns the cipher suite set that the server allows for
// the negotiation of a session data plane. User discovery is not restricted by
// this set.
func (r *Registry) AllowedCipherSuites() []cipher.Suite {
	if p := r.allowedSuites.Load(); p != nil && len(*p) != 0 {
		return *p
	}
	return cipher.AllSuites()
}

// normalizeAllowedSuites returns a copy of suites without unknown or duplicate
// entries. An empty result is replaced by all the supported cipher suites.
func normalizeAllowedSuites(suites []cipher.Suite) []cipher.Suite {
	normalized := make([]cipher.Suite, 0, len(suites))
	for _, suite := range suites {
		if !suite.IsValid() || slices.Contains(normalized, suite) {
			continue
		}
		normalized = append(normalized, suite)
	}
	if len(normalized) == 0 {
		return cipher.AllSuites()
	}
	return normalized
}

// SetHintMandatory sets whether discovery requires a matching user hint.
func (r *Registry) SetHintMandatory(mandatory bool) {
	r.hintMandatory.Store(mandatory)
}

// HasUsers reports whether the current generation contains a usable user.
func (r *Registry) HasUsers() bool {
	state := r.users.Load()
	return state != nil && len(state.users) != 0
}

// Discover decrypts metadata with the current user registry. When
// requireCurrent is true, discovery retries if users are reloaded before the
// result is returned.
//
// When the registry requires a user hint, a source address that recently
// failed discovery with the same hint is rejected before the trial
// decryption loop; a successful discovery clears the recorded failure. The
// negative cache is never consulted when hints are optional.
func (r *Registry) Discover(encryptedMetadata []byte, source Source, requireCurrent bool) (cipher.BlockCipher, []byte, Authentication, error) {
	result, err := discoverUser(&r.users, &r.hintMandatory, encryptedMetadata, source, requireCurrent, nil)
	if err != nil {
		return nil, nil, Authentication{}, err
	}
	result.block.SetBlockContext(result.userContext)
	return result.block, result.decryptedMetadata, result.authentication(source), nil
}

// discoverySuites returns the cipher suite order that user discovery tries:
// the suites the server allows first, because a client is most likely to offer
// one of them, followed by the remaining supported suites.
//
// Discovery must not be limited to the allowed suites: the envelope of a
// handshake request is protected by the first suite of the client preference
// list, which the client picks before it can know what the server allows.
func discoverySuites(allowedSuites []cipher.Suite) []cipher.Suite {
	suites := make([]cipher.Suite, 0, len(cipher.AllSuites()))
	for _, suite := range allowedSuites {
		if suite.IsValid() && !slices.Contains(suites, suite) {
			suites = append(suites, suite)
		}
	}
	for _, suite := range cipher.AllSuites() {
		if !slices.Contains(suites, suite) {
			suites = append(suites, suite)
		}
	}
	return suites
}

// buildState compiles the immutable user generation of the registry.
//
// allowedSuites is the cipher suite set the server allows for the data plane.
// It decides the trial order of discovery and nothing else: the negotiated
// suite is restricted to it in the session handshake, while discovery has to
// accept an envelope of any supported suite.
func buildState(users map[string]*appctlpb.User, allowedSuites []cipher.Suite) *state {
	if len(allowedSuites) == 0 {
		allowedSuites = cipher.AllSuites()
	}
	suites := discoverySuites(allowedSuites)
	type inputUser struct {
		mapKey string
		user   *appctlpb.User
		name   string
	}

	inputs := make([]inputUser, 0, len(users))
	nameCounts := make(map[string]int, len(users))
	for mapKey, user := range users {
		name := ""
		if user != nil {
			name = user.GetName()
		}
		inputs = append(inputs, inputUser{mapKey: mapKey, user: user, name: name})
		nameCounts[name]++
	}

	// Sort users by name.
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].name == inputs[j].name {
			return inputs[i].mapKey < inputs[j].mapKey
		}
		return inputs[i].name < inputs[j].name
	})

	compiled := make([]user, 0, len(inputs))
	loggedDuplicate := make(map[string]struct{})
	loggedEmptyName := false
	for _, input := range inputs {
		if input.name == "" {
			if !loggedEmptyName {
				log.Warnf("Skipping server user with empty name")
				loggedEmptyName = true
			}
			continue
		}
		if nameCounts[input.name] > 1 {
			if _, ok := loggedDuplicate[input.name]; !ok {
				log.Warnf("Skipping duplicate server user name %q", input.name)
				loggedDuplicate[input.name] = struct{}{}
			}
			continue
		}
		if len(input.name) > constant.MaxUserNameLen {
			log.Warnf("Skipping server user %q: name exceeds %d bytes", input.name, constant.MaxUserNameLen)
			continue
		}

		credential, err := buildCredential(input.user, input.name)
		if err != nil {
			log.Warnf("Skipping server user %q: %v", input.name, err)
			continue
		}
		decryptor, err := cipher.NewStatelessDecryptor(suites, credential[:])
		if err != nil {
			log.Warnf("Skipping server user %q: failed to prepare credential", input.name)
			continue
		}
		compiled = append(compiled, user{
			id:         uint32(len(compiled) + 1),
			name:       input.name,
			credential: credential,
			pepper:     cipher.HintPepper(input.name, string(credential[:])),
			suites:     suites,
			decryptor:  decryptor,
			policy:     buildPolicy(input.user),
		})
	}

	return &state{
		users:     compiled,
		cache:     newSourceUserCache(),
		failCache: newSourceFailCache(),
	}
}

func buildCredential(user *appctlpb.User, name string) ([sha256.Size]byte, error) {
	var credential [sha256.Size]byte
	if user == nil {
		return credential, fmt.Errorf("user record is nil")
	}
	if user.GetHashedPassword() != "" {
		decoded, err := hex.DecodeString(user.GetHashedPassword())
		if err != nil {
			return credential, fmt.Errorf("hashed credential is not valid hexadecimal")
		}
		if len(decoded) != len(credential) {
			return credential, fmt.Errorf("hashed credential decodes to %d bytes, want %d", len(decoded), len(credential))
		}
		copy(credential[:], decoded)
		return credential, nil
	}
	if user.GetPassword() == "" {
		return credential, fmt.Errorf("credential is empty")
	}
	copy(credential[:], cipher.HashPassword([]byte(user.GetPassword()), []byte(name)))
	return credential, nil
}

func buildPolicy(user *appctlpb.User) Policy {
	return Policy{name: user.GetName()}
}

// BuildPolicies snapshots the session policies for a user map.
func BuildPolicies(users map[string]*appctlpb.User) map[string]Policy {
	if len(users) == 0 {
		return nil
	}
	policies := make(map[string]Policy, len(users))
	for _, user := range users {
		if user == nil || user.GetName() == "" {
			continue
		}
		policies[user.GetName()] = buildPolicy(user)
	}
	return policies
}

// discoverUser tries one immutable state generation. When requireCurrent
// is true, a concurrent publication forces the complete discovery to retry
// before the result can be installed.
func discoverUser(
	publisher *atomic.Pointer[state],
	hintMandatory *atomic.Bool,
	encryptedMetadata []byte,
	source Source,
	requireCurrent bool,
	afterAttempt func(*state),
) (discoveryResult, error) {
	if len(encryptedMetadata) < cipher.DefaultNonceSize {
		return discoveryResult{}, fmt.Errorf("encrypted metadata is shorter than nonce")
	}
	if publisher == nil {
		return discoveryResult{}, fmt.Errorf("server user publisher is nil")
	}

	for {
		state := publisher.Load()
		if state == nil || len(state.users) == 0 {
			return discoveryResult{}, fmt.Errorf("no server user found")
		}
		mandatory := false
		if hintMandatory != nil {
			mandatory = hintMandatory.Load()
		}

		// The negative cache is only consulted while a user hint is
		// mandatory. With optional hints, a failing hint may simply mean that
		// the packet carried no hint, so suppressing the source would reject
		// a legitimate fallback user.
		var failCache *sourceFailCache
		var hint [cipher.NonceSuffixLenForUserHint]byte
		if mandatory && source.valid {
			hint = userHintFromMetadata(encryptedMetadata)
			failCache = state.failCache
			if failCache.miss(source.key, hint) {
				return discoveryResult{}, fmt.Errorf("user hint is suppressed by the source failure cache")
			}
		}

		result := tryState(state, encryptedMetadata, source, mandatory)
		if afterAttempt != nil {
			afterAttempt(state)
		}
		if requireCurrent && publisher.Load() != state {
			continue
		}
		if result.block == nil {
			if failCache != nil {
				failCache.recordFailure(source.key, hint)
			}
			return discoveryResult{}, fmt.Errorf("cipher.TryDecrypt() failed for all users")
		}
		if failCache != nil {
			failCache.clear(source.key)
		}
		result.generation = state
		return result, nil
	}
}

// userHintFromMetadata returns the 4 byte user hint embedded at the end of the
// wire nonce. The caller must ensure that the metadata is at least as long as
// a nonce; discoverUser checks this before calling the function.
func userHintFromMetadata(encryptedMetadata []byte) [cipher.NonceSuffixLenForUserHint]byte {
	var hint [cipher.NonceSuffixLenForUserHint]byte
	copy(hint[:], encryptedMetadata[cipher.DefaultNonceSize-cipher.NonceSuffixLenForUserHint:cipher.DefaultNonceSize])
	return hint
}

// hintMatches reports whether the user hint embedded in the nonce belongs to
// this user.
//
// The hint is keyed: it is derived from the credential shared by the client and
// the server as well as the user name, so the name of a registered user is not
// observable to an attacker who only knows that name, and a hint cannot be
// built or checked without the credential.
//
// A matching hint never authenticates anything: it only decides which users are
// worth an AEAD trial, see tryState.
func (u *user) hintMatches(nonce []byte) bool {
	return cipher.CheckUserFromHintV3(u.pepper, []byte(u.name), nonce)
}

// tryState applies the identity-preserving candidate order:
// cached hint matches, remaining registry hint matches, cached optional
// fallback, then remaining registry optional fallback. Each user is tried at
// most once even when it appears in more than one phase.
//
// A hint match is the only thing that narrows down which users are worth an AEAD
// trial: a hint that matches a registered user triggers the AEAD trial
// decryption of that user (up to every supported cipher suite), while a hint
// that matches nothing costs only the SHA-256 filter of every user and no AEAD
// work at all. With optional hints that difference is hidden by the
// unconditional fallback trial; with mandatory hints it is observable, but a
// matching hint cannot be built without the credential of a user, so the
// measurement only confirms a hint that a client of that user already produced.
// The source failure cache bounds how often one source can repeat the
// measurement with a repeated packet, but it does not remove the channel;
// removing it needs constant-work hashing for unmatched hints.
func tryState(state *state, encryptedMeta []byte, source Source, hintMandatory bool) discoveryResult {
	nonce := encryptedMeta[:cipher.DefaultNonceSize]
	var trialPlaintext [metadataLength]byte
	var cachedIDs [sourceUserCacheUsers]sourceUserCacheCandidate
	cachedCount := 0
	if source.valid && state.cache != nil {
		cachedIDs, cachedCount = state.cache.lookup(source.key)
	}

	var attemptedCachedIDs [sourceUserCacheUsers]uint32
	attemptedCachedCount := 0
	attempts := 0

	// A successful cached hint match is the normal warm path and returns
	// without scanning the complete registry.
	for i := 0; i < cachedCount; i++ {
		user := userByID(state, cachedIDs[i].id)
		if user == nil || userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) || !user.hintMatches(nonce) {
			continue
		}
		attemptedCachedCount = markUserIDAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id)
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], matchCachedHint, cachedIDs[i].suite); result.block != nil {
			result.attempts = attempts
			return result
		}
	}

	// All registry hint matches retain precedence over cached users whose
	// names do not match the hint, including when credentials are shared.
	// Reaching this point enters a complete-registry phase.
	for i := range state.users {
		user := &state.users[i]
		if userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) || !user.hintMatches(nonce) {
			continue
		}
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], matchRegistryHint, noSuiteHint); result.block != nil {
			result.attempts = attempts
			return result
		}
	}

	if hintMandatory {
		return discoveryResult{attempts: attempts}
	}

	for i := 0; i < cachedCount; i++ {
		user := userByID(state, cachedIDs[i].id)
		if user == nil || userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) {
			continue
		}
		// Hint matches were already tried in one of the two preceding phases.
		if user.hintMatches(nonce) {
			continue
		}
		attemptedCachedCount = markUserIDAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id)
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], matchCachedFallback, cachedIDs[i].suite); result.block != nil {
			result.attempts = attempts
			return result
		}
	}

	for i := range state.users {
		user := &state.users[i]
		if userIDWasAttempted(&attemptedCachedIDs, attemptedCachedCount, user.id) {
			continue
		}
		// Every hint match was tried during the registry hint phase. Skipping
		// them here avoids a second cipher trial without an unbounded ID set.
		if user.hintMatches(nonce) {
			continue
		}
		attempts++
		if result := tryUser(user, encryptedMeta, trialPlaintext[:0], matchRegistryFallback, noSuiteHint); result.block != nil {
			result.attempts = attempts
			return result
		}
	}
	return discoveryResult{attempts: attempts}
}

func userIDWasAttempted(attempted *[sourceUserCacheUsers]uint32, count int, userID uint32) bool {
	for i := 0; i < count; i++ {
		if attempted[i] == userID {
			return true
		}
	}
	return false
}

func markUserIDAttempted(attempted *[sourceUserCacheUsers]uint32, count int, userID uint32) int {
	if count < len(attempted) && !userIDWasAttempted(attempted, count, userID) {
		attempted[count] = userID
		return count + 1
	}
	return count
}

func userByID(state *state, userID uint32) *user {
	if state == nil || userID == 0 || userID > uint32(len(state.users)) {
		return nil
	}
	user := &state.users[userID-1]
	if user.id != userID {
		return nil
	}
	return user
}

func tryUser(user *user, encryptedMeta, dst []byte, origin matchOrigin, suiteHint cipher.Suite) discoveryResult {
	// A cached suite hint only reorders the trials of this user: the result
	// is still accepted by its AEAD tag, so a wrong hint just costs one extra
	// attempt.
	if suiteHint.IsValid() {
		if block, plaintext, ok := user.trySuite(suiteHint, encryptedMeta, dst); ok {
			return discoveryResult{
				block:             block,
				decryptedMetadata: plaintext,
				userID:            user.id,
				userContext:       cipher.BlockContext{UserName: user.name, Pepper: user.pepper},
				suite:             suiteHint,
				policy:            user.policy,
				origin:            origin,
			}
		}
	}
	block, plaintext, err := user.decryptor.TryDecrypt(encryptedMeta, dst)
	if err != nil {
		return discoveryResult{}
	}
	return discoveryResult{
		block:             block,
		decryptedMetadata: plaintext,
		userID:            user.id,
		userContext:       cipher.BlockContext{UserName: user.name, Pepper: user.pepper},
		suite:             block.Suite(),
		policy:            user.policy,
		origin:            origin,
	}
}

// noSuiteHint marks a trial that has no cached cipher suite to try first.
const noSuiteHint cipher.Suite = 0xff

// trySuite tries to decrypt encryptedMeta with a single cipher suite of the
// given user. The decryptor of the suite is built on demand and reused, so a
// repeated cache hint doesn't rebuild it.
func (u *user) trySuite(suite cipher.Suite, encryptedMeta, dst []byte) (cipher.BlockCipher, []byte, bool) {
	if !suite.IsValid() || !slices.Contains(u.suites, suite) {
		return nil, nil, false
	}
	decryptor, err := u.suiteDecryptor(suite)
	if err != nil {
		return nil, nil, false
	}
	block, plaintext, err := decryptor.TryDecrypt(encryptedMeta, dst)
	if err != nil {
		return nil, nil, false
	}
	return block, plaintext, true
}

// suiteDecryptor returns the decryptor of a single cipher suite of this user,
// building it on demand. It decrypts the same envelope key derivation as the
// decryptor of the whole user, so a cached suite hint only changes the order in
// which the suites of a user are tried.
func (u *user) suiteDecryptor(suite cipher.Suite) (*cipher.StatelessDecryptor, error) {
	u.suiteMu.Lock()
	defer u.suiteMu.Unlock()
	if u.preferred != nil && u.preferredSuite == suite {
		return u.preferred, nil
	}
	decryptor, err := cipher.NewStatelessDecryptor([]cipher.Suite{suite}, u.credential[:])
	if err != nil {
		return nil, fmt.Errorf("cipher.NewStatelessDecryptor() failed: %w", err)
	}
	u.preferredSuite = suite
	u.preferred = decryptor
	return decryptor, nil
}
