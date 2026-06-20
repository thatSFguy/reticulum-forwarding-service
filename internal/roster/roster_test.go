package roster

import (
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"
)

func mustHash(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestRoster(t *testing.T) (*Roster, string) {
	t.Helper()
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "state.json"))
	r, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	return r, dir
}

const hashA = "00112233445566778899aabbccddeeff"
const hashB = "112233445566778899aabbccddeeff00"
const hashC = "2233445566778899aabbccddeeff0011"

func TestAddOrUpdateNewVsReturning(t *testing.T) {
	r, _ := newTestRoster(t)
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	isNew, err := r.AddOrUpdate(mustHash(t, hashA), now)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Error("expected first AddOrUpdate to report new")
	}
	isNew, _ = r.AddOrUpdate(mustHash(t, hashA), now.Add(time.Minute))
	if isNew {
		t.Error("expected second AddOrUpdate to report not-new")
	}
}

func TestPruneRespectsCutoff(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-5*7*24*time.Hour)) // 5 weeks ago
	_, _ = r.AddOrUpdate(mustHash(t, hashB), t0.Add(-1*time.Hour))      // recent

	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0] != hashA {
		t.Errorf("expected %s pruned, got %v", hashA, pruned)
	}
	if !r.Has(mustHash(t, hashB)) {
		t.Error("recent user should not have been pruned")
	}
	if r.Has(mustHash(t, hashA)) {
		t.Error("stale user should have been pruned")
	}
}

func TestPruneRespectsAnnounceFreshness(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-5*7*24*time.Hour))
	// announced recently — should keep them alive even though no recent message
	_ = r.UpdateLastAnnounce(mustHash(t, hashA), t0.Add(-1*time.Hour))

	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 0 {
		t.Errorf("expected nothing pruned, got %v", pruned)
	}
}

func TestPruneSilentSweepsAnnouncingLurker(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	// A lurker who joined 7 weeks ago, never sent another message, but whose
	// client keeps announcing (last announce an hour ago). The idle rule
	// counts the announce as activity and keeps them, but the silent rule
	// (6w, keyed on LastSpoke which ignores announces) must sweep them.
	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-7*7*24*time.Hour))
	_ = r.UpdateLastAnnounce(mustHash(t, hashA), t0.Add(-1*time.Hour))

	// A regular who spoke 2 weeks ago — under both windows, must survive.
	_, _ = r.AddOrUpdate(mustHash(t, hashB), t0.Add(-2*7*24*time.Hour))

	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 6*7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0] != hashA {
		t.Errorf("expected silent lurker %s pruned, got %v", hashA, pruned)
	}
	if !r.Has(mustHash(t, hashB)) {
		t.Error("recently-active member should not be pruned by the silent rule")
	}
}

func TestPruneSilentDisabledWhenZero(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	// Silent for 7 weeks but announcing recently. With silentCutoff == 0 the
	// silent rule is off, so the recent announce keeps them via the idle rule.
	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-7*7*24*time.Hour))
	_ = r.UpdateLastAnnounce(mustHash(t, hashA), t0.Add(-1*time.Hour))

	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 0 {
		t.Errorf("silent rule disabled — expected nothing pruned, got %v", pruned)
	}
}

func TestUpdateLastAnnounceIsMonotonic(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-7*7*24*time.Hour))

	// A genuine recent announce sets a fresh timestamp.
	if err := r.UpdateLastAnnounce(mustHash(t, hashA), t0.Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A replayed OLD announce (its emission time predates the fresh one)
	// must NOT regress the timestamp.
	if err := r.UpdateLastAnnounce(mustHash(t, hashA), t0.Add(-6*7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	u, ok := r.Get(hashA)
	if !ok {
		t.Fatal("user missing")
	}
	if !u.LastAnnounceAt.Equal(t0.Add(-1 * time.Hour)) {
		t.Errorf("LastAnnounceAt = %v, want the fresher %v (replay must not regress it)", u.LastAnnounceAt, t0.Add(-1*time.Hour))
	}
}

func TestLastSpokeIgnoresAnnounce(t *testing.T) {
	joined := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	u := User{
		JoinedAt:       joined,
		LastMessageAt:  joined.Add(time.Hour),
		LastAnnounceAt: joined.Add(48 * time.Hour), // much later, but an announce
	}
	// LastSeen follows the announce; LastSpoke ignores it and stops at the
	// last message.
	if !u.LastSeen().Equal(joined.Add(48 * time.Hour)) {
		t.Errorf("LastSeen = %v, want announce time", u.LastSeen())
	}
	if !u.LastSpoke().Equal(joined.Add(time.Hour)) {
		t.Errorf("LastSpoke = %v, want last message %v (announces ignored)", u.LastSpoke(), joined.Add(time.Hour))
	}
}

func TestLastSeenFloorsOnJoinedAt(t *testing.T) {
	joined := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	// Only JoinedAt set (e.g. a fresh join, or a user loaded from a state
	// file predating the last_*_at fields) — LastSeen falls back to it.
	u := User{JoinedAt: joined}
	if !u.LastSeen().Equal(joined) {
		t.Errorf("LastSeen with only JoinedAt = %v, want %v", u.LastSeen(), joined)
	}

	// A later message beats the join floor.
	msg := joined.Add(time.Hour)
	u.LastMessageAt = msg
	if !u.LastSeen().Equal(msg) {
		t.Errorf("LastSeen = %v, want last message %v", u.LastSeen(), msg)
	}

	// A later announce beats both.
	ann := msg.Add(time.Hour)
	u.LastAnnounceAt = ann
	if !u.LastSeen().Equal(ann) {
		t.Errorf("LastSeen = %v, want last announce %v", u.LastSeen(), ann)
	}
}

func TestTouchRefreshesMemberAndIgnoresNonMember(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	// Non-member: Touch is a no-op and reports false — it must not
	// auto-create a user (that's reserved for /join + actual messages).
	ok, err := r.Touch(mustHash(t, hashA), t0)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("Touch on a non-member should report false")
	}
	if r.Has(mustHash(t, hashA)) {
		t.Error("Touch must not create a non-member")
	}

	// Member who joined 5 weeks ago, then touched an hour ago (e.g. via a
	// command) — the touch must keep them alive past a 4-week prune.
	_, _ = r.AddOrUpdate(mustHash(t, hashB), t0.Add(-5*7*24*time.Hour))
	ok, err = r.Touch(mustHash(t, hashB), t0.Add(-1*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("Touch on a member should report true")
	}
	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 0 {
		t.Errorf("a recently-touched member should not be pruned, got %v", pruned)
	}
}

func TestTouchDoesNotSaveLurkerFromSilentPrune(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	// Joined 7 weeks ago (AddOrUpdate stamps last_message_at = join time,
	// so LastSpoke is 7w stale), then ran a command an hour ago. Touch
	// records that command as presence only — it must NOT advance
	// last_message_at, so the silent clock stays at the 7w-old join.
	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-7*7*24*time.Hour))
	if _, err := r.Touch(mustHash(t, hashA), t0.Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Idle rule alone (silent disabled) keeps them — they're present.
	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 0 {
		t.Errorf("command activity should keep a member off the idle sweep, got %v", pruned)
	}

	// With the 6w silent rule on, the command-only lurker is swept.
	pruned, err = r.Prune(t0, 4*7*24*time.Hour, 6*7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 1 || pruned[0] != hashA {
		t.Errorf("expected command-only lurker %s swept by silent rule, got %v", hashA, pruned)
	}
}

func TestMarkMessageResetsSilentClock(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	// Joined 7 weeks ago (so the join-time last_message_at is stale), but
	// sent a real chat message an hour ago — MarkMessage resets the silent
	// clock, so the 6w silent rule must spare them.
	_, _ = r.AddOrUpdate(mustHash(t, hashA), t0.Add(-7*7*24*time.Hour))
	if _, err := r.MarkMessage(mustHash(t, hashA), t0.Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}

	pruned, err := r.Prune(t0, 4*7*24*time.Hour, 6*7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(pruned) != 0 {
		t.Errorf("a member who recently sent a real message must not be silent-pruned, got %v", pruned)
	}
}

func TestMarkMessageDoesNotAutoJoin(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	ok, err := r.MarkMessage(mustHash(t, hashA), t0)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("MarkMessage on a non-member should report false")
	}
	if r.Has(mustHash(t, hashA)) {
		t.Error("MarkMessage must not create a non-member")
	}
}

func TestUpdateLastAnnounceDoesNotAutoJoin(t *testing.T) {
	r, _ := newTestRoster(t)
	t0 := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)

	if err := r.UpdateLastAnnounce(mustHash(t, hashA), t0); err != nil {
		t.Fatal(err)
	}
	if r.Has(mustHash(t, hashA)) {
		t.Error("announce alone should not add a user to the roster")
	}
}

func TestBanRemovesAndDropsFutureMessages(t *testing.T) {
	r, _ := newTestRoster(t)
	now := time.Now()
	_, _ = r.AddOrUpdate(mustHash(t, hashA), now)

	if err := r.Ban(hashA); err != nil {
		t.Fatal(err)
	}
	if r.Has(mustHash(t, hashA)) {
		t.Error("ban should remove user from roster")
	}
	if !r.IsBanned(mustHash(t, hashA)) {
		t.Error("hash should be in banlist after ban")
	}
}

func TestUnban(t *testing.T) {
	r, _ := newTestRoster(t)
	_ = r.Ban(hashA)
	ok, err := r.Unban(hashA)
	if err != nil || !ok {
		t.Fatalf("unban: ok=%v err=%v", ok, err)
	}
	if r.IsBanned(mustHash(t, hashA)) {
		t.Error("unban should clear the banlist entry")
	}
	ok, _ = r.Unban(hashA)
	if ok {
		t.Error("second unban should be a no-op")
	}
}

func TestResolveByNickAndPrefix(t *testing.T) {
	r, _ := newTestRoster(t)
	now := time.Now()
	_, _ = r.AddOrUpdate(mustHash(t, hashA), now)
	_, _ = r.AddOrUpdate(mustHash(t, hashB), now)
	_, _ = r.AddOrUpdate(mustHash(t, hashC), now)
	_ = r.SetNickname(hashA, "alice")
	_ = r.SetNickname(hashB, "bob")

	if u, err := r.Resolve("ALICE"); err != nil || u.Hash != hashA {
		t.Errorf("Resolve nick: got %+v err %v", u, err)
	}
	if u, err := r.Resolve("0011"); err != nil || u.Hash != hashA {
		t.Errorf("Resolve prefix: got %+v err %v", u, err)
	}
	if _, err := r.Resolve("nobody"); err == nil {
		t.Error("Resolve(nobody) should error")
	}
}

func TestSetTextOnlyPersists(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")

	{
		store := NewStore(storePath)
		r, err := New(store)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = r.AddOrUpdate(mustHash(t, hashA), time.Now())
		if err := r.SetTextOnly(hashA, true); err != nil {
			t.Fatalf("SetTextOnly: %v", err)
		}
	}

	store := NewStore(storePath)
	r, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsTextOnly(hashA) {
		t.Error("TextOnly flag should persist across reload")
	}
	// Clearing must also persist.
	if err := r.SetTextOnly(hashA, false); err != nil {
		t.Fatal(err)
	}

	r2, err := New(NewStore(storePath))
	if err != nil {
		t.Fatal(err)
	}
	if r2.IsTextOnly(hashA) {
		t.Error("cleared TextOnly flag should persist across reload")
	}
}

func TestSetTextOnlyRejectsNonMember(t *testing.T) {
	r, _ := newTestRoster(t)
	if err := r.SetTextOnly(hashA, true); err == nil {
		t.Error("SetTextOnly on non-member should return an error")
	}
}

func TestSetRolePersistsAndRoundTrips(t *testing.T) {
	r, dir := newTestRoster(t)
	_, _ = r.AddOrUpdate(mustHash(t, hashA), time.Now())

	if err := r.SetRole(hashA, "admin"); err != nil {
		t.Fatal(err)
	}
	if u, _ := r.Get(hashA); u.Role != "admin" {
		t.Errorf("role = %q, want admin", u.Role)
	}

	// Reload from disk — the role must survive a restart.
	r2, err := New(NewStore(filepath.Join(dir, "state.json")))
	if err != nil {
		t.Fatal(err)
	}
	if u, ok := r2.Get(hashA); !ok || u.Role != "admin" {
		t.Errorf("after reload role = %q (ok=%v), want admin", u.Role, ok)
	}

	// Clearing back to "" drops the field.
	if err := r.SetRole(hashA, ""); err != nil {
		t.Fatal(err)
	}
	if u, _ := r.Get(hashA); u.Role != "" {
		t.Errorf("role after clear = %q, want empty", u.Role)
	}
}

func TestSetRoleRejectsNonMemberAndInvalid(t *testing.T) {
	r, _ := newTestRoster(t)

	if err := r.SetRole(hashA, "mod"); err == nil {
		t.Error("SetRole on a non-member should error")
	}
	_, _ = r.AddOrUpdate(mustHash(t, hashA), time.Now())
	if err := r.SetRole(hashA, "boss"); err == nil {
		t.Error("SetRole with an invalid role string should error")
	}
}

func TestPersistRoundTrip(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state.json")

	{
		store := NewStore(storePath)
		r, err := New(store)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = r.AddOrUpdate(mustHash(t, hashA), time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC))
		_ = r.SetNickname(hashA, "alice")
		_ = r.Ban(hashB)
	}

	store := NewStore(storePath)
	r, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := r.Get(hashA)
	if !ok || u.Nickname != "alice" {
		t.Errorf("expected alice persisted, got %+v ok=%v", u, ok)
	}
	if !r.IsBanned(mustHash(t, hashB)) {
		t.Error("ban should persist across reload")
	}
}
