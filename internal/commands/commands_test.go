package commands

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
)

const (
	adminHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	modHash   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	userHash  = "cccccccccccccccccccccccccccccccc"
)

func TestIsCommand(t *testing.T) {
	cases := map[string]bool{
		"/?":         true,
		"  /help ":   true,
		"/users":     true,
		"hello":      false,
		"":           false,
		"  no slash": false,
	}
	for in, want := range cases {
		if got := IsCommand(in); got != want {
			t.Errorf("IsCommand(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseSplitsArgs(t *testing.T) {
	p := Parse("/nick   alice   ")
	if p.Name != "nick" {
		t.Errorf("Name=%q", p.Name)
	}
	if len(p.Args) != 1 || p.Args[0] != "alice" {
		t.Errorf("Args=%v", p.Args)
	}
	p = Parse("/kick alice bob")
	if len(p.Args) != 2 {
		t.Errorf("/kick alice bob: Args=%v", p.Args)
	}
}

func newDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	dir := t.TempDir()
	store := roster.NewStore(filepath.Join(dir, "state.json"))
	r, err := roster.New(store)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Admins: []string{adminHash},
		Mods:   []string{modHash},
	}
	return &Dispatcher{Cfg: cfg, Roster: r}
}

func mustBytes(t *testing.T, s string) []byte {
	t.Helper()
	b := mustHexBytes(s)
	if b == nil {
		t.Fatalf("bad hex: %s", s)
	}
	return b
}

// helpTextMsgpackPayload mirrors the wire format SignAndPackOpportunistic
// produces — float64 timestamp + empty title + content + empty fixmap —
// so the test can assert size without taking a circular import on lxmf.
func helpTextMsgpackPayload(t *testing.T, c *Caller) []byte {
	t.Helper()
	payload, err := msgpack.Marshal([]any{
		0.0,
		[]byte{},
		[]byte(helpText(c)),
		map[any]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestHelpTextFitsOpportunisticPacket guards against ANY caller state
// producing a help text that exceeds the single-packet opportunistic
// LXMF cap (upstream LXMessage.ENCRYPTED_PACKET_MAX_CONTENT = 295). All
// four states need to fit because /? is dispatched without knowing in
// advance which the caller is.
func TestHelpTextFitsOpportunisticPacket(t *testing.T) {
	const maxOpportunisticPayload = 295
	cases := []struct {
		name string
		c    *Caller
	}{
		{"non-member, regular user", &Caller{Member: false, Role: RoleUser}},
		{"member, regular user", &Caller{Member: true, Role: RoleUser}},
		{"non-member, mod", &Caller{Member: false, Role: RoleMod}},
		{"member, admin", &Caller{Member: true, Role: RoleAdmin}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := helpTextMsgpackPayload(t, tc.c)
			if len(payload) > maxOpportunisticPayload {
				t.Errorf("helpText for %s = %d bytes msgpack, must be <= %d (single-packet cap)\n--- text:\n%s",
					tc.name, len(payload), maxOpportunisticPayload, helpText(tc.c))
			}
		})
	}
}

func TestHelpForNonMemberShowsJoinNotLeave(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/?"))
	for _, want := range []string{"/?", "/users", "/join"} {
		if !strings.Contains(out, want) {
			t.Errorf("non-member help missing %q\n%s", want, out)
		}
	}
	for _, missing := range []string{"/leave", "/pause", "/resume", "/kick", "/ban"} {
		if strings.Contains(out, missing) {
			t.Errorf("non-member help should not show %q\n%s", missing, out)
		}
	}
}

func TestHelpForMemberShowsLeavePauseNotKickBan(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	out := d.Dispatch(userHash, Parse("/?"))
	for _, want := range []string{"/leave", "/pause", "/resume", "/nick"} {
		if !strings.Contains(out, want) {
			t.Errorf("member help missing %q\n%s", want, out)
		}
	}
	for _, missing := range []string{"/join", "/kick", "/ban", "/unban", "/announce"} {
		if strings.Contains(out, missing) {
			t.Errorf("member help should not show %q\n%s", missing, out)
		}
	}
}

func TestHelpForModShowsAllCommands(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, modHash), time.Now())
	out := d.Dispatch(modHash, Parse("/?"))
	for _, want := range []string{"/users", "/mods", "/admin", "/nick", "/kick", "/ban", "/unban", "/announce", "/leave", "/pause", "/resume"} {
		if !strings.Contains(out, want) {
			t.Errorf("mod help missing %q\n%s", want, out)
		}
	}
}

func TestJoinAddsToRosterAndCallsOnJoin(t *testing.T) {
	d := newDispatcher(t)
	var joined string
	d.OnJoin = func(h string) { joined = h }

	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "joined") {
		t.Errorf("expected join confirmation, got %q", out)
	}
	if !d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be in roster after /join")
	}
	if joined != userHash {
		t.Errorf("OnJoin called with %q, want %q", joined, userHash)
	}
}

func TestJoinIdempotent(t *testing.T) {
	d := newDispatcher(t)
	_ = d.Dispatch(userHash, Parse("/join"))
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "already") {
		t.Errorf("second /join should be idempotent, got %q", out)
	}
}

func TestJoinRespectsMaxMembers(t *testing.T) {
	d := newDispatcher(t)
	d.Cfg.Service.MaxMembers = 2

	// Pre-fill 2 members.
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, modHash), time.Now())
	other := "1111111111111111111111111111111111111111111111111111111111111111"[:32]
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, other), time.Now())

	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "full") {
		t.Errorf("expected chat-full denial, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should NOT have been added when chat is full")
	}
}

func TestJoinUnlimitedWhenMaxMembersZero(t *testing.T) {
	d := newDispatcher(t)
	d.Cfg.Service.MaxMembers = 0
	for i := 0; i < 5; i++ {
		hash := strings.Repeat(string(rune('0'+byte(i))), 32)
		_, _ = d.Roster.AddOrUpdate(mustBytes(t, hash), time.Now())
	}
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "joined") {
		t.Errorf("max_members=0 should be unlimited, got %q", out)
	}
}

func TestJoinRejectsBanned(t *testing.T) {
	d := newDispatcher(t)
	_ = d.Roster.Ban(userHash)
	out := d.Dispatch(userHash, Parse("/join"))
	if !strings.Contains(strings.ToLower(out), "banned") {
		t.Errorf("/join should refuse banned user, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("/join shouldn't have added a banned user to the roster")
	}
}

func TestLeaveRemovesFromRoster(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	out := d.Dispatch(userHash, Parse("/leave"))
	if !strings.Contains(strings.ToLower(out), "left") {
		t.Errorf("expected leave ack, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be gone from roster after /leave")
	}
}

func TestLeaveByNonMember(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/leave"))
	if !strings.Contains(strings.ToLower(out), "not in the chat") {
		t.Errorf("expected non-member denial, got %q", out)
	}
}

func TestPauseSetsFlag(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())

	out := d.Dispatch(userHash, Parse("/pause"))
	if !strings.Contains(strings.ToLower(out), "paused") {
		t.Errorf("expected pause ack, got %q", out)
	}
	if !d.Roster.IsPaused(userHash) {
		t.Error("user should be marked paused")
	}
}

func TestPauseTwiceIsIdempotent(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())

	_ = d.Dispatch(userHash, Parse("/pause"))
	out := d.Dispatch(userHash, Parse("/pause"))
	if !strings.Contains(strings.ToLower(out), "already paused") {
		t.Errorf("expected already-paused ack, got %q", out)
	}
}

func TestPauseRequiresMembership(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/pause"))
	if !strings.Contains(strings.ToLower(out), "not in the chat") {
		t.Errorf("expected non-member denial, got %q", out)
	}
}

func TestResumeClearsFlag(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	_ = d.Roster.SetPaused(userHash, true)

	out := d.Dispatch(userHash, Parse("/resume"))
	if !strings.Contains(strings.ToLower(out), "resumed") {
		t.Errorf("expected resume ack, got %q", out)
	}
	if d.Roster.IsPaused(userHash) {
		t.Error("user should no longer be paused")
	}
}

func TestResumeWithoutPause(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	out := d.Dispatch(userHash, Parse("/resume"))
	if !strings.Contains(strings.ToLower(out), "not paused") {
		t.Errorf("expected not-paused message, got %q", out)
	}
}

func TestKickRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(userHash, Parse("/kick "+userHash[:8]))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected permission denial, got %q", out)
	}
	if !d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should still be present after denied kick")
	}
}

func TestKickByMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(modHash, Parse("/kick "+userHash[:8]))
	if !strings.Contains(strings.ToLower(out), "kicked") {
		t.Errorf("expected success, got %q", out)
	}
	if d.Roster.Has(mustBytes(t, userHash)) {
		t.Error("user should be gone after kick")
	}
}

func TestBanByAdmin(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(adminHash, Parse("/ban "+userHash[:8]))
	if !strings.Contains(strings.ToLower(out), "banned") {
		t.Errorf("expected success, got %q", out)
	}
	if !d.Roster.IsBanned(mustBytes(t, userHash)) {
		t.Error("user should be on banlist after ban")
	}
}

func TestNickSelfChange(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(userHash, Parse("/nick alice"))
	if !strings.Contains(out, "alice") {
		t.Errorf("expected nickname-set ack, got %q", out)
	}
	u, _ := d.Roster.Get(userHash)
	if u.Nickname != "alice" {
		t.Errorf("expected nickname=alice, got %q", u.Nickname)
	}
}

func TestNickSelfRequiresMembership(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/nick alice"))
	if !strings.Contains(strings.ToLower(out), "join first") {
		t.Errorf("expected join-first message for non-member /nick, got %q", out)
	}
}

func TestNickOthersRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	other := "dddddddddddddddddddddddddddddddd"
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, other), now)
	_ = d.Roster.SetNickname(other, "bob")

	out := d.Dispatch(userHash, Parse("/nick bob carol"))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected denial, got %q", out)
	}
	u, _ := d.Roster.Get(other)
	if u.Nickname != "bob" {
		t.Errorf("nickname should not have changed, got %q", u.Nickname)
	}
}

func TestNickValidation(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)

	out := d.Dispatch(userHash, Parse("/nick !!!bad"))
	if !strings.Contains(strings.ToLower(out), "1-24") {
		t.Errorf("expected validation error, got %q", out)
	}
	out = d.Dispatch(userHash, Parse("/nick "+strings.Repeat("a", 25)))
	if !strings.Contains(strings.ToLower(out), "1-24") {
		t.Errorf("expected length validation error, got %q", out)
	}
}

func TestUnknownCommand(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/foobar"))
	if !strings.Contains(strings.ToLower(out), "unknown") {
		t.Errorf("expected unknown-command response, got %q", out)
	}
}

func TestListUsers(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), now)
	_ = d.Roster.SetNickname(userHash, "alice")

	out := d.Dispatch(userHash, Parse("/users"))
	if !strings.Contains(out, "alice") {
		t.Errorf("expected alice in list, got %q", out)
	}
}

func TestListUsersMarksPaused(t *testing.T) {
	d := newDispatcher(t)
	_, _ = d.Roster.AddOrUpdate(mustBytes(t, userHash), time.Now())
	_ = d.Roster.SetNickname(userHash, "alice")
	_ = d.Roster.SetPaused(userHash, true)

	out := d.Dispatch(userHash, Parse("/users"))
	if !strings.Contains(out, "[paused]") {
		t.Errorf("expected paused users to be marked, got %q", out)
	}
}

func TestListAdminsAndMods(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/admin"))
	if !strings.Contains(out, adminHash[:8]) {
		t.Errorf("expected admin hash in /admin, got %q", out)
	}
	out = d.Dispatch(userHash, Parse("/mods"))
	if !strings.Contains(out, modHash[:8]) {
		t.Errorf("expected mod hash in /mods, got %q", out)
	}
}

func TestAnnounceRequiresMod(t *testing.T) {
	d := newDispatcher(t)
	out := d.Dispatch(userHash, Parse("/announce"))
	if !strings.Contains(strings.ToLower(out), "only mods or admins") {
		t.Errorf("expected permission denial, got %q", out)
	}
}

func TestAnnounceCallsHook(t *testing.T) {
	d := newDispatcher(t)
	called := false
	d.Announce = func() error {
		called = true
		return nil
	}
	out := d.Dispatch(modHash, Parse("/announce"))
	if !strings.Contains(strings.ToLower(out), "announced") {
		t.Errorf("expected success ack, got %q", out)
	}
	if !called {
		t.Error("Announce hook was not called")
	}
}
