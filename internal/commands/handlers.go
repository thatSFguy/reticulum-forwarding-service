package commands

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/config"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/roster"
)

// Role of the sender invoking a command. RoleUser is the default —
// in-config admins/mods take precedence over membership state.
type Role int

const (
	RoleUser Role = iota
	RoleMod
	RoleAdmin
)

func (r Role) atLeastMod() bool { return r == RoleMod || r == RoleAdmin }

// Caller bundles everything a command handler needs to know about the
// sender: their hash (hex + bytes), their role from the config (user /
// mod / admin), whether they're currently in the roster (Member),
// and whether they're paused. Derived once per inbound command.
type Caller struct {
	Hash      string // lowercase hex
	HashBytes []byte
	Role      Role
	Member    bool
	Paused    bool
}

// Dispatcher dispatches parsed commands. It's stateless apart from the
// references it holds; safe to share across the inbox goroutine.
type Dispatcher struct {
	Cfg    *config.Config
	Roster *roster.Roster

	// Announce, when set, is invoked by the /announce command to trigger
	// an immediate fresh announce broadcast. Mod/admin only.
	Announce func() error

	// OnJoin is invoked AFTER a user successfully /joins so the service
	// layer can fire replay-on-join for them. Called with the joiner's
	// hex hash; safe to call from the dispatcher goroutine.
	OnJoin func(senderHash string)
}

// Dispatch handles a single command and returns the reply text. An empty
// return means "no reply" (we currently always reply, but this leaves
// room).
func (d *Dispatcher) Dispatch(senderHash string, parsed Parsed) string {
	caller := d.deriveCaller(senderHash)
	switch parsed.Name {
	case "?", "help":
		return helpText(caller)
	case "users":
		return d.listUsers()
	case "mods":
		return d.listConfigList("mods", d.Cfg.Mods)
	case "admin", "admins":
		return d.listConfigList("admins", d.Cfg.Admins)
	case "join":
		return d.handleJoin(caller)
	case "leave":
		return d.handleLeave(caller)
	case "pause":
		return d.handlePause(caller)
	case "resume":
		return d.handleResume(caller)
	case "nick":
		return d.handleNick(caller, parsed.Args)
	case "kick":
		return d.handleKick(caller.Role, parsed.Args)
	case "ban":
		return d.handleBan(caller.Role, parsed.Args)
	case "unban":
		return d.handleUnban(caller.Role, parsed.Args)
	case "announce":
		return d.handleAnnounce(caller.Role)
	default:
		return fmt.Sprintf("unknown command /%s — try /?", parsed.Name)
	}
}

func (d *Dispatcher) deriveCaller(senderHash string) *Caller {
	sh := strings.ToLower(senderHash)
	c := &Caller{Hash: sh, HashBytes: mustHexBytes(sh)}
	switch {
	case d.Cfg.IsAdmin(sh):
		c.Role = RoleAdmin
	case d.Cfg.IsMod(sh):
		c.Role = RoleMod
	default:
		c.Role = RoleUser
	}
	if c.HashBytes != nil {
		c.Member = d.Roster.Has(c.HashBytes)
	}
	if c.Member {
		if u, ok := d.Roster.Get(sh); ok {
			c.Paused = u.Paused
		}
	}
	return c
}

// helpText is the /? and /help reply, tailored to the caller's role and
// membership so they only see commands they can actually use.
//
// MUST fit in a single opportunistic LXMF packet — the sender of /? has
// no chunked or link-based reply path. TestHelpTextFitsOpportunisticPacket
// guards the byte budget across all caller states.
func helpText(c *Caller) string {
	var b strings.Builder
	b.WriteString("Commands:\n")
	b.WriteString("/?, /help - this list\n")
	b.WriteString("/users /mods /admin - lists\n")

	if !c.Member {
		b.WriteString("/join - join the chat\n")
	} else {
		b.WriteString("/nick NAME - rename self\n")
		b.WriteString("/leave - leave the chat\n")
		b.WriteString("/pause - mute (don't receive)\n")
		b.WriteString("/resume - unmute\n")
	}

	if c.Role.atLeastMod() {
		b.WriteString("/nick USER NAME - mod\n")
		b.WriteString("/kick /ban /unban USER - mod\n")
		b.WriteString("/announce - mod\n")
		b.WriteString("USER = nick or hex (>=4)")
	} else if c.Member {
		// regular member sees the legend so /nick NAME is unambiguous
		b.WriteString("USER = nick or hex (>=4)")
	}
	return b.String()
}

func (d *Dispatcher) listUsers() string {
	users := d.Roster.List()
	if len(users) == 0 {
		return "No users."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Users (%d):\n", len(users))
	for _, u := range users {
		nick := u.Nickname
		if nick == "" {
			nick = "(no nick)"
		}
		mark := ""
		if u.Paused {
			mark = " [paused]"
		}
		fmt.Fprintf(&b, "  %s — %s%s\n", nick, u.Hash[:8], mark)
	}
	return strings.TrimRight(b.String(), "\n")
}

func (d *Dispatcher) listConfigList(label string, hashes []string) string {
	if len(hashes) == 0 {
		return fmt.Sprintf("No %s configured.", label)
	}
	sorted := append([]string(nil), hashes...)
	sort.Strings(sorted)
	var b strings.Builder
	fmt.Fprintf(&b, "%s (%d):\n", titleCase(label), len(sorted))
	for _, h := range sorted {
		nick := ""
		if u, ok := d.Roster.Get(h); ok && u.Nickname != "" {
			nick = u.Nickname
		}
		if nick != "" {
			fmt.Fprintf(&b, "  %s — %s\n", nick, h[:8])
		} else {
			fmt.Fprintf(&b, "  %s\n", h[:8])
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func (d *Dispatcher) handleJoin(c *Caller) string {
	if c.Member {
		return "You're already in the chat. Send /pause to mute, /leave to exit."
	}
	if c.HashBytes == nil {
		return "Couldn't join: malformed sender hash."
	}
	if d.Roster.IsBanned(c.HashBytes) {
		return "You're banned from this chat."
	}
	if _, err := d.Roster.AddOrUpdate(c.HashBytes, time.Now()); err != nil {
		return "Couldn't join: " + err.Error()
	}
	if d.OnJoin != nil {
		d.OnJoin(c.Hash)
	}
	return "Joined. You'll receive forwarded messages from now on. /pause to mute, /leave to exit, /? for help."
}

func (d *Dispatcher) handleLeave(c *Caller) string {
	if !c.Member {
		return "You're not in the chat."
	}
	if _, err := d.Roster.Remove(c.Hash); err != nil {
		return "Couldn't leave: " + err.Error()
	}
	return "Left the chat. Send /join any time to come back."
}

func (d *Dispatcher) handlePause(c *Caller) string {
	if !c.Member {
		return "You're not in the chat. Send /join first."
	}
	if c.Paused {
		return "You're already paused. Send /resume to come back."
	}
	if err := d.Roster.SetPaused(c.Hash, true); err != nil {
		return "Couldn't pause: " + err.Error()
	}
	return "Paused. You won't receive forwarded messages until you /resume."
}

func (d *Dispatcher) handleResume(c *Caller) string {
	if !c.Member {
		return "You're not in the chat. Send /join first."
	}
	if !c.Paused {
		return "You're not paused."
	}
	if err := d.Roster.SetPaused(c.Hash, false); err != nil {
		return "Couldn't resume: " + err.Error()
	}
	return "Resumed. You'll receive forwarded messages again."
}

var nickRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,24}$`)

func (d *Dispatcher) handleNick(c *Caller, args []string) string {
	switch len(args) {
	case 1:
		if !c.Member {
			return "Send /join first."
		}
		newNick := args[0]
		if !nickRE.MatchString(newNick) {
			return "Nickname must be 1-24 chars from [A-Za-z0-9_-]."
		}
		if err := d.Roster.SetNickname(c.Hash, newNick); err != nil {
			return "Couldn't change nickname: " + err.Error()
		}
		return "Nickname set to " + newNick + "."
	case 2:
		if !c.Role.atLeastMod() {
			return "Only mods or admins can change someone else's nickname."
		}
		target, err := d.Roster.Resolve(args[0])
		if err != nil {
			return err.Error()
		}
		newNick := args[1]
		if !nickRE.MatchString(newNick) {
			return "Nickname must be 1-24 chars from [A-Za-z0-9_-]."
		}
		if err := d.Roster.SetNickname(target.Hash, newNick); err != nil {
			return "Couldn't change nickname: " + err.Error()
		}
		return fmt.Sprintf("Set %s's nickname to %s.", target.Hash[:8], newNick)
	default:
		return "Usage: /nick <newname>   or   /nick <user> <newname>"
	}
}

func (d *Dispatcher) handleKick(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can kick."
	}
	if len(args) != 1 {
		return "Usage: /kick <user>"
	}
	target, err := d.Roster.Resolve(args[0])
	if err != nil {
		return err.Error()
	}
	removed, err := d.Roster.Remove(target.Hash)
	if err != nil {
		return "Couldn't kick: " + err.Error()
	}
	if !removed {
		return fmt.Sprintf("%s was not in the roster.", target.Hash[:8])
	}
	label := target.Nickname
	if label == "" {
		label = target.Hash[:8]
	}
	return fmt.Sprintf("Kicked %s. They can rejoin with /join.", label)
}

func (d *Dispatcher) handleBan(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can ban."
	}
	if len(args) != 1 {
		return "Usage: /ban <user>"
	}
	target, err := d.Roster.Resolve(args[0])
	if err != nil {
		return err.Error()
	}
	if err := d.Roster.Ban(target.Hash); err != nil {
		return "Couldn't ban: " + err.Error()
	}
	label := target.Nickname
	if label == "" {
		label = target.Hash[:8]
	}
	return fmt.Sprintf("Banned %s. Their messages will be dropped.", label)
}

func (d *Dispatcher) handleUnban(role Role, args []string) string {
	if !role.atLeastMod() {
		return "Only mods or admins can unban."
	}
	if len(args) != 1 {
		return "Usage: /unban <user>"
	}
	hash := strings.ToLower(strings.TrimSpace(args[0]))
	for _, h := range d.Roster.Banlist() {
		if h == hash {
			ok, err := d.Roster.Unban(h)
			if err != nil {
				return "Couldn't unban: " + err.Error()
			}
			if ok {
				return "Unbanned " + h[:8] + "."
			}
		}
	}
	var matches []string
	for _, h := range d.Roster.Banlist() {
		if strings.HasPrefix(h, hash) {
			matches = append(matches, h)
		}
	}
	switch len(matches) {
	case 0:
		return fmt.Sprintf("%s is not banned.", hash)
	case 1:
		ok, err := d.Roster.Unban(matches[0])
		if err != nil {
			return "Couldn't unban: " + err.Error()
		}
		if ok {
			return "Unbanned " + matches[0][:8] + "."
		}
		return "Unbanned."
	default:
		return fmt.Sprintf("%q matches multiple banned users: %s", hash, strings.Join(shortHashes(matches), ", "))
	}
}

func (d *Dispatcher) handleAnnounce(role Role) string {
	if !role.atLeastMod() {
		return "Only mods or admins can /announce."
	}
	if d.Announce == nil {
		return "Announce hook not wired (server bug)."
	}
	if err := d.Announce(); err != nil {
		return "Announce failed: " + err.Error()
	}
	return "OK, announced."
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	c := s[0]
	if c >= 'a' && c <= 'z' {
		c -= 'a' - 'A'
	}
	return string(c) + s[1:]
}

func shortHashes(hs []string) []string {
	out := make([]string, len(hs))
	for i, h := range hs {
		if len(h) >= 8 {
			out[i] = h[:8]
		} else {
			out[i] = h
		}
	}
	return out
}

// mustHexBytes converts a hex hash to bytes; returns nil on bad hex.
// Keeps the dispatcher decoupled from encoding/hex to avoid imports
// bouncing around.
func mustHexBytes(h string) []byte {
	if len(h) != 32 {
		return nil
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := hexNibble(h[2*i])
		lo := hexNibble(h[2*i+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}
