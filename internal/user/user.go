package user

import (
	"fmt"
	"os/user"
	"strconv"
)

// Info holds resolved user identity and home directory.
type Info struct {
	Name    string
	UID     int
	GID     int
	HomeDir string
}

// Lookup resolves an existing user by username.
func Lookup(name string) (*Info, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("lookup user %q: %w", name, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("parse uid %q for user %q: %w", u.Uid, name, err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("parse gid %q for user %q: %w", u.Gid, name, err)
	}

	return &Info{
		Name:    u.Username,
		UID:     uid,
		GID:     gid,
		HomeDir: u.HomeDir,
	}, nil
}

// LookupID resolves an existing user by UID.
func LookupID(uid int) (*Info, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return nil, fmt.Errorf("lookup uid %d: %w", uid, err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return nil, fmt.Errorf("parse gid %q for uid %d: %w", u.Gid, uid, err)
	}

	return &Info{
		Name:    u.Username,
		UID:     uid,
		GID:     gid,
		HomeDir: u.HomeDir,
	}, nil
}
