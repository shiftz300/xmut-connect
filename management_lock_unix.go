//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func lockManagementInstance() (func(), error) {
	dir := fmt.Sprintf("/tmp/zju-connect-management-%d", os.Getuid())
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, errors.New("could not create management lock directory")
	}
	var info unix.Stat_t
	if err := unix.Lstat(dir, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR ||
		info.Uid != uint32(os.Getuid()) || info.Mode&0077 != 0 {
		return nil, errors.New("management lock directory is not private")
	}
	fd, err := unix.Open(filepath.Join(dir, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("could not open management instance lock")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		return nil, errors.New("another managed VPN process holds the instance lock")
	}
	return func() { _ = unix.Close(fd) }, nil
}
