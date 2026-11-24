//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package main

// The exclusive management listener prevents duplicate binds on other systems.
func lockManagementInstance() (func(), error) { return func() {}, nil }
