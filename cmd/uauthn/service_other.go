//go:build !windows

package main

import "errors"

var errNotWindows = errors.New("Windows services are only available on Windows")

func isWindowsService() bool { return false }

func runService() error { return errNotWindows }

func installService() error { return errNotWindows }

func uninstallService() error { return errNotWindows }
