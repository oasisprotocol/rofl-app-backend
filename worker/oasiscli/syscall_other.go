//go:build !linux

package oasiscli

import "syscall"

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// Isolate process group.
		Setpgid: true,
	}
}
