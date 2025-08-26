//go:build linux

package oasiscli

import "syscall"

func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// Isolate process group.
		Setpgid: true,
		// Kill the process if the parent process dies.
		Pdeathsig: syscall.SIGKILL,
	}
}
