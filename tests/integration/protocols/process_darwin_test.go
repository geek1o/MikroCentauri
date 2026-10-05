package protocols

import (
	"os/exec"
	"syscall"
)

func attributes(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
