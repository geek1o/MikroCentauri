package grouphealth

import (
	"os/exec"
	"syscall"
)

func processAttributes(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
