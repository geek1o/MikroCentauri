//go:build linux

package linuxbarrier

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// RouterOS does not support a Compose devices property. In a reviewed
// privileged container its dedicated /dev namespace may lack the TUN node.
// Create only the fixed Linux clone-device node; refuse symlinks/foreign nodes.
func prepareAppTUN() error {
	const directory = "/dev/net"
	const path = directory + "/tun"
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		if err = os.Mkdir(directory, 0755); err != nil {
			return err
		}
		info, err = os.Lstat(directory)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid TUN directory")
	}
	var stat syscall.Stat_t
	err = syscall.Lstat(path, &stat)
	if err == syscall.ENOENT {
		if err = syscall.Mknod(path, syscall.S_IFCHR|0600, (10<<8)|200); err != nil {
			return err
		}
		err = syscall.Lstat(path, &stat)
	}
	if err != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFCHR || stat.Rdev != (10<<8)|200 {
		return errors.New("invalid TUN device")
	}
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var features uint32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x800454cf, uintptr(unsafe.Pointer(&features)))
	if errno != 0 {
		return errors.New("TUN feature ioctl unavailable")
	}
	return nil
}
