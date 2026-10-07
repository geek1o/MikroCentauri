//go:build !linux

package linuxbarrier

import "errors"

func prepareAppTUN() error { return errors.New("App kernel preparation requires Linux") }
