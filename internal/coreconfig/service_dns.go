package coreconfig

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
)

func ValidateServiceDNSOptions(m Model, o Options) error {
	host, port, err := net.SplitHostPort(o.ServiceDNSListen)
	ip, parseErr := netip.ParseAddr(host)
	n, numberErr := strconv.Atoi(port)
	if err != nil || parseErr != nil || !ip.Is4() || !ip.IsPrivate() || numberErr != nil || n < 1024 || n > 65535 || n == int(o.DNSPort) || n == int(o.MixedPort) || n == int(o.ControlPort) {
		return errors.New("invalid private service DNS listener")
	}
	for _, g := range m.Groups {
		if g.ID == o.ServiceDNSOutbound {
			return nil
		}
	}
	for _, ep := range m.Endpoints {
		if ep.Enabled && ep.ID == o.ServiceDNSOutbound {
			return nil
		}
	}
	return errors.New("service DNS requires an enabled proxy outbound")
}
