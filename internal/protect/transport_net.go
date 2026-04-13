package protect

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/pion/transport/v4"
	"github.com/pion/transport/v4/stdnet"
)

// ProtectedNet is a transport.Net implementation for pion/ice that applies
// Android VPN socket protection to TCP/UDP sockets and uses the protected
// resolver for hostname lookups.
type ProtectedNet struct {
	base *stdnet.Net
}

// NewTransportNet creates a pion transport.Net backed by protected sockets.
func NewTransportNet() (*ProtectedNet, error) {
	base, err := stdnet.NewNet()
	if err != nil {
		return nil, err
	}

	return &ProtectedNet{base: base}, nil
}

var _ transport.Net = (*ProtectedNet)(nil)

func (n *ProtectedNet) Interfaces() ([]*transport.Interface, error) {
	return n.base.Interfaces()
}

func (n *ProtectedNet) InterfaceByIndex(index int) (*transport.Interface, error) {
	return n.base.InterfaceByIndex(index)
}

func (n *ProtectedNet) InterfaceByName(name string) (*transport.Interface, error) {
	return n.base.InterfaceByName(name)
}

func (n *ProtectedNet) ListenPacket(network string, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: controlFunc}
	return lc.ListenPacket(context.Background(), network, address)
}

func (n *ProtectedNet) ListenUDP(network string, locAddr *net.UDPAddr) (transport.UDPConn, error) {
	address := ""
	if locAddr != nil {
		address = locAddr.String()
	}

	lc := net.ListenConfig{Control: controlFunc}
	conn, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected packet conn type %T", conn)
	}

	return udpConn, nil
}

func (n *ProtectedNet) Dial(network, address string) (net.Conn, error) {
	return NewDialer().Dial(network, address)
}

func (n *ProtectedNet) DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	if raddr == nil {
		return nil, fmt.Errorf("remote UDP address is required")
	}

	dialer := NewDialer()
	if laddr != nil {
		dialer.LocalAddr = laddr
	}

	conn, err := dialer.DialContext(context.Background(), network, raddr.String())
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected UDP conn type %T", conn)
	}

	return udpConn, nil
}

func (n *ProtectedNet) ResolveIPAddr(network, address string) (*net.IPAddr, error) {
	host, err := splitResolverTarget(address)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.IPAddr{IP: ip}, nil
	}

	ctx := context.Background()
	ips, err := newResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ip := pickIP(network, ips)
	if ip == nil {
		return nil, fmt.Errorf("no IPs resolved for %s", host)
	}

	return ip, nil
}

func (n *ProtectedNet) ResolveUDPAddr(network, address string) (*net.UDPAddr, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	ctx := context.Background()
	ips, err := newResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ip := pickIP(network, ips)
	if ip == nil {
		return nil, fmt.Errorf("no UDP IPs resolved for %s", host)
	}

	return &net.UDPAddr{IP: ip.IP, Zone: ip.Zone, Port: port}, nil
}

func (n *ProtectedNet) ResolveTCPAddr(network, address string) (*net.TCPAddr, error) {
	host, port, err := splitHostPort(address)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}

	ctx := context.Background()
	ips, err := newResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}

	ip := pickIP(network, ips)
	if ip == nil {
		return nil, fmt.Errorf("no TCP IPs resolved for %s", host)
	}

	return &net.TCPAddr{IP: ip.IP, Zone: ip.Zone, Port: port}, nil
}

func (n *ProtectedNet) DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	if raddr == nil {
		return nil, fmt.Errorf("remote TCP address is required")
	}

	dialer := NewDialer()
	if laddr != nil {
		dialer.LocalAddr = laddr
	}

	conn, err := dialer.DialContext(context.Background(), network, raddr.String())
	if err != nil {
		return nil, err
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected TCP conn type %T", conn)
	}

	return tcpConn, nil
}

func (n *ProtectedNet) ListenTCP(network string, laddr *net.TCPAddr) (transport.TCPListener, error) {
	address := ""
	if laddr != nil {
		address = laddr.String()
	}

	lc := net.ListenConfig{Control: controlFunc}
	listener, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("unexpected TCP listener type %T", listener)
	}

	return protectedTCPListener{TCPListener: tcpListener}, nil
}

func (n *ProtectedNet) CreateDialer(d *net.Dialer) transport.Dialer {
	copyDialer := *d
	if copyDialer.ControlContext == nil && copyDialer.Control == nil {
		copyDialer.Control = controlFunc
	}
	if copyDialer.Resolver == nil {
		copyDialer.Resolver = newResolver()
	}

	return n.base.CreateDialer(&copyDialer)
}

func (n *ProtectedNet) CreateListenConfig(c *net.ListenConfig) transport.ListenConfig {
	copyConfig := *c
	if copyConfig.Control == nil {
		copyConfig.Control = controlFunc
	}

	return n.base.CreateListenConfig(&copyConfig)
}

type protectedTCPListener struct {
	*net.TCPListener
}

func (l protectedTCPListener) AcceptTCP() (transport.TCPConn, error) {
	return l.TCPListener.AcceptTCP()
}

func splitResolverTarget(address string) (string, error) {
	if strings.Contains(address, ":") {
		host, _, err := net.SplitHostPort(address)
		if err == nil {
			return host, nil
		}
	}

	return address, nil
}

func splitHostPort(address string) (string, int, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return "", 0, err
	}

	port, err := strconv.Atoi(portString)
	if err != nil {
		return "", 0, err
	}

	return host, port, nil
}

func pickIP(network string, ips []net.IPAddr) *net.IPAddr {
	wantV4 := strings.HasSuffix(network, "4")
	wantV6 := strings.HasSuffix(network, "6")

	for i := range ips {
		ip := ips[i]
		if wantV4 && ip.IP.To4() == nil {
			continue
		}
		if wantV6 && ip.IP.To4() != nil {
			continue
		}
		return &ip
	}

	if len(ips) == 0 {
		return nil
	}

	return &ips[0]
}
