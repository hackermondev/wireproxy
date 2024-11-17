package wireproxy

import (
	"bytes"
	"fmt"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr map[int]netip.Addr
	MTU        int
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	if conf.ListenPort != nil {
		request.WriteString(fmt.Sprintf("listen_port=%d\n", *conf.ListenPort))
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		))
		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *DeviceConfig, logLevel int) (map[string]VirtualTun, error) {
	setting, err := CreateIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	devices := make(map[string]VirtualTun)
	for index, address := range setting.DeviceAddr {
		peer_equiv := conf.Peers[index]
		peer_address := peer_equiv.AllowedIPs[0]

		tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{address}, setting.DNS, setting.MTU)
		if err != nil {
			return nil, err
		}

		dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
		err = dev.IpcSet(setting.IpcRequest)
		if err != nil {
			return nil, err
		}

		err = dev.Up()
		if err != nil {
			return nil, err
		}

		devices[peer_address.String()] = VirtualTun{
			Tnet:       tnet,
			Dev:        dev,
			Conf:       conf,
			SystemDNS:  len(setting.DNS) == 0,
			PingRecord: make(map[string]uint64),
		};
	}

	

	return devices, nil
}
