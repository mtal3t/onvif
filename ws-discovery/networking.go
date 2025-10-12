package wsdiscovery

/*******************************************************
 * Copyright (C) 2018 Palanjyan Zhorzhik
 *
 * This file is part of ws-discovery project.
 *
 * ws-discovery can be copied and/or distributed without the express
 * permission of Palanjyan Zhorzhik
 *******************************************************/

import (
	"errors"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/gofrs/uuid"
	"golang.org/x/net/ipv4"
)

const bufSize = 8192

func SendProbe(interfaceName string, scopes, types []string, namespaces map[string]string) ([]string, error) {
	uuidV4 := uuid.Must(uuid.NewV4())
	probeSOAP := buildProbeMessage(uuidV4.String(), scopes, types, namespaces)
	return sendUDPMulticast(probeSOAP.String(), interfaceName)
}

func sendUDPMulticast(msg string, interfaceName string) ([]string, error) {
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer c.Close()

	p := ipv4.NewPacketConn(c)
	defer p.Close()

	group := net.IPv4(239, 255, 255, 250)
	dst := &net.UDPAddr{IP: group, Port: 3702}
	data := []byte(msg)

	// Android: avoid net.InterfaceByName (blocked by SELinux netlink routing).
	// For Probe, you can skip JoinGroup and interface selection entirely.
	if runtime.GOOS != "android" && interfaceName != "" {
		ifi, err := net.InterfaceByName(interfaceName)
		if err == nil {
			_ = p.JoinGroup(ifi, &net.UDPAddr{IP: group})
			_ = p.SetMulticastInterface(ifi)
		}
		// If lookup fails, continue without interface binding.
	}

	_ = p.SetMulticastTTL(2)

	if _, err := p.WriteTo(data, nil, dst); err != nil {
		return nil, err
	}

	// Bump timeout to improve reliability on real networks
	if err := p.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}

	var result []string
	buf := make([]byte, bufSize)
	for {
		n, _, _, err := p.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return nil, err
			}
			break
		}
		result = append(result, string(buf[:n]))
	}
	return result, nil
}
