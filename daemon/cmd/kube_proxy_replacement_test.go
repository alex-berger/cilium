// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

//go:build linux && privileged_tests
// +build linux,privileged_tests

package cmd

import (
	"net"
	"runtime"
	"sort"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	. "gopkg.in/check.v1"
)

type KubeProxySuite struct {
	currentNetNS                  netns.NsHandle
	prevConfigDevices             []string
	prevConfigDirectRoutingDevice string
	prevConfigEnableIPv4          bool
	prevConfigEnableIPv6          bool
	prevK8sNodeIP                 net.IP
}

var _ = Suite(&KubeProxySuite{})

func (s *KubeProxySuite) SetUpSuite(c *C) {
	var err error

	s.prevConfigDevices = option.Config.Devices
	s.prevConfigDirectRoutingDevice = option.Config.DirectRoutingDevice
	s.prevConfigEnableIPv4 = option.Config.EnableIPv4
	s.prevConfigEnableIPv6 = option.Config.EnableIPv6
	s.prevK8sNodeIP = node.GetK8sNodeIP()

	s.currentNetNS, err = netns.Get()
	c.Assert(err, IsNil)
}

func (s *KubeProxySuite) TearDownTest(c *C) {
	option.Config.Devices = s.prevConfigDevices
	option.Config.DirectRoutingDevice = s.prevConfigDirectRoutingDevice
	option.Config.EnableIPv4 = s.prevConfigEnableIPv4
	option.Config.EnableIPv6 = s.prevConfigEnableIPv6
	node.SetK8sNodeIP(s.prevK8sNodeIP)
}

func (s *KubeProxySuite) TestDetectDevices(c *C) {
	s.withFreshNetNS(c, func() {
		// 1. No devices = impossible to detect
		c.Assert(detectDevices(true, true, true), NotNil)

		// 2. No devices, but no detection is required
		c.Assert(detectDevices(false, false, false), IsNil)

		// 3. Direct routing mode, should find dummy0 for both opts
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("dummy2", "192.168.2.3/24", false), IsNil)
		option.Config.EnableIPv4 = true
		option.Config.EnableIPv6 = false
		option.Config.Tunnel = option.TunnelDisabled
		node.SetK8sNodeIP(net.ParseIP("192.168.0.1"))
		c.Assert(detectDevices(true, true, false), IsNil)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0"})
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

		// 4. dummy1 should be detected too
		c.Assert(addDefaultRoute("dummy1", "192.168.1.1"), IsNil)
		c.Assert(detectDevices(true, true, false), IsNil)
		sort.Strings(option.Config.Devices)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0", "dummy1"})
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

		// 5. Enable IPv6, dummy1 should not be detected, as no default route for
		// ipv6 is found
		option.Config.EnableIPv6 = true
		c.Assert(detectDevices(true, true, false), IsNil)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0"})
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy0")

		// 6. Set random NodeIP, only dummy1 should be detected
		option.Config.EnableIPv6 = false
		node.SetK8sNodeIP(net.ParseIP("192.168.34.1"))
		c.Assert(detectDevices(true, true, false), IsNil)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy1"})
		c.Assert(option.Config.DirectRoutingDevice, Equals, "dummy1")

		// 7. With IPv6 node address on dummy3, set cilium_foo interface to node IP,
		// only dummy3 should be detected matching node IP (no IPv6 default route present)
		option.Config.EnableIPv6 = true
		c.Assert(createDummy("dummy3", "2001:db8::face/64", true), IsNil)
		c.Assert(createDummy("cilium_foo", "2001:db8::face/128", true), IsNil)
		node.SetK8sNodeIP(net.ParseIP("2001:db8::face"))
		c.Assert(detectDevices(true, true, true), IsNil)
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy3"})
		c.Assert(option.Config.IPv6MCastDevice, checker.DeepEquals, "dummy3")
	})
}

func (s *KubeProxySuite) TestExpandDevices(c *C) {
	s.withFreshNetNS(c, func() {
		c.Assert(createDummy("dummy0", "192.168.0.1/24", false), IsNil)
		c.Assert(createDummy("dummy1", "192.168.1.2/24", false), IsNil)
		c.Assert(createDummy("other0", "192.168.2.3/24", false), IsNil)
		c.Assert(createDummy("other1", "192.168.3.4/24", false), IsNil)
		c.Assert(createDummy("unmatched", "192.168.4.5/24", false), IsNil)

		option.Config.Devices = []string{"dummy+", "missing+", "other0+" /* duplicates: */, "dum+", "other0", "other1"}
		expandDevices()
		c.Assert(option.Config.Devices, checker.DeepEquals, []string{"dummy0", "dummy1", "other0", "other1"})
	})
}

func (s *KubeProxySuite) withFreshNetNS(c *C, test func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	testNetNS, err := netns.New() // creates netns, and sets it to current
	c.Assert(err, IsNil)
	defer func() { c.Assert(testNetNS.Close(), IsNil) }()
	defer func() { c.Assert(netns.Set(s.currentNetNS), IsNil) }()

	test()
}

func createDummy(iface, ipAddr string, ipv6Enabled bool) error {
	var dummyFlags net.Flags
	if ipv6Enabled {
		dummyFlags = net.FlagMulticast
	}
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:  iface,
			Flags: dummyFlags,
		},
	}
	if err := netlink.LinkAdd(dummy); err != nil {
		return err
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	ip, ipnet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return err
	}
	ipnet.IP = ip

	if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet}); err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}

	return nil
}

func addDefaultRoute(iface string, ipAddr string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       nil,
		Gw:        net.ParseIP(ipAddr),
	}
	if err := netlink.RouteAdd(route); err != nil {
		return err
	}

	return nil
}
