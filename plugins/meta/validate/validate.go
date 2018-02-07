// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	"github.com/vishvananda/netlink"
)

type ValidateConf struct {
	types.NetConf
	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    *current.Result        `json:"-"`
}

func validateInterface(intf *current.Interface) error {
	link, err := netlink.LinkByName(intf.Name)
	if err != nil {
		return fmt.Errorf("failed to find sandbox interface %s: %v", intf.Name, err)
	}
	if intf.Mac != "" {
		linkAddr := link.Attrs().HardwareAddr.String()
		hw, err := net.ParseMAC(intf.Mac)
		if err != nil {
			return fmt.Errorf("failed to parse interface %s MAC %s: %v", intf.Name, intf.Mac, err)
		}
		if linkAddr != hw.String() {
			return fmt.Errorf("interface %s MAC %s does not match expected %s", intf.Name, linkAddr, intf.Mac)
		}
	}
	return nil
}

func ipNetEqual(a *net.IPNet, b *net.IPNet) bool {
	sizea, _ := a.Mask.Size()
	sizeb, _ := b.Mask.Size()
	return a.IP.Equal(b.IP) && sizea == sizeb
}

func validateAddress(ifname string, addr *current.IPConfig) error {
	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to find sandbox interface %s: %v", ifname, err)
	}
	var family int
	switch addr.Version {
	case "4":
		family = netlink.FAMILY_V4
	case "6":
		family = netlink.FAMILY_V6
	default:
		return fmt.Errorf("invalid IP address version %q", addr.Version)
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		return fmt.Errorf("failed to list interface %s addresses: %v", ifname, err)
	}
	var found bool
	for _, a := range addrs {
		if ipNetEqual(&addr.Address, a.IPNet) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("failed to find address %q on interface %s", addr.Address.String(), ifname)
	}
	return nil
}

func validateRoute(route *types.Route) error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to list routes: %v", err)
	}
	var found bool
	for _, r := range routes {
		if ipNetEqual(&route.Dst, r.Dst) && route.GW.Equal(r.Gw) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("failed to find route %s", route.Dst.String())
	}
	return nil
}

func validateResult(args *skel.CmdArgs, result *current.Result) error {
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	// Interfaces
	for _, intf := range result.Interfaces {
		if intf.Sandbox != "" && intf.Sandbox == args.Netns {
			// Container namespace
			if err := netns.Do(func(_ ns.NetNS) error {
				return validateInterface(intf)
			}); err != nil {
				return err
			}
		} else if intf.Sandbox == "" {
			// Host namespace
			if err := validateInterface(intf); err != nil {
				return err
			}
		}
	}

	// IP addresses
	for _, ip := range result.IPs {
		if ip.Interface == nil || *ip.Interface < 0 {
			continue
		}
		if *ip.Interface >= len(result.Interfaces) {
			return fmt.Errorf("IP %s interface index %d invalid", ip.Address.String(), ip.Interface)
		}
		intf := result.Interfaces[*ip.Interface]
		if intf.Sandbox != "" && intf.Sandbox == args.Netns {
			// container namespace
			if err := netns.Do(func(_ ns.NetNS) error {
				return validateAddress(intf.Name, ip)
			}); err != nil {
				return err
			}
		} else if intf.Sandbox == "" {
			// host namespace
			if err := validateAddress(intf.Name, ip); err != nil {
				return err
			}
		}
	}

	// Container routes
	for _, route := range result.Routes {
		if err := netns.Do(func(_ ns.NetNS) error {
			return validateRoute(route)
		}); err != nil {
			return err
		}
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	netConf, err := parseConfig(args.StdinData, args.IfName)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}
	return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
}

func cmdGet(args *skel.CmdArgs) error {
	netConf, err := parseConfig(args.StdinData, args.IfName)
	if err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}
	if netConf.PrevResult == nil {
		return fmt.Errorf("must be called as chained plugin")
	}
	return types.PrintResult(netConf.PrevResult, netConf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	// Validation not required
	return nil
}

func main() {
	// We only support CNI spec versions that include the detailed Result structure
	skel.PluginMain(cmdAdd, cmdGet, cmdDel, version.PluginSupports("0.3.0", version.Current()))
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte, ifName string) (*ValidateConf, error) {
	conf := ValidateConf{}

	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}

	// Parse previous result.
	if conf.RawPrevResult != nil {
		resultBytes, err := json.Marshal(conf.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(conf.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		conf.RawPrevResult = nil
		conf.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return &conf, nil
}
