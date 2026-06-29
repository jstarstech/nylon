package state

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
)

var namePattern, _ = regexp.Compile("^[0-9a-z._/-]+$")

func NameValidator(s string) error {
	if !namePattern.MatchString(s) {
		return fmt.Errorf("%s is not a valid name, must match pattern %s", s, namePattern.String())
	}
	if len(s) > 100 {
		return fmt.Errorf("len(\"%s\") = %d > 100 is too long", s, len(s))
	}
	return nil
}

func NodeConfigValidator(central *CentralCfg, node *LocalCfg) error {
	err := NameValidator(string(node.Id))
	if err != nil {
		return err
	}
	if node.Port == 0 {
		return fmt.Errorf("port must be greater than 0")
	}
	if node.Key == [32]byte{} {
		return fmt.Errorf("private key must not be empty")
	}
	if node.InterfaceName != "" {
		err = NameValidator(node.InterfaceName)
		if err != nil {
			return fmt.Errorf("interface name is invalid: %v", err)
		}
	}
	if node.Dist != nil {
		_, err := url.Parse(node.Dist.Url)
		if err != nil {
			return err
		}
	}
	if len(node.DnsResolvers) != 0 {
		for _, resolver := range node.DnsResolvers {
			if _, err := netip.ParseAddrPort(resolver); err != nil {
				return fmt.Errorf("dns resolver %s is not a valid ip:port: %v", resolver, err)
			}
		}
	}
	// validate prefixes
	for _, p := range append(node.UnexcludeIPs, node.ExcludeIPs...) {
		if !p.IsValid() {
			return fmt.Errorf("invalid prefix %s", p)
		}
	}
	// check that node is in central config
	if central != nil && !central.IsNode(node.Id) {
		return fmt.Errorf("node %s is not in central config", node.Id)
	}
	return nil
}

func AddrToPrefix(addr netip.Addr) netip.Prefix {
	res, err := addr.Prefix(addr.BitLen())
	if err != nil {
		panic(err)
	}
	if !res.IsValid() {
		panic("invalid prefix")
	}
	return res
}

func CentralConfigValidator(cfg *CentralCfg) error {
	nodes := make([]string, 0)
	for _, node := range cfg.Routers {
		err := NameValidator(string(node.Id))
		if err != nil {
			return err
		}
		if slices.Contains(nodes, string(node.Id)) {
			return fmt.Errorf("duplicate router id %s", node.Id)
		}
		nodes = append(nodes, string(node.Id))
	}
	for _, node := range cfg.Clients {
		err := NameValidator(string(node.Id))
		if err != nil {
			return err
		}
		if slices.Contains(nodes, string(node.Id)) {
			return fmt.Errorf("duplicate client id %s", node.Id)
		}
		nodes = append(nodes, string(node.Id))
	}
	_, err := ParseGraph(cfg.Graph, nodes)
	if err != nil {
		return err
	}

	// ensure each node contains unique prefixes (anycast routing allows duplicate prefixes across nodes)
	for _, router := range cfg.Routers {
		routerPrefixes := make(map[RouteKey]struct{})
		for _, p := range router.Prefixes {
			key := NewRouteKey(p.GetPrefix(), p.GetTag())
			if _, ok := routerPrefixes[key]; ok {
				return fmt.Errorf("router %s has duplicate prefix %s tag %s", router.Id, p.GetPrefix(), key.Tag)
			}
			routerPrefixes[key] = struct{}{}
		}
		for _, peer := range cfg.GetPeers(router.Id) {
			if cfg.IsClient(peer) {
				client := cfg.GetClient(peer)
				for _, cp := range client.Prefixes {
					key := NewRouteKey(cp.GetPrefix(), cp.GetTag())
					if _, ok := routerPrefixes[key]; ok {
						return fmt.Errorf("router %s has duplicate prefix %s tag %s (provided by client %s)", router.Id, cp.GetPrefix(), key.Tag, client.Id)
					}
					routerPrefixes[key] = struct{}{}
				}
			}
		}
	}

	if cfg.Dist != nil {
		// validate repos
		for _, repo := range cfg.Dist.Repos {
			_, err := url.Parse(repo)
			if err != nil {
				return err
			}
		}
	}
	// validate excludes
	for _, p := range cfg.ExcludeIPs {
		if !p.IsValid() {
			return fmt.Errorf("invalid prefix %s", p)
		}
	}
	// validate prefixes
	phs := make([]PrefixHealthWrapper, 0)
	for _, c := range cfg.Clients {
		phs = append(phs, c.Prefixes...)
	}
	for _, c := range cfg.Routers {
		phs = append(phs, c.Prefixes...)
	}
	for _, p := range phs {
		if !p.GetPrefix().IsValid() {
			return fmt.Errorf("invalid prefix %s", p.GetPrefix())
		}
		if err := validateRouteTag(p.GetTag()); err != nil {
			return fmt.Errorf("invalid tag %s for prefix %s: %w", p.GetTag(), p.GetPrefix(), err)
		}
		switch v := p.PrefixHealth.(type) {
		case *StaticPrefixHealth:
			// ok
		case *PingPrefixHealth:
			if !v.Addr.IsValid() {
				return fmt.Errorf("invalid ping address %s for prefix %s", v.Addr, p.GetPrefix())
			}
			if v.Delay != nil && *v.Delay <= 0 {
				return fmt.Errorf("ping delay must be greater than 0 for prefix %s", p.GetPrefix())
			}
			if v.MaxFailures != nil && *v.MaxFailures <= 0 {
				return fmt.Errorf("ping max_failures must be greater than 0 for prefix %s", p.GetPrefix())
			}
		case *HTTPPrefixHealth:
			_, err := url.Parse(v.URL)
			if err != nil {
				return fmt.Errorf("invalid HTTP URL %s for prefix %s: %v", v.URL, p.GetPrefix(), err)
			}
			if v.Delay != nil && *v.Delay <= 0 {
				return fmt.Errorf("HTTP delay must be greater than 0 for prefix %s", p.GetPrefix())
			}
		default:
			return fmt.Errorf("unknown prefix health type for prefix %s", p.GetPrefix())
		}
	}

	// validate per-node route tags: every steering tag must be advertised somewhere
	advertised := collectAdvertisedTags(cfg)
	for _, node := range cfg.GetNodes() {
		for _, tag := range node.RouteTags {
			if !advertised[NormalizeRouteTag(tag)] {
				return fmt.Errorf("node %s: route_tag %q is not advertised by any node", node.Id, NormalizeRouteTag(tag))
			}
		}
	}

	// ensure that passive nodes only advertise static prefixes
	for _, client := range cfg.Clients {
		for _, prefix := range client.Prefixes {
			switch prefix.PrefixHealth.(type) {
			case *StaticPrefixHealth:
				// ok
			default:
				return fmt.Errorf("passive clients may not advertise non-static prefixes")
			}
		}
	}
	return nil
}

// collectAdvertisedTags returns the set of route tags advertised by any node.
func collectAdvertisedTags(cfg *CentralCfg) map[string]bool {
	tags := map[string]bool{DefaultRouteTag: true}
	for _, r := range cfg.Routers {
		for _, p := range r.Prefixes {
			tags[p.GetTag()] = true
		}
	}
	for _, c := range cfg.Clients {
		for _, p := range c.Prefixes {
			tags[p.GetTag()] = true
		}
	}
	return tags
}

func validateRouteTag(tag string) error {
	return NameValidator(NormalizeRouteTag(tag))
}
