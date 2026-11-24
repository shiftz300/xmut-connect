//go:build !tun

package main

import (
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"os"
	"slices"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/configs"
	"github.com/mythologyli/zju-connect/dial"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"github.com/mythologyli/zju-connect/service"
	"github.com/mythologyli/zju-connect/stack"
	"github.com/mythologyli/zju-connect/stack/gvisor"
	"github.com/mythologyli/zju-connect/stack/tcptunnel"
	"github.com/mythologyli/zju-connect/stack/tun"
	"golang.org/x/crypto/pkcs12"
	"inet.af/netaddr"
)

type configuredTunnel struct {
	stack         stack.Stack
	resolver      *resolve.Resolver
	dialer        *dial.Dialer
	localResolver service.DNSServer
	useRemoteDNS  bool
}

func readEasyConnectCertificate(cfg configs.Config) (tls.Certificate, error) {
	if cfg.CertFile == "" {
		return tls.Certificate{}, nil
	}
	data, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, cert, err := pkcs12.Decode(data, cfg.CertPassword)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  key,
		Leaf:        cert,
	}, nil
}

func configureTunnel(cfg configs.Config, vpnClient client.Client) (*configuredTunnel, error) {
	ipResources, err := vpnClient.IPResources()
	if err != nil && !cfg.DisableServerConfig {
		log.Println("No IP resources")
	}

	ipSet, err := vpnClient.IPSet()
	if err != nil && !cfg.DisableServerConfig {
		log.Println("No IP set")
	}

	domainResources, err := vpnClient.DomainResources()
	if err != nil && !cfg.DisableServerConfig {
		log.Println("No domain resources")
	}

	dnsResource, err := vpnClient.DNSResource()
	if err != nil && !cfg.DisableServerConfig {
		log.Println("No DNS resource")
	}

	if cfg.Protocol == "easyconnect" {
		domainResources = maps.Clone(domainResources)
		if !cfg.DisableZJUConfig {
			if domainResources == nil {
				domainResources = make(client.DomainResources)
			}

			domainResources["zju.edu.cn"] = []client.DomainResource{{
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}

			if ipResources == nil {
				ipResources = []client.IPResource{}
			}

			ipResources = append([]client.IPResource{{
				IPMin:    net.ParseIP("10.0.0.0"),
				IPMax:    net.ParseIP("10.255.255.255"),
				PortMin:  1,
				PortMax:  65535,
				Protocol: "all",
			}}, ipResources...)

			ipSetBuilder := netaddr.IPSetBuilder{}
			if ipSet != nil {
				ipSetBuilder.AddSet(ipSet)
			}
			ipSetBuilder.AddPrefix(netaddr.MustParseIPPrefix("10.0.0.0/8"))
			ipSet, _ = ipSetBuilder.IPSet()
		}

		for _, customProxyDomain := range cfg.CustomProxyDomain {
			if domainResources != nil {
				domainResources[customProxyDomain] = append(slices.Clone(domainResources[customProxyDomain]), client.DomainResource{
					PortMin:  1,
					PortMax:  65535,
					Protocol: "all",
				})
			} else {
				domainResources = client.DomainResources{
					customProxyDomain: {{
						PortMin:  1,
						PortMax:  65535,
						Protocol: "all",
					}},
				}
			}
		}
	}

	var vpnStack stack.Stack
	if cfg.TCPTunnelMode {
		vpnStack, err = tcptunnel.NewStack(vpnClient)
		if err != nil {
			return nil, fmt.Errorf("TCP tunnel stack setup: %w", err)
		}
	} else if cfg.TUNMode {
		vpnTUNStack, err := tun.NewStack(vpnClient, cfg.DNSHijack, cfg.FakeIP, ipResources)
		if err != nil {
			return nil, fmt.Errorf("TUN stack setup: %w", err)
		}

		if cfg.AddRoute && ipSet != nil {
			for _, prefix := range ipSet.Prefixes() {
				log.Printf("Add route to %s", prefix.String())
				_ = vpnTUNStack.AddRoute(prefix.String())
			}
		} else if !cfg.AddRoute && !cfg.DisableZJUConfig && cfg.Protocol == "easyconnect" {
			log.Println("Add route to 10.0.0.0/8")
			_ = vpnTUNStack.AddRoute("10.0.0.0/8")
		}

		if cfg.FakeIP {
			_ = vpnTUNStack.AddRoute("198.18.0.0/16")
		}

		vpnStack = vpnTUNStack
	} else {
		vpnStack, err = gvisor.NewStack(vpnClient)
		if err != nil {
			return nil, fmt.Errorf("gVisor stack setup: %w", err)
		}
	}

	useRemoteDNS := !cfg.DisableRemoteDNS
	remoteDNSServer := cfg.RemoteDNSServer
	policyDNSServers, _ := vpnClient.DNSServers()
	if useRemoteDNS && remoteDNSServer == "auto" {
		remoteDNSServer, err = vpnClient.DNSServer()
		if err != nil {
			useRemoteDNS = false
			remoteDNSServer = "10.10.0.21"
			log.Println("No DNS server provided by server. Disable remote DNS")
		} else {
			log.Printf("Use DNS server %s provided by server", remoteDNSServer)
		}
	}
	secondaryDNSServer := cfg.SecondaryDNSServer
	if secondaryDNSServer == "auto" {
		secondaryDNSServer = "114.114.114.114"
		if len(policyDNSServers) > 1 {
			secondaryDNSServer = policyDNSServers[1]
			log.Printf("Use secondary DNS server %s provided by server", secondaryDNSServer)
		}
	}

	vpnResolver := resolve.NewResolver(
		vpnStack,
		remoteDNSServer,
		secondaryDNSServer,
		cfg.DNSTTL,
		domainResources,
		dnsResource,
		useRemoteDNS,
	)
	for _, customDns := range cfg.CustomDNSList {
		ipAddr := net.ParseIP(customDns.IP)
		if ipAddr == nil {
			log.Printf("Custom DNS for host name %s is invalid, SKIP", customDns.HostName)
		}
		vpnResolver.SetPermanentDNS(customDns.HostName, ipAddr)
		log.Printf("Add custom DNS: %s -> %s\n", customDns.HostName, customDns.IP)
	}
	localResolver := service.NewDnsServer(vpnResolver, []string{remoteDNSServer, cfg.SecondaryDNSServer})
	vpnStack.SetupResolve(localResolver)
	vpnStack.SetupIPPool(vpnResolver.IPPool)

	vpnDialer := dial.NewDialer(vpnStack, vpnResolver, ipResources, cfg.ProxyAll, cfg.DialDirectProxy)

	return &configuredTunnel{
		stack: vpnStack, resolver: vpnResolver, dialer: vpnDialer,
		localResolver: localResolver, useRemoteDNS: useRemoteDNS,
	}, nil
}
