/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/klog/v2"
	"sigs.k8s.io/apiserver-network-proxy/pkg/agent"
	"sigs.k8s.io/apiserver-network-proxy/pkg/features"
	"sigs.k8s.io/apiserver-network-proxy/pkg/util"
)

func main() {
	agent := &Agent{}
	o := newGrpcProxyAgentOptions()
	command := newAgentCommand(agent, o)
	flags := command.Flags()
	flags.AddFlagSet(o.Flags())
	local := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	klog.InitFlags(local)
	err := local.Set("v", "4")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error setting klog flags: %v", err)
	}
	local.VisitAll(func(fl *flag.Flag) {
		fl.Name = util.Normalize(fl.Name)
		flags.AddGoFlag(fl)
	})
	if err := command.Execute(); err != nil {
		klog.Errorf("error: %v\n", err)
		klog.Flush()
		os.Exit(1)
	}
}

type GrpcProxyAgentOptions struct {
	// Configuration for authenticating with the proxy-server
	agentCert string
	agentKey  string
	caCert    string

	// Configuration for connecting to the proxy-server
	proxyServerHost string
	proxyServerPort int

	// Ports for the health and admin server
	healthServerPort int
	adminServerPort  int

	agentID          string
	agentIdentifiers string
	syncInterval     time.Duration
	probeInterval    time.Duration

	// file contains service account authorization token for enabling proxy-server token based authorization
	serviceAccountTokenPath string

	bindAddress      string
	apiServerMapping portMapping
}

// port mapping represents the mapping between a local port and a remote
// destination.
type portMapping struct {
	localPort  int
	remoteHost string
	remotePort int
}

func (pm *portMapping) String() string {
	return fmt.Sprintf("%d:%s:%d", pm.localPort, pm.remoteHost, pm.remotePort)
}

func (pm *portMapping) Set(s string) error {
	i := strings.Index(s, ":")
	if i < 0 || i == len(s)-1 {
		return fmt.Errorf("malformed port mapping %q, expected format: <local_port>:<remote_host>:<remote_port>", s)
	}
	rawLocPort := s[:i]
	localPort, err := strconv.Atoi(rawLocPort)
	if err != nil {
		return fmt.Errorf("error occurred while parsing local port: %v", err)
	}
	pm.localPort = localPort
	h, p, err := net.SplitHostPort(s[i+1:])
	if err != nil {
		return fmt.Errorf("error occurred while splitting remote host and port: %v", err)
	}
	pm.remoteHost = h
	remotePort, err := strconv.Atoi(p)
	if err != nil {
		return fmt.Errorf("error occurred while parsing remote port: %v", err)
	}
	pm.remotePort = remotePort
	return nil
}

func (pm *portMapping) Type() string {
	return "portMapping"
}

func (o *GrpcProxyAgentOptions) ClientSetConfig(dialOptions ...grpc.DialOption) *agent.ClientSetConfig {
	return &agent.ClientSetConfig{
		Address:                 fmt.Sprintf("%s:%d", o.proxyServerHost, o.proxyServerPort),
		AgentID:                 o.agentID,
		AgentIdentifiers:        o.agentIdentifiers,
		SyncInterval:            o.syncInterval,
		ProbeInterval:           o.probeInterval,
		DialOptions:             dialOptions,
		ServiceAccountTokenPath: o.serviceAccountTokenPath,
	}
}

func (o *GrpcProxyAgentOptions) Flags() *pflag.FlagSet {
	flags := pflag.NewFlagSet("proxy-agent", pflag.ContinueOnError)
	flags.StringVar(&o.agentCert, "agent-cert", o.agentCert, "If non-empty secure communication with this cert.")
	flags.StringVar(&o.agentKey, "agent-key", o.agentKey, "If non-empty secure communication with this key.")
	flags.StringVar(&o.caCert, "ca-cert", o.caCert, "If non-empty the CAs we use to validate clients.")
	flags.StringVar(&o.proxyServerHost, "proxy-server-host", o.proxyServerHost, "The hostname to use to connect to the proxy-server.")
	flags.IntVar(&o.proxyServerPort, "proxy-server-port", o.proxyServerPort, "The port the proxy server is listening on.")
	flags.IntVar(&o.healthServerPort, "health-server-port", o.healthServerPort, "The port the health server is listening on.")
	flags.IntVar(&o.adminServerPort, "admin-server-port", o.adminServerPort, "The port the admin server is listening on.")
	flags.StringVar(&o.agentID, "agent-id", o.agentID, "The unique ID of this agent. Default to a generated uuid if not set.")
	flags.DurationVar(&o.syncInterval, "sync-interval", o.syncInterval, "The initial interval by which the agent periodically checks if it has connections to all instances of the proxy server.")
	flags.DurationVar(&o.probeInterval, "probe-interval", o.probeInterval, "The interval by which the agent periodically checks if its connections to the proxy server are ready.")
	flags.StringVar(&o.serviceAccountTokenPath, "service-account-token-path", o.serviceAccountTokenPath, "If non-empty proxy agent uses this token to prove its identity to the proxy server.")
	flags.StringVar(&o.agentIdentifiers, "agent-identifiers", o.agentIdentifiers, "Identifiers of the agent that will be used by the server when choosing agent. N.B. the list of identifiers must be in URL encoded format. e.g.,host=localhost&host=node1.mydomain.com&cidr=127.0.0.1/16&ipv4=1.2.3.4&ipv4=5.6.7.8&ipv6=:::::")
	flags.StringVar(&o.agentIdentifiers, "target", o.agentIdentifiers, "Identifiers of the agent that will be used by the server when choosing agent. N.B. the list of identifiers must be in URL encoded format. e.g.,host=localhost&host=node1.mydomain.com&cidr=127.0.0.1/16&ipv4=1.2.3.4&ipv4=5.6.7.8&ipv6=:::::")
	flags.Var(&o.apiServerMapping, "apiserver-mapping", "Mapping between a local port and the host:port used to reach the Kubernetes API Server")
	flags.StringVar(&o.bindAddress, "bind-address", o.bindAddress, "Address used to listen for traffic generated on cluster network")
	// add feature gates flag
	features.DefaultMutableFeatureGate.AddFlag(flags)
	return flags
}

func (o *GrpcProxyAgentOptions) Print() {
	klog.V(1).Infof("AgentCert set to %q.\n", o.agentCert)
	klog.V(1).Infof("AgentKey set to %q.\n", o.agentKey)
	klog.V(1).Infof("CACert set to %q.\n", o.caCert)
	klog.V(1).Infof("ProxyServerHost set to %q.\n", o.proxyServerHost)
	klog.V(1).Infof("ProxyServerPort set to %d.\n", o.proxyServerPort)
	klog.V(1).Infof("HealthServerPort set to %d.\n", o.healthServerPort)
	klog.V(1).Infof("AdminServerPort set to %d.\n", o.adminServerPort)
	klog.V(1).Infof("AgentID set to %s.\n", o.agentID)
	klog.V(1).Infof("SyncInterval set to %v.\n", o.syncInterval)
	klog.V(1).Infof("ProbeInterval set to %v.\n", o.probeInterval)
	klog.V(1).Infof("ServiceAccountTokenPath set to %q.\n", o.serviceAccountTokenPath)
	klog.V(1).Infof("AgentIdentifiers set to %s.\n", util.PrettyPrintURL(o.agentIdentifiers))
}

func (o *GrpcProxyAgentOptions) Validate() error {
	if o.agentKey != "" {
		if _, err := os.Stat(o.agentKey); os.IsNotExist(err) {
			return fmt.Errorf("error checking agent key %s, got %v", o.agentKey, err)
		}
		if o.agentCert == "" {
			return fmt.Errorf("cannot have agent cert empty when agent key is set to \"%s\"", o.agentKey)
		}
	}
	if o.agentCert != "" {
		if _, err := os.Stat(o.agentCert); os.IsNotExist(err) {
			return fmt.Errorf("error checking agent cert %s, got %v", o.agentCert, err)
		}
		if o.agentKey == "" {
			return fmt.Errorf("cannot have agent key empty when agent cert is set to \"%s\"", o.agentCert)
		}
	}
	if o.caCert != "" {
		if _, err := os.Stat(o.caCert); os.IsNotExist(err) {
			return fmt.Errorf("error checking agent CA cert %s, got %v", o.caCert, err)
		}
	}
	if o.proxyServerPort <= 0 {
		return fmt.Errorf("proxy server port %d must be greater than 0", o.proxyServerPort)
	}
	if o.healthServerPort <= 0 {
		return fmt.Errorf("health server port %d must be greater than 0", o.healthServerPort)
	}
	if o.adminServerPort <= 0 {
		return fmt.Errorf("admin server port %d must be greater than 0", o.adminServerPort)
	}

	if o.serviceAccountTokenPath != "" {
		if _, err := os.Stat(o.serviceAccountTokenPath); os.IsNotExist(err) {
			return fmt.Errorf("error checking service account token path %s, got %v", o.serviceAccountTokenPath, err)
		}
	}
	if err := validateAgentIdentifiers(o.agentIdentifiers); err != nil {
		return fmt.Errorf("agent address is invalid: %v", err)
	}
	return nil
}

func validateAgentIdentifiers(agentIdentifiers string) error {
	decoded, err := url.ParseQuery(agentIdentifiers)
	if err != nil {
		return err
	}
	for idType := range decoded {
		switch agent.IdentifierType(idType) {
		case agent.IPv4:
		case agent.IPv6:
		case agent.CIDR:
		case agent.Host:
		default:
			return fmt.Errorf("unknown address type: %s", idType)
		}
	}
	return nil
}

func newGrpcProxyAgentOptions() *GrpcProxyAgentOptions {
	o := GrpcProxyAgentOptions{
		agentCert:               "",
		agentKey:                "",
		caCert:                  "",
		proxyServerHost:         "127.0.0.1",
		proxyServerPort:         8091,
		healthServerPort:        8093,
		adminServerPort:         8094,
		agentID:                 uuid.New().String(),
		agentIdentifiers:        "",
		syncInterval:            1 * time.Second,
		probeInterval:           1 * time.Second,
		serviceAccountTokenPath: "",
		apiServerMapping:        portMapping{localPort: 6443, remoteHost: "localhost", remotePort: 6443},
		bindAddress:             "127.0.0.1",
	}
	return &o
}

func newAgentCommand(a *Agent, o *GrpcProxyAgentOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:  "agent",
		Long: `A gRPC agent, Connects to the proxy and then allows traffic to be forwarded to it.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.run(o)
		},
	}

	return cmd
}

type Agent struct {
}

func (a *Agent) run(o *GrpcProxyAgentOptions) error {
	o.Print()
	if err := o.Validate(); err != nil {
		return fmt.Errorf("failed to validate agent options with %v", err)
	}

	stopCh := make(chan struct{})
	var err error
	var cs *agent.ClientSet
	if cs, err = a.runProxyConnection(o, stopCh); err != nil {
		return fmt.Errorf("failed to run proxy connection with %v", err)
	}

	if features.DefaultMutableFeatureGate.Enabled(features.ClusterToMasterTraffic) {
		if err := a.runControlPlaneProxy(o, cs, stopCh); err != nil {
			return fmt.Errorf("failed to start listening with %v", err)
		}
	}

	if err := a.runHealthServer(o); err != nil {
		return fmt.Errorf("failed to run health server with %v", err)
	}

	if err := a.runAdminServer(o); err != nil {
		return fmt.Errorf("failed to run admin server with %v", err)
	}

	<-stopCh

	return nil
}

func (a *Agent) runProxyConnection(o *GrpcProxyAgentOptions, stopCh <-chan struct{}) (*agent.ClientSet, error) {
	var tlsConfig *tls.Config
	var err error
	if tlsConfig, err = util.GetClientTLSConfig(o.caCert, o.agentCert, o.agentKey, o.proxyServerHost); err != nil {
		return nil, err
	}
	dialOption := grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
	cc := o.ClientSetConfig(dialOption)
	cs := cc.NewAgentClientSet(stopCh)
	cs.Serve()

	return cs, nil
}

func (a *Agent) runControlPlaneProxy(o *GrpcProxyAgentOptions, cs *agent.ClientSet, stopCh <-chan struct{}) error {
	lc := net.ListenConfig{}
	listenAddr := net.JoinHostPort(o.bindAddress, strconv.Itoa(o.apiServerMapping.localPort))
	klog.V(1).InfoS("starting control plane proxy", "listen-address", listenAddr)
	listener, err := lc.Listen(context.TODO(), "tcp", listenAddr)
	if err != nil {
		return err
	}
	go func() {
		for {
			klog.V(2).InfoS("listening for connections", "listen-address", listenAddr)
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					klog.ErrorS(err, "Error occurred while waiting for connections")
				}
			} else {
				// Serve each connection in a dedicated goroutine
				go func() {
					if err := cs.HandleConnection("tcp", net.JoinHostPort(o.apiServerMapping.remoteHost, strconv.Itoa(o.apiServerMapping.remotePort)), conn); err != nil {
						if err := conn.Close(); err != nil {
							klog.ErrorS(err, "Error while closing connection")
						}
						klog.ErrorS(err, "Error occurred while handling connection")
					}
				}()
			}
		}
	}()
	return nil
}

func (a *Agent) runHealthServer(o *GrpcProxyAgentOptions) error {
	livenessHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
	readinessHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})

	muxHandler := http.NewServeMux()
	muxHandler.Handle("/metrics", promhttp.Handler())
	muxHandler.HandleFunc("/healthz", livenessHandler)
	muxHandler.HandleFunc("/ready", readinessHandler)
	healthServer := &http.Server{
		Addr:           fmt.Sprintf(":%d", o.healthServerPort),
		Handler:        muxHandler,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		err := healthServer.ListenAndServe()
		if err != nil {
			klog.ErrorS(err, "health server could not listen")
		}
		klog.V(0).Infoln("Health server stopped listening")
	}()

	return nil
}

func (a *Agent) runAdminServer(o *GrpcProxyAgentOptions) error {
	muxHandler := http.NewServeMux()
	muxHandler.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		// The port number may be omitted if the admin server is running on port
		// 80, the default port for HTTP
		if err != nil {
			host = r.Host
		}
		http.Redirect(w, r, fmt.Sprintf("%s:%d%s", host, o.healthServerPort, r.URL.Path), http.StatusMovedPermanently)
	}))

	adminServer := &http.Server{
		Addr:           fmt.Sprintf("127.0.0.1:%d", o.adminServerPort),
		Handler:        muxHandler,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		err := adminServer.ListenAndServe()
		if err != nil {
			klog.ErrorS(err, "admin server could not listen")
		}
		klog.V(0).Infoln("Admin server stopped listening")
	}()

	return nil
}
