package gcpsecret

import (
	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/andres-erbsen/clock"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/spiffe/spire/pkg/common/coretypes/x509certificate"
	"github.com/spiffe/spire/pkg/common/pemutil"
	"github.com/spiffe/spire/pkg/common/x509svid"
	"github.com/spiffe/spire/pkg/common/x509util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"path"
	"sync"
	"time"
)

type Configuration struct {
	Project string `hcl:"project_name" json:"project_name"`
	Secret  string `hcl:"secret_name" json:"secret_name"`
}

func (c Configuration) secretName() string {
	return path.Join("projects", c.Project, "secrets", c.Secret, "versions", "latest")
}

type Secret struct {
	Cert   string `json:"cert"`
	Key    string `json:"key"`
	Bundle string `json:"bundle"`
}

type Plugin struct {
	upstreamauthorityv1.UnsafeUpstreamAuthorityServer
	configv1.UnsafeConfigServer

	log hclog.Logger

	mtx           sync.RWMutex
	upstreamCerts []*x509.Certificate
	bundleCerts   []*x509.Certificate
	upstreamCA    *x509svid.UpstreamCA

	hooks struct {
		clock     clock.Clock
		getClient func(ctx context.Context) (SecretsClient, error)
	}
}

func New() *Plugin {
	return newPlugin()
}

func newPlugin() *Plugin {
	p := &Plugin{}
	p.hooks.clock = clock.New()
	p.hooks.getClient = getClient
	return p
}

func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := p.validateConfig(req)
	if err != nil {
		return nil, err
	}

	client, err := p.hooks.getClient(ctx)
	if err != nil {
		return nil, err
	}

	keyPEMstr, certsPEMstr, bundleCertsPEMstr, err := p.fetchFromSecretsManager(ctx, client, config)
	if err != nil {
		return nil, err
	}

	trustDomain, err := spiffeid.TrustDomainFromString(req.CoreConfiguration.TrustDomain)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "trust_domain is malformed: %v", err)
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	upstreamCA, upstreamCerts, bundleCerts, err := p.loadUpstreamCAAndCerts(
		trustDomain, keyPEMstr, certsPEMstr, bundleCertsPEMstr,
	)
	if err != nil {
		return nil, err
	}

	p.upstreamCerts = upstreamCerts
	p.bundleCerts = bundleCerts
	p.upstreamCA = upstreamCA

	return &configv1.ConfigureResponse{}, nil
}

// MintX509CAAndSubscribe mints an X509CA by signing presented CSR with root CA fetched from GCP Secrets Manager
func (p *Plugin) MintX509CAAndSubscribe(request *upstreamauthorityv1.MintX509CARequest, stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer) error {
	p.log.Debug("Request to GCP_SECRET to mint new X509")

	ctx := stream.Context()
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.upstreamCA == nil {
		return status.Error(codes.FailedPrecondition, "not configured")
	}

	cert, err := p.upstreamCA.SignCSR(ctx, request.Csr, time.Second*time.Duration(request.PreferredTtl))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to sign CSR: %v", err)
	}

	x509CAChain, err := x509certificate.ToPluginProtos(append([]*x509.Certificate{cert}, p.upstreamCerts...))
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response X.509 CA chain: %v", err)
	}

	upstreamX509Roots, err := x509certificate.ToPluginProtos(p.bundleCerts)
	if err != nil {
		return status.Errorf(codes.Internal, "unable to form response upstream X.509 roots: %v", err)
	}

	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       x509CAChain,
		UpstreamX509Roots: upstreamX509Roots,
	})
}

// PublishJWTKeyAndSubscribe is not implemented by the wrapper and returns a codes.Unimplemented status
func (p *Plugin) PublishJWTKeyAndSubscribe(*upstreamauthorityv1.PublishJWTKeyRequest, upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer) error {
	return status.Error(codes.Unimplemented, "publishing upstream is unsupported")
}

func (p *Plugin) fetchFromSecretsManager(ctx context.Context, client SecretsClient, config *Configuration) (string, string, string, error) {
	secretValue, err := client.ReadSecret(ctx, config.secretName())
	if err != nil {
		return "", "", "", status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.secretName(), err)
	}

	s := &Secret{}
	if err := json.Unmarshal(secretValue, s); err != nil {
		return "", "", "", status.Errorf(codes.InvalidArgument, "unable to read %s: %v", config.secretName(), err)
	}

	return s.Key, s.Cert, s.Bundle, nil
}

func (p *Plugin) loadUpstreamCAAndCerts(trustDomain spiffeid.TrustDomain, keyPEMstr, certsPEMstr, bundleCertsPEMstr string) (*x509svid.UpstreamCA, []*x509.Certificate, []*x509.Certificate, error) {
	key, err := pemutil.ParsePrivateKey([]byte(keyPEMstr))
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA key: %v", err)
	}

	certs, err := pemutil.ParseCertificates([]byte(certsPEMstr))
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA cert: %v", err)
	}

	caCert := certs[0] // pemutil guarantees at least one cert

	var trustBundle []*x509.Certificate
	if bundleCertsPEMstr == "" {
		// If there is no bundle payload configured then the value of certs
		// must be a self-signed cert. We enforce this by requiring that there is
		// exactly one certificate; this certificate is reused for the trust
		// bundle and bundleCertsPEMstr is ignored
		if len(certs) != 1 {
			return nil, nil, nil, status.Error(codes.InvalidArgument, "with no bundle configured only self-signed CAs are supported")
		}
		trustBundle = certs
		certs = nil
	} else {
		bundleCerts, err := pemutil.ParseCertificates([]byte(bundleCertsPEMstr))
		if err != nil {
			return nil, nil, nil, status.Errorf(codes.InvalidArgument, "unable to load upstream CA bundle: %v", err)
		}
		trustBundle = append(trustBundle, bundleCerts...)
	}

	// Validate cert matches private key
	matched, err := x509util.CertificateMatchesPrivateKey(caCert, key)
	if err != nil {
		return nil, nil, nil, status.Errorf(codes.InvalidArgument, "unable to verify CA cert matches private key: %v", err)
	}
	if !matched {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate and private key do not match")
	}

	intermediates := x509.NewCertPool()
	roots := x509.NewCertPool()
	for _, c := range certs {
		intermediates.AddCert(c)
	}
	for _, c := range trustBundle {
		roots.AddCert(c)
	}
	selfVerifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}
	_, err = caCert.Verify(selfVerifyOpts)
	if err != nil {
		return nil, nil, nil, status.Error(codes.InvalidArgument, "unable to load upstream CA: certificate cannot be validated with the provided bundle or is not self-signed")
	}

	return x509svid.NewUpstreamCA(
		x509util.NewMemoryKeypair(caCert, key),
		trustDomain,
		x509svid.UpstreamCAOptions{
			Clock: p.hooks.clock,
		},
	), certs, trustBundle, nil
}

func (p *Plugin) validateConfig(req *configv1.ConfigureRequest) (*Configuration, error) {
	// Parse HCL config payload into config struct
	config := new(Configuration)

	if err := hcl.Decode(&config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, status.Error(codes.InvalidArgument, "core configuration is required")
	}

	if req.CoreConfiguration.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	if config.Project == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration missing project name")
	}

	if config.Secret == "" {
		return nil, status.Error(codes.InvalidArgument, "configuration missing secret name")
	}

	return config, nil
}

type SecretsClient interface {
	ReadSecret(ctx context.Context, name string) ([]byte, error)
}

func getClient(ctx context.Context) (SecretsClient, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	return &gcpSecretsClient{client: client}, nil
}

type gcpSecretsClient struct {
	client *secretmanager.Client
}

func (c *gcpSecretsClient) ReadSecret(ctx context.Context, name string) ([]byte, error) {
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	result, err := c.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to access secret version: %v", err)
	}

	fmt.Printf("retrieved payload for: %s\n", result.Name)
	return result.Payload.Data, nil
}
