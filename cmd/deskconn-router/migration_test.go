package main_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	hub "github.com/xconnio/deskconn-router/cmd/deskconn-router"
	"github.com/xconnio/deskconn-router/internal/relay"
	api "github.com/xconnio/xconn/bindings/go"
	"github.com/xconnio/xconn/bindings/go/auth"
)

const (
	deviceRealm      = "device-realm"
	deviceID         = "backend"
	userID           = "alice"
	password         = "test-password"
	pingProcedure    = "io.xconn.deskconn.ping"
	craVerify        = "io.xconn.deskconn.account.cra.verify"
	cryptosignVerify = "io.xconn.deskconn.account.cryptosign.verify"
)

func unusedAddress(t *testing.T, network string) string {
	t.Helper()
	if network == "udp" {
		listener, err := net.ListenPacket(network, "127.0.0.1:0")
		require.NoError(t, err)
		address := listener.LocalAddr().String()
		require.NoError(t, listener.Close())
		return address
	}
	listener, err := net.Listen(network, "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())
	return address
}

func TestHubAuthenticationRoutingAndRPCStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	accountPublic, accountPrivate, err := auth.GenerateCryptoSignKeyPair()
	require.NoError(t, err)
	t.Setenv("DESKCONN_ACCOUNT_SERVICE_PUBLIC_KEY", accountPublic)
	devicePublic, devicePrivate, err := auth.GenerateCryptoSignKeyPair()
	require.NoError(t, err)
	userPublic, userPrivate, err := auth.GenerateCryptoSignKeyPair()
	require.NoError(t, err)
	identity, err := api.GenerateSelfSignedTLSConfig()
	require.NoError(t, err)
	rawAddress := unusedAddress(t, "tcp")
	quicAddress := unusedAddress(t, "udp")
	webTransportAddress := unusedAddress(t, "udp")
	router, err := hub.NewAccountRouter(ctx, relay.Config{
		Machines: func(context.Context) ([]relay.Machine, error) {
			return []relay.Machine{{AuthID: deviceID, Realm: deviceRealm}}, nil
		},
		RawSocketAddress: rawAddress, QUICAddress: quicAddress,
		WebTransportAddress: webTransportAddress, TLSConfig: identity,
	})
	require.NoError(t, err)
	t.Cleanup(router.Close)
	serving, stop := context.WithCancel(ctx)
	finished := make(chan error, 1)
	go func() { finished <- router.Serve(serving) }()
	t.Cleanup(func() {
		stop()
		select {
		case serveErr := <-finished:
			require.NoError(t, serveErr)
		case <-time.After(5 * time.Second):
			t.Error("Hub did not shut down")
		}
	})
	require.Eventually(t, func() bool {
		connection, dialErr := net.DialTimeout("tcp", rawAddress, 100*time.Millisecond)
		if dialErr != nil {
			return false
		}
		_ = connection.Close()
		return true
	}, 5*time.Second, 10*time.Millisecond)
	accounts, err := api.ConnectCryptosign(ctx, "rs://"+rawAddress, relay.CloudRealm,
		"deskconn-account-service", accountPrivate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = accounts.Close() })
	require.Equal(t, "xconnio:deskconn:cloud:service:account", accounts.Details().AuthRole())
	key := string(auth.DeriveWAMPCRAKey("salt", password, 1000, 32))
	require.NoError(t, accounts.Register(craVerify, func(_ context.Context, inv *api.Invocation) *api.Result {
		if inv.ArgStringOr(0, "") != userID {
			return api.NewResultError("wamp.error.not_authorized")
		}
		role := "user:cra"
		if inv.ArgStringOr(1, "") == deviceRealm {
			role = "user:owner"
		}
		return api.NewResult(map[string]any{
			"authrole": role, "password": key, "salt": "salt", "iteration": 1000, "key_length": 32,
		})
	}).ExecuteContext(ctx).Err)
	require.NoError(t, accounts.Register(cryptosignVerify, func(_ context.Context, inv *api.Invocation) *api.Result {
		id, public := inv.ArgStringOr(0, ""), inv.ArgStringOr(1, "")
		role := "user:cryptosign"
		switch {
		case id == deviceID && public == devicePublic:
			role = relay.MachineAuthRole(deviceID)
		case id == userID && public == userPublic:
			if inv.ArgStringOr(2, "") == deviceRealm {
				role = "user:owner"
			}
		default:
			return api.NewResultError("wamp.error.not_authorized")
		}
		return api.NewResult(map[string]any{"authid": id, "authrole": role})
	}).ExecuteContext(ctx).Err)
	cloudUser, err := api.ConnectCRA(ctx, "rs://"+rawAddress, relay.CloudRealm, userID, password)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cloudUser.Close() })
	require.Equal(t, "user:cra", cloudUser.Details().AuthRole())
	wrongPassword, err := api.ConnectCRA(ctx, "rs://"+rawAddress, relay.CloudRealm, userID, "wrong-password")
	if wrongPassword != nil {
		_ = wrongPassword.Close()
	}
	require.Error(t, err)
	cryptosignUser, err := api.ConnectCryptosign(ctx, "rs://"+rawAddress, relay.CloudRealm, userID, userPrivate)
	require.NoError(t, err)
	t.Cleanup(func() { _ = cryptosignUser.Close() })
	require.Equal(t, "user:cryptosign", cryptosignUser.Details().AuthRole())
	backend, err := api.DialQUIC(ctx, quicAddress, "localhost", identity.Certificates[0].Certificate[0])
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })
	deviceAuth, err := auth.NewCryptoSignAuthenticator(deviceID, devicePrivate, nil)
	require.NoError(t, err)
	device, err := backend.OpenSession(ctx, deviceRealm, &api.Client{Authenticator: deviceAuth})
	require.NoError(t, err)
	t.Cleanup(func() { _ = device.Close() })
	require.NoError(t, device.Register(pingProcedure, func(context.Context, *api.Invocation) *api.Result {
		return api.NewResult("pong")
	}).ExecuteContext(ctx).Err)
	user, err := api.ConnectCRA(ctx, "rs://"+rawAddress, deviceRealm, userID, password)
	require.NoError(t, err)
	t.Cleanup(func() { _ = user.Close() })
	require.Equal(t, "pong", user.Call(pingProcedure).ExecuteContext(ctx).ArgStringOr(0, ""))
	roots := x509.NewCertPool()
	certificate, err := x509.ParseCertificate(identity.Certificates[0].Certificate[0])
	require.NoError(t, err)
	roots.AddCert(certificate)
	browser, err := api.DialWebTransport(ctx, "https://"+webTransportAddress+"/wamp",
		&tls.Config{MinVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: roots})
	require.NoError(t, err)
	t.Cleanup(func() { _ = browser.Close() })
	browserUser, err := browser.OpenSession(ctx, deviceRealm,
		&api.Client{Authenticator: auth.NewWAMPCRAAuthenticator(userID, password, nil)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = browserUser.Close() })
	require.Equal(t, "pong", browserUser.Call(pingProcedure).ExecuteContext(ctx).ArgStringOr(0, ""))
	testRPCStreams(t, ctx, browserUser, device)
	require.Error(t, cloudUser.Call("io.xconn.deskconn.test.transfer").ExecuteContext(ctx).Err,
		"the cloud realm cannot reach machine endpoints")

	// A replacement backend must restore both RPC and stream routing without
	// requiring the existing users to reconnect.
	require.NoError(t, device.Close())
	require.NoError(t, backend.Close())
	require.Eventually(t, func() bool {
		return user.Call(pingProcedure).ExecuteContext(ctx).Err != nil
	}, 3*time.Second, 10*time.Millisecond)
	replacement, err := api.DialQUIC(ctx, quicAddress, "localhost", identity.Certificates[0].Certificate[0])
	require.NoError(t, err)
	t.Cleanup(func() { _ = replacement.Close() })
	replacementSession, err := replacement.OpenSession(ctx, deviceRealm, &api.Client{Authenticator: deviceAuth})
	require.NoError(t, err)
	t.Cleanup(func() { _ = replacementSession.Close() })
	require.NoError(t, replacementSession.Register(pingProcedure, func(context.Context, *api.Invocation) *api.Result {
		return api.NewResult("reconnected")
	}).ExecuteContext(ctx).Err)
	require.Equal(t, "reconnected", user.Call(pingProcedure).ExecuteContext(ctx).ArgStringOr(0, ""))
	testRPCStreams(t, ctx, browserUser, replacementSession)
}
