package main_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	api "github.com/xconnio/xconn-core/bindings/go"
)

// Exercise the Hub's production authentication and permissions with a device
// bridge and a local application. Raw stream routing must coexist with RPC streams.
func testRPCStreams(t *testing.T, ctx context.Context, client, device *api.Session) {
	t.Helper()
	local, err := api.NewRouter(nil)
	require.NoError(t, err)
	defer local.Close()
	require.NoError(t, local.AddRealm("application", &api.RealmConfig{Roles: []api.RealmRole{{
		Name: "anonymous", Permissions: []api.Permission{{
			URI: "io.xconn.deskconn.test.", MatchPolicy: "prefix", AllowCall: true, AllowRegister: true,
		}},
	}}}))
	server := api.NewServer(local, nil, nil)
	defer server.Close()
	network, address := api.NetworkUnix, filepath.Join(t.TempDir(), "app.sock")
	if runtime.GOOS == "windows" {
		network, address = api.NetworkTCP, "127.0.0.1:0"
	}
	listener, err := server.ListenAndServeYamux(network, address)
	require.NoError(t, err)
	uri := "unix+yamux://" + listener.Address
	if network == api.NetworkTCP {
		uri = "yamux://" + listener.Address
	}
	application, err := (&api.Client{}).Connect(ctx, uri, "application")
	require.NoError(t, err)
	defer application.Close()
	// The device's target session stays in process; only the application's
	// connection uses a Unix socket. XConn owns the pipes between these legs.
	target, err := api.ConnectInMemory(local, "application") //nolint:contextcheck // No context API.
	require.NoError(t, err)
	defer target.Close()
	const transferProcedure = "io.xconn.deskconn.test.transfer"
	const shellProcedure = "io.xconn.deskconn.test.shell"
	payload := bytes.Repeat([]byte("hub transfer"), 128*1024)
	require.NoError(t, application.Register(transferProcedure,
		func(_ context.Context, inv *api.Invocation) *api.Result {
			stream, openErr := inv.ArgStream(1)
			if openErr != nil {
				return api.NewResultError("app.invalid_stream", openErr.Error())
			}
			defer stream.Close()
			body, readErr := io.ReadAll(stream)
			if readErr != nil || !bytes.Equal(body, payload) {
				return api.NewResultError("app.invalid_upload")
			}
			return api.NewResult(inv.ArgStringOr(0, ""), api.ReadStream(io.NopCloser(bytes.NewReader(body))))
		}).ExecuteContext(ctx).Err)
	completed := make(chan error, 1)
	require.NoError(t, application.Register(shellProcedure,
		func(ctx context.Context, _ *api.Invocation) *api.Result {
			endpoint, process := net.Pipe()
			stop := context.AfterFunc(ctx, func() { _ = process.Close() })
			go func() {
				defer stop()
				defer process.Close()
				request := make([]byte, 4)
				_, readErr := io.ReadFull(process, request)
				if readErr == nil && string(request) == "ping" {
					_, readErr = process.Write([]byte("pong"))
				}
				completed <- readErr
			}()
			return api.NewResult(api.DuplexStream(endpoint))
		}).ExecuteContext(ctx).Err)
	bridge, err := device.Bridge(ctx, api.BridgeConfig{
		Target: target,
		Routes: []api.BridgeRoute{{Procedure: transferProcedure}, {Procedure: shellProcedure}},
	})
	require.NoError(t, err)
	defer bridge.Close()

	result := client.Call(transferProcedure).Arg("report.txt").
		Arg(api.ReadStream(io.NopCloser(bytes.NewReader(payload)))).ExecuteContext(ctx)
	require.NoError(t, result.Err)
	require.Equal(t, "report.txt", result.ArgStringOr(0, ""))
	stream, err := result.ArgStream(1)
	require.NoError(t, err)
	defer stream.Close()
	body, err := io.ReadAll(stream)
	require.NoError(t, err)
	require.Equal(t, payload, body)
	require.NoError(t, stream.Close())

	result = client.Call(shellProcedure).ExecuteContext(ctx)
	require.NoError(t, result.Err)
	stream, err = result.ArgStream(0)
	require.NoError(t, err)
	defer stream.Close()
	_, err = stream.Write([]byte("ping"))
	require.NoError(t, err)
	body = make([]byte, 4)
	_, err = io.ReadFull(stream, body)
	require.NoError(t, err)
	require.Equal(t, "pong", string(body))
	require.NoError(t, stream.Close())
	select {
	case err = <-completed:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("bridged shell did not finish")
	}
}
