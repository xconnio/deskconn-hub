package main_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	hub "github.com/xconnio/deskconn-router/cmd/deskconn-hub"
	api "github.com/xconnio/xconn/bindings/go"
	"github.com/xconnio/xconn/bindings/go/auth"
	"github.com/xconnio/xconn/bindings/go/messages"
)

func TestAccountAuthenticationTimesOut(t *testing.T) {
	for _, method := range []auth.Method{auth.WAMPCRA, auth.CryptoSign} {
		t.Run(string(method), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()

			router, err := api.NewRouter(nil)
			require.NoError(t, err)
			defer router.Close()
			require.NoError(t, router.AddRealm("accounts", nil))
			caller, err := api.ConnectInMemory(router, "accounts") //nolint:contextcheck // No context API.
			require.NoError(t, err)
			defer caller.Close()
			backend, err := api.ConnectInMemory(router, "accounts") //nolint:contextcheck // No context API.
			require.NoError(t, err)
			defer backend.Close()

			procedure := craVerify
			if method == auth.CryptoSign {
				procedure = cryptosignVerify
			}
			started := make(chan struct{})
			interrupted := make(chan struct{})
			require.NoError(t, backend.Register(procedure, func(ctx context.Context, _ *api.Invocation) *api.Result {
				close(started)
				<-ctx.Done()
				close(interrupted)
				return api.NewResult()
			}).ExecuteContext(ctx).Err)

			hello := messages.NewHello("accounts", "alice", nil, nil, []string{string(method)})
			request := auth.NewRequest(hello, method)
			if method == auth.CryptoSign {
				request = auth.NewCryptoSignRequest(hello, "test-public-key")
			}
			finished := make(chan error, 1)
			go func() {
				_, authErr := hub.AuthenticateAccount(caller, request)
				finished <- authErr
			}()

			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("authentication did not call the account backend")
			}
			select {
			case err = <-finished:
				require.ErrorIs(t, err, context.DeadlineExceeded)
			case <-ctx.Done():
				t.Fatal("authentication did not enforce its deadline")
			}
			select {
			case <-interrupted:
			case <-ctx.Done():
				t.Fatal("timed-out authentication did not cancel the account request")
			}
		})
	}
}
