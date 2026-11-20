package main_test

import (
	"context"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	hub "github.com/xconnio/deskconn-router/cmd/deskconn-hub"
	api "github.com/xconnio/xconn/bindings/go"
	"github.com/xconnio/xconn/bindings/go/auth"
	"github.com/xconnio/xconn/bindings/go/messages"
)

func TestLoginThrottleLimitsEachAccount(t *testing.T) {
	now := time.Unix(0, 0)
	throttle := hub.NewLoginThrottle(func() time.Time { return now })
	for range 20 {
		require.NoError(t, throttle.Admit(userID))
		now = now.Add(2 * time.Second)
	}
	require.ErrorIs(t, throttle.Admit(userID), hub.ErrTooManyLoginAttempts)
	require.ErrorIs(t, throttle.Admit(" ALICE "), hub.ErrTooManyLoginAttempts, "case and spaces are the same account")
	require.NoError(t, throttle.Admit("bob"), "other accounts are not limited by alice's attempts")

	now = now.Add(15 * time.Minute)
	require.NoError(t, throttle.Admit(userID), "attempts are allowed again in the next window")
}

// TestLoginThrottleBoundsTrackedAccounts keeps attempts at many accounts from growing the
// throttle without bound: once it tracks its limit of accounts, it starts counting afresh.
func TestLoginThrottleBoundsTrackedAccounts(t *testing.T) {
	now := time.Unix(0, 0)
	throttle := hub.NewLoginThrottle(func() time.Time { return now })
	for range 20 {
		require.NoError(t, throttle.Admit(userID))
	}
	require.ErrorIs(t, throttle.Admit(userID), hub.ErrTooManyLoginAttempts)
	for index := range hub.MaxTrackedAccounts - 1 {
		require.NoError(t, throttle.Admit(strconv.Itoa(index)))
	}
	require.Equal(t, hub.MaxTrackedAccounts, throttle.Tracked())
	require.NoError(t, throttle.Admit("one-more"), "a full throttle starts a new window")
	require.Equal(t, 1, throttle.Tracked())
}

// TestPasswordLoginsAreThrottledBeforeTheAccountService keeps refused attempts away from the
// account service, and leaves key logins alone.
func TestPasswordLoginsAreThrottledBeforeTheAccountService(t *testing.T) {
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
	const role = "authrole"
	var verified atomic.Int32
	require.NoError(t, backend.Register(craVerify, func(context.Context, *api.Invocation) *api.Result {
		verified.Add(1)
		return api.NewResult(map[string]any{role: "user:cra", "password": "key", salt: salt})
	}).ExecuteContext(ctx).Err)
	require.NoError(t, backend.Register(cryptosignVerify, func(context.Context, *api.Invocation) *api.Result {
		return api.NewResult(map[string]any{"authid": userID, role: "user:cryptosign"})
	}).ExecuteContext(ctx).Err)

	authenticate := hub.NewAccountAuthenticator(caller)
	hello := messages.NewHello("accounts", userID, nil, nil, []string{string(auth.WAMPCRA)})
	for range 20 {
		_, err := authenticate(auth.NewRequest(hello, auth.WAMPCRA))
		require.NoError(t, err)
	}
	_, err = authenticate(auth.NewRequest(hello, auth.WAMPCRA))
	require.ErrorIs(t, err, hub.ErrTooManyLoginAttempts)
	require.EqualValues(t, 20, verified.Load(), "a refused attempt must not reach the account service")

	keyHello := messages.NewHello("accounts", userID, nil, nil, []string{string(auth.CryptoSign)})
	_, err = authenticate(auth.NewCryptoSignRequest(keyHello, "test-public-key"))
	require.NoError(t, err, "key logins are not throttled")
}
