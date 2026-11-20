package main

import (
	"context"
	"time"

	"github.com/xconnio/deskconn-router/internal/relay"
	"github.com/xconnio/xconn/bindings/go"
	"github.com/xconnio/xconn/bindings/go/auth"
)

// NewAccountRouter exercises the production account adapter with test listeners
// and machine inventory, without requiring the deployment's Postgres database.
func NewAccountRouter(ctx context.Context, config relay.Config) (*relay.Router, error) {
	accounts := &accountService{}
	config.Authenticate = accounts.authenticate
	config.Roles = cloudRoles()
	config.MachinePermissions = machinePermissions
	config.UserRoles = desktopUserRoles()
	router, err := relay.New(ctx, config)
	if err != nil {
		return nil, err
	}
	accounts.session = router.Session()
	return router, nil
}

// AuthenticateAccount exposes the production authentication adapter to tests.
func AuthenticateAccount(session *xconn.Session, request auth.Request) (auth.Response, error) {
	accounts := &accountService{session: session}
	return accounts.authenticate(request)
}

// NewAccountAuthenticator is the production authentication adapter, keeping its state
// across requests as the Hub does.
func NewAccountAuthenticator(session *xconn.Session) func(auth.Request) (auth.Response, error) {
	accounts := &accountService{session: session}
	return accounts.authenticate
}

// LoginThrottle limits password logins, on now's clock.
type LoginThrottle struct{ throttle loginThrottle }

func NewLoginThrottle(now func() time.Time) *LoginThrottle {
	return &LoginThrottle{throttle: loginThrottle{now: now}}
}

func (l *LoginThrottle) Admit(authID string) error { return l.throttle.admit(authID) }

// Tracked reports how many accounts the throttle is counting attempts for.
func (l *LoginThrottle) Tracked() int { return len(l.throttle.account.counts) }

var (
	ErrTooManyLoginAttempts = errTooManyLoginAttempts
	MaxTrackedAccounts      = maxTrackedAccounts
)
