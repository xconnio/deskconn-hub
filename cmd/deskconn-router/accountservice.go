package main

import (
	"context"
	"fmt"
	"os"

	"github.com/xconnio/deskconn/relay"
	"github.com/xconnio/xconn-core/bindings/go"
	"github.com/xconnio/xconn-core/bindings/go/auth"
)

// The account service backend: it keeps the accounts and machines, and the router asks it
// who may join.

const (
	procedureCRAVerify        = "io.xconn.deskconn.account.cra.verify"
	procedureCryptosignVerify = "io.xconn.deskconn.account.cryptosign.verify"
	procedureCoturnCreate     = "io.xconn.deskconn.coturn.credentials.create"

	accountServiceAuthRole         = "xconnio:deskconn:cloud:service:account"
	accountServiceAuthID           = "deskconn-account-service"
	defaultAccountServicePublicKey = "c98fb454dfda50be26b74818d3c20caf6810970b9de4a01fe5cd6282603400f1"

	webAppAuthRole  = "xconnio:deskconn:app:web"
	webAppAuthID    = "deskconn-web-app"
	webAppPublicKey = "f71727af7b6fa2007d59253486a4dd24d9c18df64a1f5dfa17785530214ec781"

	mobileAppAuthRole  = "xconnio:deskconn:app:mobile"
	mobileAppAuthID    = "deskconn-mobile-app"
	mobileAppPublicKey = "c318732cd9dadb040ce79dc2559bfb7d7de8187d10d14b62393261e6cae1c216"

	ciAuthRole  = "xconnio:deskconn:ci"
	ciAuthID    = "deskconn-ci"
	ciPublicKey = "af12b0d04d8e2e468e31115d6c7ca665ff39d7dd78455ae2e3f73f61962e16bb"

	// A user's role on the system realm (io.xconn.deskconn), by how they authenticated. On
	// a desktop realm they get one of the desktop roles below instead.
	craUserAuthRole        = "user:cra"
	cryptosignUserAuthRole = "user:cryptosign"

	// A user's role on a desktop realm, from the account service: its access role there.
	desktopOwnerAuthRole  = "user:owner"
	desktopAdminAuthRole  = "user:admin"
	desktopMemberAuthRole = "user:member"
)

// accountServicePublicKey can be overridden so local setups can use their own key pair.
func accountServicePublicKey() string {
	if key := os.Getenv("DESKCONN_ACCOUNT_SERVICE_PUBLIC_KEY"); key != "" {
		return key
	}
	return defaultAccountServicePublicKey
}

// accountService authenticates sessions by asking the account service, over session.
type accountService struct {
	session *xconn.Session
}

// machinesFromDatabase reads the attached machines from the account service's database.
func machinesFromDatabase(databaseURL string) func(context.Context) ([]relay.Machine, error) {
	return func(context.Context) ([]relay.Machine, error) {
		db, err := openDB(databaseURL)
		if err != nil {
			return nil, fmt.Errorf("error opening database: %w", err)
		}
		defer func() {
			if sqlDB, err := db.DB(); err == nil {
				_ = sqlDB.Close()
			}
		}()

		desktops, err := getDesktops(db)
		if err != nil {
			return nil, fmt.Errorf("error getting desktops from db: %w", err)
		}
		machines := make([]relay.Machine, 0, len(desktops))
		for _, desktop := range desktops {
			machines = append(machines, relay.Machine{AuthID: desktop.AuthID, Realm: desktop.Realm})
		}
		return machines, nil
	}
}

func (a *accountService) authenticate(request auth.Request) (auth.Response, error) {
	switch request.AuthMethod() {
	case auth.MethodCRA:
		callResp := a.session.Call(procedureCRAVerify).Args(request.AuthID(), request.Realm()).Execute()
		if callResp.Err != nil {
			return nil, callResp.Err
		}

		dict, err := callResp.ArgDict(0)
		if err != nil {
			return nil, err
		}

		authrole, err := dict.String("authrole")
		if err != nil {
			return nil, fmt.Errorf("failed to get authrole for user(%s): %w", request.AuthID(), err)
		}
		secret, err := dict.String("password")
		if err != nil {
			return nil, fmt.Errorf("failed to get secret for user(%s): %w", request.AuthID(), err)
		}
		salt, err := dict.String("salt")
		if err != nil {
			return nil, fmt.Errorf("failed to get salt for user(%s): %w", request.AuthID(), err)
		}
		iteration := dict.Int64Or("iteration", 1000)
		keyLength := dict.Int64Or("key_length", 32)
		return auth.NewCRAResponseSalted(request.AuthID(), authrole, secret, salt, int(iteration), int(keyLength), 0), nil

	case auth.MethodCryptoSign:
		cryptosignRequest, ok := request.(*auth.RequestCryptoSign)
		if !ok {
			return nil, fmt.Errorf("invalid request")
		}
		if cryptosignRequest.AuthID() == accountServiceAuthID {
			if cryptosignRequest.PublicKey() == accountServicePublicKey() {
				return auth.NewResponse(cryptosignRequest.AuthID(), accountServiceAuthRole, 0)
			}

			return nil, fmt.Errorf("invalid private key for account service")
		}

		if cryptosignRequest.PublicKey() == webAppPublicKey && cryptosignRequest.AuthID() == webAppAuthID {
			return auth.NewResponse(cryptosignRequest.AuthID(), webAppAuthRole, 0)
		}

		if cryptosignRequest.PublicKey() == mobileAppPublicKey && cryptosignRequest.AuthID() == mobileAppAuthID {
			return auth.NewResponse(cryptosignRequest.AuthID(), mobileAppAuthRole, 0)
		}

		if cryptosignRequest.PublicKey() == ciPublicKey && cryptosignRequest.AuthID() == ciAuthID {
			return auth.NewResponse(cryptosignRequest.AuthID(), ciAuthRole, 0)
		}

		callResp := a.session.Call(procedureCryptosignVerify).Args(request.AuthID(), cryptosignRequest.PublicKey(),
			request.Realm()).Execute()
		if callResp.Err != nil {
			return nil, callResp.Err
		}

		dict, err := callResp.ArgDict(0)
		if err != nil {
			return nil, err
		}

		authid, err := dict.String("authid")
		if err != nil {
			return nil, fmt.Errorf("failed to get authid for user(%s): %w", request.AuthID(), err)
		}

		authrole, err := dict.String("authrole")
		if err != nil {
			return nil, fmt.Errorf("failed to get authrole for user(%s): %w", request.AuthID(), err)
		}

		return auth.NewResponse(authid, authrole, 0)

	default:
		return nil, fmt.Errorf("unsupported authentication method: %v", request.AuthMethod())
	}
}

func webAppPermissions() []xconn.Permission {
	return []xconn.Permission{
		{URI: "io.xconn.deskconn.account.create", MatchPolicy: relay.MatchExact, AllowCall: true},
		{URI: "io.xconn.deskconn.account.verify", MatchPolicy: relay.MatchExact, AllowCall: true},
		{URI: "io.xconn.deskconn.account.otp.resend", MatchPolicy: relay.MatchExact, AllowCall: true},
		{URI: "io.xconn.deskconn.account.password.forget", MatchPolicy: relay.MatchExact, AllowCall: true},
		{URI: "io.xconn.deskconn.account.password.reset", MatchPolicy: relay.MatchExact, AllowCall: true},
	}
}

// cloudRoles are the cloud realm's roles for the account service, its apps and its users.
func cloudRoles() []xconn.RealmRole {
	return []xconn.RealmRole{
		{
			Name: accountServiceAuthRole,
			Permissions: []xconn.Permission{
				{URI: "io.xconn.deskconn.", MatchPolicy: relay.MatchPrefix, AllowRegister: true},
				{URI: relay.ProcedureAddRealm, MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: relay.ProcedureRemoveRealm, MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.*.key.add", MatchPolicy: relay.MatchWildcard, AllowPublish: true},
				{URI: "io.xconn.deskconn.desktop.*.key.remove", MatchPolicy: relay.MatchWildcard, AllowPublish: true},
				{URI: "io.xconn.deskconn.desktop.*.detach", MatchPolicy: relay.MatchWildcard, AllowPublish: true},
				{URI: "wamp.session.kill_by_authid", MatchPolicy: relay.MatchExact, AllowCall: true},
			},
		},
		{Name: webAppAuthRole, Permissions: webAppPermissions()},
		{Name: mobileAppAuthRole, Permissions: webAppPermissions()},
		{
			Name: ciAuthRole,
			Permissions: []xconn.Permission{
				{URI: "io.xconn.deskconn.app.update", MatchPolicy: relay.MatchExact, AllowCall: true},
			},
		},
		{
			Name: cryptosignUserAuthRole,
			Permissions: []xconn.Permission{
				{URI: "io.xconn.webrtc.", MatchPolicy: relay.MatchPrefix, AllowCall: true, AllowRegister: true,
					AllowSubscribe: true, AllowPublish: true},
				{URI: "io.xconn.deskconn.organization.", MatchPolicy: relay.MatchPrefix, AllowCall: true},
				{URI: "io.xconn.deskconn.account.get", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.account.principal.", MatchPolicy: relay.MatchPrefix, AllowCall: true},
				{URI: "io.xconn.deskconn.account.update", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.account.delete", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.list", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.update", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.access", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.access.", MatchPolicy: relay.MatchPrefix, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.invitation.", MatchPolicy: relay.MatchPrefix, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.detach", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.device.", MatchPolicy: relay.MatchPrefix, AllowCall: true},
				{URI: "io.xconn.deskconn.app.", MatchPolicy: relay.MatchPrefix, AllowCall: true},
				{URI: procedureCoturnCreate, MatchPolicy: relay.MatchExact, AllowCall: true},
			},
		},
		{
			Name: craUserAuthRole,
			Permissions: []xconn.Permission{
				{URI: "io.xconn.deskconn.account.login", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.account.login.verify", MatchPolicy: relay.MatchExact, AllowCall: true},
				{URI: "io.xconn.deskconn.desktop.attach", MatchPolicy: relay.MatchExact, AllowCall: true},
			},
		},
	}
}

// desktopUserRoles are a desktop realm's user roles: owners and admins may also call the
// procedures under relay.AdminPrefix.
func desktopUserRoles() []xconn.RealmRole {
	managerPermissions := append(relay.MachineUserPermissions(),
		xconn.Permission{URI: relay.AdminPrefix, MatchPolicy: relay.MatchPrefix, AllowCall: true})
	return []xconn.RealmRole{
		{Name: desktopOwnerAuthRole, Permissions: managerPermissions},
		{Name: desktopAdminAuthRole, Permissions: managerPermissions},
		{Name: desktopMemberAuthRole, Permissions: relay.MachineUserPermissions()},
	}
}

// machinePermissions is what machine authid's daemon may do on the cloud realm: follow
// its access keys and being detached, and get TURN credentials.
func machinePermissions(authid string) []xconn.Permission {
	return []xconn.Permission{
		{URI: "io.xconn.deskconn.desktop.access.key.list", MatchPolicy: relay.MatchExact, AllowCall: true},
		{URI: fmt.Sprintf("io.xconn.deskconn.desktop.%s.key.add", authid), MatchPolicy: relay.MatchExact,
			AllowSubscribe: true},
		{URI: fmt.Sprintf("io.xconn.deskconn.desktop.%s.key.remove", authid), MatchPolicy: relay.MatchExact,
			AllowSubscribe: true},
		{URI: fmt.Sprintf("io.xconn.deskconn.desktop.%s.detach", authid), MatchPolicy: relay.MatchExact,
			AllowSubscribe: true},
		{URI: procedureCoturnCreate, MatchPolicy: relay.MatchExact, AllowCall: true},
	}
}
