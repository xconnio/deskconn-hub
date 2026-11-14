package main

import (
	"context"

	"github.com/xconnio/deskconn-router/internal/relay"
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
