# DeskConn Hub

The DeskConn Hub connects services and devices through XConn. The Go module,
command and deployment image still use the `deskconn-router` name.

## Setup

1. Clone the project

```bash
git clone git@github.com:xconnio/deskconn-router.git
cd deskconn-router
```

2. Configure environment variables
   Create or edit the .env file with appropriate values:

```bash
DESKCONN_POSTGRES_HOST=localhost
DESKCONN_POSTGRES_URL=postgres://router:random@${DESKCONN_POSTGRES_HOST}:5432/deskconn_account_service?sslmode=disable&search_path=deskconn
DESKCONN_ROUTER_RAWSOCKET_ADDRESS=127.0.0.1:8084
DESKCONN_ROUTER_QUIC_ADDRESS=127.0.0.1:8081
DESKCONN_ROUTER_WT_ADDRESS=127.0.0.1:8082
```

> **Note:** `DESKCONN_POSTGRES_URL` must point to the same Postgres database used by
> the [account service](https://github.com/xconnio/deskconn-account-service).
>
> When running `make run-docker`, the router joins the `deskconn` Docker network created by the
> account service (start it first) and should use
> `DESKCONN_POSTGRES_HOST=deskconn-account-service-postgres` in `.env`.

## Build

Install Go 1.26, a C compiler, pkg-config and the matching XConn native SDK.
A Rust toolchain is not needed to build the application from published releases:

```sh
make native-sdk
make build
make test
```

`make build-static` produces a standalone Linux executable. The Docker build
uses the target platform's compiler and glibc SDK, with emulation for ARM64 on
an amd64 CI runner. The final scratch image contains the binary and CA roots.
Alpine/musl and `CGO_ENABLED=0` builds do not support the native binding.

### RPC stream migration

The Go binding and native SDK use published XConn 0.1.6 artifacts. The DeskConn
module is pinned to its migrated, pushed commit, so ordinary `make build` and
`make test` need no sibling source checkout or Go workspace.

The integration test uses the production account-authentication adapter and
permission rules with a local account RPC fixture. It covers salted WAMP-CRA,
CryptoSign, routed calls, RPC streams, cross-realm isolation,
backend replacement and shutdown without production credentials or Postgres.
It also exercises RPC-associated uploads, downloads and bidirectional streams
through WebTransport → Hub → QUIC device bridge → local yamux application, both
before and after the device reconnects. The local fixture uses a Unix socket
(TCP on Windows).

The Hub needs no additional forwarding loop or stream permissions: XConn routes
RPC stream references to the caller and callee selected by the existing WAMP
permissions. The published 0.1.6 SDK includes RPC stream bridge support. The header-based raw-stream protocol is removed; DeskConn applications
and clients must use RPC-associated streams for routed byte transfers.

## Run

```bash
make run
```

## Using your own backend

The router itself lives in the `relay` package of [deskconn](https://github.com/xconnio/deskconn)
and doesn't depend on the account service. What depends on the deployment is left to callbacks
in `relay.Config`:

| Field                | What you decide                                                                  |
|----------------------|----------------------------------------------------------------------------------|
| `Authenticate`       | Who may join, as which authid and role (required)                                |
| `Machines`           | The machines to serve at startup                                                 |
| `Roles`              | The cloud realm's roles and permissions                                          |
| `MachinePermissions` | What a machine's daemon may do on the cloud realm                                |
| `UserRoles`          | Users' roles in a machine's realm and what each may do there; RPC streams follow those permissions |

Machines can also be added and removed at runtime with `Router.AddMachine` and `Router.RemoveMachine`, or by
calling `io.xconn.deskconn.realm.add` / `io.xconn.deskconn.realm.remove` (realm, authid) with a role allowed to.

`cmd/deskconn-router` plugs in the account service; a minimal router with its own logic looks like this:

```go
r, err := relay.New(ctx, relay.Config{
	Machines: func(ctx context.Context) ([]relay.Machine, error) {
		return []relay.Machine{{AuthID: "office-pc", Realm: "office-pc-realm"}}, nil
	},
	Authenticate: func(request auth.Request) (auth.Response, error) {
		// Look the key up wherever you keep them.
		if request.AuthID() == "office-pc" {
			return auth.NewResponse("office-pc", relay.MachineAuthRole("office-pc"), 0)
		}
		return auth.NewResponse(request.AuthID(), "user", 0)
	},
	UserRoles:   []xconn.RealmRole{{Name: "user", Permissions: relay.MachineUserPermissions()}},
	QUICAddress: "0.0.0.0:8081",
})
if err != nil {
	log.Fatal(err)
}
log.Fatal(r.Serve(ctx))
```

The example admits anyone as a user; a real `Authenticate` checks the CryptoSign public key
(`request.(*auth.RequestCryptoSign).PublicKey()`) or answers WAMP-CRA with the user's secret.
