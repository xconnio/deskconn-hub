package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"os/signal"

	"github.com/joho/godotenv"
	log "github.com/sirupsen/logrus"

	"github.com/xconnio/deskconn/relay"
)

// The Deskconn cloud router with the account service as its backend. To run it with your
// own accounts, build a main like this one with your own relay.Config callbacks.
func main() {
	_ = godotenv.Load()

	databaseURL, ok := os.LookupEnv("DESKCONN_POSTGRES_URL")
	if !ok || databaseURL == "" {
		log.Fatalln("DESKCONN_POSTGRES_URL not set")
	}

	tlsConfig, err := loadTLSConfig()
	if err != nil {
		log.Fatalf("failed to load TLS config: %v", err)
	}

	accounts := &accountService{}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	r, err := relay.New(ctx, relay.Config{
		Authenticate:        accounts.authenticate,
		Machines:            machinesFromDatabase(databaseURL),
		Roles:               cloudRoles(),
		MachinePermissions:  machinePermissions,
		UserRoles:           desktopUserRoles(),
		RawSocketAddress:    envOr("DESKCONN_ROUTER_RAWSOCKET_ADDRESS", "0.0.0.0:8084"),
		QUICAddress:         envOr("DESKCONN_ROUTER_QUIC_ADDRESS", "0.0.0.0:8081"),
		WebTransportAddress: envOr("DESKCONN_ROUTER_WT_ADDRESS", "[::]:8082"),
		CertHashAddress:     envOr("DESKCONN_ROUTER_WT_HASH_ADDRESS", "localhost:8083"),
		TLSConfig:           tlsConfig,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer r.Close()
	// The account service registers its procedures on the router's own realm.
	accounts.session = r.Session()

	if err := r.Serve(ctx); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// loadTLSConfig loads the QUIC and WebTransport certificate, or returns nil for self-signed
// ones; browsers then trust WebTransport's through its fingerprint (see CertHashAddress).
func loadTLSConfig() (*tls.Config, error) {
	certFile := os.Getenv("DESKCONN_ROUTER_QUIC_TLS_CERT")
	keyFile := os.Getenv("DESKCONN_ROUTER_QUIC_TLS_KEY")
	if certFile == "" || keyFile == "" {
		log.Warn("DESKCONN_ROUTER_QUIC_TLS_CERT/KEY not set, using self-signed certificates")
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair: %w", err)
	}
	log.Infof("using the certificate in %s", certFile)
	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
