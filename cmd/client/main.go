package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/islishude/grpc-mtls-example/greet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	tlsConfig, err := LoadTLSConfig("./certs/client.a.crt", "./certs/client.a.key", "./certs/ca.crt")
	if err != nil {
		panic(err)
	}

	conn, err := grpc.Dial("localhost:6443", grpc.WithTransportCredentials(tlsConfig))
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	client := greet.NewGreetingClient(conn)

	var name = "world"
	if len(os.Args) > 1 {
		name = os.Args[1]
	}

	go waitForShutdown()

	for {
		resp, err := client.SayHello(context.Background(), &greet.SayHelloRequest{Name: name})
		if err != nil {
			panic(err)
		}

		fmt.Println(resp.GetGreet())

		time.Sleep(5 * time.Second)

	}
}

func waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	fmt.Println("Shutting down server...")

	// Perform cleanup and shutdown tasks here

	os.Exit(0)
}

func LoadTLSConfig(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certification: %w", err)
	}

	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("faild to read CA certificate: %w", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("faild to append the CA certificate to CA pool")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
		RootCAs:      capool,
	}

	return credentials.NewTLS(tlsConfig), nil
}
