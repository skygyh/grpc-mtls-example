package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/islishude/grpc-mtls-example/greet"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const ca_cert string = "ca.crt"
const server_cert string = "server.crt"
const server_key string = "server.key"

func main() {
	//tlsConfig, err := LoadTlSConfig("server.pem", "server-key.pem", "root.pem")
	//if err != nil {
	//	panic(err)
	//}

	// load CA certificate file and add it to list of client CAs
	caCertFile, err := ioutil.ReadFile(ca_cert)
	if err != nil {
		log.Fatalf("error reading CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertFile)

	//	caCertFilebk, err := ioutil.ReadFile("./certs.bk/ca.crt")
	//	if err != nil {
	//		log.Fatalf("error reading CA certificate: %v", err)
	//	}
	//	caCertPool.AppendCertsFromPEM(caCertFilebk)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs: caCertPool,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			// Always get latest localhost.crt and localhost.key
			// ex: keeping certificates file somewhere in global location where created certificates updated and this closure function can refer that
			log.Printf("tlsconfig reloading")
			caCertFile, err := ioutil.ReadFile(ca_cert)
			if err != nil {
				log.Fatalf("error reading CA certificate: %v", err)
			}
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCertFile)

			tls_config := &tls.Config{
				ClientCAs: caCertPool,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
					// Always get latest localhost.crt and localhost.key
					// ex: keeping certificates file somewhere in global location where created certificates updated and this closure function can refer that
					log.Printf("GetCertificate reloading")
					cert, err := tls.LoadX509KeyPair(server_cert, server_key)
					if err != nil {
						return nil, err
					}
					return &cert, nil
				},
				ClientAuth:               tls.RequireAndVerifyClientCert,
				MinVersion:               tls.VersionTLS12,
				CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
				PreferServerCipherSuites: true,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				},
			}

			if err != nil {
				return nil, err
			}
			return tls_config, nil
		},
		//GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		//	return &newCert, nil
		//},
		ClientAuth:               tls.RequireAndVerifyClientCert,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}

	config := credentials.NewTLS(tlsConfig)

	server := grpc.NewServer(grpc.Creds(config), grpc.UnaryInterceptor(MiddlewareHandler))

	greet.RegisterGreetingServer(server, new(GreetServer))

	basectx, casncel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer casncel()

	go func() {
		port := ":6443"

		log.Println("listen and serving on", port)

		listener, err := net.Listen("tcp", port)
		if err != nil {
			panic(err)
		}

		if err := server.Serve(listener); err != nil {
			panic(err)
		}
	}()

	<-basectx.Done()
	log.Println("bye")
	server.GracefulStop()
}

func MiddlewareHandler(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	// you can write your own code here to check client tls certificate
	if p, ok := peer.FromContext(ctx); ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			for _, item := range mtls.State.PeerCertificates {
				log.Println("client certificate subject:", item.Subject)
			}
		}
	}
	return handler(ctx, req)
}

type GreetServer struct {
	greet.UnimplementedGreetingServer
}

func (g *GreetServer) SayHello(ctx context.Context, req *greet.SayHelloRequest) (*greet.SayHelloResponse, error) {
	respdata := "Hello," + req.GetName()
	return &greet.SayHelloResponse{Greet: respdata}, nil
}

func LoadTlSConfig(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certification: %w", err)
	}

	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("faild to read CA certificate: %w", err)
	}

	capool := x509.NewCertPool()
	if !capool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("unable to append the CA certificate to CA pool")
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    capool,
	}
	return credentials.NewTLS(tlsConfig), nil
}
