package main

import (
	"context"
	"fmt"
	"io"
	"time"

	grpcjwt "github.com/LdDl/grpc-jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

var (
	addr = "localhost"
	port = 65012

	correctUsername = "user"
	correctPassword = "pass"
)

func main() {
	// Connect to server
	grpcURL := fmt.Sprintf("%s:%d", addr, port)
	grpcConn, err := grpc.Dial(grpcURL, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		fmt.Printf("\t\t;Can't connect to gRPC (1): %s\n", err.Error())
		return
	}
	defer grpcConn.Close()

	// Init client for authentication purposes
	grpcAuthClient := grpcjwt.NewJWTServiceClient(grpcConn)
	loginData := grpcjwt.LoginRequest{
		Username: correctUsername,
		Password: correctPassword,
	}

	// Do login
	authResp, err := grpcAuthClient.LoginHandler(context.Background(), &loginData)
	if err != nil {
		fmt.Println(err)
		return
	}
	if authResp != nil {
		fmt.Println("auth response is", *authResp)
	} else {
		fmt.Println("auth response is nil")
	}

	// Init simple client
	grpcClient := NewServerExampleClient(grpcConn)

	// Do request for public data
	pubcliData, err := grpcClient.GetPublicData(context.Background(), &NoArguments{})
	if err != nil {
		fmt.Println(err)
		return
	}
	if pubcliData != nil {
		fmt.Println("public data is", pubcliData)
	} else {
		fmt.Println("public data is nil")
	}

	// Do UNARY request for private data.
	// Do not forget to provide token!!!
	ctx, cancel := context.WithTimeout(
		metadata.NewOutgoingContext(
			context.Background(),
			metadata.New(map[string]string{"token": authResp.Token}),
		),
		1*time.Second,
	)
	defer cancel()
	privateData, err := grpcClient.GetHiddenData(ctx, &NoArguments{})
	if err != nil {
		fmt.Println(err)
		return
	}
	if privateData != nil {
		fmt.Println("private data is", privateData)
	} else {
		fmt.Println("private data is nil")
	}

	// Try to refresh token
	ctx, cancel = context.WithTimeout(
		metadata.NewOutgoingContext(
			context.Background(),
			metadata.New(map[string]string{"token": authResp.Token}),
		),
		1*time.Second,
	)
	defer cancel()
	refreshTokenResp, err := grpcAuthClient.RefreshToken(ctx, &grpcjwt.NoArguments{})
	if err != nil {
		fmt.Println(err)
		return
	}
	if refreshTokenResp != nil {
		fmt.Println("refresh token response is", *refreshTokenResp)
	} else {
		fmt.Println("refresh token response is nil")
	}

	// Do STREAM request for private data.
	// Do not forget to provide token!!!
	ctxStream, cancelStream := context.WithTimeout(
		metadata.NewOutgoingContext(
			context.Background(),
			metadata.New(map[string]string{"token": authResp.Token}),
		),
		10*time.Second,
	)
	defer cancelStream()
	privateStreamData, err := grpcClient.GetHiddenStreamData(ctxStream, &NoArguments{})
	if err != nil {
		fmt.Println(err)
		return
	}
	done := make(chan bool)
	go func() {
		for {
			serverResp, err := privateStreamData.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				fmt.Println(err)
				break
			}
			if serverResp == nil {
				fmt.Println("Nil data")
				return
			}
			fmt.Printf("Message from server: %v\n", serverResp.Message)
		}
	}()
	<-done
}
