package main

import (
	"fmt"
	"net"
	"time"

	grpcjwt "github.com/LdDl/grpc-jwt"
	jwt "github.com/dgrijalva/jwt-go"
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

// MyCustomServer Wrap ServerExampleServer
type MyCustomServer struct {
	ServerExampleServer
}

// GetHiddenData Implement GetHiddenData() to match interface of server_example.pb.go
func (server *MyCustomServer) GetHiddenData(ctx context.Context, in *NoArguments) (*HiddenData, error) {
	return &HiddenData{Message: "this is very hidden data (jwt token is required)"}, nil
}

// GetPublicData Implement GetPublicData() to match interface of server_example.pb.go
func (server *MyCustomServer) GetPublicData(ctx context.Context, in *NoArguments) (*PublicData, error) {
	return &PublicData{Message: "this is public data (jwt token is not required)"}, nil
}

// UserData Fake representation of data in database
type UserData struct {
	Name        string
	Password    string
	Description string
	Access      string
}

// Database Fake representation of database
type Database []UserData

// CheckUser Muck up function for checking users in database
func (db Database) CheckUser(login string) (UserData, error) {
	for i := range db {
		if db[i].Name == login {
			return db[i], nil
		}
	}
	return UserData{}, fmt.Errorf("No user")
}

var (
	addr = "localhost"
	port = 65012
)

func main() {
	// Init your server
	myCoolServer := MyCustomServer{}

	// Push info about methods you want to be intercepted
	/*
		Let's spell out '/main.ServerExample/GetHiddenData':
			main - name of your server implementation package
			ServerExample - name of gRPC service
			GetHiddenData - name of method
	*/
	methodsToIntercept := []string{
		"/main.ServerExample/GetHiddenData",
	}

	// Init database
	database := Database{
		UserData{
			Name:        "user",
			Password:    "pass",
			Description: "simple user",
			Access:      "Authentication",
		},
		UserData{
			Name:        "user2",
			Password:    "pass",
			Description: "simple user2",
			Access:      "Banned",
		},
	}

	// Init interceptor
	jwtInterceptor, err := grpcjwt.NewJWTInterceptor(&grpcjwt.JWTgRPC{
		Realm:            "my custom realm",
		Key:              []byte("my very secret key"),
		Timeout:          time.Hour * 7 * 24,
		MaxRefresh:       time.Hour * 7 * 24,
		IdentityKey:      "my identity key",
		SigningAlgorithm: "HS256",
		TimeFunc:         time.Now,
		PayloadFunc: func(login interface{}) map[string]interface{} {
			user, err := database.CheckUser(login.(string))
			if err != nil {
				return jwt.MapClaims{}
			}
			return jwt.MapClaims{
				"login": login.(string), // ignore type checking if you sure
				"desc":  user.Description,
			}
		},
		IdentityHandler: func(claims map[string]interface{}) interface{} {
			login, ok := claims["login"]
			if !ok {
				return nil
			}
			desc, ok := claims["desc"]
			if !ok {
				return nil
			}
			return &UserData{
				Name:        login.(string), // ignore type checking if you sure
				Description: desc.(string),  // ignore type checking if you sure
			}
		},
		Authenticator: func(login, password string) (interface{}, error) {
			user, err := database.CheckUser(login)
			if err != nil {
				return login, grpcjwt.ErrFailedAuthentication
			}
			if password == user.Password {
				if user.Access == "Authentication" {
					return login, nil
				} else {
					return login, grpcjwt.ErrForbidden
				}
			}
			return login, grpcjwt.ErrFailedAuthentication
		},
		Authorizator: func(userInfo interface{}) bool {
			user, err := database.CheckUser(userInfo.(*UserData).Name) // ignore type checking if you sure
			if err != nil {
				return false
			}
			if user.Access == "Authentication" {
				return true
			}
			return false
		},
	}, methodsToIntercept...)

	if err != nil {
		fmt.Println(err)
		return
	}

	// Init full server: your server implementation + JWT part
	fullServer := grpc.NewServer(
		grpc.UnaryInterceptor(jwtInterceptor.AuthInterceptor),
	)

	// Register your server implementation
	RegisterServerExampleServer(fullServer, &myCoolServer)

	// Do not forget to register JWT part!!!
	grpcjwt.RegisterJWTServiceServer(fullServer, jwtInterceptor)

	// Register all stuff for reflection
	reflection.Register(fullServer)

	// Init STD TCP-listener
	stdListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Starting gRPC server...")
	if err := fullServer.Serve(stdListener); err != nil {
		fmt.Println(err)
		return
	}
}
