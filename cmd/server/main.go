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

// UserData Representation of data in database
type UserData struct {
	Login  string
	RoleID string
	ID     string
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
			if login == "admin" {
				return jwt.MapClaims{
					"login": login.(string),
					"role":  "role_info",
					"id":    "user's ID",
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(claims map[string]interface{}) interface{} {
			return &UserData{
				Login:  claims["login"].(string),
				RoleID: claims["role"].(string),
				ID:     claims["id"].(string),
			}
		},
		Authenticator: func(login, password string) (interface{}, error) {
			if login == "admin" && password == "strong_password" {
				return login, nil
			} else {
				return login, grpcjwt.ErrFailedAuthentication
			}
		},
		Authorizator: func(userInfo interface{}) bool {
			userInfoStruct := userInfo.(*UserData)
			if userInfoStruct.Login == "admin" {
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
