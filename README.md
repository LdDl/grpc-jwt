[![GoDoc](https://godoc.org/github.com/LdDl/grpc-jwt?status.svg)](https://godoc.org/github.com/LdDl/grpc-jwt)
[![Build Status](https://travis-ci.com/LdDl/grpc-jwt.svg?branch=master)](https://travis-ci.com/LdDl/grpc-jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/LdDl/grpc-jwt/-/badge.svg)](https://sourcegraph.com/github.com/LdDl/grpc-jwt?badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/LdDl/grpc-jwt)](https://goreportcard.com/report/github.com/LdDl/grpc-jwt)
[![GitHub tag](https://img.shields.io/github/tag/LdDl/grpc-jwt.svg)](https://github.com/LdDl/grpc-jwt/releases)

# grpc-jwt - JWT recipe for gRPC-based server

### *preamble: almost all code for JWT stuff was taken from [appleyboy's](https://github.com/appleboy/gin-jwt#jwt-middleware-for-gin-framework) repository*

## Table of Contents
- [Usage](#usage)
    - [Server](#server-example)
    - [Client](#client-example)
- [Support](#support)
- [Dependencies](#dependencies)
- [License](#license)


## **Usage**

If you are planning to use private/public keys, you should generate it first. There is example of generting RS512 keys below:
```shell
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS512.key
openssl rsa -in jwtRS512.key -pubout -outform PEM -out jwtRS512.key.pub
```

If you want to re-build *.pb.go files
```bash
protoc -I . *.proto --go_out=plugins=grpc:.
```

### **Server example**

Whole example for server-side is [here](cmd/server/main.go)

Here is a little explanation about main stuff:

* Determine what services you want to intercept for JWT validation:
    ```go
    // ...
    // Let's spell out '/main.ServerExample/GetHiddenData':
    // main - name of your server implementation package
    // ServerExample - name of gRPC service
    // GetHiddenData - name of method
    methodsToIntercept := []string{
        "/main.ServerExample/GetHiddenData",
    }
    // ...
    ```

* Initialize JWT interceptor
    ```go
    // ...
    jwtInterceptor, err := grpcjwt.NewJWTInterceptor(&grpcjwt.JWTgRPC{
        Realm:            "Provide realm name",
        Key:              []byte("Provide secret key"),
        Timeout:          time.Hour * 7 * 24,
        MaxRefresh:       time.Hour * 7 * 24,
        IdentityKey:      "Provide identity key",
        SigningAlgorithm: "HS256", // You can pick RS512 and provide PrivKeyFile, PubKeyFile fields
        TimeFunc:         time.Now,
        PayloadFunc: func(login interface{}) map[string]interface{} {
            // Describe logic to handle payloading
        },
        IdentityHandler: func(claims map[string]interface{}) interface{} {
            // Describe logic to make indentity work
        },
        Authenticator: func(login, password string) (interface{}, error) {
            // Describe logic to handle authentication
        },
        Authorizator: func(userInfo interface{}) bool {
        // Describe logic to handle authorization
        },
    }, methodsToIntercept...) // <=-- Do not forget to provide desired methods to be intercepted with JWT validation
    // ...
    ```

* Initialize gRPC server and register JWT
    ```go
    //...
    fullServer := grpc.NewServer(
        grpc.UnaryInterceptor(jwtInterceptor.AuthInterceptor),
    )
    //...
    grpcjwt.RegisterJWTServiceServer(fullServer, jwtInterceptor)
    //...
    ```

### **Client example**

Whole example for client-side is [here](cmd/client/main.go)
    
## **Support**

If you have troubles or questions please [open an issue](https://github.com/LdDl/grpc-jwt/issues/new).
PRs are welcome!

## **Dependencies**

* github.com/dgrijalva/jwt-go - License is [MIT](https://github.com/dgrijalva/jwt-go/blob/master/LICENSE)
* gRPC and protobuf for doing "'client-server'" application - [grpc](https://github.com/grpc/grpc-go). License is Apache-2.0

## **License**

You can check it [here](https://github.com/LdDl/grpc-jwt/blob/master/LICENSE.md)
