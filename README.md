[![GoDoc](https://godoc.org/github.com/LdDl/grpc-jwt?status.svg)](https://godoc.org/github.com/LdDl/grpc-jwt)
[![Build Status](https://travis-ci.com/LdDl/grpc-jwt.svg?branch=master)](https://travis-ci.com/LdDl/grpc-jwt)
[![Sourcegraph](https://sourcegraph.com/github.com/LdDl/grpc-jwt/-/badge.svg)](https://sourcegraph.com/github.com/LdDl/grpc-jwt?badge)
[![Go Report Card](https://goreportcard.com/badge/github.com/LdDl/grpc-jwt)](https://goreportcard.com/report/github.com/LdDl/grpc-jwt)
[![GitHub tag](https://img.shields.io/github/tag/LdDl/grpc-jwt.svg)](https://github.com/LdDl/grpc-jwt/releases)

# grpc-jwt - JWT recipe for gRPC-based server

### *preamble: almost all code for JWT stuff was taken from [appleyboy's](https://github.com/appleboy/gin-jwt#jwt-middleware-for-gin-framework) repository*

## Table of Contents
- [Usage](#usage)
- [Support](#support)
- [Dependencies](#dependencies)
- [License](#license)


## Usage

If you want to re-build *.pb.go files
```bash
protoc -I . *.proto --go_out=plugins=grpc:.
```
@todo

## Support
If you have troubles or questions please [open an issue](https://github.com/LdDl/grpc-jwt/issues/new).

## Dependencies
* github.com/dgrijalva/jwt-go - License is [MIT](https://github.com/dgrijalva/jwt-go/blob/master/LICENSE)
* gRPC and protobuf for doing "'client-server'" application - [grpc](https://github.com/grpc/grpc-go). License is Apache-2.0

## License
You can check it [here](https://github.com/LdDl/grpc-jwt/blob/master/LICENSE.md)
