package grpcjwt

import (
	fmt "fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// JWTInterceptor Interceptor for JWT validation. Wraps JWTServiceServer structure
type JWTInterceptor struct {
	JWTServiceServer
	jwtObject          *JWTgRPC
	interceptedMethods map[string]bool
}

// NewJWTInterceptor Creates new instance of JWTInterceptor
// jwtOptions - pointer to object of type JWTgRPC
// methods - what methods do you want to intercept for JWT validation (optional)
func NewJWTInterceptor(jwtOptions *JWTgRPC, methods ...string) (*JWTInterceptor, error) {
	jwtObject, err := NewJWT(jwtOptions)
	if err != nil {
		return nil, errors.Wrap(err, "Can't init JWT engine")
	}
	interceptor := JWTInterceptor{
		jwtObject: jwtObject,
	}
	interceptor.InterceptMethods(methods...)
	return &interceptor, nil
}

// InterceptMethods Provide list of methods for interception
func (jwtService *JWTInterceptor) InterceptMethods(methods ...string) {
	if jwtService.interceptedMethods == nil {
		jwtService.interceptedMethods = make(map[string]bool)
	}
	for i := range methods {
		jwtService.interceptedMethods[methods[i]] = true
	}
}

// IgnoreMethods Delete methods from list for interception
func (jwtService *JWTInterceptor) IgnoreMethods(methods ...string) {
	if jwtService.interceptedMethods == nil {
		jwtService.interceptedMethods = make(map[string]bool)
		return
	}
	for i := range methods {
		delete(jwtService.interceptedMethods, methods[i])
	}
}

func (jwtService *JWTInterceptor) checkMethod(method string) bool {
	return jwtService.interceptedMethods[method]
}

// LoginHandler Implement LoginHandler() to match interface of JWTServiceServer in jwt.pb.go
func (jwtService *JWTInterceptor) LoginHandler(ctx context.Context, in *LoginRequest) (*LoginResponse, error) {
	if in == nil {
		return nil, fmt.Errorf("LoginRequest is nil")
	}

	middleware := jwtService.jwtObject
	data, err := middleware.Authenticator(in.Username, in.Password)
	if err != nil {
		return nil, err
	}

	token := jwt.New(jwt.GetSigningMethod(middleware.SigningAlgorithm))
	claims := token.Claims.(jwt.MapClaims)

	if middleware.PayloadFunc != nil {
		for key, value := range middleware.PayloadFunc(data) {
			claims[key] = value
		}
	}

	expire := middleware.TimeFunc().Add(middleware.Timeout)
	claims["exp"] = expire.Unix()
	claims["orig_iat"] = middleware.TimeFunc().Unix()
	tokenString, err := middleware.signedString(token)
	if err != nil {
		return nil, ErrFailedTokenCreation
	}

	return &LoginResponse{Code: 200, Token: tokenString, Expire: uint64(expire.Unix())}, nil
}

// wrappedStream wraps around the embedded grpc.ServerStream, and intercepts the RecvMsg and
// SendMsg method call.
type wrappedStream struct {
	ctx context.Context
	grpc.ServerStream
}

func (w *wrappedStream) RecvMsg(m interface{}) error {
	return w.ServerStream.RecvMsg(m)
}

func (w *wrappedStream) SendMsg(m interface{}) error {
	return w.ServerStream.SendMsg(m)
}

func newWrappedStream(s grpc.ServerStream, ctx context.Context) grpc.ServerStream {
	return &wrappedStream{ServerStream: s, ctx: ctx}
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}

// AuthInterceptor Intercept provided methods and check token
func (jwtService *JWTInterceptor) AuthStreamInterceptor(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {

	needIntercept := jwtService.checkMethod(info.FullMethod)
	if !needIntercept {
		return handler(srv, ss)
	}

	meta, ok := metadata.FromIncomingContext(ss.Context())

	if !ok {
		return status.Error(codes.Unauthenticated, ErrEmptyParamToken.Error())
	}
	if len(meta["token"]) != 1 {
		return status.Error(codes.Unauthenticated, ErrEmptyParamToken.Error())
	}

	tokenString := meta["token"][0]
	mw := jwtService.jwtObject
	claims, err := mw.GetClaimsFromJWT(tokenString)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if claims["exp"] == nil {
		return status.Error(codes.Unauthenticated, ErrMissingExpField.Error())
	}

	if _, ok := claims["exp"].(float64); !ok {
		return status.Error(codes.Unauthenticated, ErrWrongFormatOfExp.Error())
	}

	if int64(claims["exp"].(float64)) < mw.TimeFunc().Unix() {
		return status.Error(codes.Unauthenticated, ErrExpiredToken.Error())
	}

	identity := mw.IdentityHandler(claims)
	if !mw.Authorizator(identity) {
		return status.Error(codes.Unauthenticated, ErrForbidden.Error())
	}

	ctx := metadata.NewIncomingContext(ss.Context())
	newSS := newWrappedStream(ss, ctx)
	return handler(ctx, newSS)
}

// AuthInterceptor Intercept provided methods and check token
func (jwtService *JWTInterceptor) AuthInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {

	needIntercept := jwtService.checkMethod(info.FullMethod)
	if !needIntercept {
		return handler(ctx, req)
	}

	meta, ok := metadata.FromIncomingContext(ctx)

	if !ok {
		return nil, status.Error(codes.Unauthenticated, ErrEmptyParamToken.Error())
	}
	if len(meta["token"]) != 1 {
		return nil, status.Error(codes.Unauthenticated, ErrEmptyParamToken.Error())
	}

	tokenString := meta["token"][0]
	mw := jwtService.jwtObject
	claims, err := mw.GetClaimsFromJWT(tokenString)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if claims["exp"] == nil {
		return nil, status.Error(codes.Unauthenticated, ErrMissingExpField.Error())
	}

	if _, ok := claims["exp"].(float64); !ok {
		return nil, status.Error(codes.Unauthenticated, ErrWrongFormatOfExp.Error())
	}

	if int64(claims["exp"].(float64)) < mw.TimeFunc().Unix() {
		return nil, status.Error(codes.Unauthenticated, ErrExpiredToken.Error())
	}

	identity := mw.IdentityHandler(claims)
	if !mw.Authorizator(identity) {
		return nil, status.Error(codes.Unauthenticated, ErrForbidden.Error())
	}

	return handler(ctx, req)
}

// RefreshToken Implement RefreshToken() to match interface of JWTServiceServer in jwt.pb.go
func (jwtService *JWTInterceptor) RefreshToken(ctx context.Context, in *NoArguments) (*RefreshTokenResponse, error) {
	meta, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, ErrEmptyParamToken.Error())
	}
	if len(meta["token"]) != 1 {
		return nil, status.Error(codes.Unauthenticated, ErrEmptyParamToken.Error())
	}
	tokenString := meta["token"][0]
	mw := jwtService.jwtObject

	claims, err := mw.CheckIfTokenExpire(tokenString)
	if err != nil {
		return &RefreshTokenResponse{Code: 500, Token: "", Expire: uint64(time.Now().Unix())}, err
	}

	newToken := jwt.New(jwt.GetSigningMethod(mw.SigningAlgorithm))
	newClaims := newToken.Claims.(jwt.MapClaims)
	for key := range claims {
		newClaims[key] = claims[key]
	}
	expire := mw.TimeFunc().Add(mw.Timeout)
	newClaims["exp"] = expire.Unix()
	newClaims["orig_iat"] = mw.TimeFunc().Unix()
	newTokenString, err := mw.signedString(newToken)
	if err != nil {
		return &RefreshTokenResponse{Code: 500, Token: "", Expire: uint64(time.Now().Unix())}, err
	}
	return &RefreshTokenResponse{Code: 200, Token: newTokenString, Expire: uint64(expire.Unix())}, nil
}

// ParseToken provides access to private method ParseToken
func (jwtService *JWTInterceptor) ParseToken(token string) (*jwt.Token, error) {
	return jwtService.jwtObject.ParseToken(token)
}

// GetClaimsFromJWT provides access to private method GetClaimsFromJWT
func (jwtService *JWTInterceptor) GetClaimsFromJWT(token string) (map[string]interface{}, error) {
	return jwtService.jwtObject.GetClaimsFromJWT(token)
}
