package grpcjwt

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTgRPC Hold jwt-engine methods
type JWTgRPC struct {
	Realm             string
	SigningAlgorithm  string
	Key               []byte
	Timeout           time.Duration
	MaxRefresh        time.Duration
	IdentityKey       string
	TokenLookup       string
	TokenHeadName     string
	TimeFunc          func() time.Time
	PrivKeyFile       string
	PubKeyFile        string
	privKey           *rsa.PrivateKey
	pubKey            *rsa.PublicKey
	SendAuthorization bool
	DisabledAbort     bool
	PayloadFunc       func(data interface{}) map[string]interface{}
	IdentityHandler   func(claims map[string]interface{}) interface{}
	Authenticator     func(login, password string) (interface{}, error)
	Authorizator      func(userInfo interface{}) bool
}

func NewJWT(m *JWTgRPC) (*JWTgRPC, error) {
	if err := m.Init(); err != nil {
		return nil, err
	}
	return m, nil
}

func (mw *JWTgRPC) Init() error {
	if mw.TokenLookup == "" {
		mw.TokenLookup = "header:Authorization"
	}

	if mw.SigningAlgorithm == "" {
		mw.SigningAlgorithm = "HS256"
	}

	if mw.Timeout == 0 {
		mw.Timeout = time.Hour
	}

	if mw.TimeFunc == nil {
		mw.TimeFunc = time.Now
	}

	mw.TokenHeadName = strings.TrimSpace(mw.TokenHeadName)
	if len(mw.TokenHeadName) == 0 {
		mw.TokenHeadName = "Bearer"
	}

	if mw.IdentityKey == "" {
		mw.IdentityKey = "identity"
	}

	if mw.Realm == "" {
		mw.Realm = "grpc jwt"
	}

	if mw.usingPublicKeyAlgo() {
		return mw.readKeys()
	}

	if mw.Key == nil {
		return fmt.Errorf("secret key is required")
	}

	return nil
}

// CheckIfTokenExpire check if token expire
func (mw *JWTgRPC) CheckIfTokenExpire(tokenString string) (jwt.MapClaims, error) {
	token, err := mw.ParseToken(tokenString)
	if err != nil {
		validationErr, ok := err.(*jwt.ValidationError)
		if !ok || validationErr.Errors != jwt.ValidationErrorExpired {
			return nil, err
		}
	}
	claims := token.Claims.(jwt.MapClaims)
	origIat := int64(claims["orig_iat"].(float64))
	if origIat < mw.TimeFunc().Add(-mw.MaxRefresh).Unix() {
		return nil, ErrExpiredToken
	}
	return claims, nil
}

// GetClaimsFromJWT get claims from JWT token
func (mw *JWTgRPC) GetClaimsFromJWT(tokenString string) (map[string]interface{}, error) {
	token, err := mw.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}
	claims := make(map[string]interface{})
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}
	return claims, nil
}

// ExtractClaimsFromToken help to extract the JWT claims from token
func ExtractClaimsFromToken(token *jwt.Token) map[string]interface{} {
	if token == nil {
		return make(map[string]interface{})
	}
	claims := map[string]interface{}{}
	for key, value := range token.Claims.(jwt.MapClaims) {
		claims[key] = value
	}
	return claims
}

// ParseToken parse jwt token from gin context
func (mw *JWTgRPC) ParseToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		if jwt.GetSigningMethod(mw.SigningAlgorithm) != t.Method {
			return nil, ErrInvalidSigningAlgorithm
		}
		if mw.usingPublicKeyAlgo() {
			return mw.pubKey, nil
		}
		return mw.Key, nil
	})
}

func (mw *JWTgRPC) readKeys() error {
	err := mw.privateKey()
	if err != nil {
		return err
	}
	err = mw.publicKey()
	if err != nil {
		return err
	}
	return nil
}

func (mw *JWTgRPC) privateKey() error {
	keyData, err := ioutil.ReadFile(mw.PrivKeyFile)
	if err != nil {
		return ErrNoPrivKeyFile
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPrivKey
	}
	mw.privKey = key
	return nil
}

func (mw *JWTgRPC) publicKey() error {
	keyData, err := ioutil.ReadFile(mw.PubKeyFile)
	if err != nil {
		return ErrNoPubKeyFile
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		return ErrInvalidPubKey
	}
	mw.pubKey = key
	return nil
}

func (mw *JWTgRPC) usingPublicKeyAlgo() bool {
	switch mw.SigningAlgorithm {
	case "RS256", "RS512", "RS384":
		return true
	}
	return false
}

func (mw *JWTgRPC) signedString(token *jwt.Token) (string, error) {
	var tokenString string
	var err error
	if mw.usingPublicKeyAlgo() {
		tokenString, err = token.SignedString(mw.privKey)
	} else {
		tokenString, err = token.SignedString(mw.Key)
	}
	return tokenString, err
}

var (
	// ErrMissingSecretKey indicates Secret key is required
	ErrMissingSecretKey = fmt.Errorf("secret key is required")

	// ErrForbidden when HTTP status 403 is given
	ErrForbidden = fmt.Errorf("you don't have permission to access this resource")

	// ErrMissingAuthenticatorFunc indicates Authenticator is required
	ErrMissingAuthenticatorFunc = fmt.Errorf("ginJWTMiddleware.Authenticator func is undefined")

	// ErrMissingLoginValues indicates a user tried to authenticate without username or password
	ErrMissingLoginValues = fmt.Errorf("missing Username or Password")

	// ErrFailedAuthentication indicates authentication failed, could be faulty username or password
	ErrFailedAuthentication = fmt.Errorf("incorrect Username or Password")

	// ErrFailedTokenCreation indicates JWT Token failed to create, reason unknown
	ErrFailedTokenCreation = fmt.Errorf("failed to create JWT Token")

	// ErrExpiredToken indicates JWT token has expired. Can't refresh.
	ErrExpiredToken = fmt.Errorf("token is expired")

	// ErrEmptyAuthHeader can be thrown if authing with a HTTP header, the Auth header needs to be set
	ErrEmptyAuthHeader = fmt.Errorf("auth header is empty")

	// ErrMissingExpField missing exp field in token
	ErrMissingExpField = fmt.Errorf("missing exp field")

	// ErrWrongFormatOfExp field must be float64 format
	ErrWrongFormatOfExp = fmt.Errorf("exp must be float64 format")

	// ErrInvalidAuthHeader indicates auth header is invalid, could for example have the wrong Realm name
	ErrInvalidAuthHeader = fmt.Errorf("auth header is invalid")

	// ErrEmptyQueryToken can be thrown if authing with URL Query, the query token variable is empty
	ErrEmptyQueryToken = fmt.Errorf("query token is empty")

	// ErrEmptyCookieToken can be thrown if authing with a cookie, the token cookie is empty
	ErrEmptyCookieToken = fmt.Errorf("cookie token is empty")

	// ErrEmptyParamToken can be thrown if authing with parameter in path, the parameter in path is empty
	ErrEmptyParamToken = fmt.Errorf("parameter token is empty")

	// ErrInvalidSigningAlgorithm indicates signing algorithm is invalid, needs to be HS256, HS384, HS512, RS256, RS384 or RS512
	ErrInvalidSigningAlgorithm = fmt.Errorf("invalid signing algorithm")

	// ErrNoPrivKeyFile indicates that the given private key is unreadable
	ErrNoPrivKeyFile = fmt.Errorf("private key file unreadable")

	// ErrNoPubKeyFile indicates that the given public key is unreadable
	ErrNoPubKeyFile = fmt.Errorf("public key file unreadable")

	// ErrInvalidPrivKey indicates that the given private key is invalid
	ErrInvalidPrivKey = fmt.Errorf("private key invalid")

	// ErrInvalidPubKey indicates the the given public key is invalid
	ErrInvalidPubKey = fmt.Errorf("public key invalid")
)
