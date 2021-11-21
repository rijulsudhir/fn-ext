package tokenvalidator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/rijulsudhir/fn-1/api/server"
	"github.com/rijulsudhir/fn-1/fnext"

	jwt "github.com/dgrijalva/jwt-go"
)

type contextKey string

const (
	EnvSecret = "JWT_KEY"
)

var (
	claimsKey = contextKey("claims")
)

func init() {
	server.RegisterExtension(&tokenvalidatorExt{})
}

type tokenvalidatorExt struct {
}

func (e *tokenvalidatorExt) Name() string {
	return "github.com/rijulsudhir/fn-ext/tokenvalidator"
}

func (e *tokenvalidatorExt) Setup(s fnext.ExtServer) error {
	s.AddAppMiddleware(&tokenvalidatorMiddleware{})
	return nil
}

type tokenvalidatorMiddleware struct{}

func (h *tokenvalidatorMiddleware) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secretKey := os.Getenv(EnvSecret)

		if len(secretKey) == 0 {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()

		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader == "" {
			server.WriteError(ctx, w, http.StatusUnauthorized, errors.New("No Authorization header, access denied"))
			return
		}

		ahSplit := strings.Split(authorizationHeader, " ")
		if len(ahSplit) != 2 {
			server.WriteError(ctx, w, http.StatusUnauthorized, errors.New("Invalid authorization header, access denied"))
			return
		}
		token, err := jwt.Parse(ahSplit[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv(EnvSecret)), nil
		})
		if err != nil {
			server.WriteError(ctx, w, http.StatusUnauthorized, err)
			return
		}
		if !token.Valid {
			server.WriteError(ctx, w, http.StatusUnauthorized, errors.New("Invalid authorization token, access denied"))
			return
		}
		var claims jwt.MapClaims
		var ok bool
		if claims, ok = token.Claims.(jwt.MapClaims); !ok {
			server.WriteError(ctx, w, http.StatusUnauthorized, errors.New("Invalid authorization token, invalid claims, access denied"))
			return
		}

		ctx = context.WithValue(ctx, claimsKey, claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
