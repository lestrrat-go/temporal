// The MIT License
//
// Copyright (c) 2020 Temporal Technologies Inc.  All rights reserved.
//
// Copyright (c) 2020 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package authorization

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"go.temporal.io/api/serviceerror"

	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
)

const (
	defaultPermissionsClaimName = "permissions"
	authorizationBearer         = "bearer"
	headerSubject               = "sub"
	permissionScopeSystem       = "system"
	permissionRead              = "read"
	permissionWrite             = "write"
	permissionWorker            = "worker"
	permissionAdmin             = "admin"
)

// Default claim mapper that gives system level admin permission to everybody
type defaultJWTClaimMapper struct {
	keyProvider          TokenKeyProvider
	logger               log.Logger
	permissionsClaimName string
}

func NewDefaultJWTClaimMapper(provider TokenKeyProvider, cfg *config.Authorization, logger log.Logger) ClaimMapper {
	claimName := cfg.PermissionsClaimName
	if claimName == "" {
		claimName = defaultPermissionsClaimName
	}
	return &defaultJWTClaimMapper{keyProvider: provider, logger: logger, permissionsClaimName: claimName}
}

var _ ClaimMapper = (*defaultJWTClaimMapper)(nil)

func (a *defaultJWTClaimMapper) GetClaims(authInfo *AuthInfo) (*Claims, error) {

	claims := Claims{}

	if authInfo.AuthToken == "" {
		return &claims, nil
	}

	parts := strings.Split(authInfo.AuthToken, " ")
	if len(parts) != 2 {
		return nil, serviceerror.NewPermissionDenied("unexpected authorization token format", "")
	}
	if !strings.EqualFold(parts[0], authorizationBearer) {
		return nil, serviceerror.NewPermissionDenied("unexpected name in authorization token", "")
	}
	tok, err := parseJWTWithAudience(parts[1], a.keyProvider, authInfo.Audience)
	if err != nil {
		return nil, err
	}
	v, ok := tok.Get(jwt.SubjectKey)
	if !ok {
		return nil, serviceerror.NewPermissionDenied(`"sub" claim not present`, "")
	}
	subject, ok := v.(string)
	if !ok {
		return nil, serviceerror.NewPermissionDenied("unexpected value type of \"sub\" claim", "")
	}
	claims.Subject = subject
	rawPerms, ok := tok.Get(a.permissionsClaimName)
	if ok {
		permissions, ok := rawPerms.([]interface{})
		if ok {
			err := a.extractPermissions(permissions, &claims)
			if err != nil {
				return nil, err
			}
		}
	}
	return &claims, nil
}

func (a *defaultJWTClaimMapper) extractPermissions(permissions []interface{}, claims *Claims) error {
	for _, permission := range permissions {
		p, ok := permission.(string)
		if !ok {
			a.logger.Warn(fmt.Sprintf("ignoring permission that is not a string: %v", permission))
			continue
		}
		parts := strings.Split(p, ":")
		if len(parts) != 2 {
			a.logger.Warn(fmt.Sprintf("ignoring permission in unexpected format: %v", permission))
			continue
		}
		namespace := strings.ToLower(parts[0])
		if strings.EqualFold(namespace, permissionScopeSystem) {
			claims.System |= permissionToRole(parts[1])
		} else {
			if claims.Namespaces == nil {
				claims.Namespaces = make(map[string]Role)
			}
			role := claims.Namespaces[namespace]
			role |= permissionToRole(parts[1])
			claims.Namespaces[namespace] = role
		}
	}
	return nil
}

func parseJWT(tokenString string, keyProvider TokenKeyProvider) (jwt.Token, error) {
	return parseJWTWithAudience(tokenString, keyProvider, "")
}

func parseJWTWithAudience(tokenString string, keyProvider TokenKeyProvider, audience string) (jwt.Token, error) {
	msg, err := jws.Parse([]byte(tokenString))
	if err != nil {
		return nil, err
	}

	// A JWS message can contain multiple signatures, but the original code
	// based on dgrijalva/jwt-go assumed the presence of a single signature.
	// This code mimics that behavior, and might fail if the user provides
	// multiple signatures.
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, fmt.Errorf(`malformed token - no signatures`)
	}

	kid := sigs[0].ProtectedHeaders().KeyID()
	if kid == "" {
		return nil, fmt.Errorf(`malformed token - no "kid" header`)
	}

	var key interface{}

	alg := sigs[0].ProtectedHeaders().Algorithm()
	switch alg {
	case jwa.ES256, jwa.ES384, jwa.ES512:
		v, err := keyProvider.EcdsaKey(alg.String(), kid)
		if err != nil {
			return nil, err
		}
		key = v
	case jwa.HS256, jwa.HS384, jwa.HS512:
		v, err := keyProvider.HmacKey(alg.String(), kid)
		if err != nil {
			return nil, err
		}
		key = v
	case jwa.PS256, jwa.PS384, jwa.PS512, jwa.RS256, jwa.RS384, jwa.RS512:
		v, err := keyProvider.RsaKey(alg.String(), kid)
		if err != nil {
			return nil, err
		}
		key = v
	default:
		return nil, serviceerror.NewPermissionDenied(
			fmt.Sprintf("unexpected signing method: algorithm: %v", alg), "")
	}

	options := []jwt.ParseOption{jwt.WithVerify(alg, key)}
	if strings.TrimSpace(audience) != "" {
		options = append(options, jwt.WithAudience(audience), jwt.WithValidate(true))
	}
	tok, err := jwt.Parse([]byte(tokenString), options...)
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func permissionToRole(permission string) Role {
	switch strings.ToLower(permission) {
	case permissionRead:
		return RoleReader
	case permissionWrite:
		return RoleWriter
	case permissionAdmin:
		return RoleAdmin
	case permissionWorker:
		return RoleWorker
	}
	return RoleUndefined
}
