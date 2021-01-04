/**
 * Copyright (c) 2021 Maciej Tarnowski
 *
 * Permission is hereby granted, free of charge,
 * to any person obtaining a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies
 * or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
 * FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

// Package csrf generates and validates HMAC Based CSRF Tokens
package csrf

import (
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

var (
	TokenTimestampSeparator = "."
)

// GenerateToken generates HMAC Based CSRF Token.
// sessionId should be unique for every user and operation, e.g. sha256(userId + operationName), but it depends on the use-case.
// expireAt is the date when the token expires, ideally this should be not too far in the future - an hour or 2 should be just right.
// secret is what makes the tokens secure - it is known only to the server, so only the server can generate tokens.
func GenerateToken(sessionId string, expireAt time.Time, secret string) string {
	ts := strconv.FormatInt(expireAt.Unix(), 10)
	contents := tokenContents(sessionId, ts)

	var tsb strings.Builder
	tsb.WriteString(hmacToken(contents, secret))
	tsb.WriteString(TokenTimestampSeparator)
	tsb.WriteString(ts)

	return tsb.String()
}

// ValidateToken checks if the HMAC Based CSRF Token is valid for the session and has not expired.
// Token is compared using subtle.ConstantTimeCompare to mitigate timing attacks.
func ValidateToken(token, sessionId string, now time.Time, secret string) bool {
	parts := strings.Split(token, TokenTimestampSeparator)
	if len(parts) != 2 {
		return false
	}
	hash := parts[0]
	expireAt := parts[1]

	expireAtInt, err := strconv.ParseInt(expireAt, 10, 64)
	if err != nil {
		return false
	}
	// expiration is in the past (before now)
	if time.Unix(expireAtInt, 0).Before(now) {
		return false
	}

	hashSample := hmacToken(tokenContents(sessionId, expireAt), secret)

	return subtle.ConstantTimeCompare([]byte(hash), []byte(hashSample)) == 1
}

func tokenContents(sessionId, expireAtUnix string) string {
	var csb strings.Builder

	csb.WriteString(sessionId)
	csb.WriteString("|")
	csb.WriteString(expireAtUnix)

	return csb.String()
}

func hmacToken(contents, secret string) string {
	hash := hmac.New(sha512.New512_224, []byte(secret))
	hash.Write([]byte(contents))
	sum := hash.Sum(nil)

	return hex.EncodeToString(sum)
}
