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

package csrf

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidTokenFlow(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret)

	if !ValidateToken(token, sessionId, now, secret) {
		t.Errorf("token validation failed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}

	if !ValidateToken(token, sessionId, now.Add(4*time.Minute), secret) {
		t.Errorf("token validation failed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func TestExpiredTokenIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(-5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret)

	if ValidateToken(token, sessionId, now, secret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func replaceTimestampInToken(token, newTs string) string {
	parts := strings.Split(token, TokenTimestampSeparator)
	if len(parts) != 2 {
		panic(fmt.Errorf("source token invalid"))
	}
	hash := parts[0]

	return hash + "." + newTs
}

func TestTokenWithChangedTimestampIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(-5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret)

	tamperedToken := replaceTimestampInToken(token, strconv.FormatInt(now.Add(5*time.Minute).Unix(), 10))

	if ValidateToken(tamperedToken, sessionId, now, secret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func TestTokenWithDifferentSessionIdIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret)

	otherSessionId := "user2-login"

	if ValidateToken(token, otherSessionId, now, secret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func TestTokenWithDifferentSecretIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret)

	otherSecret := "LoremIpsum1234"

	if ValidateToken(token, sessionId, now, otherSecret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func TestTokenWithInvalidTimestampIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(-5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret)

	tamperedToken := replaceTimestampInToken(token, "loremipsum")

	if ValidateToken(tamperedToken, sessionId, now, secret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func TestTokenWithMoreThanTwoPartsIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(5 * time.Minute)

	token := GenerateToken(sessionId, expireAt, secret) + ".loremipsum"

	if ValidateToken(token, sessionId, now, secret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}

func TestTokenWithOnePartIsInvalid(t *testing.T) {
	sessionId := "user1-login"
	secret := "LoremIpsum123"
	now := time.Now()
	expireAt := now.Add(5 * time.Minute)

	token := strings.Split(GenerateToken(sessionId, expireAt, secret), TokenTimestampSeparator)[0]

	if ValidateToken(token, sessionId, now, secret) {
		t.Errorf("token validation was expected to fail, but passed: token=%s, sessionId=%s, expireAt=%s, secret=%s, now=%s", token, sessionId, expireAt, secret, now)
	}
}
