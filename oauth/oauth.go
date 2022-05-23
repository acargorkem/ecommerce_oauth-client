package oauth

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/acargorkem/ecommerce_utils-go/rest_errors"
	resty "github.com/go-resty/resty/v2"
)

const (
	baseUrl = "http://localhost:8080"

	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"

	getAccessTokenInternalErrorMessage = "error when trying to get access token"
)

var (
	oauthRestClient = resty.New().
		SetBaseURL(baseUrl).SetTimeout(200 * time.Millisecond)
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {

		return 0
	}

	return clientId
}

func clearRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func AuthenticateRequest(request *http.Request) *rest_errors.RestErr {
	if request == nil {
		return nil
	}

	clearRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))

	return nil
}

func getAccessToken(accessTokenId string) (*accessToken, *rest_errors.RestErr) {
	var at accessToken
	var restErr rest_errors.RestErr
	response, err := oauthRestClient.R().
		SetPathParam("access_token_id", accessTokenId).
		SetResult(&at).
		SetError(&restErr).
		Get("/oauth/access_token")
	if err != nil {
		return nil, rest_errors.NewInternalServerError(getAccessTokenInternalErrorMessage, rest_errors.NewError("rest_client_error"))
	}
	if response.IsError() {
		return nil, &restErr
	}
	return &at, nil
}
