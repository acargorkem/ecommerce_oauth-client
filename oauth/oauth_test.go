package oauth

import (
	"net/http"
	"os"
	"testing"

	"github.com/acargorkem/ecommerce_utils-go/rest_errors"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

const (
	accessTokenId = "test"
)

var (
	fakeUrl = baseUrl + "/oauth/access_token/" + accessTokenId
)

func TestMain(m *testing.M) {
	mockClient := oauthRestClient.GetClient()
	mockClient.Transport = httpmock.DefaultTransport
	httpmock.ActivateNonDefault(mockClient)
	os.Exit(m.Run())
}

func TestOauthConstants(t *testing.T) {
	assert.Equal(t, "http://localhost:8080", baseUrl)
	assert.Equal(t, "X-Public", headerXPublic)
	assert.Equal(t, "X-Client-Id", headerXClientId)
	assert.Equal(t, "X-Caller-Id", headerXCallerId)
	assert.Equal(t, "access_token", paramAccessToken)
	assert.Equal(t, "error when trying to get access token", getAccessTokenInternalErrorMessage)
}

func TestIsPublicNilRequest(t *testing.T) {
	assert.True(t, IsPublic(nil), "should return true when nil request")
}

func TestIsPublicWithoutPublicHeader(t *testing.T) {
	request := http.Request{}
	assert.False(t, IsPublic(&request), "should return false when request without public header")
}

func TestIsPublicNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add(headerXPublic, "true")
	assert.True(t, IsPublic(&request), "should return true when request has X-Public header")
}

func TestGetCallerIdNilRequest(t *testing.T) {
	assert.Equal(t, int64(0), GetCallerId(nil), "should return 0 when nil request")
}

func TestGetCallerIdInvalidFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("random header", "123456")
	request.Header.Add(headerXCallerId, "")
	assert.Equal(t, int64(0), GetCallerId(&request), "should return 0 when invalid format")
}

func TestGetCallerIdNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add(headerXCallerId, "123456")
	assert.Equal(t, int64(123456), GetCallerId(&request), "should return caller id")
}

func TestGetClientIdNilRequest(t *testing.T) {
	assert.Equal(t, int64(0), GetClientId(nil), "should return 0 when nil request")
}

func TestGetClientIdInvalidFormat(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add("random header", "123456")
	request.Header.Add(headerXClientId, "")
	assert.Equal(t, int64(0), GetClientId(&request), "should return 0 when invalid format")
}

func TestGetClientIdNoError(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add(headerXClientId, "34567")
	assert.Equal(t, int64(34567), GetClientId(&request), "should return client id")
}

func TestClearRequestNil(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add(headerXClientId, "34567")
	clearRequest(nil)
	assert.Equal(t, int64(34567), GetClientId(&request), "should client id after invalid clean")
}

func TestClearRequest(t *testing.T) {
	request := http.Request{
		Header: make(http.Header),
	}
	request.Header.Add(headerXClientId, "123456")
	request.Header.Add(headerXCallerId, "34567")

	clearRequest(&request)

	assert.Equal(t, "", request.Header.Get(headerXClientId), "should return empty string on client id header")
	assert.Equal(t, "", request.Header.Get(headerXCallerId), "should return empty string on caller id header")
}

func TestAuthenticateRequestNilRequest(t *testing.T) {
	assert.Nil(t, AuthenticateRequest(nil), "should return nil when nil request")
}

func TestAuthentiaceRequestWithoutQueryParam(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()

	request, err := http.NewRequest("GET", baseUrl, nil)
	assert.Nil(t, err, "should not give error during creating request")

	authErr := AuthenticateRequest(request)
	assert.Nil(t, authErr, "should not give error during auth")
	assert.Equal(t, "", request.Header.Get(headerXClientId), "should return empty string on client id header")
	assert.Equal(t, "", request.Header.Get(headerXCallerId), "should return empty string on caller id header")
}

func TestAuthentiaceRequestNotFound(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()
	request, _ := http.NewRequest("GET", baseUrl, nil)

	q := request.URL.Query()
	q.Add(paramAccessToken, accessTokenId)
	request.URL.RawQuery = q.Encode()

	responseBody := rest_errors.NewNotFoundError("not found")
	responder := httpmock.NewJsonResponderOrPanic(404, responseBody)
	httpmock.RegisterResponder("GET", fakeUrl, responder)

	authErr := AuthenticateRequest(request)
	assert.Nil(t, authErr, "should not give error during auth")
	assert.Equal(t, "", request.Header.Get(headerXClientId), "should return empty string on client id header")
	assert.Equal(t, "", request.Header.Get(headerXCallerId), "should return empty string on caller id header")
}

func TestAuthentiaceRequestClientError(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()

	request, _ := http.NewRequest("GET", baseUrl, nil)

	q := request.URL.Query()
	q.Add(paramAccessToken, accessTokenId)
	request.URL.RawQuery = q.Encode()

	responseBody := rest_errors.NewBadRequestError("bad request")
	responder := httpmock.NewJsonResponderOrPanic(400, responseBody)
	httpmock.RegisterResponder("GET", fakeUrl, responder)

	authErr := AuthenticateRequest(request)
	assert.NotNil(t, authErr)
	assert.Equal(t, 400, authErr.Status)
	assert.Equal(t, "bad request", authErr.Message)
	assert.Equal(t, "", request.Header.Get(headerXClientId), "should return empty string on client id header")
	assert.Equal(t, "", request.Header.Get(headerXCallerId), "should return empty string on caller id header")
}

func TestAuthentiaceRequestSuccessful(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()

	request, _ := http.NewRequest("GET", baseUrl, nil)

	q := request.URL.Query()
	q.Add(paramAccessToken, accessTokenId)
	request.URL.RawQuery = q.Encode()

	responseBody := accessToken{
		Id:       accessTokenId,
		UserId:   234,
		ClientId: 345,
	}
	responder := httpmock.NewJsonResponderOrPanic(200, responseBody)
	httpmock.RegisterResponder("GET", fakeUrl, responder)

	authErr := AuthenticateRequest(request)
	assert.Nil(t, authErr, "should not give error during auth")
	assert.Equal(t, "345", request.Header.Get(headerXClientId), "should access client id in header")
	assert.Equal(t, "234", request.Header.Get(headerXCallerId), "should access caller id in header")
}

func TestGetAccessTokenInternalServerError(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()

	responseBody := rest_errors.NewInternalServerError(getAccessTokenInternalErrorMessage, rest_errors.NewError("rest_client_error"))
	responder := httpmock.NewJsonResponderOrPanic(500, responseBody)
	fakeUrl := baseUrl + "/oauth/access_token"
	httpmock.RegisterResponder("GET", fakeUrl, responder)

	at, err := getAccessToken(accessTokenId)

	assert.Nil(t, at)
	assert.NotNil(t, err)
	assert.Equal(t, 500, err.Status)
	assert.Equal(t, getAccessTokenInternalErrorMessage, err.Message)
}

func TestGetAccessTokenResponseError(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()

	responseBody := rest_errors.NewBadRequestError("bad request")
	responder := httpmock.NewJsonResponderOrPanic(400, responseBody)
	httpmock.RegisterResponder("GET", fakeUrl, responder)

	at, err := getAccessToken(accessTokenId)

	assert.Nil(t, at)
	assert.NotNil(t, err)
	assert.Equal(t, 400, err.Status)
	assert.Equal(t, "bad request", err.Message)
}

func TestGetAccessTokenSuccessful(t *testing.T) {
	httpmock.Reset()
	defer httpmock.DeactivateAndReset()

	responseBody := accessToken{
		Id:       accessTokenId,
		UserId:   234,
		ClientId: 345,
	}
	responder := httpmock.NewJsonResponderOrPanic(200, responseBody)
	httpmock.RegisterResponder("GET", fakeUrl, responder)

	at, err := getAccessToken(accessTokenId)
	assert.Nil(t, err)
	assert.NotNil(t, at)
	assert.Equal(t, responseBody.Id, at.Id)
	assert.Equal(t, responseBody.UserId, at.UserId)
	assert.Equal(t, responseBody.ClientId, at.ClientId)
}
