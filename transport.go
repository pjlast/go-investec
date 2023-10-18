package goinvestec

import (
	"net/http"
)

// Transport sets the "x-api-key" header on a request before executing the request.
//
// Investec uses the "client credentials" token flow, also known as the "tow-legged OAuth 2.0".
// This flow is implemented by "golang.org/x/oauth2/clientcredentials".
// However, Investec requires an additional "x-api-key" header to be set,
// and the oauth2/clientcredentials package does not support setting custom headers
// for token fetch requests. It does, however, support setting a custom http.Client
// for token requests, so we provide a Transport layer that does the required header
// setting.
type Transport struct {
	APIKey string

	Base http.RoundTripper
}

// RoundTrip sets the "x-api-key" header on a request.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBodyClosed := false
	if req.Body != nil {
		defer func() {
			if !reqBodyClosed {
				req.Body.Close()
			}
		}()
	}
	req2 := cloneRequest(req) // RoundTripper dictates that we should not modify the original request at all

	req2.Header.Add("x-api-key", t.APIKey)

	reqBodyClosed = true
	return t.base().RoundTrip(req2)
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

// cloneRequest returns a clone of the provided *http.Request.
// The clone is a shallow copy of the struct and its Header map.
//
// From golang.org/x/oauth2/transport.go
func cloneRequest(r *http.Request) *http.Request {
	// shallow copy of the struct
	r2 := new(http.Request)
	*r2 = *r
	// deep copy of the Header
	r2.Header = make(http.Header, len(r.Header))
	for k, s := range r.Header {
		r2.Header[k] = append([]string(nil), s...)
	}
	return r2
}
