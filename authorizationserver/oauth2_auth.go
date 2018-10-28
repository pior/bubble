package authorizationserver

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/ory/fosite"
	"github.com/rs/xid"
)

type authRequest struct {
	postValues url.Values
}

type loginToken string

type MemoryRequestStore struct {
	requests map[loginToken]*authRequest
}

func (s *MemoryRequestStore) store(postValues url.Values) loginToken {
	token := loginToken(xid.New().String())
	s.requests[token] = &authRequest{postValues: postValues}
	return token
}

func (s *MemoryRequestStore) fetch(token loginToken) *authRequest {
	return s.requests[token]
}

var requestStore = &MemoryRequestStore{requests: make(map[loginToken]*authRequest)}

func sendEmailLink(to string, url string) {
	fmt.Printf("Sending email to %s with link %s\n", to, url)
}

func handleAuthAndConsent(rw http.ResponseWriter, req *http.Request, ar fosite.AuthorizeRequester) (abort bool, err error) {
	/*
		- page to ask user how to authenticate (email?)
		- generate an email-token
		- record AuthorizationRequest with email-token
		- send email with link with email-token
		- respond with "email sent. wait or click here to resend"

		1. show the page for login method: ""
		2. show the page "email sent": "login_method=email email_address=poi@poi.poi"
		3. from email: "login_method=email login_token=QWERTY"

	*/

	req.ParseForm()

	tok := req.Form.Get("login_token")

	// We have a token, check it and return success!
	if tok != "" {

		authReq := requestStore.fetch(loginToken(tok))
		if authReq == nil {
			return false, fmt.Errorf("unknown login token %s", tok)
		}

		// let's see what scopes the user gave consent to
		// for _, scope := range req.PostForm["scopes"] {
		// 	ar.GrantScope(scope)
		// }
		fmt.Println("success")
		return false, nil
	}

	// No login token
	loginMethod := req.PostForm.Get("login_method")
	if loginMethod == "" {
		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(`<h1>Login page</h1>`))
		rw.Write([]byte(fmt.Sprintf(`
			<p>Do you want to login by email?</p>
			<form method="post">
				<input type="email" name="email_address" />
				<input type="hidden" name="login_method" value="email" />
				<input type="submit">
			</form>
		`)))
		return true, nil
	}

	if loginMethod == "email" {

		tok := requestStore.store(req.Form)

		q := req.Form
		q.Del("email_address")
		q.Del("login_method")
		q.Set("login_token", string(tok))

		// u := &url.URL{
		// 	Scheme: "http",
		// 	Host:   req.Host,
		// 	Path:   req.URL.Path,
		// }
		// u.RawQuery = q.Encode()

		u := &url.URL{
			Scheme: "http",
			Host:   req.Host,
			Path:   req.URL.Path,
		}
		u.RawQuery = q.Encode()

		emailAddress := req.PostForm.Get("email_address")
		sendEmailLink(emailAddress, u.String())

		rw.Header().Set("Content-Type", "text/html; charset=utf-8")
		rw.Write([]byte(`<h1>Login page</h1>`))
		rw.Write([]byte(fmt.Sprintf(`
			<p>Email sent to %s</p>
		`, emailAddress)))
		return true, nil
	}

	return false, fmt.Errorf("param login_method is invalid: %s", loginMethod)
}

func authEndpoint(rw http.ResponseWriter, req *http.Request) {
	// This context will be passed to all methods.
	ctx := fosite.NewContext()

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeRequest: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	abortRequest, err := handleAuthAndConsent(rw, req, ar)
	if err != nil {
		log.Printf("Error occurred in handleAuthAndConsent: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}
	if abortRequest { // handleAuthAndConsent wrote a response, just do nothing
		return
	}

	// Now that the user is authorized, we set up a session:
	mySessionData := newSession("peter")

	// When using the HMACSHA strategy you must use something that implements the HMACSessionContainer.
	// It brings you the power of overriding the default values.
	//
	// mySessionData.HMACSession = &strategy.HMACSession{
	//	AccessTokenExpiry: time.Now().Add(time.Day),
	//	AuthorizeCodeExpiry: time.Now().Add(time.Day),
	// }
	//

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

	// It's also wise to check the requested scopes, e.g.:
	// if authorizeRequest.GetScopes().Has("admin") {
	//     http.Error(rw, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
	// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
	// to support open id connect.
	response, err := oauth2.NewAuthorizeResponse(ctx, ar, mySessionData)

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if err != nil {
		log.Printf("Error occurred in NewAuthorizeResponse: %+v", err)
		oauth2.WriteAuthorizeError(rw, ar, err)
		return
	}

	// Last but not least, send the response!
	oauth2.WriteAuthorizeResponse(rw, ar, response)
}
