package goinvestec

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

type Client struct {
	apiKey     string
	baseURL    string
	auther     *investecAuth
	httpClient *http.Client
}

type investecAuth struct {
	sync.Mutex

	baseURL  string
	clientID string
	secret   string
	apiKey   string

	token *Token

	httpClient *http.Client
}

type tokenJSON struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type Token struct {
	*oauth2.Token
	Scope string
}

func (t *Token) Valid() bool {
	if t != nil && t.Token != nil {
		return t.Token.Valid()
	}

	return false
}

func (t tokenJSON) expiry() time.Time {
	return time.Now().Add(time.Second * time.Duration(t.ExpiresIn))
}

func (a *investecAuth) Token() (*Token, error) {
	a.Lock()
	defer a.Unlock()
	if a.token.Valid() {
		return a.token, nil
	}

	reqURL, err := url.JoinPath(a.baseURL, "/identity/v2/oauth2/token")
	if err != nil {
		return nil, err
	}

	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	r, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}

	r.Header.Add("x-api-key", a.apiKey)
	r.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", a.clientID, a.secret))))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tk tokenJSON
	if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil {
		return nil, err
	}

	a.token = &Token{
		Token: &oauth2.Token{
			AccessToken: tk.AccessToken,
			TokenType:   tk.TokenType,
			Expiry:      tk.expiry(),
		},
		Scope: tk.Scope,
	}

	return a.token, nil
}

func NewClient(ctx context.Context, baseURL, clientID, secret, apiKey string) Client {
	return Client{
		apiKey:  apiKey,
		baseURL: baseURL,
		auther: &investecAuth{
			baseURL:    baseURL,
			clientID:   clientID,
			secret:     secret,
			apiKey:     apiKey,
			httpClient: &http.Client{},
		},
		httpClient: &http.Client{},
	}
}

type Account struct {
	ID            string `json:"accountId"`
	Number        string `json:"accountNumber"`
	Name          string `json:"accountName"`
	ReferenceName string `json:"referenceName"`
	ProductName   string `json:"productName"`
	KYCCompliant  bool   `json:"kycCompliant"`
	ProfileID     string `json:"profileId"`
	ProfileName   string `json:"profileName"`
}

func (c Client) newAuthorizedRequest(ctx context.Context, method string, url string, body io.Reader) (*http.Request, error) {
	r, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	tok, err := c.auther.Token()
	if err != nil {
		return nil, err
	}

	tok.SetAuthHeader(r)

	return r, nil
}

// GetAccounts returns a list of accounts for the authenticated client.
func (c Client) GetAccounts(ctx context.Context) ([]Account, error) {
	reqURL, err := url.JoinPath(c.baseURL, "/za/pb/v1/accounts")
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respData struct {
		Data struct {
			Accounts []Account `json:"accounts"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data.Accounts, nil
}

type Balance struct {
	AccountID        string  `json:"accountId"`
	CurrentBalance   float64 `json:"currentBalance"`
	AvailableBalance float64 `json:"availableBalance"`
	BudgetBalance    float64 `json:"budgetBalance"`
	StraightBalance  float64 `json:"straightBalance"`
	CashBalance      float64 `json:"cashBalance"`
	Currency         string  `json:"currency"`
}

// GetAccountBalance returns the balance for the provided accountID.
func (c Client) GetAccountBalance(ctx context.Context, accountID string) (Balance, error) {
	reqURL, err := url.JoinPath(c.baseURL, fmt.Sprintf("/za/pb/v1/accounts/%s/balance", accountID))
	if err != nil {
		return Balance{}, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Balance{}, nil
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return Balance{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return Balance{}, errors.New(string(b))
	}

	var respData struct {
		Data Balance `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return Balance{}, err
	}

	return respData.Data, nil
}

type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(data []byte) error {
	var err error
	var timeString string
	if err = json.Unmarshal(data, &timeString); err != nil {
		return err
	}
	if strings.Contains(timeString, "/") {
		t.Time, err = time.Parse("02/01/2006", timeString)
	} else if strings.Contains(timeString, "-") {
		t.Time, err = time.Parse(time.DateOnly, timeString)
	}

	return err
}

type Transaction struct {
	AccountID       string  `json:"accountId"`
	Type            string  `json:"type"`
	TransactionType string  `json:"transactionType"`
	Status          string  `json:"status"`
	Description     string  `json:"description"`
	CardNumber      string  `json:"cardNumber"`
	PostedOrder     int     `json:"postedOrder"`
	PostingDate     Time    `json:"postingDate"`
	ValueDate       Time    `json:"valueDate"`
	ActionDate      Time    `json:"actionDate"`
	TransactionDate Time    `json:"transactionDate"`
	Amount          float64 `json:"amount"`
	RunningBalance  float64 `json:"runningBalance"`
}

// GetAccountTransactions gets a list of account transactions for the provided account ID.
func (c Client) GetAccountTransactions(ctx context.Context, accountID string) ([]Transaction, error) {
	reqURL, err := url.JoinPath(c.baseURL, fmt.Sprintf("/za/pb/v1/accounts/%s/transactions", accountID))
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(b))
	}

	var respData struct {
		Data struct {
			Transactions []Transaction `json:"transactions"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data.Transactions, nil
}

type Profile struct {
	ID      string `json:"profileId"`
	Name    string `json:"profileName"`
	Default bool   `json:"defaultProfile"`
}

// GetProfiles returns a list of profiles associated with the authenticatd user.
func (c Client) GetProfiles(ctx context.Context) ([]Profile, error) {
	reqURL, err := url.JoinPath(c.baseURL, "/za/pb/v1/profiles")
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respData struct {
		Data []Profile `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data, nil
}

// GetProfileAccounts returns a list of accounts associated with the provided profile ID.
func (c Client) GetProfileAccounts(ctx context.Context, profileID string) ([]Account, error) {
	reqURL, err := url.JoinPath(c.baseURL, fmt.Sprintf("/za/pb/v1/profiles/%s/accounts", profileID))
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(b))
	}

	var respData struct {
		Data []Account `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data, nil
}

type Beneficiary struct {
	BeneficiaryID          string `json:"beneficiaryId"`
	AccountNumber          string `json:"accountNumber"`
	Code                   string `json:"code"`
	Bank                   string `json:"bank"`
	BeneficiaryName        string `json:"beneficiaryName"`
	LastPaymentAmount      string `json:"lastPaymentAmount"`
	LastPaymentDate        Time   `json:"lastPaymentDate"`
	CellNo                 string `json:"cellNo"`
	EmailAddress           string `json:"emailAddress"`
	Name                   string `json:"name"`
	ReferenceAccountNumber string `json:"referenceAccountNumber"`
	ReferenceName          string `json:"referenceName"`
	CategoryID             string `json:"categoryId"`
	ProfileID              string `json:"profileId"`
	FasterPaymentAllowed   bool   `json:"fasterPaymentAllowed"`
}

// GetAccountBeneficiaries lists the beneficiaries for the provided profile and account ID.
func (c Client) GetAccountBeneficiaries(ctx context.Context, profileID string, accountID string) ([]Beneficiary, error) {
	reqURL, err := url.JoinPath(c.baseURL, fmt.Sprintf("/za/pb/v1/profiles/%s/accounts/%s/beneficiaries", profileID, accountID))
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(b))
	}

	var respData struct {
		Data []Beneficiary `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data, nil
}

// GetBeneficiaries lists the beneficiaries for the authenticated profile.
func (c Client) GetBeneficiaries(ctx context.Context) ([]Beneficiary, error) {
	reqURL, err := url.JoinPath(c.baseURL, "/za/pb/v1/accounts/beneficiaries")
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respData struct {
		Data []Beneficiary `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data, nil
}

type BeneficiaryCategory struct {
	CategoryID      string `json:"CategoryId"`
	DefaultCategory bool   `json:"DefaultCategory,string"`
	CategoryName    string `json:"CategoryName"`
}

// GetBeneficiaryCatagories lists all the beneficiary categories associated with the authenticated profile.
func (c Client) GetBeneficiaryCatagories(ctx context.Context) ([]BeneficiaryCategory, error) {
	reqURL, err := url.JoinPath(c.baseURL, "/za/pb/v1/accounts/beneficiarycategories")
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var respData struct {
		Data []BeneficiaryCategory `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	return respData.Data, nil
}

type TransferResponse struct {
	PaymentReferenceNumber string `json:"PaymentReferenceNumber"`
	PaymentDate            Time   `json:"PaymentDate"`
	Status                 string `json:"Status"`
	BeneficiaryName        string `json:"BeneficiaryName"`
	BeneficiaryAccountID   string `json:"BeneficiaryAccountId"`
	AuthorisationRequired  bool   `json:"AuthorisationRequired"`
}

type Transfer struct {
	BeneficiaryAccountID string `json:"beneficiaryAccountId"`
	Amount               string `json:"amount"`
	MyReference          string `json:"myReference"`
	TheirReference       string `json:"theirReference"`
}

func (c Client) TransferMultiple(ctx context.Context, accountID string, profileID string, transferList []Transfer) ([]TransferResponse, error) {
	reqURL, err := url.JoinPath(c.baseURL, fmt.Sprintf("/za/pb/v1/accounts/%s/transfermultiple", accountID))
	if err != nil {
		return nil, err
	}

	rBody := struct {
		TransferList []Transfer `json:"transferList"`
		ProfileID    string     `json:"profileId"`
	}{
		TransferList: transferList,
		ProfileID:    profileID,
	}

	rBodyJSON, err := json.Marshal(rBody)
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodPost, reqURL, bytes.NewBuffer(rBodyJSON))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(b))
	}

	var respData struct {
		Data struct {
			TransferResponses []TransferResponse `json:"TransferResponses"`
			ErrorMessage      string             `json:"ErrorMessage"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	if respData.Data.ErrorMessage != "" {
		err = errors.New(respData.Data.ErrorMessage)
	}

	return respData.Data.TransferResponses, err
}

type Payment struct {
	BeneficiaryID  string `json:"beneficiaryId"`
	Amount         string `json:"amount"`
	MyReference    string `json:"myReference"`
	TheirReference string `json:"theirReference"`
}

// PayMultiple executes all payments specified in the payment list.
func (c Client) PayMultiple(ctx context.Context, accountID string, paymentList []Payment) ([]TransferResponse, error) {
	reqURL, err := url.JoinPath(c.baseURL, fmt.Sprintf("/za/pb/v1/accounts/%s/paymultiple", accountID))
	if err != nil {
		return nil, err
	}

	rBody := struct {
		PaymentList []Payment `json:"paymentList"`
	}{
		PaymentList: paymentList,
	}

	rBodyJSON, err := json.Marshal(rBody)
	if err != nil {
		return nil, err
	}

	r, err := c.newAuthorizedRequest(ctx, http.MethodPost, reqURL, bytes.NewBuffer(rBodyJSON))
	if err != nil {
		return nil, err
	}
	r.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return nil, errors.New(string(b))
	}

	var respData struct {
		Data struct {
			TransferResponses []TransferResponse `json:"TransferResponses"`
			ErrorMessage      string             `json:"ErrorMessage"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return nil, err
	}

	if respData.Data.ErrorMessage != "" {
		err = errors.New(respData.Data.ErrorMessage)
	}

	return respData.Data.TransferResponses, err
}
