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
	baseURL    string
	auther     *Authenticator
	httpClient *http.Client
}

type Authenticator struct {
	sync.Mutex

	BaseURL  string
	ClientID string
	Secret   string
	APIKey   string

	OAuthToken *oauth2.Token

	HTTPClient *http.Client

	// PostRefreshHook is called after a new OAuth token is fetched successfully.
	PostRefreshHook func(*oauth2.Token)
}

type tokenJSON struct {
	AccessToken string     `json:"access_token"`
	TokenType   string     `json:"token_type"`
	Expiry      expiryTime `json:"expires_in"`
	Scope       string     `json:"scope"`
}

// expiryTime is an intermediary struct that converts an `expires_in` parameter
// to an `expiry` parameter during JSON unmarshaling.
type expiryTime struct {
	time.Time
}

func (t *expiryTime) UnmarshalJSON(data []byte) error {
	var expiresIn time.Duration
	if err := json.Unmarshal(data, &expiresIn); err != nil {
		return err
	}

	t.Time = time.Now().Add(time.Second * expiresIn)

	return nil
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

func (a *Authenticator) Token() (*oauth2.Token, error) {
	a.Lock()
	defer a.Unlock()
	if a.OAuthToken.Valid() {
		return a.OAuthToken, nil
	}

	reqURL, err := url.JoinPath(a.BaseURL, "/identity/v2/oauth2/token")
	if err != nil {
		return nil, err
	}

	body := url.Values{}
	body.Set("grant_type", "client_credentials")
	r, err := http.NewRequest(http.MethodPost, reqURL, strings.NewReader(body.Encode()))
	if err != nil {
		return nil, err
	}

	r.Header.Add("x-api-key", a.APIKey)
	r.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", a.ClientID, a.Secret))))
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.HTTPClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var tk tokenJSON
	if err := json.NewDecoder(resp.Body).Decode(&tk); err != nil {
		return nil, err
	}

	a.OAuthToken = &oauth2.Token{
		AccessToken: tk.AccessToken,
		TokenType:   tk.TokenType,
		Expiry:      tk.Expiry.Time,
	}

	a.OAuthToken.WithExtra(map[string]interface{}{
		"scope": tk.Scope,
	})

	if a.PostRefreshHook != nil {
		a.PostRefreshHook(a.OAuthToken)
	}

	return a.OAuthToken, nil
}

func NewClient(ctx context.Context, baseURL string, a *Authenticator) *Client {
	return &Client{
		baseURL: baseURL,
		auther:     a,
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

func (c Client) newAuthorizedRequest(ctx context.Context, method string, url string, body any) (*http.Request, error) {
	var bdy io.Reader
	if body != nil {
		rBodyJSON, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bdy = bytes.NewReader(rBodyJSON)
	}

	r, err := http.NewRequestWithContext(ctx, method, url, bdy)
	if err != nil {
		return nil, err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
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

	accts, err := doRequest[struct {
		Accounts []Account `json:"accounts"`
	}](c.httpClient, r)

	return accts.Accounts, nil
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

	return doRequest[Balance](c.httpClient, r)
}

// apiTime is an intermediary struct that facilitates translation
// from dates provided by Investec's API to standard time.Time.
type apiTime struct {
	time.Time
}

// UnmarshalJSON for apiTime infers which of the two date formats
// the JSON is representing, and parses a time.Time object
// accordingly.
func (t *apiTime) UnmarshalJSON(data []byte) error {
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

type transactionJSON struct {
	AccountID       string  `json:"accountId"`
	Type            string  `json:"type"`
	TransactionType string  `json:"transactionType"`
	Status          string  `json:"status"`
	Description     string  `json:"description"`
	CardNumber      string  `json:"cardNumber"`
	PostedOrder     int     `json:"postedOrder"`
	PostingDate     apiTime `json:"postingDate"`
	ValueDate       apiTime `json:"valueDate"`
	ActionDate      apiTime `json:"actionDate"`
	TransactionDate apiTime `json:"transactionDate"`
	Amount          float64 `json:"amount"`
	RunningBalance  float64 `json:"runningBalance"`
}

type Transaction struct {
	AccountID       string
	Type            string
	TransactionType string
	Status          string
	Description     string
	CardNumber      string
	PostedOrder     int
	PostingDate     time.Time
	ValueDate       time.Time
	ActionDate      time.Time
	TransactionDate time.Time
	Amount          float64
	RunningBalance  float64
}

func (t *Transaction) UnmarshalJSON(data []byte) error {
	var tj transactionJSON
	if err := json.Unmarshal(data, &tj); err != nil {
		return err
	}

	*t = Transaction{
		AccountID:       tj.AccountID,
		Type:            tj.Type,
		TransactionType: tj.TransactionType,
		Status:          tj.Status,
		Description:     tj.Description,
		CardNumber:      tj.CardNumber,
		PostedOrder:     tj.PostedOrder,
		PostingDate:     tj.PostingDate.Time,
		ValueDate:       tj.ValueDate.Time,
		ActionDate:      tj.ActionDate.Time,
		TransactionDate: tj.TransactionDate.Time,
		Amount:          tj.Amount,
		RunningBalance:  tj.RunningBalance,
	}

	return nil
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

	txs, err := doRequest[struct {
		Transactions []Transaction `json:"transactions"`
	}](c.httpClient, r)

	if err != nil {
		return nil, err
	}

	return txs.Transactions, nil
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

	return doRequest[[]Profile](c.httpClient, r)
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

	return doRequest[[]Account](c.httpClient, r)
}

type beneficiaryJSON struct {
	ID                     string  `json:"beneficiaryId"`
	AccountNumber          string  `json:"accountNumber"`
	Code                   string  `json:"code"`
	Bank                   string  `json:"bank"`
	BeneficiaryName        string  `json:"beneficiaryName"`
	LastPaymentAmount      string  `json:"lastPaymentAmount"`
	LastPaymentDate        apiTime `json:"lastPaymentDate"`
	CellNo                 string  `json:"cellNo"`
	EmailAddress           string  `json:"emailAddress"`
	Name                   string  `json:"name"`
	ReferenceAccountNumber string  `json:"referenceAccountNumber"`
	ReferenceName          string  `json:"referenceName"`
	CategoryID             string  `json:"categoryId"`
	ProfileID              string  `json:"profileId"`
	FasterPaymentAllowed   bool    `json:"fasterPaymentAllowed"`
}

type Beneficiary struct {
	ID                     string    `json:"beneficiaryId"`
	AccountNumber          string    `json:"accountNumber"`
	Code                   string    `json:"code"`
	Bank                   string    `json:"bank"`
	BeneficiaryName        string    `json:"beneficiaryName"`
	LastPaymentAmount      string    `json:"lastPaymentAmount"`
	LastPaymentDate        time.Time `json:"lastPaymentDate"`
	CellNo                 string    `json:"cellNo"`
	EmailAddress           string    `json:"emailAddress"`
	Name                   string    `json:"name"`
	ReferenceAccountNumber string    `json:"referenceAccountNumber"`
	ReferenceName          string    `json:"referenceName"`
	CategoryID             string    `json:"categoryId"`
	ProfileID              string    `json:"profileId"`
	FasterPaymentAllowed   bool      `json:"fasterPaymentAllowed"`
}

func (b *Beneficiary) UnmarshalJSON(data []byte) error {
	var bj beneficiaryJSON
	if err := json.Unmarshal(data, &bj); err != nil {
		return err
	}

	*b = Beneficiary{
		ID:                     bj.ID,
		AccountNumber:          bj.AccountNumber,
		Code:                   bj.Code,
		Bank:                   bj.Bank,
		BeneficiaryName:        bj.BeneficiaryName,
		LastPaymentAmount:      bj.LastPaymentAmount,
		LastPaymentDate:        bj.LastPaymentDate.Time,
		CellNo:                 bj.CellNo,
		EmailAddress:           bj.EmailAddress,
		Name:                   bj.Name,
		ReferenceAccountNumber: bj.ReferenceAccountNumber,
		ReferenceName:          bj.ReferenceName,
		CategoryID:             bj.CategoryID,
		ProfileID:              bj.ProfileID,
		FasterPaymentAllowed:   bj.FasterPaymentAllowed,
	}

	return nil
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

	return doRequest[[]Beneficiary](c.httpClient, r)
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

	return doRequest[[]Beneficiary](c.httpClient, r)
}

type BeneficiaryCategory struct {
	ID      string `json:"CategoryId"`
	Default bool   `json:"DefaultCategory,string"`
	Name    string `json:"CategoryName"`
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

	return doRequest[[]BeneficiaryCategory](c.httpClient, r)
}

type transferResponseJSON struct {
	PaymentReferenceNumber string  `json:"PaymentReferenceNumber"`
	PaymentDate            apiTime `json:"PaymentDate"`
	Status                 string  `json:"Status"`
	BeneficiaryName        string  `json:"BeneficiaryName"`
	BeneficiaryAccountID   string  `json:"BeneficiaryAccountId"`
	AuthorisationRequired  bool    `json:"AuthorisationRequired"`
}

type TransferResponse struct {
	PaymentReferenceNumber string    `json:"PaymentReferenceNumber"`
	PaymentDate            time.Time `json:"PaymentDate"`
	Status                 string    `json:"Status"`
	BeneficiaryName        string    `json:"BeneficiaryName"`
	BeneficiaryAccountID   string    `json:"BeneficiaryAccountId"`
	AuthorisationRequired  bool      `json:"AuthorisationRequired"`
}

func (tr *TransferResponse) UnmarshalJSON(data []byte) error {
	var trj transferResponseJSON
	if err := json.Unmarshal(data, &trj); err != nil {
		return err
	}

	*tr = TransferResponse{
		PaymentReferenceNumber: trj.PaymentReferenceNumber,
		PaymentDate:            trj.PaymentDate.Time,
		Status:                 trj.Status,
		BeneficiaryName:        trj.BeneficiaryName,
		BeneficiaryAccountID:   trj.BeneficiaryAccountID,
		AuthorisationRequired:  trj.AuthorisationRequired,
	}

	return nil
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

	r, err := c.newAuthorizedRequest(ctx, http.MethodPost, reqURL,
		struct {
			TransferList []Transfer `json:"transferList"`
			ProfileID    string     `json:"profileId"`
		}{
			TransferList: transferList,
			ProfileID:    profileID,
		},
	)
	if err != nil {
		return nil, err
	}

	resp, err := doRequest[struct {
		TransferResponses []TransferResponse `json:"TransferResponses"`
		ErrorMessage      string             `json:"ErrorMessage"`
	}](c.httpClient, r)

	if resp.ErrorMessage != "" {
		err = errors.New(resp.ErrorMessage)
	}

	return resp.TransferResponses, err
}

func doRequest[T any](c *http.Client, r *http.Request) (t T, _ error) {
	resp, err := c.Do(r)
	if err != nil {
		return t, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		return t, errors.New(string(b))
	}

	var respData struct {
		Data T `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return t, err
	}

	return respData.Data, nil
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

	r, err := c.newAuthorizedRequest(ctx, http.MethodPost, reqURL,
		struct {
			PaymentList []Payment `json:"paymentList"`
		}{
			PaymentList: paymentList,
		},
	)
	if err != nil {
		return nil, err
	}

	resp, err := doRequest[struct {
		TransferResponses []TransferResponse `json:"TransferResponses"`
		ErrorMessage      string             `json:"ErrorMessage"`
	}](c.httpClient, r)

	if resp.ErrorMessage != "" {
		err = errors.New(resp.ErrorMessage)
	}

	return resp.TransferResponses, err
}
