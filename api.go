package goinvestec

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	productionURL = "https://openapi.investec.com"

	sandboxURL          = "https://openapisandbox.investec.com"
	sandboxClientID     = "yAxzQRFX97vOcyQAwluEU6H6ePxMA5eY"
	sandboxClientSecret = "4dY0PjEYqoBrZ99r"
	sandboxAPIKey       = "eUF4elFSRlg5N3ZPY3lRQXdsdUVVNkg2ZVB4TUE1ZVk6YVc1MlpYTjBaV010ZW1FdGNHSXRZV05qYjNWdWRITXRjMkZ1WkdKdmVBPT0="
)

// Client is a client for the Investec API.
type Client struct {
	// BaseURL is the URL of the server to which requests should be sent.
	// BaseURL should never be specified with a trailing slash.
	//
	// Production URL: "https://openapi.investec.com"
	// Sandbox URL: "https://openapisandbox.investec.com"
	BaseURL string

	// HTTPClient is the underlying HTTP client to use when making requests,
	// and is responsible for authenticating requests before executing them.
	//
	// Should never be nil.
	HTTPClient *http.Client
}

// NewAuthorizedClient returns a Client with an authorized http.Client.
//
// The http.Client caches tokens in-memory and will re-use them if they are
// still valid, otherwise it will fetch a new token.
//
// If you require a longer-living cache, consider creating a Client struct
// yourself and providing your own http.Client that handles authentication
// and caching.
func NewAuthorizedClient(clientID, clientSecret, apiKey string) *Client {
	c := &http.Client{
		Transport: &Transport{
			APIKey: apiKey,
		},
	}

	conf := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     "https://openapi.investec.com/identity/v2/oauth2/token",
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, c)

	return &Client{
		BaseURL:    "https://openapi.investec.com",
		HTTPClient: conf.Client(ctx),
	}
}

// NewSandboxClient returns a Client that communicates and authenticates
// with the Investec sandbox API.
//
// Useful for experimentation.
func NewSandboxClient() *Client {
	c := &http.Client{
		Transport: &Transport{
			APIKey: sandboxAPIKey,
		},
	}

	conf := &clientcredentials.Config{
		ClientID:     sandboxClientID,
		ClientSecret: sandboxClientSecret,
		TokenURL:     sandboxURL + "/identity/v2/oauth2/token",
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, c)

	return &Client{
		BaseURL:    sandboxURL,
		HTTPClient: conf.Client(ctx),
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

func (c Client) newRequest(ctx context.Context, method string, path string, body any) (*http.Request, error) {
	var bdy io.Reader
	if body != nil {
		rBodyJSON, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bdy = bytes.NewReader(rBodyJSON)
	}

	r, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bdy)
	if err != nil {
		return nil, err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}

	return r, nil
}

// GetAccounts returns a list of accounts for the authenticated client.
func (c Client) GetAccounts(ctx context.Context) ([]Account, error) {
	r, err := c.newRequest(ctx, http.MethodGet, "/za/pb/v1/accounts", nil)
	if err != nil {
		return nil, err
	}

	accts, err := doRequest[struct {
		Accounts []Account `json:"accounts"`
	}](c.HTTPClient, r)

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
	path := fmt.Sprintf("/za/pb/v1/accounts/%s/balance", accountID)

	r, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return Balance{}, nil
	}

	return doRequest[Balance](c.HTTPClient, r)
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

type GetTransactionsOpts struct {
	FromDate        time.Time
	ToDate          time.Time
	TransactionType string
}

// GetAccountTransactions gets a list of account transactions for the provided account ID.
func (c Client) GetAccountTransactions(ctx context.Context, accountID string, opts GetTransactionsOpts) ([]Transaction, error) {
	path := fmt.Sprintf("/za/pb/v1/accounts/%s/transactions", accountID)

	var params url.Values
	if !opts.FromDate.IsZero() {
		params.Set("fromDate", opts.FromDate.Format(time.DateOnly))
	}
	if !opts.ToDate.IsZero() {
		params.Set("toDate", opts.ToDate.Format(time.DateOnly))
	}
	if opts.TransactionType != "" {
		params.Set("transactionType", opts.TransactionType)
	}

	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	r, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	txs, err := doRequest[struct {
		Transactions []Transaction `json:"transactions"`
	}](c.HTTPClient, r)
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
	r, err := c.newRequest(ctx, http.MethodGet, "/za/pb/v1/profiles", nil)
	if err != nil {
		return nil, err
	}

	return doRequest[[]Profile](c.HTTPClient, r)
}

// GetProfileAccounts returns a list of accounts associated with the provided profile ID.
func (c Client) GetProfileAccounts(ctx context.Context, profileID string) ([]Account, error) {
	path := fmt.Sprintf("/za/pb/v1/profiles/%s/accounts", profileID)

	r, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	return doRequest[[]Account](c.HTTPClient, r)
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
	path := fmt.Sprintf("/za/pb/v1/profiles/%s/accounts/%s/beneficiaries", profileID, accountID)

	r, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	return doRequest[[]Beneficiary](c.HTTPClient, r)
}

// GetBeneficiaries lists the beneficiaries for the authenticated profile.
func (c Client) GetBeneficiaries(ctx context.Context) ([]Beneficiary, error) {
	r, err := c.newRequest(ctx, http.MethodGet, "/za/pb/v1/accounts/beneficiaries", nil)
	if err != nil {
		return nil, err
	}

	return doRequest[[]Beneficiary](c.HTTPClient, r)
}

type BeneficiaryCategory struct {
	ID      string `json:"CategoryId"`
	Default bool   `json:"DefaultCategory,string"`
	Name    string `json:"CategoryName"`
}

// GetBeneficiaryCatagories lists all the beneficiary categories associated with the authenticated profile.
func (c Client) GetBeneficiaryCatagories(ctx context.Context) ([]BeneficiaryCategory, error) {
	r, err := c.newRequest(ctx, http.MethodGet, "/za/pb/v1/accounts/beneficiarycategories", nil)
	if err != nil {
		return nil, err
	}

	return doRequest[[]BeneficiaryCategory](c.HTTPClient, r)
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
	path := fmt.Sprintf("/za/pb/v1/accounts/%s/transfermultiple", accountID)

	r, err := c.newRequest(ctx, http.MethodPost, path,
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
	}](c.HTTPClient, r)

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
	path := fmt.Sprintf("/za/pb/v1/accounts/%s/paymultiple", accountID)

	r, err := c.newRequest(ctx, http.MethodPost, path,
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
	}](c.HTTPClient, r)

	if resp.ErrorMessage != "" {
		err = errors.New(resp.ErrorMessage)
	}

	return resp.TransferResponses, err
}
