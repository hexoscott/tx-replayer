package main

type BlockDetail struct {
	Number       string   `json:"number"`
	Hash         string   `json:"hash"`
	Transactions []string `json:"transactions"`
}

type GetBlockByNumberResponse struct {
	Jsonrpc string       `json:"jsonrpc"`
	ID      string       `json:"id"`
	Result  *BlockDetail `json:"result"`
}

type GetTransactionByHashRequest struct {
	Hash string `json:"hash"`
}

type SendRawTransactionRequest struct {
	Rlp string `json:"rlp"`
}

type ResponseError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type SendRawTransactionResponse struct {
	Result string         `json:"result"`
	Error  *ResponseError `json:"error,omitempty"`
}

type AccessTuple struct {
	Address     string
	StorageKeys []string
}

type TxType int64

const (
	LegacyTx     TxType = 0x0
	AccessListTx TxType = 0x01
	StateTx      TxType = 0x7f
	DynamicFeeTx TxType = 0x02
)

const (
	HashLength    = 32
	AddressLength = 20
)

type Hash [HashLength]byte

func (h Hash) Bytes() []byte {
	return h[:]
}

type Address [AddressLength]byte

func (a Address) Bytes() []byte {
	return a[:]
}

type GetBlockByNumberRequest struct {
	Number string
}

type GetTransactionByHashResponse struct {
	Jsonrpc string `json:"jsonrpc"`
	ID      string `json:"id"`
	Result  struct {
		Nonce            string        `json:"nonce"`
		GasPrice         string        `json:"gasPrice"`
		GasTipCap        string        `json:"gasTipCap"`
		GasFeeCap        string        `json:"gasFeeCap"`
		Gas              string        `json:"gas"`
		To               *string       `json:"to,omitempty"`
		Value            string        `json:"value"`
		Input            string        `json:"input"`
		V                string        `json:"v"`
		R                string        `json:"r"`
		S                string        `json:"s"`
		Hash             string        `json:"hash"`
		From             string        `json:"from"`
		BlockHash        string        `json:"blockHash"`
		BlockNumber      string        `json:"blockNumber"`
		TransactionIndex string        `json:"transactionIndex"`
		Type             string        `json:"type"`
		ChainID          string        `json:"chainId"`
		AccessList       []AccessTuple `json:"accessList"`
	}
}
