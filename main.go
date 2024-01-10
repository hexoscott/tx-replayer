package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/umbracle/fastrlp"
)

type destinations []string

func (d *destinations) String() string {
	res := ""
	for _, dest := range *d {
		res += dest + ","
	}
	return res
}

func (d *destinations) Set(value string) error {
	*d = append(*d, value)
	return nil
}

var (
	source string
	dests  destinations
	block  uint64
	toDisk bool

	getBlockTemplate           *template.Template
	getTransactionTemplate     *template.Template
	sendRawTransactionTemplate *template.Template

	destinationIdx = 0
	brokenAttempts = 0
)

func main() {
	flag.StringVar(&source, "source", "http://localhost:8545", "RPC address to get transactions from")
	flag.Var(&dests, "destination", "RPC addresses to send transactions to - can take multiple")
	flag.Uint64Var(&block, "block", 0, "Block number to start from")
	flag.BoolVar(&toDisk, "to-disk", false, "Write to disk")
	flag.Parse()

	if toDisk {
		err := os.MkdirAll("./txs", 0755)
		if err != nil {
			fmt.Println("Error creating txs directory: ", err)
			return
		}
	}

	// first check if we've made progress before and continue from there
	progressBytes, err := os.ReadFile("./progress.txt")
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Println("Error reading progress file: ", err)
			return
		}
	}

	if progressBytes != nil && len(progressBytes) > 0 {
		progressBlock, err := strconv.Atoi(string(progressBytes))
		if err != nil {
			fmt.Println("Error parsing progress file: ", err)
			return
		}

		if uint64(progressBlock) > block {
			block = uint64(progressBlock)
		}
	}

	getBlockTemplate, err = template.New("getBlock").Parse(GetBlockByNumberTemplate)
	if err != nil {
		fmt.Println("Error parsing block template: ", err)
		return
	}

	getTransactionTemplate, err = template.New("getTransaction").Parse(GetTransactionByHashTemplate)
	if err != nil {
		fmt.Println("Error parsing transaction template: ", err)
		return
	}

	sendRawTransactionTemplate, err = template.New("sendRawTransaction").Parse(SendRawTransactionTemplate)
	if err != nil {
		fmt.Println("Error parsing sendRawTransaction template: ", err)
		return
	}

LOOP:
	for {
		if block%100 == 0 {
			fmt.Printf("checking block %v \n", block)
		}

		// attempt to read the block, we might not be there yet so just wait until we are
		b, err := getBlockResponse(block, source)
		if err != nil {
			fmt.Println("Error getting block: ", err)
			break
		}

		if b.Result == nil {
			fmt.Printf("Block %v not ready yet, waiting... \n", block)
			time.Sleep(1 * time.Second)
			continue
		}

		if len(b.Result.Transactions) == 0 {
			block++
			if err := writeProgress(block); err != nil {
				fmt.Println("Error writing progress: ", err)
				break
			}
			continue
		}

		fmt.Printf("block %v has transactions, processing... \n", block)

		if toDisk {
			// just write the tx to disk for use later
			for _, txHash := range b.Result.Transactions {
				tx, err := getTransaction(txHash)
				if err != nil {
					fmt.Println("Error getting transaction: ", err)
					break LOOP
				}

				rlp, err := convertTransactionResponseToRLP(tx)
				if err != nil {
					fmt.Println("Error converting transaction to RLP: ", err)
					break LOOP
				}
				unix := time.Now().UnixNano()
				fileName := fmt.Sprintf("./txs/%v-%s.txt", unix, txHash)
				hexEncoded := "0x" + hex.EncodeToString(rlp)
				fmt.Println("Writing transaction to disk: ", fileName)
				err = os.WriteFile(fileName, []byte(hexEncoded), 0644)
				if err != nil {
					fmt.Println("Error writing transaction to disk: ", err)
					break LOOP
				}
			}
			block++
			continue LOOP
		}

		latestBlock, err := getLatestDestinationBlock()
		if err != nil {
			fmt.Println("Error getting latest block, trying again: ", err)
			continue
		}
		latestBlockNumber, err := stringToUint(latestBlock.Result.Number)
		if err != nil {
			fmt.Println("Error converting latest block number: ", err)
			break
		}

		var hashes []string
		for _, txHash := range b.Result.Transactions {
			tx, err := getTransaction(txHash)
			if err != nil {
				fmt.Println("Error getting transaction: ", err)
				break LOOP
			}

			rlp, err := convertTransactionResponseToRLP(tx)
			if err != nil {
				fmt.Println("Error converting transaction to RLP: ", err)
				break LOOP
			}

			res, err := sendRawTransaction(rlp)
			if err != nil {
				fmt.Println("Error sending transaction: ", err)
				break LOOP
			}
			if res.Error != nil {
				fmt.Println("Error sending transaction, will attempt again...: ", res.Error.Message)
				time.Sleep(3 * time.Second)
				brokenAttempts++
				if brokenAttempts > 100 {
					fmt.Println("Too many broken attempts, exiting...")
					break LOOP
				}
				continue LOOP
			}

			hashes = append(hashes, res.Result)
			fmt.Println("Sent transaction: ", res.Result)
		}

		if len(hashes) > 0 {
			err = monitorForTransactions(hashes, latestBlockNumber-2)
			if err != nil {
				fmt.Println("Error monitoring for transactions: ", err)
				break
			}
		}

		brokenAttempts = 0
		block++

		// write progress to file
		if err := writeProgress(block); err != nil {
			fmt.Println("Error writing progress: ", err)
			break
		}
	}
}

func writeProgress(block uint64) error {
	return os.WriteFile("./progress.txt", []byte(fmt.Sprintf("%v", block)), 0644)
}

func getBlockResponse(blockNumber uint64, target string) (*GetBlockByNumberResponse, error) {
	hex := fmt.Sprintf("0x%x", blockNumber)
	req := GetBlockByNumberRequest{
		Number: hex,
	}

	return doBlockRequest(req, target)

}

func doBlockRequest(req GetBlockByNumberRequest, target string) (*GetBlockByNumberResponse, error) {
	var b []byte
	buf := bytes.NewBuffer(b)
	err := getBlockTemplate.Execute(buf, req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest("POST", target, buf)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var blockRes GetBlockByNumberResponse
	err = json.Unmarshal(bytes, &blockRes)
	if err != nil {
		return nil, err
	}

	return &blockRes, nil
}

func getTransaction(hash string) (*GetTransactionByHashResponse, error) {
	getTransactionReq := GetTransactionByHashRequest{
		Hash: hash,
	}

	var b []byte
	buf := bytes.NewBuffer(b)
	err := getTransactionTemplate.Execute(buf, getTransactionReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", source, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var transactionRes GetTransactionByHashResponse
	err = json.Unmarshal(bytes, &transactionRes)
	if err != nil {
		return nil, err
	}

	return &transactionRes, nil
}

func convertTransactionResponseToRLP(res *GetTransactionByHashResponse) ([]byte, error) {
	arena := fastrlp.DefaultArenaPool.Get()
	defer fastrlp.DefaultArenaPool.Put(arena)

	vv := arena.NewArray()

	t := res.Result

	typInt, err := stringToInt(t.Type)
	if err != nil {
		return nil, err
	}
	typ := TxType(typInt)

	chainId := stringToBig(t.ChainID)
	gasPrice := stringToBig(t.GasPrice)
	value := stringToBig(t.Value)
	v := stringToBig(t.V)
	r := stringToBig(t.R)
	s := stringToBig(t.S)

	gas, err := stringToUint(t.Gas)
	if err != nil {
		return nil, err
	}

	nonce, err := stringToUint(t.Nonce)
	if err != nil {
		return nil, err
	}

	from, err := hex.DecodeString(trimHex(t.From))
	if err != nil {
		return nil, err
	}

	var to []byte
	if t.To != nil {
		to, err = hex.DecodeString(trimHex(*t.To))
		if err != nil {
			return nil, err
		}
	}

	input, err := hex.DecodeString(trimHex(t.Input))
	if err != nil {
		return nil, err
	}

	if typ == AccessListTx {
		vv.Set(arena.NewBigInt(chainId))
		vv.Set(arena.NewUint(nonce))
		vv.Set(arena.NewBigInt(gasPrice))
		vv.Set(arena.NewUint(gas))
		if t.To != nil {
			vv.Set(arena.NewCopyBytes(to))
		} else {
			vv.Set(arena.NewNull())
		}
		vv.Set(arena.NewBigInt(value))
		vv.Set(arena.NewCopyBytes(input))

		err = RlpEncodeAccessList(arena, vv, t.AccessList)
		if err != nil {
			return nil, err
		}

		vv.Set(arena.NewBigInt(v))
		vv.Set(arena.NewBigInt(r))
		vv.Set(arena.NewBigInt(s))

		dst := vv.MarshalTo(nil)
		return dst, nil
	}

	// Specify zero chain ID as per spec.
	// This is needed to have the same format as other EVM chains do.
	// There is no chain ID in the TX object, so it is always 0 here just to be compatible.
	// Check Transaction1559Payload there https://eips.ethereum.org/EIPS/eip-1559#specification
	if typ == DynamicFeeTx {
		vv.Set(arena.NewBigInt(chainId))
	}

	vv.Set(arena.NewUint(nonce))

	if typ == DynamicFeeTx {
		tip := stringToBig(t.GasTipCap)
		fee := stringToBig(t.GasFeeCap)

		// Add EIP-1559 related fields.
		// For non-dynamic-fee-tx gas price is used.
		vv.Set(arena.NewBigInt(tip))
		vv.Set(arena.NewBigInt(fee))
	} else {
		vv.Set(arena.NewBigInt(gasPrice))
	}

	vv.Set(arena.NewUint(gas))

	// Address may be empty
	if t.To != nil {
		vv.Set(arena.NewCopyBytes(to))
	} else {
		vv.Set(arena.NewNull())
	}

	vv.Set(arena.NewBigInt(value))
	vv.Set(arena.NewCopyBytes(input))

	// Specify access list as per spec.
	// This is needed to have the same format as other EVM chains do.
	// There is no access list feature here, so it is always empty just to be compatible.
	// Check Transaction1559Payload there https://eips.ethereum.org/EIPS/eip-1559#specification
	if typ == DynamicFeeTx {
		vv.Set(arena.NewArray())
	}

	// signature values
	vv.Set(arena.NewBigInt(v))
	vv.Set(arena.NewBigInt(r))
	vv.Set(arena.NewBigInt(s))

	if typ == StateTx {
		vv.Set(arena.NewCopyBytes(from))
	}

	dst := vv.MarshalTo(nil)

	return dst, nil
}

func RlpEncodeAccessList(arena *fastrlp.Arena, vv *fastrlp.Value, list []AccessTuple) error {
	if len(list) == 0 {
		vv.Set(arena.NewNullArray())
	} else {
		ar1 := arena.NewArray()
		for _, at := range list {

			addr, err := hex.DecodeString(trimHex(at.Address))
			if err != nil {
				return err
			}

			ar2 := arena.NewArray()
			ar2.Set(arena.NewCopyBytes(addr))

			ar3 := arena.NewArray()
			for _, sKey := range at.StorageKeys {
				sk, err := hex.DecodeString(trimHex(sKey))
				if err != nil {
					return err
				}
				ar3.Set(arena.NewCopyBytes(sk))
			}
			ar2.Set(ar3)
		}
		vv.Set(ar1)
	}

	return nil
}

func sendRawTransaction(rlp []byte) (*SendRawTransactionResponse, error) {
	hexEncoded := hex.EncodeToString(rlp)
	tReq := SendRawTransactionRequest{
		Rlp: "0x" + hexEncoded,
	}
	fmt.Println("sending raw rlp", tReq.Rlp)

	var b []byte
	buf := bytes.NewBuffer(b)
	err := sendRawTransactionTemplate.Execute(buf, tReq)
	if err != nil {
		return nil, err
	}

	nextDestination := destinationIdx + 1
	if nextDestination >= len(dests)-1 {
		nextDestination = 0
	}

	fmt.Printf("sending tx to %s \n", dests[nextDestination])

	req, err := http.NewRequest("POST", dests[nextDestination], buf)
	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		return nil, err
	}
	destinationIdx = nextDestination

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var transactionRes SendRawTransactionResponse
	err = json.Unmarshal(bytes, &transactionRes)
	if err != nil {
		return nil, err
	}

	return &transactionRes, nil
}

func monitorForTransactions(hashes []string, searchFromBlock uint64) error {
	attempts := 0
	sleeps := 0
	var found []string
	for {
		// get the latest block and see we find any there
		b, err := getBlockResponse(searchFromBlock, dests[destinationIdx])
		if err != nil {
			return err
		}

		if b.Result == nil {
			time.Sleep(1 * time.Second)
			sleeps++
			if sleeps > 100 {
				return fmt.Errorf("block not found: %d", searchFromBlock)
			}
			continue
		}

		searchFromBlock++

		for _, tx := range b.Result.Transactions {
			for _, hash := range hashes {
				if tx == hash {
					found = append(found, hash)
				}
			}
		}

		if len(found) == len(hashes) {
			return nil
		}

		attempts++
		time.Sleep(1 * time.Second)
		if attempts > 200 {
			return fmt.Errorf("transactions not found: %v", hashes)
		}
	}
}

func getLatestDestinationBlock() (*GetBlockByNumberResponse, error) {
	r := GetBlockByNumberRequest{Number: "latest"}
	b, err := doBlockRequest(r, dests[destinationIdx])
	if err != nil {
		return nil, err
	}
	return b, nil
}
