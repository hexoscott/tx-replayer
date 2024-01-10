package main

const GetBlockByNumberTemplate = `
{
	"jsonrpc":"2.0",
	"method":"eth_getBlockByNumber",
	"params":[
		"{{ .Number }}", 
		false
	],
	"id":"1"
}
`

const GetTransactionByHashTemplate = `
{
	"jsonrpc":"2.0",
	"method":"eth_getTransactionByHash",
	"params":[
		"{{ .Hash }}"
	],
	"id":"1"
}
`

const SendRawTransactionTemplate = `{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["{{ .Rlp }}"],"id":1}`
