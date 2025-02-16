package app

import (
	"encoding/json"
	"net/http"
)

var ProtocolName = []byte("lumentro-0.1")

func ProtocolHandler(w http.ResponseWriter, r *http.Request) {
	w.Write(ProtocolName)
}

type Account struct {
	Data struct {
		Meta struct {
			Name    string `json:"name"`
			Surname string `json:"surname"`
		} `json:"meta"`
		Pk64            string `json:"pk64"`
		EncryptedSk64   string `json:"sk64"`
		EncryptedSk64IV string `json:"skiv"`
	} `json:"data"`
	Signature string `json:"sign"`
}

func (req Account) DataToBytea() ([]byte, error) {
	return json.Marshal(req.Data)
}

func (req Account) Bytea() ([]byte, error) {
	return json.Marshal(req)
}
