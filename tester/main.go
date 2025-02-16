package main

import (
	"flag"
	"gibrid_0/app"
	"gibrid_0/common"
	"log"
)

func main() {
	do := flag.String("do", "", "")
	flag.Parse()

	if *do == "reg" {
		log.Println("Генерация ключей...")

		sk, pk, err := common.GenerateKeyPair(2048)
		if err != nil {
			log.Fatal("Ошибка генерации ключей:", err)
		}

		req := app.Account{
			Data: struct {
				Meta struct {
					Name    string `json:"name"`
					Surname string `json:"surname"`
				} `json:"meta"`
				Pk64            string `json:"pk64"`
				EncryptedSk64   string `json:"sk64"`
				EncryptedSk64IV string `json:"skiv"`
			}{
				Meta: struct {
					Name    string `json:"name"`
					Surname string `json:"surname"`
				}{
					Name:    "Вася",
					Surname: "Костыль",
				},
				Pk64: common.EncodePublicKey(pk),
			},
			Signature: "",
		}

		sk64 := common.EncodePrivateKey(sk)

		password, err := common.GenerateRandomString(16)
		if err != nil {
			log.Fatal(err)
		}

		encryptedSK, err := common.EncryptAES([]byte(password), []byte(sk64))
		if err != nil {
			log.Fatal(err)
		}

		req.Data.EncryptedSk64 = encryptedSK.Message
		req.Data.EncryptedSk64IV = common.BytesToB64(encryptedSK.IV)

		dat, err := req.DataToBytea()
		if err != nil {
			log.Fatal(err)
		}

		req.Signature, err = common.CreateSignature(sk, dat)
		if err != nil {
			log.Fatal(err)
		}

		req_text, err := req.Bytea()
		if err != nil {
			log.Fatal(err)
		}

		log.Println("Отправка запроса...")
		log.Println(common.Post("http://localhost:4097/reg", req_text))

		/*log.Println("Тестовое получение аккаунта...")
		fmt.Println(common.Get("http://localhost:4097/account?id=" + common.Sha(req.Data.Pk64)))*/
	}
}
