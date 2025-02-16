package main

import (
	"encoding/json"
	"gibrid_0/common"
	"gibrid_0/registerer/registerer"
	"log"
	"net/http"
)

func init() {
	data, err := common.In("registerer.json")
	if err != nil {
		log.Println("Ошибка чтения 'registerer.json':", err)
		return
	}

	err = json.Unmarshal([]byte(data), &registerer.Settings)
	if err != nil {
		log.Println("Ошибка декодирования настроек:", err)
		return
	}
}

func main() {
	http.HandleFunc("/reg", registerer.HandleRegister)
	http.HandleFunc("/account", registerer.ReturnAccount)

	log.Println("Сервер-регистратор запущен на", registerer.Settings.Addr)

	if registerer.Settings.TLS {
		err := http.ListenAndServeTLS(registerer.Settings.Addr, registerer.Settings.CertPath, registerer.Settings.KeyPath, nil)
		if err != nil {
			log.Fatal("Ошибка при запуске сервера-регистратора:", err)
		}
	} else {
		err := http.ListenAndServe(registerer.Settings.Addr, nil)
		if err != nil {
			log.Fatal("Ошибка при запуске сервера-регистратора:", err)
		}
	}
}
