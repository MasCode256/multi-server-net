package main

import (
	"encoding/json"
	"gibrid_0/app"
	"gibrid_0/common"
	"gibrid_0/filebase/filebase"
	"log"
	"net/http"
)

func init() {
	data, err := common.In("json")
	if err != nil {
		log.Println("Ошибка чтения 'json':", err)
		return
	}

	err = json.Unmarshal([]byte(data), &filebase.Settings)
	if err != nil {
		log.Println("Ошибка декодирования настроек:", err)
		return
	}
}

func main() {
	http.HandleFunc("/protocol", app.ProtocolHandler)

	log.Println("Сервер-хранитель запущен на", filebase.Settings.Addr)

	if filebase.Settings.TLS {
		err := http.ListenAndServeTLS(filebase.Settings.Addr, filebase.Settings.CertPath, filebase.Settings.KeyPath, nil)
		if err != nil {
			log.Fatal("Ошибка при запуске сервера-хранителя:", err)
		}
	} else {
		err := http.ListenAndServe(filebase.Settings.Addr, nil)
		if err != nil {
			log.Fatal("Ошибка при запуске сервера-хранителя:", err)
		}
	}
}
