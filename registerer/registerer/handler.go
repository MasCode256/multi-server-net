package registerer

import (
	"encoding/json"
	"fmt"
	"gibrid_0/app"
	"gibrid_0/common"
	"log"
	"net/http"
)

func HandleRegister(w http.ResponseWriter, r *http.Request) {
	// Убедитесь, что это POST-запрос
	if r.Method != http.MethodPost {
		if Settings.LogErrors {
			log.Println("Ошибка при регистрации пользователя: регистрация поддерживается только через метод 'POST'.")
		}
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Декодируйте JSON из тела запроса
	var data app.Account
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&data)
	if err != nil {
		if Settings.LogErrors {
			log.Println("Неудачная регистрация пользователя: ошибка декодирования данных:", err)
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Обработка данных
	//log.Printf("Received: %+v", data)

	user_pk, err := common.DecodePublicKey(data.Data.Pk64)
	if err != nil {
		if Settings.LogErrors {
			log.Println("Неудачная регистрация пользователя: ошибка декодирования публичного ключа:", err)
		}
		http.Error(w, err.Error(), 500)
		return
	}

	if dat, err := data.DataToBytea(); err == nil {
		if err := common.VerifySignature(user_pk, dat, data.Signature); err == nil {
			if dat, err := data.Bytea(); err == nil {
				if len(dat) < Settings.MaxFileSize {
					if accounts, err := common.CountFilesInDirectory("db/accounts"); err == nil {
						if accounts < Settings.MaxAccountsCount || Settings.MaxAccountsCount <= 0 {
							if err := common.Out("db/accounts/"+common.Sha(data.Data.Pk64), string(dat)); err == nil {
								if Settings.LogSuccess {
									log.Println("Пользователь", data.Data.Meta.Name, data.Data.Meta.Surname, "успешно зарегистрирован.", func() string {
										if Settings.MaxAccountsCount > 0 {
											return "Осталось свободного места: " + fmt.Sprint(Settings.MaxAccountsCount-(accounts+1)) + " ( использовано: " + fmt.Sprint(accounts+1) + " / " + fmt.Sprint(Settings.MaxAccountsCount) + " )"
										}
										return ""
									}())
								}
								w.Write([]byte{'1'})
								return
							} else {
								if Settings.LogErrors {
									log.Println("Неудачная регистрация пользователя: ошибка записи в файл (", "db/accounts/"+data.Data.Pk64, "):", err)
								}
								http.Error(w, "Error writing to file", 500)
								return
							}
						} else {
							if Settings.LogErrors {
								log.Println("Неудачная регистрация пользователя: слишком много аккаунтов зарегистрировано ( максимум:", accounts, ")")
							}
							http.Error(w, "Too many users registered", 500)
							return
						}
					} else {
						if Settings.LogErrors {
							log.Println("Неудачная регистрация пользователя: ошибка проверки кол-ва аккаунтов:", err)
						}
						http.Error(w, "Server filesystem error", 500)
						return
					}
				} else {
					if Settings.LogErrors {
						log.Println("Неудачная регистрация пользователя: слишком большой файл (", len(dat), ">", Settings.MaxFileSize, ")")
					}
					http.Error(w, "Too big file", 400)
					return
				}
			} else {
				if Settings.LogErrors {
					log.Println("Неудачная регистрация пользователя: ошибка преобразования структуры в текст:", err)
				}
				http.Error(w, "Encoding error", 500)
				return
			}
		} else {
			if Settings.LogErrors {
				log.Printf("%#v", data)
				log.Println("Неудачная регистрация пользователя: неверная подпись:", err)
			}
			http.Error(w, "Invalid signature", 400)
			return
		}
	} else {
		if Settings.LogErrors {
			log.Println("Неудачная регистрация пользователя: ошибка декодирования данных:", err)
		}
		http.Error(w, "Error decoding data", 500)
		return
	}
}

func ReturnAccount(w http.ResponseWriter, r *http.Request) {
	if dat, err := common.In("db/accounts/" + r.URL.Query().Get("id")); err == nil {
		w.Write([]byte(dat))
	} else {
		http.Error(w, "Account not founded", 404)
	}
}
