package common

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

type EncryptedMessage struct {
	IV      string `json:"iv"`
	Key     string `json:"key"`
	Message string `json:"message"`
}

type AESEncryptedMessage struct {
	IV      []byte `json:"iv"`
	Message string `json:"message"`
}

func (msg AESEncryptedMessage) EncodeAESMessage() ([]byte, error) {
	return json.Marshal(msg)
}

func DecodeAESMessage(msg []byte) (AESEncryptedMessage, error) {
	var ret AESEncryptedMessage
	err := json.Unmarshal(msg, &ret)
	if err != nil {
		return ret, err
	}

	return ret, nil
}

func NewEncryptedMessage(jsonStr string) (EncryptedMessage, error) {
	var this EncryptedMessage

	err := json.Unmarshal([]byte(jsonStr), &this)
	if err != nil {
		log.Fatal(err)
		return this, err
	}

	return this, nil
}

func (msg EncryptedMessage) String() (string, error) {
	ret, err := json.Marshal(msg)
	if err != nil {
		return "", err
	}

	return string(ret), nil
}

func GenerateRandomString(length int) (string, error) {
	// Генерируем случайные байты
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Кодируем байты в строку Base64
	return strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(bytes)[:length], "/", "_"), nil
}

// Генерация пары ключей RSA
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privKey, &privKey.PublicKey, nil
}

// Кодирование приватного ключа в Base64
func EncodePrivateKey(priv *rsa.PrivateKey) string {
	privASN1 := x509.MarshalPKCS1PrivateKey(priv)
	return base64.StdEncoding.EncodeToString(privASN1)
}

// Кодирование публичного ключа в Base64
func EncodePublicKey(pub *rsa.PublicKey) string {
	pubASN1 := x509.MarshalPKCS1PublicKey(pub)
	return base64.StdEncoding.EncodeToString(pubASN1)
}

// Декодирование приватного ключа из Base64
func DecodePrivateKey(encoded string) (*rsa.PrivateKey, error) {
	privASN1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(privASN1)
}

// Декодирование публичного ключа из Base64
func DecodePublicKey(encoded string) (*rsa.PublicKey, error) {
	pubASN1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PublicKey(pubASN1)
}

// Функция для дополнения данных до размера блока
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Функция для удаления дополнения
func unpad(data []byte) ([]byte, error) {
	length := len(data)
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:(length - unpadding)], nil
}

// Шифрование сообщения с использованием AES
func encryptAES(key []byte, plaintext []byte) (string, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", nil, err
	}

	// Дополнение текста перед шифрованием
	paddedText := pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	return base64.StdEncoding.EncodeToString(ciphertext), iv, nil
}

// Расшифрование сообщения с использованием AES
func decryptAES(key []byte, ciphertext string, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertextBytes, _ := base64.StdEncoding.DecodeString(ciphertext)
	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertextBytes))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertextBytes)

	// Удаление дополнения после расшифрования
	return unpad(plaintext)
}

// Шифрование AES ключа с использованием RSA
func encryptRSA(pub *rsa.PublicKey, aesKey []byte) (string, error) {
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedKey), nil
}

// Расшифрование AES ключа с использованием RSA
func decryptRSA(priv *rsa.PrivateKey, encryptedKey string) ([]byte, error) {
	encryptedKeyBytes, _ := base64.StdEncoding.DecodeString(encryptedKey)
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encryptedKeyBytes, nil)
}

func Encrypt(pk *rsa.PublicKey, str []byte) (string, error) {
	aesKey, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	encryptedKey, err := encryptRSA(pk, []byte(aesKey))
	if err != nil {
		return "", err
	}

	encryptedStr, iv, err := encryptAES([]byte(aesKey), str)
	if err != nil {
		return "", err
	}

	// Кодируем IV в Base64 и формируем JSON
	encryptedMessage := EncryptedMessage{
		Key:     encryptedKey,
		IV:      base64.StdEncoding.EncodeToString(iv), // Кодируем IV
		Message: encryptedStr,
	}

	jsonResult, err := json.Marshal(encryptedMessage)
	if err != nil {
		return "", err
	}

	return string(jsonResult), nil
}

func Decrypt(sk *rsa.PrivateKey, str string) (string, error) {
	encryptedMessage, err := NewEncryptedMessage(str)
	if err != nil {
		return "", err
	}

	aesKey, err := decryptRSA(sk, encryptedMessage.Key)
	if err != nil {
		return "", err
	}

	// Декодируем IV из Base64
	ivBytes, err := base64.StdEncoding.DecodeString(encryptedMessage.IV)
	if err != nil {
		return "", err
	}

	decryptedMessage, err := decryptAES(aesKey, encryptedMessage.Message, ivBytes)
	if err != nil {
		return "", err
	}

	return string(decryptedMessage), nil
}

func EncryptAES(key, msg []byte) (AESEncryptedMessage, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return AESEncryptedMessage{}, err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return AESEncryptedMessage{}, err
	}

	// Дополнение текста перед шифрованием
	paddedText := pad(msg, aes.BlockSize)
	ciphertext := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedText)

	return AESEncryptedMessage{
		Message: base64.StdEncoding.EncodeToString(ciphertext),
		IV:      iv,
	}, err
}

func DecryptAES(key []byte, msg AESEncryptedMessage) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	ciphertextBytes, _ := base64.StdEncoding.DecodeString(msg.Message)
	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertextBytes))
	mode := cipher.NewCBCDecrypter(block, msg.IV)
	mode.CryptBlocks(plaintext, ciphertextBytes)

	// Удаление дополнения после расшифрования
	return unpad(plaintext)
}

// Создание цифровой подписи
func CreateSignature(priv *rsa.PrivateKey, message []byte) (string, error) {
	hash := sha256.New()
	hash.Write(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// Проверка цифровой подписи
func VerifySignature(pub *rsa.PublicKey, message []byte, signature string) error {
	hash := sha256.New()
	hash.Write(message)
	signatureBytes, _ := base64.StdEncoding.DecodeString(signature)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash.Sum(nil), signatureBytes)
}

/*
func test() {
	// Генерация ключей
	privKey, pubKey, err := GenerateKeyPair(2048)
	if err != nil {
		fmt.Println("Ошибка генерации ключей:", err)
		return
	}

	encrypted, err := Encrypt(pubKey, []byte("Привет, Россия!")); if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Зашифрованное сообщение:", encrypted)

	decrypted, err := Decrypt(privKey, encrypted); if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("Расшифрованное сообщение:", decrypted)
}
*/

func In(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func Out(path, str string) error {
	err := ioutil.WriteFile(path, []byte(str), 0644) // Записываем в файл
	if err != nil {
		return err
	}

	return nil
}

func Get(url string) (string, string, error) {
	// Отправляем GET-запрос
	resp, err := http.Get(url)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() // Закрываем тело ответа после завершения работы

	// Проверяем статус ответа
	if resp.StatusCode != http.StatusOK {
		return "", resp.Status, fmt.Errorf("server returned non-200 status: %s", resp.Status)
	}

	// Читаем ответ
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	return string(body), resp.Status, nil
}

func Post(url string, data []byte) (string, string, error) {
	// Отправляем POST-запрос
	resp, err := http.Post(url, "text/plain", bytes.NewBuffer(data))
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close() // Закрываем тело ответа после завершения работы

	// Читаем ответ
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	return string(body), resp.Status, nil
}

// Принимает строку и возвращает её хеш в виде строки
func Sha(message string) string {
	// Создаем новый хеш
	hash := sha256.New()

	// Записываем сообщение в хеш
	hash.Write([]byte(message))

	// Получаем хеш в виде байтового среза
	hashInBytes := hash.Sum(nil)

	// Преобразуем байты в строку в формате hex
	return hex.EncodeToString(hashInBytes)
}

// EncodeToBase64 кодирует входную строку в Base64.
func StringToB64(input string) string {
	// Преобразуем строку в байтовый массив
	data := []byte(input)

	// Кодируем данные в Base64
	encoded := base64.StdEncoding.EncodeToString(data)

	return encoded
}

// Функция для декодирования строки из Base64
func B64ToString(encodedStr string) (string, error) {
	// Декодируем строку
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return "", err // Возвращаем ошибку, если декодирование не удалось
	}
	return string(decodedBytes), nil // Возвращаем декодированную строку
}

// Кодирует входной вектор байт в Base64.
func BytesToB64(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

// Функция для декодирования вектора байт из Base64
func B64ToBytes(encodedStr string) ([]byte, error) {
	decodedBytes, err := base64.StdEncoding.DecodeString(encodedStr)
	if err != nil {
		return nil, err // Возвращаем ошибку, если декодирование не удалось
	}
	return decodedBytes, nil // Возвращаем декодированную строку
}

/*func sync_cmd(command string, arguments ...string) error {
	// Команда, которую вы хотите запустить
	cmd := exec.Command(command, arguments...) // Замените на вашу команду и аргументы

	// Устанавливаем вывод команды в stdout и stderr текущего процесса
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Запускаем команду и ждем её завершения
	err := cmd.Run()
	if err != nil {
		return err
	}

	return nil
}*/

func CountFilesInDirectory(dir string) (int, error) {
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() { // Проверяем, что это не директория
			count++
		}
	}
	return count, nil
}
