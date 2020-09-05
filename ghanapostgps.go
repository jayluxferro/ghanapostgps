package ghanapostgps


import (
	"strings"
	"net/http"
  "io/ioutil"
  "net/url"
	mrand "math/rand"
  "time"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

const  (
  ALLOWED_CHARACTERS = "0123456789qwertyuiopasdfghjklzxcvbnm!@$#^&*()"
)

type params struct {
  apiKey          string
  uuid            string
  apiURL          string
  asaaseAPI       string
  language        string
  languageCode    string
  androidCert     string
  androidPackage  string
  country         string
  countryName     string
}

func APIRequest(method string, params *params, payload *strings.Reader) string {
	client := &http.Client{}
	req, err := http.NewRequest(method, params.apiURL, payload)

	if err != nil {
		print(err)
	}
	req.Header.Add("Language", params.language)
	req.Header.Add("X-Android-Cert", params.androidCert)
	req.Header.Add("X-Android-Package", params.androidPackage)
	req.Header.Add("DeviceID", params.uuid)
	req.Header.Add("LanguageCode", params.languageCode)
	req.Header.Add("Country", params.country)
	req.Header.Add("CountryName", params.countryName)
	req.Header.Add("AsaaseUser", params.asaaseAPI)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	res, err := client.Do(req)
	body, err := ioutil.ReadAll(res.Body)
	
  defer res.Body.Close()

	return string(body)
}

func RandomString(number int) string {
	allowedCharacters := []byte(ALLOWED_CHARACTERS)
	data := make([]byte, number)
	mrand.Seed(time.Now().UnixNano())
	for i := 0; i < number; i++ {
		data[i] = allowedCharacters[mrand.Intn(len(allowedCharacters))]
	}
	return string(data)
}

func GetLocation(code string, defaults *params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetLocation"},
		"GPSName":    {code},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

func GetDataRequest(v *url.Values, defaults *params) *strings.Reader {
	data := GPGPSEncrypt(v.Encode(), defaults)
	params := url.Values{
		"DataRequest": {data},
	}
	return strings.NewReader(params.Encode() + "&")
}

func GPGPSEncrypt(data string, params *params) string {
	decryptionKey := []byte(params.apiKey)
	iv := []byte(RandomString(len(decryptionKey)))
	encryptedMsg := AESEncrypt(iv, decryptionKey, data)
	payload := []byte{}
	payload = append(payload, iv...)
	payload = append(payload, encryptedMsg...)
	// encode payload to base64

	return base64.StdEncoding.EncodeToString(payload)
}

func GPGPSDecrypt(encodedData string, params *params) string {
	decodedData, _ := base64.StdEncoding.DecodeString(encodedData)
	// remove IV (16 byte)
	decryptionKey := []byte(params.apiKey)
	iv := decodedData[:len(decryptionKey)]
	msg := decodedData[len(decryptionKey):]

	return string(AESDecrypt(iv, decryptionKey, msg))
}

func AESEncrypt(iv []byte, key []byte, src string) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		print("key error1", err)
	}

	if src == "" {
		print("plain content empty")
	}
	ecb := cipher.NewCBCEncrypter(block, iv)
	content := []byte(src)
	content = PKCS5Padding(content, block.BlockSize())
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)

	return crypted
}

func AESDecrypt(iv []byte, key []byte, crypt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		print("key error1", err)
	}
	if len(crypt) == 0 {
		print("plain content empty")
	}
	ecb := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)

	return PKCS5Trimming(decrypted)
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}

func CheckError(err error) {
	if err != nil {
		panic(err)
	}
}