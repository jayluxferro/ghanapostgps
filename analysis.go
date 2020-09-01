package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	mrand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiurlString = "https://api.ghanapostgps.com/GetAPIData.aspx"
const APIKey = "bn$l9k8avhp954pr"
const UUID = "40606d07-9a1b-493b-b60d-9bde85ddedad"
const pubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlO6O2gAGlT4+YP+evP9c9qynWdv/qIAx5Jc4kp+UTmrsn8wJn4bD9H8rynSvepH0navZiDwYvioAPbIcR6cGMMFnP5/2wN9zrBFZtnofcpSrk4q9/GRHj4IuHheQjvMiislrRdIEgqxjMQ1aaiG7+MeoeQuHz08O+aecHuMtJTXzcIQDqkMHkeA/yt/ge/ASDqSRn0Hdpa/4OA/ZtVpT8Ph2lLgMv+O5Iz11UIwSqyewSdAZzX0H4jUPKCCfnhgWsS+7WJU6KufYptvl0/P4NSdJKSdYg/y44pWiPxlgMUf6s1nOXJJ0vSi0zrDFjx+y+GD2h+dMBRWe9nym+NmJ1QIDAQAB"

const APIData = "TiJ/O4d2rFzaR046lLMYBJ6yU3e+vqDjkrYNVrhFm9K+jLXbMzTB6xAdtz/f/Rx+Nyw5ZB64ok3v8MRJq9jf8NwpYeFQZUGR0UzMmgEgYR3MlAgFz7vRkQt0GGt/BwEaK081PJKxnqVqqXjr3NqNbfJr3GDDkfIfVKT4xOZRZbcCFdPpDD6Ofb5RD7mL8LQLvwOPOUVq3+/MlNDVhxOD4Osq0PqWh8CvrZY8y2Q1sDJYDTUsKFn0ChxFNtJhso1ImtqLBkNFZbrWUXn6NbHV+p3HBJVeZNcJxlWPPHaBh8Ip7qPOnnMww4ZXWC88/tWTlScFemwTcyGpT58T9rMySA=="

var APIDataResponse = "\"IVhUP3lIMjJxc3lgR0ZNcbwZEDugNX4tz9oLIhEjHrvw/UnpTDovfZPlFQKqw+gaTSVDhDB7HThhNUXy0qPKhAyGQ+rlmRBKnf3HG3i3nFXS1xGJXsyI2I6a1Tn+lqCT\""

const ALLOWED_CHARACTERS = "0123456789qwertyuiopasdfghjklzxcvbnm!@$#^&*()"
const APIDataResponseDecrypted = "PlsUseYourOwnKey||https://api.ghanapostgps.com/PublicGPGPSAPI.aspx"
const AsaaseApi = "VGgxcyAhcyBOI3cgQG5kcjBpNiA4cypy"
const Language = "English"
const AndroidCert = "49:DD:00:18:04:D3:47:D0:77:44:A0:B3:93:47:4F:BE:B6:7E:D7:67"
const AndroidPackage = "com.ghanapostgps.ghanapost"
const LanguageCode = "en"
const Country = "GH"
const CountryName = "Ghana"
const STR_SEC_SYMBOL = "\""
const APIAndroidKey = "PlsUseYourOwnKey"
const APIURL = "https://api.ghanapostgps.com/PublicGPGPSAPI.aspx"
const PHONE = "233545283614"
const locationTest = "AK3849328"
const lat = "6.6726548"
const lon = "-1.5724652"

func main() {
	print(GPGPSDecrypt(GetAddress(lat, lon)))
	//print(GPGPSDecrypt(GetLocation("katanga hall")))
}

func GetAddress(latitude string, longitude string) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetGPSName"},
		"Lati":       {latitude},
		"Longi":      {longitude},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func GetLocation(code string) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetLocation"},
		"GPSName":    {code},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func GetUserAddress() string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetUserAddress"},
		"MSISDN":     {PHONE},
		"DeviceID":   {UUID},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func SIPDetails() string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetSIPDetails"},
		"MSISDN":     {PHONE},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func AddCustomer() string {
	params := url.Values{
		"AsaaseLogs":   {""},
		"Action":       {"AddCustomer"},
		"FirstName":    {"KK"},
		"LastName":     {"KK"},
		"MobileNumber": {PHONE},
		"Msisdn":       {PHONE},
		"IMSI":         {UUID},
		"IMEI":         {UUID},
		"DeviceID":     {UUID},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func verifySMS(code string) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"VerifyCode"},
		"GPSName":    {code},
		"MSISDN":     {PHONE},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func sendLoginSMS() string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"SendSMS"},
		"GPSName":    {PHONE},
	}
	dataRequest := getDataRequest(&params)
	return apiRequest("POST", APIURL, dataRequest)
}

func getDataRequest(v *url.Values) *strings.Reader {
	data := GPGPSEncrypt(v.Encode())
	params := url.Values{
		"DataRequest": {data},
	}
	return strings.NewReader(params.Encode() + "&")
}

func getPublicAPI() string {
	v := url.Values{}
	v.Set("ApiData", APIData)
	return GPGPSDecrypt(strings.ReplaceAll(apiRequest("GET", apiurlString+"?"+v.Encode(), strings.NewReader("")), STR_SEC_SYMBOL, ""))
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

func print(data ...interface{}) (n int, err error) {
	return fmt.Println(data...)
}

func GPGPSEncrypt(data string) string {
	decryptionKey := []byte(APIKey)
	iv := []byte(RandomString(len(decryptionKey)))
	encryptedMsg := AESEncrypt(iv, decryptionKey, data)
	payload := []byte{}
	payload = append(payload, iv...)
	payload = append(payload, encryptedMsg...)
	// encode payload to base64

	return base64.StdEncoding.EncodeToString(payload)
}

func GPGPSDecrypt(encodedData string) string {
	decodedData, _ := base64.StdEncoding.DecodeString(encodedData)
	// remove IV (16 byte)
	decryptionKey := []byte(APIKey)
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

func apiRequest(method string, url string, payload *strings.Reader) string {
	//print(method, url, payload)
	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	if err != nil {
		print(err)
	}
	req.Header.Add("Language", Language)
	req.Header.Add("X-Android-Cert", AndroidCert)
	req.Header.Add("X-Android-Package", AndroidPackage)
	req.Header.Add("DeviceID", UUID)
	req.Header.Add("LanguageCode", LanguageCode)
	req.Header.Add("Country", Country)
	req.Header.Add("CountryName", CountryName)
	req.Header.Add("AsaaseUser", AsaaseApi)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")

	res, err := client.Do(req)
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)

	return string(body)
}

func getIdRsaPubFromStr(keyStr string) *rsa.PublicKey {
	// key is base64 encoded
	data, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		log.Printf("ERROR: fail get rsapub, %s", err.Error())
		return nil
	}

	// this for ios key
	var pubKey rsa.PublicKey
	if rest, err := asn1.Unmarshal(data, &pubKey); err != nil {
		log.Printf("INFO: not ios key", keyStr)
	} else if len(rest) != 0 {
		log.Printf("INFO: not ios key, invalid length, %s", keyStr)
	} else {
		return &pubKey
	}

	// this is for android
	// get rsa public key
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		log.Printf("INFO: not android key, %s", keyStr)
		return nil
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub
	default:
		return nil
	}

	return nil
}

func RSAEncrypt(payload string, publicKey *rsa.PublicKey) (string, error) {
	// params
	msg := []byte(payload)
	rnd := rand.Reader

	// encrypt with PKCS1v15
	ciperText, err := rsa.EncryptPKCS1v15(rnd, publicKey, msg)
	if err != nil {
		log.Printf("ERROR: fail to encrypt, %s", err.Error())
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciperText), nil
}

func getRSADataToBeEncrypted() string {
	return "Android||" + UUID + "||" + APIKey
}
