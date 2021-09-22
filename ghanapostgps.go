package ghanapostgps

import (
  "bytes"
  "crypto/aes"
  "crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"log"
  "encoding/base64"
  "io/ioutil"
  mrand "math/rand"
  "net/http"
  "net/url"
  "strings"
  "time"
  "fmt"
	"github.com/google/uuid"
)

const (
  BaseAPIURL = "https://api.ghanapostgps.com/GetAPIData.aspx"
	ALLOWED_CHARACTERS = "0123456789qwertyuiopasdfghjklzxcvbnm!@$#^&*()"
	STR_SEC_SYMBOL = "\""
	PUB_KEY_START = "-----BEGIN PUBLIC KEY-----"
	PUB_KEY_END = "-----END PUBLIC KEY-----"
)


type Params struct {
	ApiKey         string
	UUID           string
	ApiURL         string
	AsaaseAPI      string
	Language       string
	LanguageCode   string
	AndroidCert    string
	AndroidPackage string
	Country        string
	CountryName    string
}

func GetAPIKeys(params *Params) string {
  // Get public key
  pubKey := GetPublicAPIKey(params)

  // Get payload to be encrypted using RSA
  initPayload := GetRSADataToBeEncrypted(params.UUID, params.ApiKey)

  // Getting RSA Public key
  rsaPubKey := GetIdRsaPubFromStr(pubKey)

  encPayload, err := RSAEncrypt(initPayload, rsaPubKey)
  if err == nil {
    // send encPayload to server
    params.ApiURL = BaseAPIURL
    res := strings.Split(GetPublicAPI(encPayload, params), "||")

    if len(res) == 2 {
      params.ApiURL = res[1]
      envData := `GPGPS_apiKey="` + params.ApiKey + `"
GPGPS_uuid="` + params.UUID + `"
GPGPS_apiURL="` + params.ApiURL + `"
GPGPS_asaaseAPI="` + params.AsaaseAPI + `"
GPGPS_language="` + params.Language + `"
GPGPS_languageCode="` + params.LanguageCode + `"
GPGPS_androidCert="` + params.AndroidCert + `"
GPGPS_androidPackage="` + params.AndroidPackage + `"
GPGPS_country="` + params.Country + `"
GPGPS_countryName="` + params.CountryName + `"`

			// envData
			return envData
    }
  }
	return ""
}

func APIRequest(method string, params *Params, payload *strings.Reader) string {
	client := &http.Client{}
	req, err := http.NewRequest(method, params.ApiURL, payload)

	if err != nil {
		print(err)
	}

	req.Header.Add("Language", params.Language)
	req.Header.Add("X-Android-Cert", params.AndroidCert)
	req.Header.Add("X-Android-Package", params.AndroidPackage)
	req.Header.Add("DeviceID", params.UUID)
	req.Header.Add("LanguageCode", params.LanguageCode)
	req.Header.Add("Country", params.Country)
	req.Header.Add("CountryName", params.CountryName)
	req.Header.Add("AsaaseUser", params.AsaaseAPI)
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

func GetLocation(code string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetLocation"},
		"GPSName":    {code},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return GPGPSDecrypt(APIRequest("POST", defaults, dataRequest), defaults)
}

func GetDataRequest(v *url.Values, defaults *Params) *strings.Reader {
	data := GPGPSEncrypt(v.Encode(), defaults)
	params := url.Values{
		"DataRequest": {data},
	}
	return strings.NewReader(params.Encode() + "&")
}

func Print(data ...interface{}) (n int, err error) {
	return fmt.Println(data...)
}

func GetPublicAPI(clientDeviceData string, params *Params) string {
	v := url.Values{}
	v.Set("ApiData", clientDeviceData)
	params.ApiURL = params.ApiURL + "?" + v.Encode() + "&"
	return GPGPSDecrypt(strings.ReplaceAll(APIRequest("GET", params, strings.NewReader("")), STR_SEC_SYMBOL, ""), params)
}

func GPGPSEncrypt(data string, params *Params) string {
	decryptionKey := []byte(params.ApiKey)
	iv := []byte(RandomString(len(decryptionKey)))
	encryptedMsg := AESEncrypt(iv, decryptionKey, data)
	payload := []byte{}
	payload = append(payload, iv...)
	payload = append(payload, encryptedMsg...)
	// encode payload to base64

	return base64.StdEncoding.EncodeToString(payload)
}

func GPGPSDecrypt(encodedData string, params *Params) string {
	decodedData, _ := base64.StdEncoding.DecodeString(encodedData)
	// remove IV (16 byte)
	decryptionKey := []byte(params.ApiKey)
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

func IsValidGPAddress(address string) (bool, string){
  isValid := true
  address = FormatString(address)

  if len(address) < 9 {
    isValid = false
  }

  return isValid, address
}

func GetAddress(latitude string, longitude string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetGPSName"},
		"Lati":       {latitude},
		"Longi":      {longitude},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return GPGPSDecrypt(APIRequest("POST", defaults, dataRequest), defaults)
}

func FormatString(address string) string {
  return strings.Join(strings.Split(strings.ToUpper(strings.Trim(address, "")), "-"), "")
}

func GetRSADataToBeEncrypted(uuid string, aesKey string) string {
	return "Android||" + uuid + "||" + aesKey
}

func GetPublicAPIKey(params *Params) string {
	res := APIRequest("GET", params, strings.NewReader(""))
	res = strings.ReplaceAll(res, "\n", "")
	res = strings.ReplaceAll(res, PUB_KEY_START, "")
	res = strings.ReplaceAll(res, PUB_KEY_END, "")
	return strings.ToValidUTF8(res, "")
}

func UUID() string {
	return uuid.New().String()
}

func GetIdRsaPubFromStr(keyStr string) *rsa.PublicKey {
	// key is base64 encoded
	data, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil {
		log.Printf("ERROR: fail get rsapub, %s", err.Error())
		return nil
	}

	// this for ios key
	var pubKey rsa.PublicKey
	if rest, err := asn1.Unmarshal(data, &pubKey); err != nil {
		//log.Printf("INFO: not ios key", keyStr)
		fmt.Print("")
	} else if len(rest) != 0 {
		//log.Printf("INFO: not ios key, invalid length, %s", keyStr)
		fmt.Print("")
	} else {
		return &pubKey
	}

	// this is for android
	// get rsa public key
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		//log.Printf("INFO: not android key, %s", keyStr)
		return nil
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub
	default:
		return nil
	}
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


func getUserAddress(phone string, uuid string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetUserAddress"},
		"MSISDN":     {phone},
		"DeviceID":   {uuid},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

func sipDetails(phone string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetSIPDetails"},
		"MSISDN":     {phone},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

func addCustomer(firstName string, lastName string, phone string, uuid string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs":   {""},
		"Action":       {"AddCustomer"},
		"FirstName":    {firstName},
		"LastName":     {lastName},
		"MobileNumber": {phone},
		"Msisdn":       {phone},
		"IMSI":         {phone},
		"IMEI":         {phone},
		"DeviceID":     {uuid},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

func verifySMS(phone string, code string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"VerifyCode"},
		"GPSName":    {code},
		"MSISDN":     {phone},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

func sendLoginSMS(phone string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"SendSMS"},
		"GPSName":    {phone},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

