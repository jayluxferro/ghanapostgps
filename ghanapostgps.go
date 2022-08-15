package ghanapostgps

import (
  "io/ioutil"
  "net/http"
  "net/url"
  "strings"
  "fmt"
)

const (
  BaseAPIURL = "https://api.ghanapostgps.com/v2/PublicGPGPSAPI.aspx"
)
var (
  HeaderByPass = []string {"Base-Url", "Client-IP", "Http-Url", "Proxy-Host", "Proxy-Url", "Real-Ip", "Redirect",
            "Referer", "Referrer", "Refferer", "Request-Uri", "Uri", "Url", "X-Client-Ip", "X-Forwarded-For",
            "Cf-Connecting-Ip", "X-Client-IP", "X-Custom-IP-Authorization", "X-Forward-For", "X-Forwarded-By",
            "X-Forwarded-By-Original", "X-Forwarded-For-Original", "X-Forwarded-For", "X-Forwarded-Host",
            "X-Forwarded-Server", "X-Forwarder-For", "X-HTTP-Destinationurl", "X-Http-Host-Override",
            "X-Original-Remote-Addr", "X-Original-Url", "X-Originating-IP", "X-Proxy-Url", "X-Remote-Addr",
            "X-Remote-IP", "X-Rewrite-Url", "X-True-IP", "Fastly-Client-Ip", "True-Client-Ip", "X-Cluster-Client-Ip",
            "X-Forwarded", "Forwarded-For", "Forwarded", "X-Real-Ip"}
)

type Params struct {
	ApiURL         string
	Authorization  string
	AsaaseUser		 string
	LanguageCode   string
	Language       string
	DeviceId			 string
	AndroidCert    string
	AndroidPackage string
	Country        string
	CountryName    string
}

func GetAPIKeys(params *Params) string {
  envData := `GPGPS_apiURL="` + params.ApiURL + `"\n` +
`GPGPS_authorization="` + params.Authorization + `"\n` +
`GPGPS_asaaseUser="` + params.AsaaseUser + `"\n` + 
`GPGPS_languageCode="` + params.LanguageCode + `"\n` +
`GPGPS_language="` + params.Language + `"\n` +
`GPGPS_deviceId="` + params.DeviceId + `"\n` +
`GPGPS_androidCert="` + params.AndroidCert + `"\n` +
`GPGPS_androidPackage="` + params.AndroidPackage + `"\n` +
`GPGPS_countryName="` + params.CountryName + `"\n` +
`GPGPS_country="` + params.Country + `"`
	return envData
}

func APIRequest(method string, params *Params, payload *strings.Reader) string {
	client := &http.Client{}
	req, err := http.NewRequest(method, params.ApiURL, payload)

	if err != nil {
		print(err)
	}

	req.Header.Add("Authorization", "Basic " + params.Authorization)
	req.Header.Add("LanguageCode", params.LanguageCode)
	req.Header.Add("Language", params.Language)
	req.Header.Add("CountryName", params.CountryName)
	req.Header.Add("DeviceId", params.DeviceId)
	req.Header.Add("X-Android-Cert", params.AndroidCert)
	req.Header.Add("AsaaseUser", params.AsaaseUser)
	req.Header.Add("Country", params.Country)
	req.Header.Add("X-Android-Package", params.AndroidPackage)
	req.Header.Add("X-Android-Package", params.AndroidPackage)
	for _, h := range HeaderByPass {
		req.Header.Add(h, "127.0.0.1")
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	body, err := ioutil.ReadAll(res.Body)

	defer res.Body.Close()

	return string(body)
}

func GetLocation(code string, defaults *Params) string {
	params := url.Values{
		"AsaaseLogs": {""},
		"Action":     {"GetLocation"},
		"GPSName":    {code},
	}
	dataRequest := GetDataRequest(&params, defaults)
	return APIRequest("POST", defaults, dataRequest)
}

func GetDataRequest(v *url.Values, defaults *Params) *strings.Reader {
	return strings.NewReader(v.Encode())
}

func Print(data ...interface{}) (n int, err error) {
	return fmt.Println(data...)
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
	return APIRequest("POST", defaults, dataRequest)
}

func FormatString(address string) string {
  return strings.Join(strings.Split(strings.ToUpper(strings.Trim(address, "")), "-"), "")
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
