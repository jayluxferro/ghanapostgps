package main

import (
	gp "ghanapostgps"
	"github.com/joho/godotenv"
	"os"
	"log"
)

func main() {
	//load .env file
	err := godotenv.Load(".env")

	if err != nil {
			log.Fatal("Error loading .env file")
	}

	// init
	params := gp.Params{}
	prefix := "GPGPS_"
	params = gp.Params{}
	params.ApiURL = os.Getenv(prefix + "apiURL")
	params.Authorization = os.Getenv(prefix + "authorization")
	params.AsaaseUser = os.Getenv(prefix + "asaaseUser")
	params.LanguageCode = os.Getenv(prefix + "languageCode")
	params.Language = os.Getenv(prefix + "language")
	params.DeviceId = os.Getenv(prefix + "deviceId")
	params.AndroidCert = os.Getenv(prefix + "androidCert")
	params.AndroidPackage = os.Getenv(prefix + "androidPackage")
	params.CountryName = os.Getenv(prefix + "countryName")
	params.Country = os.Getenv(prefix + "country")

	gp.Print(gp.GetAPIKeys(&params))

	gp.Print(gp.GetAddress("5.551176", "-0.271404", &params))

	gp.Print(gp.GetLocation("AK-484-9321", &params))
}
