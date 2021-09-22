package main

import (
  gp "ghanapostgps"
)

func main(){
  // init
  params := gp.Params{
    ApiKey: gp.RandomString(16),
    UUID: gp.UUID(),
    ApiURL: gp.BaseAPIURL + "?publickey=1",
    AsaaseAPI: "VGgxcyAhcyBOI3cgQG5kcjBpNiA4cypy",
    Language: "English",
    LanguageCode: "en",
    AndroidCert: "49:DD:00:18:04:D3:47:D0:77:44:A0:B3:93:47:4F:BE:B6:7E:D7:67",
    AndroidPackage: "com.ghanapostgps.ghanapost",
    Country: "GH",
    CountryName: "Ghana",
  }

  gp.Print(gp.GetAPIKeys(&params))
}
