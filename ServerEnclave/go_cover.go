package main

import (
    "encoding/base64"
    "fmt"
	"crypto/ed25519"

)

func main() {
    rawDecodedText, err := base64.StdEncoding.DecodeString("Tk2eBohNQDG6Vql5MY86IWQKlZ7rn/11lHVvu4iCdk4=")
    if err != nil {
        panic(err)
    }
	// encodedStr := hex.EncodeToString(rawDecodedText)
    for i:=0;i<len(rawDecodedText);i++{
        fmt.Printf("0x%X,",rawDecodedText[i])
    }
    signatureBytes,err := base64.StdEncoding.DecodeString("6aqQDoWf78RcnurIV/1L9bMJp0n+wYCXTalzOtFZKW6uXd1iM7CxCFAODTtMmAXFhT2X0UCv0JndlOIvTPyNDg==")
    if err != nil{
        panic(err)
    }
    text := "exists104"
    fmt.Println("")
    fmt.Printf("%X ",[]byte(text))
    fmt.Println("")
    fmt.Printf("%X",signatureBytes)
    fmt.Println("")
    if ed25519.Verify(ed25519.PublicKey(rawDecodedText), []byte(text),signatureBytes){
        fmt.Println("True")
    }
}

//65786973747332333336 

// 20E1EE3BF99FF5ED0340F394626242A41050CAB7D59DDE1BD276EDC07D588FD2D21AE71AE7DC6976B81A39D8102D5771C988DDF29BA70D7FF601D56FD3D50A00