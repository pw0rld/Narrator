package main

import (
    "encoding/base64"
    "fmt"
	// "encoding/hex"
)

func main() {
    rawDecodedText, err := base64.StdEncoding.DecodeString("aofYf8GVQlf/g8V4nhiBVFZLWVlojmv4s7Uqe5bCsYo=")
    if err != nil {
        panic(err)
    }
	// encodedStr := hex.EncodeToString(rawDecodedText)
    fmt.Println( rawDecodedText)
}
//aa aa 95 3a d9 8e ea 71 ea 8f 64 36 f7 ed 37 bf 6f 3c 2f 1e 82 d1 b1 95 f0 39 72 bc bf 20 87 34 63 3b f7 ca b9 c7 a0 1b 1a d8 ac 58 c2 4c 1c 91 3f 97 24 b7 ea 18 4e d1 a4 4 fd e0 48 f8 72 9
//170 170 149 58 217 142 234 113 234 143 100 54 247 237 55 191 111 60 47 30 130 209 177 149 240 57 114 188 191 32 135 52 99 59 247 202 185 199 160 27 26 216 172 88 194 76 28 145 63 151 36 183 234 24 78 209 164 4 253 224 72 248 114 9