package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

type Secrets struct {
	Installed struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		AuthURI      string `json:"auth_uri"`
		TokenURI     string `json:"token_uri"`
	} `json:"installed"`
}

func xorEncode(data []byte, key []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ key[i%len(key)]
	}
	return result
}

func splitBytes(data []byte, parts int) [][]byte {
	result := make([][]byte, parts)
	partSize := len(data) / parts
	
	for i := 0; i < parts-1; i++ {
		result[i] = data[i*partSize : (i+1)*partSize]
	}
	// Last part gets any remaining bytes
	result[parts-1] = data[(parts-1)*partSize:]
	
	return result
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run encode-secrets.go <client_secrets.json>")
		os.Exit(1)
	}
	
	// Read secrets
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		panic(fmt.Errorf("failed to read secrets file: %w", err))
	}
	
	var secrets Secrets
	if err := json.Unmarshal(data, &secrets); err != nil {
		panic(fmt.Errorf("failed to parse secrets JSON: %w", err))
	}
	
	// Generate random XOR key (32 bytes)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(fmt.Errorf("failed to generate random key: %w", err))
	}
	
	// Split and encode client ID into 3 parts
	clientIDBytes := []byte(secrets.Installed.ClientID)
	clientIDParts := splitBytes(clientIDBytes, 3)
	
	clientIDPart1 := xorEncode(clientIDParts[0], key)
	clientIDPart2 := xorEncode(clientIDParts[1], key[8:])
	clientIDPart3 := xorEncode(clientIDParts[2], key[16:])
	
	// Split and encode client secret into 3 parts
	clientSecretBytes := []byte(secrets.Installed.ClientSecret)
	clientSecretParts := splitBytes(clientSecretBytes, 3)
	
	clientSecretPart1 := xorEncode(clientSecretParts[0], key[5:])
	clientSecretPart2 := xorEncode(clientSecretParts[1], key[11:])
	clientSecretPart3 := xorEncode(clientSecretParts[2], key[21:])
	
	// Generate additional obfuscation data
	decoyData1 := make([]byte, 16)
	decoyData2 := make([]byte, 12)
	rand.Read(decoyData1)
	rand.Read(decoyData2)
	
	// Output Go code
	fmt.Println("package calendar")
	fmt.Println()
	fmt.Println("import (")
	fmt.Println("\t\"encoding/base64\"")
	fmt.Println("\t\"fmt\"")
	fmt.Println(")")
	fmt.Println()
	
	fmt.Printf("// XOR key generated at build time\n")
	fmt.Printf("var xorKey1 = %#v\n\n", key)
	
	fmt.Printf("// Decoy data to confuse analysis\n")
	fmt.Printf("var decoyData1 = %#v\n", decoyData1)
	fmt.Printf("var decoyData2 = %#v\n\n", decoyData2)
	
	fmt.Printf("// Client ID split into 3 XOR-encrypted parts\n")
	fmt.Printf("var clientIDPart1 = %#v\n", clientIDPart1)
	fmt.Printf("var clientIDPart2 = %#v\n", clientIDPart2)
	fmt.Printf("var clientIDPart3 = %#v\n\n", clientIDPart3)
	
	fmt.Printf("// Client Secret split into 3 XOR-encrypted parts\n")
	fmt.Printf("var clientSecretPart1 = %#v\n", clientSecretPart1)
	fmt.Printf("var clientSecretPart2 = %#v\n", clientSecretPart2)
	fmt.Printf("var clientSecretPart3 = %#v\n\n", clientSecretPart3)
	
	// Output lengths for validation
	fmt.Printf("// Original lengths for validation\n")
	fmt.Printf("var clientIDLen = %d\n", len(clientIDBytes))
	fmt.Printf("var clientSecretLen = %d\n", len(clientSecretBytes))
	fmt.Println()
	
	fmt.Printf("// URI constants (not sensitive)\n")
	fmt.Printf("const authURI = %q\n", secrets.Installed.AuthURI)
	fmt.Printf("const tokenURI = %q\n", secrets.Installed.TokenURI)
}