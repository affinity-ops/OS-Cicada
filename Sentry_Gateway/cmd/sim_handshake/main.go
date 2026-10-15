package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"golang.org/x/crypto/curve25519"
)

func main() {
	// Load QR response
	f, _ := os.Open("/tmp/cicada_qr.json")
	defer f.Close()
	var resp struct {
		Data struct {
			QRPayload string `json:"qr_payload"`
		} `json:"data"`
	}
	json.NewDecoder(f).Decode(&resp)

	var qr struct {
		N  string `json:"n"`
		GW string `json:"gw"`
	}
	json.Unmarshal([]byte(resp.Data.QRPayload), &qr)

	// Generate device Ed25519 keypair
	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)
	pubB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Generate X25519 keypair
	var x25519Priv [32]byte
	rand.Read(x25519Priv[:])
	x25519Pub, _ := curve25519.X25519(x25519Priv[:], curve25519.Basepoint)
	x25519PubB64 := base64.StdEncoding.EncodeToString(x25519Pub)

	// Sign the nonce (same as the Flutter app does in pairing_bloc.dart)
	sig := ed25519.Sign(privKey, []byte(qr.N))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	// Build handshake payload (matching HandshakeRequest struct)
	handshake := map[string]string{
		"ed25519_pub":         pubB64,
		"x25519_pub":          x25519PubB64,
		"nonce":               qr.N,
		"challenge_signature": sigB64,
		"ml_dsa65_pub":        "", // PQC optional during dev
		"ml_kem768_pub":       "",
	}
	body, _ := json.Marshal(handshake)

	// POST to gateway (using localhost since we're on the same machine)
	url := "http://localhost:8080/v1/mobile/pair/handshake"
	fmt.Println("=== SIMULATED DEVICE HANDSHAKE ===")
	fmt.Println("Gateway URL:", qr.GW)
	fmt.Println("Nonce:", qr.N[:20]+"...")
	fmt.Println("Device Ed25519 pub:", pubB64[:20]+"...")
	fmt.Println("Device X25519 pub:", x25519PubB64[:20]+"...")
	fmt.Println("ML-DSA-65 pub: (empty — PQC not compiled in emulator)")
	fmt.Println()

	r, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	defer r.Body.Close()
	result, _ := io.ReadAll(r.Body)
	fmt.Printf("HTTP Status: %d\n", r.StatusCode)
	
	var prettyJSON bytes.Buffer
	json.Indent(&prettyJSON, result, "", "  ")
	fmt.Println("Response:", prettyJSON.String())
}
