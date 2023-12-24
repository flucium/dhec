/*
   Diffie-Hellman and Diffie-Hellman Ephemeral combination (DHEC)
   v0.0.1

   What? This is an Example based on a paper.
   Warning! Not perfect.
*/

/*
   MIT License

   Copyright (c) 2023 flucium

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

/* ./go.mod
   go 1.21.5
   require golang.org/x/crypto v0.17.0 // indirect
*/

/* ./src/main.go
 */

package main

import (
   "crypto/ecdh"
   "crypto/rand"
   "fmt"
)

func main() {

   message := []byte("Hello World")

   // Alice generates ephemeral key pair
   aliceEphemeralPrivateKey, aliceEphemeralPublicKey := genAliceEphemeralKeys()

   // Bob generate key pair
   bobPrivateKey, bobPublicKey := genBobKeys()

   // Alice compute shared secret
   aliceSharedSecret, _ := aliceEphemeralPrivateKey.ECDH(bobPublicKey)

   // Alice append ephemeral public key to message
   message = append(message, aliceEphemeralPublicKey.Bytes()...)

   // Bob compute shared secret
   messageAliceEphemeralPublicKey, _ := ecdh.X25519().NewPublicKey(message[len(message)-32:])
   bobSharedSecret, _ := bobPrivateKey.ECDH(messageAliceEphemeralPublicKey)

   // Print shared secret
   fmt.Printf("Alice shared secret: %x\nBob shared secret: %x\n", aliceSharedSecret, bobSharedSecret)

   // Print message
   fmt.Printf("Message: %s\n", message[:len(message)-32])

}

func genAliceEphemeralKeys() (*ecdh.PrivateKey, *ecdh.PublicKey) {
   x25519 := ecdh.X25519()

   aliceEphemeralPrivateKey, _ := x25519.GenerateKey(rand.Reader)
   aliceEphemeralPublicKey := aliceEphemeralPrivateKey.PublicKey()

   return aliceEphemeralPrivateKey, aliceEphemeralPublicKey
}

func genBobKeys() (*ecdh.PrivateKey, *ecdh.PublicKey) {
   x25519 := ecdh.X25519()

   bobPrivateKey, _ := x25519.GenerateKey(rand.Reader)
   bobPublicKey := bobPrivateKey.PublicKey()

   return bobPrivateKey, bobPublicKey
}

