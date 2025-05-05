# HCSC 2025 - Capture me if you can

## Description

Supercomputers are advancing at an astonishing pace, and our team of security researchers has been hard at work exploring post-quantum cryptography. We even developed a proof of concept—until recent layoffs derailed our progress (we had to kick out Jack) and it never made it into production. Now, we don't even know how to communicate with these experimental services. It all feels like complete gibberish. If you can cut through the confusion and solve the challenge, you’ll earn a special reward: the flag. Good luck!

Remarks from the creator:
* The challenge requires no server side brute-forcing
* latest `challenge.zip` sha256sum: `0c5b3c327c6c8f259f78a0db0ae47b44d3e848ffbce50a3ac4cb337030aeb82a`
* the challenge uses two ports (one for part one, one for part two).

**Flag format**: `HCSC{...}`

Thanks to **@alex_hcsc** for the indirect inspiration!

```
10.10.1-9.12:1337
10.10.1-9.12:8443
```

*By MJ*

## Metadata

- Filename: [`challenges.zip`](files/challenge.zip)
- Tags: `go`, `tls1.3`, `certificate`
- Points: 400 / 200
- Number of solvers: 17 / 15

## Solution

For this challenge we get to applications written in `go`, a `backend` and a `keyprovider`.

Each applications contain one flag.

The `keyprovider` stores the flag in its TLS certificate:

```go
    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"Honeylab"},
        },
        DNSNames:              []string{flag},
        NotBefore:             notBefore,
        NotAfter:              notAfter,
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }
```

So if we can set up a TLS connection with the server, we will get the flag.

Now let's check the TLS configuration of the server:

```go
    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:   tls.VersionTLS13,
        MaxVersion:   tls.VersionTLS13,
        CipherSuites: []uint16{
            tls.TLS_AES_128_GCM_SHA256,
            tls.TLS_AES_256_GCM_SHA384,
        },
    }
```

This can be easily matched, however, we have a problem with the signature algorithm of the certificate.

```go
    pkcs8Key := pkcs8{
        Version: 0,
        Algo: pkix.AlgorithmIdentifier{
            Algorithm:  asn1.ObjectIdentifier{1, 5, 1, 2},
            Parameters: asn1.RawValue{Bytes: pubKey},
        },
        PrivateKey: key,
    }
```

If we build a docker image for ourselves, the server logs will say upon connection that the client does not support the signature algorithm.

To overcome this issue, we can use the given `go` application as a template and connect to the server from `go`. The following prints the important fields of the certificate of the server, and also print the data sent by the server.

```go
package main

import (
    "crypto/tls"
    "log"
    "fmt"
    "io"
)

func main() {
    conf := &tls.Config{
        InsecureSkipVerify: true,
    }
    tlsConn, err := tls.Dial("tcp", "10.10.1.12:1337", conf)
    if err != nil {
        log.Printf("Failed to connect to key provider")
        return
    }
    err = tlsConn.Handshake()
    if err != nil {
        log.Fatalf("Error performing TLS handshake: %v\n", err)
    }
    certs := tlsConn.ConnectionState().PeerCertificates
    if len(certs) > 0 {
        fmt.Printf("Server Certificate:\n")
        for _, cert := range certs {
            fmt.Printf("DNSNames: %s\n", cert.DNSNames)
            fmt.Printf("Subject: %s\n", cert.Subject)
            fmt.Printf("Issuer: %s\n", cert.Issuer)
            fmt.Printf("Not Before: %s\n", cert.NotBefore)
            fmt.Printf("Not After: %s\n", cert.NotAfter)
            fmt.Printf("Certificate Serial Number: %s\n", cert.SerialNumber)
            fmt.Printf("Public Key Algorithm: %s\n", cert.PublicKeyAlgorithm)
            fmt.Printf("Public Key: %x\n", cert.PublicKey)
        }
    } else {
        fmt.Println("No server certificates received.")
    }

    buffer := make([]byte, 4096)
    for {
        n, err := tlsConn.Read(buffer)
        if err != nil && err != io.EOF {
            log.Fatalf("Error reading data: %v\n", err)
        }
        if n == 0 {
            break
        }
        fmt.Print(string(buffer[:n]))
    }
}
```

If we build and run this application, we get the first flag:

```
Server Certificate:
DNSNames: [HCSC{why_wa1t_f0r_NIST_wh3n_y0u_c4n_r0ll_ur_0wn_c0nstants}]
Subject: O=Honeylab
Issuer: O=Honeylab
Not Before: 2025-04-24 15:48:06 +0000 UTC
Not After: 2026-04-24 15:48:06 +0000 UTC
Certificate Serial Number: 359254688303624826890576373006270156750199382992
Public Key Algorithm: Dilithium5
Public Key: &[...]
```

We also get some encoded and encrypted data:

```
T7OGBAehXChUxdLGYd4U5/W23XZ5VnF2Ur1TpfLTezJdcweeao59Nu4xQwxrr1ECTLNl9qq5axIXQMSTcFYOV3Np05o3oBNLsE9KEkBrcReVYKGsb6xPjso82ss9EmvAOtFagRkHKp+3a6lFx0tSkrLEgfATZd1IyihT4cBGLS5XhCynIIP01p/ItqRS7pMDZ5kocercy7MNoF7YcYdJ42ELqteOeNvWNMtd2Z22uGY8ba+UrPUwRp9Kx4ICPGo4LTa+5hsd6tMI/9E/ZMF3AEmWj+8bgl8JMbSP4C9e+egVrhyxgIdFnJX6AuJMGs3xmQ1HRiQetzPXZD5a71Fei843qlDcwCqq5yGDSSbPLJC+682kJzxXPVceMagoGuX1jlh6kQ+7LmLoedunvxqE6jRi5r3bWF2jMqFxrdwfyrR28aCNTGM2T6OzxtbNjU/EvQ58rQac1M6AeuLNNof2+exlsluVf69bIPKYU1QVzzGW58EqJ7OPVwpJv7gJUyru1KWIe6ImfjgvJBnDYGkqfwSthWsZApXtEnjW/CHxCAxmxizGFTWYyQJNyO5gKtydCsXc+S3SJ9Hud1MDijX/vK0ne79S/M47VoELuif1U+QQNBBUzVPijujia8esgkjaOJsnagK6BqGgZ2VC7xVkNhGMD853Tvfi1JqXX3z6mpozmcodJMS2lZmxaVcUM+NJpGVMfJHb1Pya5ZBA3IbvEg1N4jAD3vnF4zmeTsUsQg8=
```

Basically we get a client certificate and private key for the `backend` encrypted with a symmetric key algorithm and a hardcoded key:

```go
func encryptData(data string) string {
    key := []byte("radiofrequencies")

    encrypted, err := sm4.Sm4Cbc(key, []byte(data), true)
    if err != nil {
        log.Fatalf("Failed to encrypt password: %v", err)
    }

    return base64.StdEncoding.EncodeToString(encrypted)
}
```

We can create a new `go` application which decrypts the certificate and private key:

```go
import (
    "encoding/base64"
    "log"
    "fmt"
    "crypto/sm4"
)

func main() {
    encryptedData := "T7OGBAehXChUxdLGYd4U5/W23XZ5VnF2Ur1TpfLTezJdcweeao59Nu4xQwxrr1ECTLNl9qq5axIXQMSTcFYOV3Np05o3oBNLsE9KEkBrcReVYKGsb6xPjso82ss9EmvAOtFagRkHKp+3a6lFx0tSkrLEgfATZd1IyihT4cBGLS5XhCynIIP01p/ItqRS7pMDZ5kocercy7MNoF7YcYdJ42ELqteOeNvWNMtd2Z22uGY8ba+UrPUwRp9Kx4ICPGo4LTa+5hsd6tMI/9E/ZMF3AEmWj+8bgl8JMbSP4C9e+egVrhyxgIdFnJX6AuJMGs3xmQ1HRiQetzPXZD5a71Fei843qlDcwCqq5yGDSSbPLJC+682kJzxXPVceMagoGuX1jlh6kQ+7LmLoedunvxqE6jRi5r3bWF2jMqFxrdwfyrR28aCNTGM2T6OzxtbNjU/EvQ58rQac1M6AeuLNNof2+exlsluVf69bIPKYU1QVzzGW58EqJ7OPVwpJv7gJUyru1KWIe6ImfjgvJBnDYGkqfwSthWsZApXtEnjW/CHxCAxmxizGFTWYyQJNyO5gKtydCsXc+S3SJ9Hud1MDijX/vK0ne79S/M47VoELuif1U+QQNBBUzVPijujia8esgkjaOJsnagK6BqGgZ2VC7xVkNhGMD853Tvfi1JqXX3z6mpozmcodJMS2lZmxaVcUM+NJpGVMfJHb1Pya5ZBA3IbvEg1N4jAD3vnF4zmeTsUsQg8="
    decryptedData := decryptData(encryptedData)
    fmt.Printf("Decrypted Data: %s\n", decryptedData)
}

func decryptData(encryptedData string) string {
    key := []byte("radiofrequencies")
    encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
    if err != nil {
        log.Fatalf("Failed to decode base64 data: %v", err)
    }
    decrypted, err := sm4.Sm4Cbc(key, encryptedBytes, false)
    if err != nil {
        log.Fatalf("Failed to decrypt data: %v", err)
    }
    return string(decrypted)
}
```

The result:

```
# client.key
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA1n6qweDTuAKNNSd8x1u6hInc2y0TguV8TkK61wU4W8
-----END PRIVATE KEY-----

# client.pem
-----BEGIN CERTIFICATE-----
MIIBFDCBx6ADAgECAhBLB6vrNGFpgJksdEydUm3SMAUGAytlcDARMQ8wDQYDVQQD
EwZjbGllbnQwHhcNMjUwNDI0MTU0ODA2WhcNMjYwNDI0MTU0ODA2WjARMQ8wDQYD
VQQDEwZjbGllbnQwKjAFBgMrZXADIQBdThZg5qYkHFKtW8vuet44bA9PpScmHiCY
K1dtI7DAzaM1MDMwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMC
MAwGA1UdEwEB/wQCMAAwBQYDK2VwA0EAzF2tiFe6hJLDzw+2mgtJgCqOWfUtQUlp
pW8ua5sG1EoVZjKJ3304/HpNbJghf//0DHybzQCrhhSHlS2FZs8xBA==
-----END CERTIFICATE-----
```

Now we can just simply use `curl` the get the flag from the `backend` service:

```
curl --cert client.pem --key client.key -k -v https://10.10.4.10:8443/api/v1/flag
*   Trying 10.10.4.10:8443...
[...]
> GET /api/v1/flag HTTP/2
> Host: 10.10.4.10:8443
> User-Agent: curl/8.13.0
> Accept: */*
>
* Request completely sent off
* TLSv1.3 (IN), TLS handshake, Newsession Ticket (4):
< HTTP/2 200
< content-type: text/plain
< content-length: 34
< date: Fri, 25 Apr 2025 06:26:03 GMT
<
* Connection #0 to host 10.10.4.10 left intact
HCSC{sh00t_YoU_1nd33d_c4ptured_m3}% 
```

The first flag is: `HCSC{why_wa1t_f0r_NIST_wh3n_y0u_c4n_r0ll_ur_0wn_c0nstants}`

The second flag is: `HCSC{sh00t_YoU_1nd33d_c4ptured_m3}`