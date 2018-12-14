package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

var database = make(map[string]string)


func verificationHandler(r *http.Request)(bool,string){
	username, ok := r.URL.Query()["username"]
	if ok == false{
		fmt.Println("Username Error")
		return false,username[0]
	}
	password, ok := r.URL.Query()["password"]
	if ok == false{
		fmt.Println("Password Error")
		return false,username[0]
	}
	database["John"]="password"
	database["Harold"]="password"
	val, ok :=database[username[0]]
	if ok == false{
		return false,username[0]
	}else {
		if strings.Compare(val,password[0])!=0{
			return false,username[0]
		}
	}
	return true,username[0]
}

func main() {
	certPem := []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
	cert,err := tls.X509KeyPair(certPem,keyPem)
	if err != nil{
		fmt.Println("Certficate Error")
		os.Exit(1)
	}
	mux := http.NewServeMux()


	cfg := tls.Config{
		Renegotiation:			   tls.RenegotiateNever,
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		Certificates: []tls.Certificate{cert},
	}

	server := http.Server{
		Addr:		"127.0.0.1:443",
		Handler:	mux,
		TLSConfig:  &cfg,
		TLSNextProto:  make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	/*Han*/

	mux.HandleFunc("/shutdown", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("TLS connection Terminated\n"))
		go func() {
			err :=server.Shutdown(context.Background())
			if err !=nil{
				fmt.Println(err)
			}
		}()

	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

	})

	mux.HandleFunc("/verify", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		output,username := verificationHandler(req)
		filename :="sgx_logs.txt"
		//file,_:= os.OpenFile(filename,os.O_CREATE|os.O_APPEND,0666)
		file,err := os.OpenFile(filename,os.O_APPEND|os.O_CREATE,0666)
		if err!=nil{
			fmt.Println("Eoor Here")
		}
		current_time := time.Now().UTC()
		if output{
			fmt.Fprint(file,username+" Authentication Success "+current_time.Format("Mon Jan 2 15:04:05 MST ")+"\n")
			w.Write([]byte("true\n"))
		}else{
			w.Write([]byte("false\n"))
			fmt.Fprint(file,username+" Failed Authentication "+current_time.Format("Mon Jan 2 15:04:05 MST ")+"\n")
		}
		defer file.Close()
	})
	log.Fatal(server.ListenAndServeTLS("",""))

}
