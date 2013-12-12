package main

import (
	"code.google.com/p/gosshnew/ssh"
	"code.google.com/p/gosshnew/ssh/terminal"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"
)

var bindAddressFlag = flag.String("b", "0.0.0.0", "Bind Address")
var portFlag = flag.String("p", "22", "Port Number")

func main() {

	log.Print("\n")
	log.Print("***************************************************************\n")
	log.Print("                                                               \n")
	log.Print("              gohoney: SSH Honeypot written in Go              \n")
	log.Print("                                                               \n")
	log.Print(" This SSH daemon will accept any username/password/key.        \n")
	log.Print(" It only allows 'session' channels (not port forwards or SFTP).\n")
	log.Print(" It will present a fake shell and record any commands that     \n")
	log.Print(" people attempt to run, along with the date and their IP.      \n")
	log.Print("                                                               \n")
	log.Print(" It will log all sessions to:                                  \n")
	log.Print(" /var/log/gohoney-YYYYMMDD.log                                 \n")
	log.Print("                                                               \n")
	log.Print(" Usage:                                                        \n")
	log.Print(" ./gohoney -b <bind address> -p <port>                         \n")
	log.Print("                                                               \n")
	log.Print("***************************************************************\n")

	flag.Parse()

	// Set the bind address for the server
	bind := *bindAddressFlag + ":" + *portFlag

	log.Printf("Settings max processes to %d", runtime.NumCPU())
	runtime.GOMAXPROCS(runtime.NumCPU())

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.

	config := &ssh.ServerConfig{

		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) bool {

			// Accept any username/password
			log.Printf("Accepted user authentication (%s/%s) from %s", c.User(), string(pass), c.RemoteAddr().String())
			return true

		},
		PublicKeyCallback: func(c ssh.ConnMetadata, algorithm string, pubkey []byte) bool {

			// Accept any private key
			log.Printf("Accepted key authentication for user %s from %s", c.User(), c.RemoteAddr().String())
			return true

		},
	}

	// Setup a host key to use
	keyBytes := generateHostKey(1024)

	hostKey, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		log.Fatalf("Error: Failed to parse host key (%s)", err)
	}

	config.AddHostKey(hostKey)

	// Now that we've configured the server, we can start listening
	socket, err := net.Listen("tcp", bind)
	if err != nil {
		log.Fatalf("Error: Failed to bind to %s (%s)", bind, err)
	}

	log.Printf("Listening on %s", bind)

	go func() {
		for {

			// A ServerConn multiplexes several channels, which must
			// themselves be Accepted.
			networkConnection, err := socket.Accept()

			if err != nil {
				log.Printf("Error: Failed to accept an incoming connection from %s (%s)", socket.Addr().String(), err)
				continue
			}

			// Launch a new goroutine (lite-thread) to handle the connection
			// freeing us up to accept more.
			go handleNetworkConnection(networkConnection, config)

		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	for _ = range c {
		log.Println("Received a ctrl+c - shutting down...")
		if socket != nil {
			socket.Close()
		}
		return
	}

}

func handleNetworkConnection(networkConnection net.Conn, config *ssh.ServerConfig) {

	serverConnection, err := ssh.Server(networkConnection, config)
	if err != nil {
		log.Printf("Error: SSH handshake failed (%s)", err)
		networkConnection.Close()
		return
	}

	for {

		// Accept reads from the connection, demultiplexes packets
		// to their corresponding channels and returns when a new
		// channel request is seen. Some goroutine must always be
		// calling Accept; otherwise no messages will be forwarded
		// to the channels.
		channelRequest, err := serverConnection.Accept()

		if serverConnection == nil {
			return
		}

		if IsEOF(err) {
			log.Printf("Connection from %s closed", serverConnection.RemoteAddr())
			serverConnection.Close()
			serverConnection = nil
			return
		}

		if err != nil {
			log.Printf("Error: Failed to open channel (%s)", err)
			break
		}

		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.

		switch channelRequest.ChannelType() {
		case "session":
			go func() {
				handleSessionChannel(channelRequest, serverConnection.User(), serverConnection.RemoteAddr().String())
				log.Printf("Closing connection from %s", serverConnection.RemoteAddr())
				serverConnection.Close()
				serverConnection = nil
			}()

		default:
			log.Printf("Error: Refusing to open unknown channel type: %s", channelRequest.ChannelType())
			channelRequest.Reject(ssh.UnknownChannelType, "unknown channel type")
		}

	}
}

func handleSessionChannel(channelRequest ssh.NewChannel, user, addr string) {

	sessionChannel, _, err := channelRequest.Accept()
	if err != nil {
		log.Printf("Could not accept direct-tcpip channel from %s", channelRequest)
		return
	}

	defer sessionChannel.Close()

	term := terminal.NewTerminal(sessionChannel, user+"@server35:~$ ")
	serverTerm := &ssh.ServerTerminal{
		Term:    term,
		Channel: sessionChannel,
	}

	// Generate the date for the banner
	// Format: Thu Dec 31 15:30:14 GMT 2013
	date := time.Now().Format("Mon Jan 2 15:04:05 MST 2006")

	term.Write([]byte("\r\n"))
	term.Write([]byte("Welcome to Ubuntu 12.04.3 LTS (GNU/Linux 3.8.0-34-generic x86_64)\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte(" * Documentation:  https://help.ubuntu.com/                      \r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("  System information as of " + date + "\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("  System load:     0.03                IP address for eth0:    10.10.86.42\r\n"))
	term.Write([]byte("  Usage of /:      0.5% of 82.3TB\r\n")) // Tee-hee-hee
	term.Write([]byte("  Memory usage:    3%\r\n"))
	term.Write([]byte("  Swap usage:      0%\r\n"))
	term.Write([]byte("  Processes:       33\r\n"))
	term.Write([]byte("  Users logged in: 1\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("  Graph this data and manage this system at https://landscape.canonical.com/\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("394 packages can be updated.\r\n"))
	term.Write([]byte("63 updates are security updates.\r\n"))
	term.Write([]byte("\r\n"))
	term.Write([]byte("Last login: Wed Aug 23 18:28:57 2013 from 10.10.35.1\r\n"))
	term.Write([]byte("\r\n"))

	logDate := time.Now().Format("20060201")
	logFileName := "/var/log/gohoney-" + logDate + ".log"
	logFile, err := os.OpenFile(logFileName, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Printf("Error: Could not write to %s (%s)", logFileName, err)
	}

	logFile.WriteString("***************************************************************\r\n")
	logFile.WriteString(" Session Started: " + date + "\r\n")
	logFile.WriteString(" From: " + addr + "\r\n")

	defer func() {
		finishedDate := time.Now().Format("Mon Jan 2 15:04:05 MST 2006")
		logFile.WriteString(" Session Finished: " + finishedDate + "\r\n")
		logFile.WriteString("***************************************************************\r\n\r\n")
		logFile.Close()
	}()

	for {

		line, err := serverTerm.ReadLine()

		if IsEOF(err) {
			return
		}
		if err != nil {
			log.Println("Could not read command:", err)
			continue
		}

		entryTime := time.Now().Format("15:04:05")
		entry := " " + entryTime + ": " + line + "\r\n"
		logFile.WriteString(entry)

		log.Printf("%s entered: %s", addr, line)
		if strings.Contains(line, "exit") {
			return
		}

	}
}

/**
 * Generates a private key and returns it as a byte array
 */
func generateHostKey(bits int) (key []byte) {

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("Could not generate host key (%s)", err)
	}

	privateKey.Validate()
	if err != nil {
		log.Fatalf("Could not validate host key (%s)", err)
	}

	// Get der format. priv_der []byte
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)

	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDER,
	}

	// Resultant private key in PEM format.
	return pem.EncodeToMemory(&privateKeyBlock)

}

/**
 * A utility function which tests if an error returned from a TCPConnection or
 * TCPListener is actually an EOF. In some edge cases this which should be treated
 * as EOFs are not returned as one.
 */
func IsEOF(err error) bool {
	if err == nil {
		return false
	} else if err == io.EOF {
		return true
	} else if oerr, ok := err.(*net.OpError); ok {
		/* this hack happens because the error is returned when the
		 * network socket is closing and instead of returning a
		 * io.EOF it returns this error.New(...) struct. */
		if oerr.Err.Error() == "use of closed network connection" {
			return true
		}
	} else {
		if err.Error() == "use of closed network connection" {
			return true
		}
	}
	return false
}
