gohoney: SSH Honeypot written in Go
=======

# Description

 This SSH daemon will accept any username/password/key.
 It only allows 'session' channels (not port forwards or SFTP).
 It will present a fake shell and record any commands that
 people attempt to run, along with the date and their IP.

 It will log all sessions to:
 /var/log/gohoney/gohoney-yyyymmdd.log

# Build & Run

First download and install Go. 
On OSX this is as easy as:

```bash
$ brew install go
```

For other linux/windows/freebsd check http://golang.org

Then build it!

```bash
# Clone this repo
$ git clone https://github.com/PaulMaddox/gohoney.git

# Fetch all of the Go module dependencies
$ cd gohoney
$ go get ./...

# Build it!
$ go build main.go
```

# Usage

```bash
 Usage:
 ./gohoney -b <bind address> -p <port>
```


