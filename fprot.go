// Copyright (C) 2018 Andrew Colin Kissa <andrew@datopdog.io>
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

/*
Package fprot Golang F-Prot client
Fprot - Golang F-Prot client
*/
package fprot

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultTimeout = 15 * time.Second
	defaultSleep   = 1 * time.Second
	chunkSize      = 1024
)

const (
	// Infected 1 Atleast one virus-infected object was found
	Infected StatusCode = 1 << iota
	// HeuristicMatch 2 Atleast one suspicious (heuristic match) object was found
	HeuristicMatch
	// UserError 4 Interrupted by user
	UserError
	// RestrictionError 8 Scan restriction caused scan to skip files
	RestrictionError
	// SystemError 16 Platform error
	SystemError
	// InternalError 32 Internal engine error
	InternalError
	// SkipError 64 Atleast one object was not scanned
	SkipError
	// DisinfectError 128 Atleast one object was disinfected
	DisinfectError
)

const (
	// Help is the HELP command
	Help Command = iota + 1
	// ScanFile is the SCAN FILE command
	ScanFile
	// ScanStream is the SCAN STREAM command
	ScanStream
	// Queue is the QUEUE command
	Queue
	// ScanQueue is the SCAN command
	ScanQueue
	// Quit is the QUIT command
	Quit
)

var (
	responseRe = regexp.MustCompile(`^(?P<statuscode>[0-9]+)\s<(?P<status>[^:]+):\s+(?P<signature>.+?)>\s?(?P<filename>.+?)?(?:->(?P<aname>.*))?$`)
)

// StatusCode represents the returned status code
type StatusCode int

func (c StatusCode) String() (s string) {
	switch c {
	case Infected:
		s = "Atleast one virus-infected object was found"
	case HeuristicMatch:
		s = "Atleast one suspicious (heuristic match) object was found"
	case UserError:
		s = "Scanning interrupted by user"
	case RestrictionError:
		s = "Scan restriction caused scan to skip files"
	case SystemError:
		s = "Platform error"
	case InternalError:
		s = "Internal Engine error"
	case SkipError:
		s = "Atleast one object was not scanned"
	case DisinfectError:
		s = "Atleast one object was disinfected"
	default:
		s = ""
	}
	return
}

// A Command represents a Fprot Command
type Command int

func (c Command) String() (s string) {
	n := [...]string{
		"",
		"HELP",
		"SCAN FILE",
		"SCAN STREAM",
		"QUEUE",
		"SCAN",
		"QUIT",
	}
	if c < Help || c > Quit {
		s = ""
		return
	}
	s = n[c]
	return
}

// RequiresParam returns a bool to indicate if command takes a
// file or directory as a param
func (c Command) RequiresParam() (b bool) {
	switch c {
	case ScanFile, ScanStream:
		b = true
	}
	return
}

// Response is the response from the server
type Response struct {
	Filename    string
	ArchiveItem string
	Signature   string
	Status      string
	StatusCode  StatusCode
	Infected    bool
	Raw         string
}

// A Client represents a Fprot client.
type Client struct {
	address     string
	connTimeout time.Duration
	connRetries int
	connSleep   time.Duration
	cmdTimeout  time.Duration
	tc          *textproto.Conn
}

// SetConnTimeout sets the connection timeout
func (c *Client) SetConnTimeout(t time.Duration) {
	c.connTimeout = t
}

// SetCmdTimeout sets the cmd timeout
func (c *Client) SetCmdTimeout(t time.Duration) {
	c.cmdTimeout = t
}

// SetConnRetries sets the number of times
// connection is retried
func (c *Client) SetConnRetries(s int) {
	if s < 0 {
		s = 0
	}
	c.connRetries = s
}

// SetConnSleep sets the connection retry sleep
// duration in seconds
func (c *Client) SetConnSleep(s time.Duration) {
	c.connSleep = s
}

// Info returns server information
func (c *Client) Info() (s string, err error) {
	if s, err = c.basicCmd(Help); err != nil {
		return
	}

	return
}

// Close closes the server connection
func (c *Client) Close() (err error) {
	_, err = c.basicCmd(Quit)

	c.tc.Close()

	return
}

// ScanFile submits a single file for scanning
func (c *Client) ScanFile(f string) (r []*Response, err error) {
	r, err = c.fileCmd(ScanFile, f)
	return
}

// ScanFiles submits multiple files for scanning
func (c *Client) ScanFiles(f ...string) (r []*Response, err error) {
	r, err = c.fileCmd(ScanFile, f...)
	return
}

// ScanStream submits a stream for scanning
func (c *Client) ScanStream(f ...string) (r []*Response, err error) {
	r, err = c.fileCmd(ScanStream, f...)
	return
}

// ScanReader submits an io reader via a stream for scanning
func (c *Client) ScanReader(i io.Reader) (r []*Response, err error) {
	r, err = c.readerCmd(i)
	return
}

// ScanDir submits a directory for scanning
func (c *Client) ScanDir(d string) (r []*Response, err error) {
	var fl []string

	fl, err = getFiles(d)
	if err != nil {
		return
	}

	r, err = c.fileCmd(ScanFile, fl...)
	return
}

// ScanDirStream submits a directory for scanning as streams
func (c *Client) ScanDirStream(d string) (r []*Response, err error) {
	var fl []string

	fl, err = getFiles(d)
	if err != nil {
		return
	}

	r, err = c.fileCmd(ScanStream, fl...)
	return
}

func (c *Client) dial() (conn net.Conn, err error) {
	d := &net.Dialer{}

	if c.connTimeout > 0 {
		d.Timeout = c.connTimeout
	}

	for i := 0; i <= c.connRetries; i++ {
		conn, err = d.Dial("tcp4", c.address)
		if e, ok := err.(net.Error); ok && e.Timeout() {
			time.Sleep(c.connSleep)
			continue
		}
		break
	}
	return
}

func (c *Client) basicCmd(cmd Command) (r string, err error) {
	var l []byte
	var conn net.Conn
	var b strings.Builder

	if c.tc == nil {
		conn, err = c.dial()
		if err != nil {
			return
		}

		c.tc = textproto.NewConn(conn)
	}

	id := c.tc.Next()
	c.tc.StartRequest(id)
	fmt.Fprintf(c.tc.W, "n%s\n", cmd)
	c.tc.W.Flush()
	c.tc.EndRequest(id)

	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)

	if cmd == Quit {
		return
	}

	for {
		l, err = c.tc.R.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			break
		}
		fmt.Fprintf(&b, "%s", l)
	}

	r = strings.TrimRight(b.String(), "\n")

	return
}

func (c *Client) fileCmd(cmd Command, p ...string) (r []*Response, err error) {
	var n int
	var conn net.Conn

	n = len(p)

	if n == 0 || p[0] == "" {
		err = fmt.Errorf("Atleast one path to scan is required")
		return
	}

	if c.tc == nil {
		conn, err = c.dial()
		if err != nil {
			return
		}

		c.tc = textproto.NewConn(conn)
	}

	id := c.tc.Next()
	c.tc.StartRequest(id)

	if cmd == ScanStream {
		if n > 1 {
			if _, err = fmt.Fprintf(c.tc.W, "%s", Queue); err != nil {
				return
			}

			for _, fn := range p {
				if err = c.streamCmd(fn); err != nil {
					return
				}
			}

			if _, err = fmt.Fprintf(c.tc.W, "%s", ScanQueue); err != nil {
				return
			}
		} else {
			if err = c.streamCmd(p[0]); err != nil {
				return
			}
		}
	} else if cmd == ScanFile {
		if n > 1 {
			if _, err = fmt.Fprintf(c.tc.W, "%s", Queue); err != nil {
				return
			}

			for _, fn := range p {
				if _, err = fmt.Fprintf(c.tc.W, "%s %s", ScanFile, fn); err != nil {
					return
				}
			}

			if _, err = fmt.Fprintf(c.tc.W, "%s", ScanQueue); err != nil {
				return
			}
		} else {
			if _, err = fmt.Fprintf(c.tc.W, "%s %s", ScanFile, p[0]); err != nil {
				return
			}
		}
	}

	c.tc.EndRequest(id)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)
	r, err = c.processResponse()

	return
}

func (c *Client) readerCmd(i io.Reader) (r []*Response, err error) {
	var clen int64
	var conn net.Conn
	var stat os.FileInfo

	if c.tc == nil {
		conn, err = c.dial()
		if err != nil {
			return
		}

		c.tc = textproto.NewConn(conn)
	}

	id := c.tc.Next()
	c.tc.StartRequest(id)

	switch v := i.(type) {
	case *bytes.Buffer:
		clen = int64(v.Len())
	case *bytes.Reader:
		clen = int64(v.Len())
	case *strings.Reader:
		clen = int64(v.Len())
	case *os.File:
		stat, err = v.Stat()
		if err != nil {
			return
		}
		clen = stat.Size()
	default:
		err = fmt.Errorf("The content length could not be determined")
		return
	}

	if _, err = fmt.Fprintf(c.tc.W, "%s stream SIZE %d\n", ScanStream, clen); err != nil {
		return
	}

	_, err = io.Copy(c.tc.Writer.W, i)
	if err != nil {
		return
	}
	c.tc.W.Flush()

	c.tc.EndRequest(id)
	c.tc.StartResponse(id)
	defer c.tc.EndResponse(id)
	r, err = c.processResponse()

	return
}

func (c *Client) streamCmd(fn string) (err error) {
	var f *os.File
	var stat os.FileInfo

	if f, err = os.Open(fn); err != nil {
		return
	}
	defer f.Close()

	if stat, err = f.Stat(); err != nil {
		return
	}

	if _, err = fmt.Fprintf(c.tc.W, "%s %s SIZE %d\n", ScanStream, fn, stat.Size()); err != nil {
		return
	}

	if _, err = io.Copy(c.tc.Writer.W, f); err != nil {
		return
	}

	c.tc.W.Flush()

	return
}

func (c *Client) processResponse() (r []*Response, err error) {
	var sc int
	var seen bool
	var gerr error
	var lineb []byte

	r = make([]*Response, 1)

	for {
		lineb, err = c.tc.R.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			}
			return
		}
		mb := responseRe.FindSubmatch(lineb)
		if mb == nil {
			err = fmt.Errorf("Invalid Server Response: %s", lineb)
			break
		}

		rs := Response{}
		sc, err = strconv.Atoi(string(mb[1]))
		if err != nil {
			return
		}
		rs.StatusCode = StatusCode(sc)
		rs.Status = string(mb[2])
		rs.Signature = string(mb[3])
		rs.Filename = string(mb[4])
		rs.ArchiveItem = string(mb[5])

		if !seen {
			r[0] = &rs
			seen = true
		} else {
			r = append(r, &rs)
		}

		if rs.StatusCode&(UserError|RestrictionError|SystemError|InternalError|SkipError|DisinfectError) != 0 {
			if gerr == nil {
				gerr = fmt.Errorf("ERROR: %s", rs.StatusCode)
			}
		}

		if rs.StatusCode&(Infected|DisinfectError|HeuristicMatch) != 0 {
			rs.Infected = true
		}
	}

	err = gerr

	return
}

// NewClient creates and returns a new instance of Client
func NewClient(address string) (c *Client) {
	if address == "" {
		address = "127.0.0.1:10200"
	}

	c = &Client{
		address:     address,
		connTimeout: defaultTimeout,
		connSleep:   defaultSleep,
	}

	return
}

func getFiles(d string) (fl []string, err error) {
	err = filepath.Walk(d, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			fl = append(fl, path)
		}
		return nil
	})
	if err != nil {
		return
	}

	return
}
