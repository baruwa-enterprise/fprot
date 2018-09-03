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
	"go/build"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"testing"
	"time"
)

const (
	eicarVirus = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`
)

type CommandTestKey struct {
	in  Command
	out string
}

type StatusCodeTestKey struct {
	in  StatusCode
	out string
}

var TestCommands = []CommandTestKey{
	{Help, "HELP"},
	{ScanFile, "SCAN FILE"},
	{ScanStream, "SCAN STREAM"},
	{Queue, "QUEUE"},
	{ScanQueue, "SCAN"},
	{Quit, "QUIT"},
	{Command(100), ""},
}

var TestStatusCodes = []StatusCodeTestKey{
	{NoMatch, "No signature was matched"},
	{Infected, "Atleast one virus-infected object was found"},
	{HeuristicMatch, "Atleast one suspicious (heuristic match) object was found"},
	{UserError, "Scanning interrupted by user"},
	{RestrictionError, "Scan restriction caused scan to skip files"},
	{SystemError, "Platform error"},
	{InternalError, "Internal Engine error"},
	{SkipError, "Atleast one object was not scanned"},
	{DisinfectError, "Atleast one object was disinfected"},
	{StatusCode(100), ""},
}

func TestCommand(t *testing.T) {
	for _, tt := range TestCommands {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}

func TestStatusCode(t *testing.T) {
	for _, tt := range TestStatusCodes {
		if s := tt.in.String(); s != tt.out {
			t.Errorf("%q.String() = %q, want %q", tt.in, s, tt.out)
		}
	}
}

func TestBasics(t *testing.T) {
	c, e := NewClient("")
	if e != nil {
		t.Fatalf("An error should not be returned")
	}
	if c.address != "127.0.0.1:10200" {
		t.Errorf("Got %q want %q", c.address, "127.0.0.1:10200")
	}
	if c.connTimeout != defaultTimeout {
		t.Errorf("The default conn timeout should be set")
	}
	if c.connSleep != defaultSleep {
		t.Errorf("The default conn sleep should be set")
	}
	if c.connRetries != 0 {
		t.Errorf("The default conn retries should be set")
	}
	expected := 2 * time.Second
	c.SetConnTimeout(expected)
	if c.connTimeout != expected {
		t.Errorf("Calling c.SetConnTimeout(%q) failed", expected)
	}
	c.SetCmdTimeout(expected)
	if c.cmdTimeout != expected {
		t.Errorf("Calling c.SetCmdTimeout(%q) failed", expected)
	}
	c.SetConnSleep(expected)
	if c.connSleep != expected {
		t.Errorf("Calling c.SetConnSleep(%q) failed", expected)
	}
	c.SetConnRetries(2)
	if c.connRetries != 2 {
		t.Errorf("Calling c.SetConnRetries(%q) failed", 2)
	}
	c.SetConnRetries(-2)
	if c.connRetries != 0 {
		t.Errorf("Preventing negative values in c.SetConnRetries(%q) failed", -2)
	}
	if _, e = NewClient("/var/lib/ms/ms.sock"); e == nil {
		t.Errorf("An error should be returned")
	}
	if _, e = NewClient("fe80::879:d85f:f836:1b56%en1"); e == nil {
		t.Errorf("An error should be returned")
	} else {
		expect := "The supplied address is invalid"
		if e.Error() != expect {
			t.Errorf("Got %q want %q", e, expect)
		}
	}
}

func TestGetFiles(t *testing.T) {
	dir, e := ioutil.TempDir("", "")
	if e != nil {
		t.Fatalf("Temp directory creation failed")
	}
	defer os.RemoveAll(dir)
	if e = os.Chmod(dir, 0755); e != nil {
		t.Errorf("Temp directory chmod failed")
	}
	// cm := map[string]bool{}
	pts := []string{path.Join(dir, "file1.txt"), path.Join(dir, "file2.txt")}
	content := []byte("temporary file's content")
	for _, fn := range pts {
		e = ioutil.WriteFile(fn, content, 0640)
		if e != nil {
			t.Errorf("Temp directory chmod failed")
			continue
		}
		// cm[fn] = true
		defer os.Remove(fn)
	}
	fls, e := getFiles(dir)
	found := len(fls)
	if found != 2 {
		t.Errorf("Calling getFiles(%q) should return %q got %q", dir, 2, found)
	}
	if fls[0] != pts[0] && fls[1] != pts[1] {
		t.Errorf("Files returned do not match created")
	}
	_, e = getFiles("/tmxts/hylsgxut.2s.sas")
	if e == nil {
		t.Errorf("An error should be returned")
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	fn := path.Join(gopath, "src/github.com/baruwa-enterprise/fprot/README.md")
	_, e = getFiles(fn)
	if e == nil {
		t.Errorf("An error should be returned")
	}
}

func TestScan(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		fn := "/var/spool/testfiles/install.log"
		s, e := c.ScanFile(fn)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		if len(s) != 1 {
			t.Fatalf("Expected 1 got %d", len(s))
		}
		if s[0].Filename != fn {
			t.Fatalf("Filename expected %s got %s", fn, s[0].Filename)
		}
		if s[0].Infected {
			t.Fatalf("Infected expected %t got %t", false, s[0].Infected)
		}
		if s[0].Signature != "" {
			t.Fatalf("Filename expected %s got %s", "", s[0].Signature)
		}
		fn = "/var/spool/testfiles/eicar.txt"
		s, e = c.ScanFile(fn)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		if len(s) != 1 {
			t.Fatalf("Expected 1 got %d", len(s))
		}
		if s[0].Filename != fn {
			t.Fatalf("Filename expected %s got %s", fn, s[0].Filename)
		}
		if !s[0].Infected {
			t.Fatalf("Infected expected %t got %t", true, s[0].Infected)
		}
		if s[0].Signature != "EICAR_Test_File" {
			t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", s[0].Signature)
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestScanFiles(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		fns := []string{
			"/var/spool/testfiles/eicar.txt",
			"/var/spool/testfiles/eicar.tar.bz2",
		}
		s, e := c.ScanFiles(fns[0], fns[1])
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		if len(s) != len(fns) {
			t.Fatalf("Expected %d got %d", len(fns), len(s))
		}
		for _, r := range s {
			if r.Filename != fns[0] && r.Filename != fns[1] {
				t.Fatalf("Filename expected %s or %s got %s", fns[0], fns[1], r.Filename)
			}
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

// func TestScanDir(t *testing.T) {
// 	address := os.Getenv("FPROT_ADDRESS")
// 	if address != "" {
// 		c, e := NewClient(address)
// 		if e != nil {
// 			t.Fatalf("Error should not be returned: %s", e)
// 		}
// 		defer c.Close()
// 		s, e := c.ScanDir("/var/spool/testfiles")
// 		if e != nil {
// 			t.Fatalf("Error should not be returned: %s", e)
// 		}
// 		if len(s) == 0 {
// 			t.Fatalf("Expected > 1 got %d", len(s))
// 		}
// 	}
// }

func TestScanDirStream(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		dn := path.Join(gopath, "src/github.com/baruwa-enterprise/fprot/examples/data")
		s, e := c.ScanDirStream(dn)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		for _, r := range s {
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestScanStream(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn := path.Join(gopath, "src/github.com/baruwa-enterprise/fprot/examples/data/eicar.tar.bz2")
		s, e := c.ScanStream(fn)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		for _, r := range s {
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestScanReader(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		gopath := os.Getenv("GOPATH")
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		fn := path.Join(gopath, "src/github.com/baruwa-enterprise/fprot/examples/data/eicar.tar.bz2")
		f, e := os.Open(fn)
		if e != nil {
			t.Fatalf("Failed to open file: %s", fn)
		}
		defer f.Close()
		s, e := c.ScanReader(f)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		for _, r := range s {
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestScanReaderBytes(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		m := []byte(eicarVirus)
		f := bytes.NewReader(m)
		s, e := c.ScanReader(f)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		for _, r := range s {
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestScanReaderBuffer(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		f := bytes.NewBufferString(eicarVirus)
		s, e := c.ScanReader(f)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		for _, r := range s {
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestScanReaderString(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		f := strings.NewReader(eicarVirus)
		s, e := c.ScanReader(f)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		for _, r := range s {
			if !r.Infected {
				t.Fatalf("Infected expected %t got %t", true, r.Infected)
			}
			if r.Signature != "EICAR_Test_File" {
				t.Fatalf("Filename expected %s got %s", "EICAR_Test_File", r.Signature)
			}
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}

func TestInfo(t *testing.T) {
	address := os.Getenv("FPROT_ADDRESS")
	if address != "" {
		c, e := NewClient(address)
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		defer c.Close()
		i, e := c.Info()
		if e != nil {
			t.Fatalf("Error should not be returned: %s", e)
		}
		if i.Engine == "" {
			t.Errorf("i.Engine should be none empty string")
		}
		if i.Version == "" {
			t.Errorf("i.Version should be none empty string")
		}
		if i.Protocol == "" {
			t.Errorf("i.Protocol should be none empty string")
		}
		if i.Signature == "" {
			t.Errorf("i.Signature should be none empty string")
		}
		if i.Uptime == "" {
			t.Errorf("i.Uptime should be none empty string")
		}
	} else {
		t.Skip("skipping test; $FPROT_ADDRESS not set")
	}
}
