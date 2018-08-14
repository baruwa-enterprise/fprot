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
	"go/build"
	"io/ioutil"
	"os"
	"path"
	"testing"
	"time"
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
		t.Errorf("An error should not be returned")
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
		t.Errorf("Temp directory creation failed")
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
