package main

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/baruwa-enterprise/fprot"
	flag "github.com/spf13/pflag"
)

var (
	cfg     *Config
	cmdName string
)

// Config holds the configuration
type Config struct {
	Address string
	Port    int
}

func init() {
	cfg = &Config{}
	cmdName = path.Base(os.Args[0])
	flag.StringVarP(&cfg.Address, "host", "H", "192.168.1.126",
		`Specify Fprot host to connect to.`)
	flag.IntVarP(&cfg.Port, "port", "p", 10200,
		`In TCP/IP mode, connect to Fprot server listening on given port`)
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\n", cmdName)
	fmt.Fprint(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
}

func scanv(c *fprot.Client) {
	ctx := context.Background()
	s, e := c.ScanFile(ctx, "/var/spool/testfiles/eicar.txt")
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nstatuscode\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.StatusCode, rt.Signature, rt.Infected)
	}
}

func scan(ctx context.Context, c *fprot.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	s, e := c.ScanFile(ctx, "/var/spool/testfiles/install.log")
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nstatuscode\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.StatusCode, rt.Signature, rt.Infected)
		// fmt.Println("RAW=>", rt.Raw)
	}
}

func scanFiles(ctx context.Context, c *fprot.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	s, e := c.ScanFiles(ctx, "/var/spool/testfiles/install.log", "/var/spool/testfiles/eicar.tar.bz2")
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nstatuscode\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.StatusCode, rt.Signature, rt.Infected)
		// fmt.Println("RAW=>", rt.Raw)
	}
}

func scanDirStream(ctx context.Context, c *fprot.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	dn := path.Join(gopath, "src/github.com/baruwa-enterprise/fprot/examples/data")
	s, e := c.ScanDirStream(ctx, dn)
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nstatuscode\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.StatusCode, rt.Signature, rt.Infected)
		// fmt.Println("RAW=>", rt.Raw)
	}
}

func scanStream(ctx context.Context, c *fprot.Client, w *sync.WaitGroup) {
	defer func() {
		w.Done()
	}()

	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	fn := path.Join(gopath, "src/github.com/baruwa-enterprise/fprot/examples/data/eicar.tar.bz2")
	s, e := c.ScanStream(ctx, fn)
	if e != nil {
		log.Println("ERROR:", e)
		return
	}
	for _, rt := range s {
		fmt.Printf("Scan:\t\t%s\naname\t\t=>\t%s\nstatus\t\t=>\t%s\nstatuscode\t\t=>\t%s\nsignature\t\t=>\t%s\ninfected\t\t=>\t%t\n",
			rt.Filename, rt.ArchiveItem, rt.Status, rt.StatusCode, rt.Signature, rt.Infected)
		// fmt.Println("RAW=>", rt.Raw)
	}
}

func main() {
	var s fprot.Info
	flag.Usage = usage
	flag.ErrHelp = errors.New("")
	flag.CommandLine.SortFlags = false
	flag.Parse()
	address := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	c, e := fprot.NewClient(address)
	if e != nil {
		log.Println(e)
		return
	}
	ctx := context.Background()
	defer c.Close(ctx)
	c.SetConnTimeout(5 * time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go scan(ctx, c, &wg)
	wg.Add(1)
	go scanFiles(ctx, c, &wg)
	wg.Add(1)
	go scanDirStream(ctx, c, &wg)
	wg.Add(1)
	go scanStream(ctx, c, &wg)
	wg.Wait()

	// Run in main goroutine
	scanv(c)
	if s, e = c.Info(ctx); e != nil {
		log.Println(e)
		return
	}
	fmt.Println("INFO:",
		"Version =>", s.Version,
		"Engine =>", s.Engine,
		"Protocol =>", s.Protocol,
		"Signature =>", s.Signature,
		"Uptime =>", s.Uptime)
	fmt.Println("Done")
}
