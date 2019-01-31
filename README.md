# fprot

Golang Fprot Client

[![Build Status](https://travis-ci.org/baruwa-enterprise/fprot.svg?branch=master)](https://travis-ci.org/baruwa-enterprise/fprot)
[![codecov](https://codecov.io/gh/baruwa-enterprise/fprot/branch/master/graph/badge.svg)](https://codecov.io/gh/baruwa-enterprise/fprot)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/fprot)](https://goreportcard.com/report/github.com/baruwa-enterprise/fprot)
[![GoDoc](https://godoc.org/github.com/baruwa-enterprise/fprot?status.svg)](https://godoc.org/github.com/baruwa-enterprise/fprot)
[![MPLv2 License](https://img.shields.io/badge/license-MPLv2-blue.svg?style=flat-square)](https://www.mozilla.org/MPL/2.0/)

## Description

fprot is a Golang library and cmdline tool that implements the
Fprot client protocol used by F-Prot.

## Requirements

* Golang 1.10.x or higher

## Getting started

### Fprot client

The fprot client can be installed as follows

```console
$ go get github.com/baruwa-enterprise/fprot/cmd/fprotscan
```

Or by cloning the repo and then running

```console
$ make build
$ ./bin/fprotscan
```

### Fprot library

To install the library

```console
go get github.com/baruwa-enterprise/fprot
```

You can then import it in your code

```golang
import "github.com/baruwa-enterprise/fprot"
```

### Testing

``make test``

## License

MPL-2.0
