# fprot

Golang Fprot Client

[![Ci](https://github.com/baruwa-enterprise/fprot/workflows/Ci/badge.svg)](https://github.com/baruwa-enterprise/fprot/actions?query=workflow%3ACi)
[![codecov](https://codecov.io/gh/baruwa-enterprise/fprot/branch/master/graph/badge.svg)](https://codecov.io/gh/baruwa-enterprise/fprot)
[![Go Report Card](https://goreportcard.com/badge/github.com/baruwa-enterprise/fprot)](https://goreportcard.com/report/github.com/baruwa-enterprise/fprot)
[![Go Reference](https://pkg.go.dev/badge/github.com/baruwa-enterprise/fprot.svg)](https://pkg.go.dev/github.com/baruwa-enterprise/fprot)
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
