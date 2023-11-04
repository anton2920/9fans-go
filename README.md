[![Go Reference](https://pkg.go.dev/badge/9fans.net/go.svg)](https://pkg.go.dev/github.com/9fans/go)

# Overview

## Description

This repository contains packages for interacting with Plan 9 as well as ports of common Plan 9 libraries and tools.

## Differences from 9fans.net/go

I've removed everything except for `Watch` and `acmego`. They were ported to work with `acme(1)` from fourth edition of Plan 9.

# Installation

```
$ export GO111MODULE=off
$ go get github.com/anton2920/9fans-go/acme/Watch
$ go get github.com/anton2920/9fans-go/acme/acmego
```
