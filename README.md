# Sign In With Apple SDK

[godoc]: https://godoc.org/github.com/jmind-systems/go-apple-signin
[godoc-img]: https://godoc.org/github.com/jmind-systems/go-apple-signin?status.svg

[goreport]: https://goreportcard.com/report/github.com/jmind-systems/go-apple-signin
[goreport-img]: https://goreportcard.com/badge/github.com/jmind-systems/go-apple-signin

[version]: https://img.shields.io/github/v/tag/jmind-systems/go-apple-signin?sort=semver

[![Docs][godoc-img]][godoc]
[![Go Report][goreport-img]][goreport]
[![Version][version]][version]

:apple: Golang client for [Sign in with Apple](https://developer.apple.com/sign-in-with-apple).

Install it with command below

```sh
go get github.com/jmind-systems/go-apple-signin
```

You can take a look and inspire by following [examples](./examples)

## Example

```go
package main

import (
    "fmt"
    "os"
    "time"

    "github.com/jmind-systems/go-apple-signin"
)

func main() {
    client := apple.NewClient()
}
```

## License

Project released under the terms of the MIT [license](./LICENSE).
