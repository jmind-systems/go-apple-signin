package main

import (
	"context"
	"fmt"

	"github.com/jmind-systems/go-apple-signin"
)

func main() {
	client, err := apple.NewClient(
		apple.WithCredentials("CT7CVV7D59", "com.jmindsystems.MetamorphDev", "4BS65URLZB"),
	)
	if err != nil {
		panic(err)
	}

	if err := client.LoadP8CertByFile("./keys/apple.pem"); err != nil {
		panic(err)
	}

	tok, err := client.Authenticate(context.Background(), "ce47cc89t73da4d3897905f349d404hq5.0.nrrxy.H2Pt0rU0wi0VdumPWM9pEg")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v", tok)
}
