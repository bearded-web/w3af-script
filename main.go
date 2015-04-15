package main

// Temporary file

import (
	"github.com/bearded-web/bearded/pkg/script"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/net/context"

	"github.com/bearded-web/bearded/pkg/transport/mango"
	"github.com/bearded-web/w3af-script/w3af"
)

func run(addr string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transp, err := mango.NewServer(addr)
	if err != nil {
		panic(err)
	}
	client, err := script.NewRemoteClient(transp)
	if err != nil {
		panic(err)
	}
	go func() {
		err := transp.Serve(ctx, client)
		if err != nil {
			panic(err)
		}
	}()
	println("wait for connection")
	client.WaitForConnection(ctx)
	println("request config")
	conf, err := client.GetConfig(ctx)
	if err != nil {
		panic(err)
	}

	app := w3af.NewW3af()

	println("handle with conf", spew.Sdump(conf))
	err = app.Handle(ctx, client, conf)
	if err != nil {
		panic(err)
	}
}

func main() {
	run("tcp://:9238")
	//	run(":9238")
}
