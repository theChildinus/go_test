package main

import (
	proto "casbinsvr/proto"
	"context"
	"fmt"
	"google.golang.org/grpc"
	"log"
)

const (
	address = "localhost:50051"
)

func main() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := proto.NewAccessControlClient(conn)

	fmt.Println("Please input: sub obj act")
	for {
		var sub, obj, act string
		_, _ = fmt.Scanf("%s %s %s", &sub, &obj, &act)
		if sub == "exit" {
			break
		}
		r, err := c.Check(context.Background(), &proto.AccessControlReq{Sub: sub, Obj: obj, Act: act})
		if err != nil {
			log.Fatalf("could not access control: %v", err)
		}
		log.Println("CheckResult:", r.GetRes())
	}

}
