package main

import (
	proto "casbinsvr/proto"
	"context"
	"fmt"
	"github.com/casbin/casbin"
	"log"
)

type server struct {
}

const (
	MODEL_PATH  = "server/rbac_model.conf"
	POLICY_PATH = "server/rbac_policy.csv"
)

func (s *server) Check(ctx context.Context, req *proto.AccessControlReq) (*proto.AccessControlResp, error) {
	e := casbin.NewEnforcer(MODEL_PATH, POLICY_PATH)
	sub, obj, act := req.GetSub(), req.GetObj(), req.GetAct()
	fmt.Println("received:", sub, obj, act)
	res := e.Enforce(sub, obj, act)
	return &proto.AccessControlResp{Res: res}, nil
}

func (s *server) Echo(ctx context.Context, req *proto.StringMessage) (*proto.StringMessage, error) {
	log.Println("request: ", req.Value)
	return &proto.StringMessage{Value: "Hello " + req.Value}, nil
}

func main() {
	//lis, err := net.Listen("tcp", ":50051")
	//if err != nil {
	//	log.Fatalf("failed to listen: %v", err)
	//}
	//
	//fmt.Println("AccessControl Server is starting... no panic means ok!")
	//s := grpc.NewServer()
	//proto.RegisterAccessControlServer(s, &server{})
	//if err := s.Serve(lis); err != nil {
	//	log.Fatalf("failed to serve: %v", err)
	//}

	e := casbin.NewEnforcer(MODEL_PATH, POLICY_PATH)
	sub, obj, act := "alice", "data1", "read"
	fmt.Println("received:", sub, obj, act)
	res := e.Enforce(sub, obj, act)
	fmt.Println("res: ", res)
}
