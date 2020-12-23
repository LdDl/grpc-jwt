// Code generated by protoc-gen-go. DO NOT EDIT.
// source: server_example.proto

/*
Package main is a generated protocol buffer package.

It is generated from these files:
	server_example.proto

It has these top-level messages:
	HiddenData
	PublicData
	NoArguments
*/
package main

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type HiddenData struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *HiddenData) Reset()                    { *m = HiddenData{} }
func (m *HiddenData) String() string            { return proto.CompactTextString(m) }
func (*HiddenData) ProtoMessage()               {}
func (*HiddenData) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *HiddenData) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

type PublicData struct {
	Message string `protobuf:"bytes,1,opt,name=message" json:"message,omitempty"`
}

func (m *PublicData) Reset()                    { *m = PublicData{} }
func (m *PublicData) String() string            { return proto.CompactTextString(m) }
func (*PublicData) ProtoMessage()               {}
func (*PublicData) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *PublicData) GetMessage() string {
	if m != nil {
		return m.Message
	}
	return ""
}

type NoArguments struct {
}

func (m *NoArguments) Reset()                    { *m = NoArguments{} }
func (m *NoArguments) String() string            { return proto.CompactTextString(m) }
func (*NoArguments) ProtoMessage()               {}
func (*NoArguments) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func init() {
	proto.RegisterType((*HiddenData)(nil), "main.HiddenData")
	proto.RegisterType((*PublicData)(nil), "main.PublicData")
	proto.RegisterType((*NoArguments)(nil), "main.NoArguments")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for ServerExample service

type ServerExampleClient interface {
	GetHiddenData(ctx context.Context, in *NoArguments, opts ...grpc.CallOption) (*HiddenData, error)
	GetPublicData(ctx context.Context, in *NoArguments, opts ...grpc.CallOption) (*PublicData, error)
}

type serverExampleClient struct {
	cc *grpc.ClientConn
}

func NewServerExampleClient(cc *grpc.ClientConn) ServerExampleClient {
	return &serverExampleClient{cc}
}

func (c *serverExampleClient) GetHiddenData(ctx context.Context, in *NoArguments, opts ...grpc.CallOption) (*HiddenData, error) {
	out := new(HiddenData)
	err := grpc.Invoke(ctx, "/main.ServerExample/GetHiddenData", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *serverExampleClient) GetPublicData(ctx context.Context, in *NoArguments, opts ...grpc.CallOption) (*PublicData, error) {
	out := new(PublicData)
	err := grpc.Invoke(ctx, "/main.ServerExample/GetPublicData", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for ServerExample service

type ServerExampleServer interface {
	GetHiddenData(context.Context, *NoArguments) (*HiddenData, error)
	GetPublicData(context.Context, *NoArguments) (*PublicData, error)
}

func RegisterServerExampleServer(s *grpc.Server, srv ServerExampleServer) {
	s.RegisterService(&_ServerExample_serviceDesc, srv)
}

func _ServerExample_GetHiddenData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NoArguments)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerExampleServer).GetHiddenData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/main.ServerExample/GetHiddenData",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerExampleServer).GetHiddenData(ctx, req.(*NoArguments))
	}
	return interceptor(ctx, in, info, handler)
}

func _ServerExample_GetPublicData_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NoArguments)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ServerExampleServer).GetPublicData(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/main.ServerExample/GetPublicData",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ServerExampleServer).GetPublicData(ctx, req.(*NoArguments))
	}
	return interceptor(ctx, in, info, handler)
}

var _ServerExample_serviceDesc = grpc.ServiceDesc{
	ServiceName: "main.ServerExample",
	HandlerType: (*ServerExampleServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetHiddenData",
			Handler:    _ServerExample_GetHiddenData_Handler,
		},
		{
			MethodName: "GetPublicData",
			Handler:    _ServerExample_GetPublicData_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "server_example.proto",
}

func init() { proto.RegisterFile("server_example.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 161 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x29, 0x4e, 0x2d, 0x2a,
	0x4b, 0x2d, 0x8a, 0x4f, 0xad, 0x48, 0xcc, 0x2d, 0xc8, 0x49, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9,
	0x17, 0x62, 0xc9, 0x4d, 0xcc, 0xcc, 0x53, 0x52, 0xe3, 0xe2, 0xf2, 0xc8, 0x4c, 0x49, 0x49, 0xcd,
	0x73, 0x49, 0x2c, 0x49, 0x14, 0x92, 0xe0, 0x62, 0xcf, 0x4d, 0x2d, 0x2e, 0x4e, 0x4c, 0x4f, 0x95,
	0x60, 0x54, 0x60, 0xd4, 0xe0, 0x0c, 0x82, 0x71, 0x41, 0xea, 0x02, 0x4a, 0x93, 0x72, 0x32, 0x93,
	0x09, 0xa8, 0xe3, 0xe5, 0xe2, 0xf6, 0xcb, 0x77, 0x2c, 0x4a, 0x2f, 0xcd, 0x4d, 0xcd, 0x2b, 0x29,
	0x36, 0xaa, 0xe7, 0xe2, 0x0d, 0x06, 0x5b, 0xee, 0x0a, 0xb1, 0x5b, 0xc8, 0x8c, 0x8b, 0xd7, 0x3d,
	0xb5, 0x04, 0xc9, 0x4a, 0x41, 0x3d, 0x90, 0x3b, 0xf4, 0x90, 0x34, 0x49, 0x09, 0x40, 0x84, 0x10,
	0x8a, 0x94, 0x18, 0xa0, 0xfa, 0x90, 0x9c, 0x80, 0x5b, 0x1f, 0x42, 0x91, 0x12, 0x43, 0x12, 0x1b,
	0xd8, 0xb3, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x22, 0x48, 0xef, 0xa3, 0x04, 0x01, 0x00,
	0x00,
}
