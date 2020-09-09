// Copyright 2018 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"io/ioutil"
	"strings"

	pb "github.com/casbin/casbin-server/proto"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	gormadapter "github.com/casbin/gorm-adapter/v2"
)

// Server is used to implement proto.CasbinServer.
type Server struct {
	enforcer *casbin.Enforcer
	adapter  persist.Adapter
}

func NewServer() *Server {
	s := Server{}

	// 加载配置文件
	cfg := LoadConfiguration("config/connection_config.json")

	// 初始化 adapter
	var err error
	switch cfg.Driver {
	case "file":
		s.adapter = fileadapter.NewAdapter(cfg.Connection)
	default:
		s.adapter, err = gormadapter.NewAdapter(cfg.Driver, cfg.Connection, cfg.DBSpecified)
		if err != nil {
			panic(err)
		}
	}

	// 初始化 enforcer
	data, err := ioutil.ReadFile(cfg.Enforcer)
	if err != nil {
		panic(err)
	}
	m, err := model.NewModelFromString(string(data))
	if err != nil {
		panic(err)
	}
	s.enforcer, err = casbin.NewEnforcer(m, s.adapter)
	if err != nil {
		panic(err)
	}

	return &s
}

func (s *Server) NewEnforcer(ctx context.Context, in *pb.NewEnforcerRequest) (*pb.NewEnforcerReply, error) {
	var a = s.adapter
	var e *casbin.Enforcer

	if in.ModelText == "" {
		cfg := LoadConfiguration("config/connection_config.json")
		data, err := ioutil.ReadFile(cfg.Enforcer)
		if err != nil {
			return &pb.NewEnforcerReply{Handler: 0}, err
		}
		in.ModelText = string(data)
	}

	if a == nil {
		m, err := model.NewModelFromString(in.ModelText)
		if err != nil {
			return &pb.NewEnforcerReply{Handler: 0}, err
		}

		e, err = casbin.NewEnforcer(m)
		if err != nil {
			return &pb.NewEnforcerReply{Handler: 0}, err
		}
	} else {
		m, err := model.NewModelFromString(in.ModelText)
		if err != nil {
			return &pb.NewEnforcerReply{Handler: 0}, err
		}

		e, err = casbin.NewEnforcer(m, a)
		if err != nil {
			return &pb.NewEnforcerReply{Handler: 0}, err
		}
	}
	s.enforcer = e

	return &pb.NewEnforcerReply{Handler: 0}, nil
}

func (s *Server) NewAdapter(ctx context.Context, in *pb.NewAdapterRequest) (*pb.NewAdapterReply, error) {
	a, err := newAdapter(in)
	if err != nil {
		return nil, err
	}
	s.adapter = a

	return &pb.NewAdapterReply{Handler: 0}, nil
}

func (s *Server) parseParam(param, matcher string) (interface{}, string) {
	if strings.HasPrefix(param, "ABAC::") {
		attrList, err := resolveABAC(param)
		if err != nil {
			panic(err)
		}
		for k, v := range attrList.nameMap {
			old := "." + k
			if strings.Contains(matcher, old) {
				matcher = strings.Replace(matcher, old, "."+v, -1)
			}
		}
		return attrList, matcher
	} else {
		return param, matcher
	}
}

func (s *Server) Enforce(ctx context.Context, in *pb.EnforceRequest) (*pb.BoolReply, error) {
	var param interface{}
	params := make([]interface{}, 0, len(in.Params))
	m := s.enforcer.GetModel()["m"]["m"].Value

	for index := range in.Params {
		param, m = s.parseParam(in.Params[index], m)
		params = append(params, param)
	}

	res, err := s.enforcer.EnforceWithMatcher(m, params...)
	if err != nil {
		return &pb.BoolReply{Res: false}, err
	}

	return &pb.BoolReply{Res: res}, nil
}

func (s *Server) LoadPolicy(ctx context.Context, in *pb.EmptyRequest) (*pb.EmptyReply, error) {
	err := s.enforcer.LoadPolicy()
	return &pb.EmptyReply{}, err
}

func (s *Server) SavePolicy(ctx context.Context, in *pb.EmptyRequest) (*pb.EmptyReply, error) {
	err := s.enforcer.SavePolicy()
	return &pb.EmptyReply{}, err
}
