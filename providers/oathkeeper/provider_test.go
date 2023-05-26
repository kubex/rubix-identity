package oathkeeper

import (
	"encoding/json"
	"github.com/valyala/fasthttp"
	"log"
	"testing"
)

func TestProvider_CreateSession(t *testing.T) {
	p, _ := FromJson([]byte("{}"))
	inMem := &fasthttp.RequestCtx{}
	session, _ := p.CreateSession(inMem)
	jsn, _ := json.Marshal(session)
	log.Println(string(jsn))
}
