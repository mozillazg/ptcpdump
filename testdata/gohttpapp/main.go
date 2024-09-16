package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
)

func newHttpServer() *httptest.Server {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("response from TLS Server"))
	}))
	return s
}

func main() {
	s := newHttpServer()
	defer s.Close()

	client := s.Client()
	resp, err := client.Get(s.URL + "/foo/bar")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
}
