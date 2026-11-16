package main

import (
	"net"
	"net/http"
	"os/exec"
)

func ping(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(r.URL.Query().Get("host"))
	if ip == nil {
		http.Error(w, "invalid host", http.StatusBadRequest)
		return
	}
	out, _ := exec.Command("ping", "-c", "1", ip.String()).Output()
	w.Write(out)
}
