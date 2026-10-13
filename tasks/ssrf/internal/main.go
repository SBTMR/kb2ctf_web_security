package main

import (
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "strings"
    "time"
)

func port() string {
    if os.Getenv("ROLE") == "sample" { return "8080" }
    return "1337"
}

func handler(role string) http.Handler {
    mux := http.NewServeMux()
    mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
        if role != "sample" {
            content, err := os.ReadFile("/run/lab/flag.txt")
            if err != nil || !strings.HasPrefix(string(content), "KB2CTF{") {
                http.Error(w, "unavailable", http.StatusServiceUnavailable); return
            }
        }
        fmt.Fprintln(w, "ready")
    })
    if role == "sample" {
        mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            fmt.Fprintln(w, "Web Sheriff sample-site: the backend retrieved this local page.")
        })
    } else {
        mux.HandleFunc("/flag", func(w http.ResponseWriter, r *http.Request) {
            // Original internal-service authorization rule retained for source review.
            if r.Header.Get("Authorization") != "Bearer MireactfG00000000l" {
                http.Error(w, "Unauthorized", http.StatusUnauthorized); return
            }
            content, err := os.ReadFile("/run/lab/flag.txt")
            if err != nil { http.Error(w, "Configuration unavailable", 503); return }
            w.Header().Set("Content-Type", "text/plain; charset=utf-8")
            fmt.Fprintln(w, strings.TrimSpace(string(content)))
        })
    }
    return mux
}

func main() {
    if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
        client := &http.Client{Timeout: 2 * time.Second}
        response, err := client.Get("http://127.0.0.1:" + port() + "/healthz")
        if err != nil { os.Exit(1) }
        defer response.Body.Close()
        io.Copy(io.Discard, response.Body)
        if response.StatusCode != 200 { os.Exit(1) }
        return
    }
    server := &http.Server{Addr: ":" + port(), Handler: handler(os.Getenv("ROLE"))}
    log.Fatal(server.ListenAndServe())
}
