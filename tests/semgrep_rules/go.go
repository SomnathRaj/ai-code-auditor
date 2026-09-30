// Semgrep rule tests. Lines after a "rule id" annotation must match; lines after an "ok" annotation must not.
package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

func sqli(db *sql.DB, id string) {
	// ruleid: aca-go-sqli-string-built-query
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	q := "DELETE FROM users WHERE id = " + id
	// ruleid: aca-go-sqli-string-built-query
	db.Exec(q)
	// ok: aca-go-sqli-string-built-query
	db.Query("SELECT * FROM users WHERE id = $1", id)
}

func commands(host string) {
	// ruleid: aca-go-command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ok: aca-go-command-injection
	exec.Command("ping", "-c", "1", host).Run()
}

func tlsConfig() *tls.Config {
	// ruleid: aca-go-tls-insecure-skip-verify
	return &tls.Config{InsecureSkipVerify: true}
}

func hashes(b []byte) {
	// ruleid: aca-go-weak-hash
	md5.Sum(b)
	// ok: aca-go-weak-hash
	sha256.Sum256(b)
}

func download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	// ruleid: aca-go-path-traversal
	http.ServeFile(w, r, filepath.Join("/srv/files", name))
}

func downloadSafe(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	// ok: aca-go-path-traversal
	data, _ := os.ReadFile(filepath.Join("/srv/files", name))
	w.Write(data)
}

func proxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	// ruleid: aca-go-ssrf
	resp, _ := http.Get(target)
	defer resp.Body.Close()
}
