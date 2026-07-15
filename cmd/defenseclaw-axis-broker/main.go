package main

import (
	"database/sql"
	"github.com/defenseclaw/defenseclaw/internal/axis"
	"log"
	_ "modernc.org/sqlite"
	"net/http"
	"os"
	"time"
)

func main() {
	dbPath := os.Getenv("DEFENSECLAW_AXIS_DB")
	if dbPath == "" {
		dbPath = "/var/lib/defenseclaw-axis/broker.sqlite"
	}
	db, e := sql.Open("sqlite", dbPath)
	if e != nil {
		log.Fatal(e)
	}
	defer db.Close()
	b := axis.NewBroker(db, map[string]string{"/home/cisco/workspaces/defenseclaw": "/home/cisco/workspaces/defenseclaw"})
	b.ReleaseID = os.Getenv("DEFENSECLAW_AXIS_RELEASE")
	b.PolicyHash = os.Getenv("DEFENSECLAW_AXIS_POLICY_HASH")
	if e = b.Init(); e != nil {
		log.Fatal(e)
	}
	s := &http.Server{Addr: ":18971", Handler: b.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	log.Printf("mandatory AXIS broker listening on %s", s.Addr)
	log.Fatal(s.ListenAndServe())
}
