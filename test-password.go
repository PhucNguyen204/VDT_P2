package main

import (
	"database/sql"
	"fmt"
	"log"
	
	_ "github.com/lib/pq"
)

func main() {
	// Try with correct password
	connStrings := []string{
		"host=127.0.0.1 port=5432 user=edr_user password=edr_password dbname=edr_db sslmode=disable",
		"host=localhost port=5432 user=edr_user password=edr_password dbname=edr_db sslmode=disable",
		"postgresql://edr_user:edr_password@127.0.0.1:5432/edr_db?sslmode=disable",
	}
	
	for i, connString := range connStrings {
		fmt.Printf("Testing lib/pq with password %d: %s\n", i+1, connString)
		
		db, err := sql.Open("postgres", connString)
		if err != nil {
			fmt.Printf("  ❌ Error opening: %v\n", err)
			continue
		}
		
		err = db.Ping()
		if err != nil {
			fmt.Printf("  ❌ Error pinging: %v\n", err)
		} else {
			fmt.Printf("  ✅ Success!\n")
			
			// Test query
			var result int
			err = db.QueryRow("SELECT 1").Scan(&result)
			if err != nil {
				fmt.Printf("  ❌ Query failed: %v\n", err)
			} else {
				fmt.Printf("  ✅ Query success: %d\n", result)
			}
			
			db.Close()
			return
		}
		db.Close()
		fmt.Println()
	}
	
	log.Println("All connection attempts failed")
}
