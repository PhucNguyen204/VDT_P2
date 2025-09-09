package main

import (
	"database/sql"
	"fmt"
	"log"
	
	_ "github.com/lib/pq"
)

func main() {
	// Try different connection strings with lib/pq driver
	connStrings := []string{
		"host=127.0.0.1 port=5432 user=edr_user dbname=edr_db sslmode=disable",
		"host=localhost port=5432 user=edr_user dbname=edr_db sslmode=disable",
		"host=127.0.0.1 port=5432 user=test_user password=test123 dbname=edr_db sslmode=disable",
		"postgresql://edr_user@127.0.0.1:5432/edr_db?sslmode=disable",
	}
	
	for i, connString := range connStrings {
		fmt.Printf("Testing lib/pq %d: %s\n", i+1, connString)
		
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
	
	log.Println("All lib/pq connection attempts failed")
}
