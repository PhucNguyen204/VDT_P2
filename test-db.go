package main

import (
	"fmt"
	"log"
	
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Try different DSN formats
	dsnList := []string{
		"host=127.0.0.1 user=test_user password=test123 dbname=edr_db port=5432 sslmode=disable",
		"host=localhost user=test_user password=test123 dbname=edr_db port=5432 sslmode=disable",
		"host=127.0.0.1 user=edr_user password=edr_password dbname=edr_db port=5432 sslmode=disable",
		"host=127.0.0.1 user=edr_user dbname=edr_db port=5432 sslmode=disable",
		"postgresql://test_user:test123@127.0.0.1:5432/edr_db?sslmode=disable",
		"postgresql://edr_user:edr_password@127.0.0.1:5432/edr_db?sslmode=disable",
	}
	
	for i, dsn := range dsnList {
		fmt.Printf("Testing DSN %d: %s\n", i+1, dsn)
		
		db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err != nil {
			fmt.Printf("  ❌ Error: %v\n", err)
		} else {
			fmt.Printf("  ✅ Success!\n")
			
			// Test query
			var result int
			err = db.Raw("SELECT 1").Scan(&result).Error
			if err != nil {
				fmt.Printf("  ❌ Query failed: %v\n", err)
			} else {
				fmt.Printf("  ✅ Query success: %d\n", result)
			}
			
			sqlDB, _ := db.DB()
			sqlDB.Close()
			return
		}
		fmt.Println()
	}
	
	log.Println("All connection attempts failed")
}
