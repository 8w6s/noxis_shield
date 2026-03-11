//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

func main() {
	fmt.Println("Launching sustained attack for 20 seconds...")

	var wg sync.WaitGroup
	start := time.Now()

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Since(start) < 20*time.Second {
				client.Get("http://localhost:8080/")
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	wg.Wait()
	fmt.Printf("Attack completed in %s.\n", time.Since(start))
}
