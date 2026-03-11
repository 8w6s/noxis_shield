//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

func main() {
	var wg sync.WaitGroup
	// Send 7 rapid requests to raise the Reputation Score to ~3.5
	for i := 0; i < 7; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			http.Get("http://localhost:8080")
		}()
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	// The 8th request should hit the JS PoW Challenge (Score > 3.0)
	resp, err := http.Get("http://localhost:8080")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Status Code: %d\n", resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if resp.StatusCode == 503 && len(html) > 100 {
		fmt.Println("SUCCESS! Received JS Challenge HTML:")
		fmt.Println(html[:250] + "...\n[TRUNCATED]")
	} else {
		fmt.Println("FAILED to get Challenge. Output:")
		fmt.Println(html)
	}
}
