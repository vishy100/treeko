package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"
)

const (
	GreptileAPIUrl = "https://api.greptile.com/v1/search"
	APIKey         = "your_greptile_api_key"
	CodebaseID     = "your_codebase_identifier"
	MaxConcurrent  = 5 // Set the maximum number of concurrent Greptile requests
)

type GreptileRequest struct {
	Prompt   string `json:"prompt"`
	Codebase string `json:"codebase"`
}

type GreptileResponse struct {
	Result string `json:"result"`
	Error  string `json:"error"`
}

var authSearchPrompts = []string{
	"Find functions related to password hashing, e.g., bcrypt, scrypt, argon2.",
	"Locate login routes or endpoints, e.g., routes containing '/login' or 'auth'.",
	"Search for token generation methods, e.g., JWT (json web token) creation.",
	"Look for hardcoded credentials or sensitive tokens.",
	"Identify OAuth configuration or calls to external authentication providers.",
	"Search for references to user sessions, session management, and cookies.",
	"Find environment variable lookups for secrets, e.g., SECRET_KEY, API_KEY.",
}

var sqlInjectionPrompts = []string{
	"Find SQL query constructions without parameterized queries, e.g., direct string concatenation with SQL statements.",
	"Locate raw SQL query executions with user inputs.",
	"Identify potential SQL injection vulnerabilities by inspecting query building functions or user inputs in SQL contexts.",
}

var owaspTop10Prompts = []string{
	"Look for SQL injections, such as unparameterized SQL queries.",
	"Find insecure deserialization usage, which can lead to remote code execution.",
	"Identify potential XSS vulnerabilities, such as unescaped user inputs in HTML.",
	"Check for weak or missing authentication mechanisms in endpoints.",
	"Detect sensitive data exposure, such as unencrypted data storage or transmission.",
	"Search for misconfigurations in security headers, such as missing Content-Security-Policy.",
	"Find code that allows unrestricted file uploads, which may lead to RCE.",
	"Identify usage of vulnerable libraries by analyzing imported dependencies.",
	"Look for improper access controls, e.g., endpoints without authorization checks.",
	"Identify excessive data exposure in APIs, e.g., exposing sensitive fields directly.",
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func CreateGreptileRequest(prompt string, sem chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	sem <- struct{}{} // Acquire semaphore

	payload := GreptileRequest{Prompt: prompt, Codebase: CodebaseID}
	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Error marshaling JSON payload for prompt '%s': %v\n", prompt, err)
		<-sem // Release semaphore
		return
	}

	req, err := http.NewRequest("POST", GreptileAPIUrl, bytes.NewBuffer(body))
	if err != nil {
		log.Printf("Error creating request for prompt '%s': %v\n", prompt, err)
		<-sem // Release semaphore
		return
	}

	req.Header.Set("Authorization", "Bearer "+APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("Error sending request for prompt '%s': %v\n", prompt, err)
		<-sem // Release semaphore
		return
	}
	defer resp.Body.Close()

	responseData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response for prompt '%s': %v\n", prompt, err)
		<-sem // Release semaphore
		return
	}

	var greptileResponse GreptileResponse
	if err := json.Unmarshal(responseData, &greptileResponse); err != nil {
		log.Printf("Error parsing JSON response for prompt '%s': %v\n", prompt, err)
		<-sem // Release semaphore
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error from Greptile for prompt '%s': %v\n", prompt, greptileResponse.Error)
	} else {
		fmt.Printf("Result for '%s': %s\n", prompt, greptileResponse.Result)
	}

	<-sem // Release semaphore
}

func RunAudit(prompts []string, auditName string, sem chan struct{}, wg *sync.WaitGroup) {
	fmt.Printf("Starting %s audit:\n", auditName)
	var localWg sync.WaitGroup
	for _, prompt := range prompts {
		localWg.Add(1)
		go CreateGreptileRequest(prompt, sem, &localWg)
	}
	localWg.Wait()
	fmt.Printf("%s audit completed.\n", auditName)
	wg.Done()
}

func main() {
	var wg sync.WaitGroup
	sem := make(chan struct{}, MaxConcurrent) // Semaphore with max concurrency limit

	wg.Add(3)
	go RunAudit(authSearchPrompts, "Authentication", sem, &wg)
	go RunAudit(sqlInjectionPrompts, "SQL Injection", sem, &wg)
	go RunAudit(owaspTop10Prompts, "OWASP Top 10", sem, &wg)

	wg.Wait()
	fmt.Println("All audits completed.")
}
