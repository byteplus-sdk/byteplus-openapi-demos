/*
Copyright 2023 Byteplus Pte. Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	// Request credential, obtained from Identity and Access Management
	AccessKeyID     = "AK"
	SecretAccessKey = "****"

	// Request URL
	Addr = "https://open.byteplusapi.com"
	Path = "/" // Path, excluding the query string

	// Information about the API operation
	Service = "iam"
	Region  = "ap-singapore-1"
	Action  = "ListUsers"
	Version = "2018-01-01"
)

func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

func getSignedKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte(secretKey), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "request")

	return kSigning
}

func hashSHA256(data []byte) []byte {
	hash := sha256.New()
	if _, err := hash.Write(data); err != nil {
		log.Printf("input hash err:%s", err.Error())
	}

	return hash.Sum(nil)
}

func doRequest(method string, queries url.Values, body []byte) error {
	// 1. Construct a request
	queries.Set("Action", Action)
	queries.Set("Version", Version)
	requestAddr := fmt.Sprintf("%s%s?%s", Addr, Path, queries.Encode())
	log.Printf("request addr: %s\n", requestAddr)

	request, err := http.NewRequest(method, requestAddr, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("bad request: %w", err)
	}

	// 2. Construct signature materials
	now := time.Now()
	date := now.UTC().Format("20060102T150405Z")
	authDate := date[:8]
	request.Header.Set("X-Date", date)

	payload := hex.EncodeToString(hashSHA256(body))
	request.Header.Set("X-Content-Sha256", payload)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	queryString := strings.Replace(queries.Encode(), "+", "%20", -1)
	signedHeaders := []string{"host", "x-date", "x-content-sha256", "content-type"}
	var headerList []string
	for _, header := range signedHeaders {
		if header == "host" {
			headerList = append(headerList, header+":"+request.Host)
		} else {
			v := request.Header.Get(header)
			headerList = append(headerList, header+":"+strings.TrimSpace(v))
		}
	}
	headerString := strings.Join(headerList, "\n")

	canonicalString := strings.Join([]string{
		method,
		Path,
		queryString,
		headerString + "\n",
		strings.Join(signedHeaders, ";"),
		payload,
	}, "\n")
	log.Printf("canonical string:\n%s\n", canonicalString)

	hashedCanonicalString := hex.EncodeToString(hashSHA256([]byte(canonicalString)))
	log.Printf("hashed canonical string: %s\n", hashedCanonicalString)

	credentialScope := authDate + "/" + Region + "/" + Service + "/request"
	signString := strings.Join([]string{
		"HMAC-SHA256",
		date,
		credentialScope,
		hashedCanonicalString,
	}, "\n")
	log.Printf("sign string:\n%s\n", signString)

	// 3. Construct an authorization request header
	signedKey := getSignedKey(SecretAccessKey, authDate, Region, Service)
	signature := hex.EncodeToString(hmacSHA256(signedKey, signString))
	log.Printf("signature: %s\n", signature)

	authorization := "HMAC-SHA256" +
		" Credential=" + AccessKeyID + "/" + credentialScope +
		", SignedHeaders=" + strings.Join(signedHeaders, ";") +
		", Signature=" + signature
	request.Header.Set("Authorization", authorization)
	log.Printf("authorization: %s\n", authorization)

	// 4. Print and initiate a request
	requestRaw, err := httputil.DumpRequest(request, true)
	if err != nil {
		return fmt.Errorf("dump request err: %w", err)
	}

	log.Printf("request:\n%s\n", string(requestRaw))

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("do request err: %w", err)
	}

	// 5. Print a response
	responseRaw, err := httputil.DumpResponse(response, true)
	if err != nil {
		return fmt.Errorf("dump response err: %w", err)
	}

	log.Printf("response:\n%s\n", string(responseRaw))

	if response.StatusCode == 200 {
		log.Printf("请求成功")
	} else {
		log.Printf("请求失败")
	}

	return nil
}

func main() {
	// GET request example
	query1 := make(url.Values)
	query1.Set("Limit", "100")
	query1.Set("Offset", "0")
	err := doRequest(http.MethodGet, query1, nil)
	if err != nil {
		log.Printf("do Request err: %+v", err)
	}

	// POST request example
	// query2 := make(url.Values)
	// query2.Set("args1", "value1")
	// query2.Set("args2", "value2")
	// doRequest(http.MethodPost, query2, []byte(`Scope=System`))
}
