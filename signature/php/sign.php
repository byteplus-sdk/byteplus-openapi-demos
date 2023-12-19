<?php
/**
 * Copyright 2023 Byteplus Pte. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require 'vendor/autoload.php';

// Install the composer (https://getcomposer.org/doc/00-intro.md) and the GuzzleHttp dependency: composer require guzzlehttp/guzzle:^7.0.
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;


$AK = 'AK****';
$SK = '****';

$Service = "iam";
$Version = "2018-01-01";
$Region = "ap-singapore-1";
$Host = "open.byteplusapi.com";
$ContentType = "application/x-www-form-urlencoded";

$now = time();

$requestBody = "";

try {
    $response = request("GET", [
        'Limit' => '100'
    ], [], $AK, $SK, "ListUsers", $requestBody);
    print_r($response->getBody()->getContents());
} catch (GuzzleException $e) {
    print_r($e->getMessage());
}

/**
 * @throws GuzzleException
 */
// Step 1: Create an API request function that includes a signature calculation method.
function request($method, $query, $header, $ak, $sk, $action, $body)
{

    // Step 2: Create an identity credential. 
    // The values of the Service and Region fields are fixed and the values of the ak and sk fields indicate an access key ID and a secret access key, respectively. 
    // Signature struct initialization is also required. Some attributes required for signature calculation also need to be processed here. 
    // Initialize the identity credential struct.
    global $Service, $Region, $Host, $Version, $ContentType;
    $credential = [
        'accessKeyId' => $ak,
        'secretKeyId' => $sk,
        'service' => $Service,
        'region' => $Region,
    ];

    // Initialize the signature struct.
    $query = array_merge($query, [
        'Action' => $action,
        'Version' => $Version
    ]);
    ksort($query);
    $requestParam = [
        // The body is the native body required by HTTP requests.
        'body' => $body,
        'host' => $Host,
        'path' => '/',
        'method' => $method,
        'contentType' => $ContentType,
        'date' => gmdate('Ymd\THis\Z'),
        'query' => $query
    ];

    // Step 3: Prepare a signResult variable for receiving the signature calculation result and set the required parameters. 
    // Initialize the signature result struct.
    $xDate = $requestParam['date'];
    $shortXDate = substr($xDate, 0, 8);
    $xContentSha256 = hash('sha256', $requestParam['body']);
    $signResult = [
        'Host' => $requestParam['host'],
        'X-Content-Sha256' => $xContentSha256,
        'X-Date' => $xDate,
        'Content-Type' => $requestParam['contentType']
    ];
    // Step 4: Calculate a signature.
    $signedHeaderStr = join(';', ['content-type', 'host', 'x-content-sha256', 'x-date']);
    $canonicalRequestStr = join("\n", [
        $requestParam['method'],
        $requestParam['path'],
        http_build_query($requestParam['query']),
        join("\n", ['content-type:' . $requestParam['contentType'], 'host:' . $requestParam['host'], 'x-content-sha256:' . $xContentSha256, 'x-date:' . $xDate]),
        '',
        $signedHeaderStr,
        $xContentSha256
    ]);
    $hashedCanonicalRequest = hash("sha256", $canonicalRequestStr);
    $credentialScope = join('/', [$shortXDate, $credential['region'], $credential['service'], 'request']);
    $stringToSign = join("\n", ['HMAC-SHA256', $xDate, $credentialScope, $hashedCanonicalRequest]);
    $kDate = hash_hmac("sha256", $shortXDate, $credential['secretKeyId'], true);
    $kRegion = hash_hmac("sha256", $credential['region'], $kDate, true);
    $kService = hash_hmac("sha256", $credential['service'], $kRegion, true);
    $kSigning = hash_hmac("sha256", 'request', $kService, true);
    $signature = hash_hmac("sha256", $stringToSign, $kSigning);
    $signResult['Authorization'] = sprintf("HMAC-SHA256 Credential=%s, SignedHeaders=%s, Signature=%s", $credential['accessKeyId'] . '/' . $credentialScope, $signedHeaderStr, $signature);
    $header = array_merge($header, $signResult);
    // Step 5: Write the signature into the HTTP header and send the HTTP request.
    $client = new Client([
        'base_uri' => 'https://' . $requestParam['host'],
        'timeout' => 120.0,
    ]);
    return $client->request($method, 'https://' . $requestParam['host'] . $requestParam['path'], [
        'headers' => $header,
        'query' => $requestParam['query'],
        'body' => $requestParam['body']
    ]);
}
