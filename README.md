<img width="1536" height="409" alt="e7454660-a0e6-48e8-827a-ff47943d0606" src="https://github.com/user-attachments/assets/dd60aff3-cd10-4c76-9ad5-0c404e99692b" />


## Overview

DoomScope is a comprehensive Automation Recon and Security Scanning tool designed to replace days of manual reconnaissance with a single intelligent, dependency-aware pipeline.

Instead of running multiple tools independently, DoomScope builds a structured workflow where each stage consumes verified outputs from previous stages. This approach significantly improves accuracy, reduces noise, and avoids redundant or random scanning.

---

## Core Concept

DoomScope is not a collection of tools stitched together.

It is a dependency-aware pipeline where:
- Each stage relies on validated results from the previous stage
- Only confirmed data is allowed to move forward
- False positives are filtered early

The pipeline starts from a single domain and ends with a unified security report.

---

## High-Level Workflow

1. Domain input
2. Subdomain enumeration
3. Subdomain reconnaissance
4. Endpoints and parameters analysis
5. Reflected parameters detection
6. JavaScript deep analysis
7. Page identification and smart filtering
8. Targeted security scanning
9. Unified JSON report generation

---

## Architecture

DoomScope is built using approximately 30 independent services.

Each service:
- Runs only after the previous stage completes
- Consumes structured output from earlier stages
- Produces validated input for the next stage

This architecture ensures strong correlation between recon data and security findings.

---

## Subdomain Enumeration

The pipeline begins with a single domain provided by the user.

DoomScope collects subdomains from multiple sources, including:
- Certificate Transparency logs
- Wayback Machine
- Brute-force wordlists
- Public intelligence sources

Subdomain enumeration is the backbone of the entire pipeline.

---

## Subdomain Reconnaissance

For each discovered subdomain, DoomScope performs active reconnaissance.

### Directory and Path Discovery
- Extracts real paths
- Captures HTTP status codes
- Identifies valid URLs for further analysis

### Technology Fingerprinting
- Detects backend and frontend technologies
- Classifies targets based on technology stack

### Early Security Scanning
- Fast and lightweight scans
- Eliminates obvious noise early in the pipeline

---

## Endpoints and Parameters Analysis

DoomScope does not rely on a single data source.

### Endpoints Discovery

Endpoints are extracted from:
- Live responses
- JavaScript files
- Archived content

Available HTTP methods such as GET, POST, PUT, and others are identified.

### Parameters Collection

Parameters are gathered from:
- Directory scan outputs
- JavaScript analysis
- Archived URLs
- Public datasets

All parameters are merged into a single unified dataset.

---

## Reflected Parameters Detection

Not every parameter is trusted by default.

DoomScope:
- Injects unique test values
- Observes HTML responses
- Confirms real parameter reflection

Reflection sources include:
- Live reflected parameters
- Public reflected parameters
- Archived reflected parameters

Only confirmed reflected parameters proceed to later stages.

---

## JavaScript Analysis

JavaScript files are collected from multiple sources:
- Live pages
- Archived pages
- Public crawling
- JavaScript discovery techniques
- Directory scan results

Analysis focuses on identifying:
- Secrets
- Tokens
- API keys
- Hidden endpoints
- Sensitive patterns using regular expressions

---

## Page Identification and Smart Filtering

DoomScope analyzes page behavior to understand its nature.

Static pages are detected when:
- Response length is constant
- Response length changes only based on URL length

Pages are classified into categories such as:
- Authentication pages
- Upload pages
- Checkout pages
- Administrative panels
- API endpoints

This prevents random scanning and focuses effort on high-value targets.

---

## Targeted Security Scanning

The final security scanning stage runs only on:
- Confirmed endpoints
- Reflected parameters
- Dynamic pages

This stage performs:
- Deeper vulnerability scans
- Targeted testing instead of broad noise-based scanning

---

## Output

DoomScope produces a single unified JSON report containing:
- Subdomains
- Paths
- Endpoints
- Parameters
- Reflections
- API endpoints
- JavaScript secrets
- Security findings

This provides high recon coverage without wasting time.

---

## Flexibility and Customization

All detection logic is configurable.

Regular expressions, patterns, and detection rules are stored in separate files, allowing users to:
- Reduce false positives
- Add new detection rules
- Customize logic based on target requirements

---

## Disclaimer

DoomScope is intended for authorized security testing and educational purposes only.  
Unauthorized use against systems you do not own or have permission to test is strictly prohibited.



