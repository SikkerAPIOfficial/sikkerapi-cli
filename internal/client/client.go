package client

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sikkerapi/sikker-cli/internal/config"
)

var version = "dev"

func SetVersion(v string) {
	version = v
}

type Client struct {
	cfg    *config.Config
	http   *http.Client
}

func New(cfg *config.Config) *Client {
	return &Client{
		cfg: cfg,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Get performs a GET request and returns the raw response body and headers.
func (c *Client) Get(path string) ([]byte, int, http.Header, error) {
	url := c.cfg.BaseURL + path
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	c.setHeaders(req)
	return c.do(req)
}

// Post performs a POST request with a JSON body.
func (c *Client) Post(path string, body []byte) ([]byte, int, http.Header, error) {
	url := c.cfg.BaseURL + path
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	c.setHeaders(req)
	return c.do(req)
}

// PostMultipart uploads a file as multipart/form-data.
func (c *Client) PostMultipart(path string, fieldName string, filePath string) ([]byte, int, http.Header, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("cannot open file: %w", err)
	}
	defer file.Close()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile(fieldName, filePath)
	if err != nil {
		return nil, 0, nil, err
	}
	if _, err := io.Copy(part, file); err != nil {
		return nil, 0, nil, err
	}
	writer.Close()

	url := c.cfg.BaseURL + path
	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	c.setHeaders(req)
	return c.do(req)
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("User-Agent", "sikker-cli/"+version)
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
}

func (c *Client) do(req *http.Request) ([]byte, int, http.Header, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == 429 {
		retryAfter := resp.Header.Get("Retry-After")
		if retryAfter != "" {
			if secs, err := strconv.Atoi(retryAfter); err == nil {
				return body, 429, resp.Header, fmt.Errorf("rate limited — try again in %ds", secs)
			}
		}
		return body, 429, resp.Header, fmt.Errorf("rate limited — try again later")
	}

	if resp.StatusCode == 401 {
		return body, 401, resp.Header, fmt.Errorf("invalid API key — run `sikker auth <key>` to set your key")
	}

	if resp.StatusCode == 403 {
		return body, 403, resp.Header, fmt.Errorf("API key disabled or expired")
	}

	return body, resp.StatusCode, resp.Header, nil
}

// RequireKey checks that an API key is configured and exits with a helpful message if not.
func RequireKey(cfg *config.Config) {
	if cfg.APIKey == "" {
		red := color.New(color.FgRed)
		red.Fprintln(os.Stderr, "No API key configured.")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Set your key with:")
		fmt.Fprintln(os.Stderr, "  sikker auth <your-api-key>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Or set the SIKKERAPI_KEY environment variable.")
		os.Exit(1)
	}
}

// BuildQuery builds a query string from key-value pairs, skipping empty values.
func BuildQuery(params map[string]string) string {
	var parts []string
	for k, v := range params {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}
