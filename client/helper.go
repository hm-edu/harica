package client

import (
	"strings"

	"github.com/go-resty/resty/v2"
	"golang.org/x/net/html"
)

func getVerificationToken(r *resty.Client, BaseURL string) (string, error) {
	resp, err := r.
		R().
		Get(BaseURL)
	if err != nil {
		return "", err
	}
	doc, err := html.Parse(strings.NewReader(resp.String()))
	if err != nil {
		return "", err
	}
	verificationToken := ""
	var processHtml func(*html.Node)
	processHtml = func(n *html.Node) {
		if verificationToken != "" {
			return
		}
		if n.Type == html.ElementNode && n.Data == "input" {
			for _, a := range n.Attr {
				if a.Key == "name" && a.Val == "__RequestVerificationToken" {
					for _, a := range n.Attr {
						if a.Key == "value" {
							if verificationToken == "" {
								verificationToken = a.Val
								return
							}
						}
					}
				}
			}
		}

		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if verificationToken != "" {
				return
			}
			processHtml(c)
		}
	}

	processHtml(doc)
	return verificationToken, nil
}
