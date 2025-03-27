package imap

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-message/mail"
)

type ValidationCode struct {
	Code     string
	mailDate time.Time
}

func FetchValidationCodes(imapHost, imapUsername, imapPassword string, imapPort int, validationStart time.Time, domains []string, debug bool, graceDelta int) (map[string]ValidationCode, error) {
	// Fetch validation codes from IMAP server
	// Create IMAP client
	options := imapclient.Options{}
	if debug {
		options.DebugWriter = os.Stderr
	}
	imapClient, err := imapclient.DialTLS(fmt.Sprintf("%s:%v", imapHost, imapPort), &options)
	if err != nil {
		return nil, err
	}
	imapClient.Login(imapUsername, imapPassword)
	defer imapClient.Logout()

	// Select INBOX
	_, err = imapClient.Select("INBOX", nil).Wait()
	if err != nil {
		return nil, err
	}

	validationCodes := make(map[string]ValidationCode)
	validationRegex := regexp.MustCompile(`(.*) IN TXT &quot;(.*?)&quot;`)

	for {
		mails, err := imapClient.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "HARICA - DNS Change Validation"}},
		}, nil).Wait()
		if err != nil {
			return nil, err
		}
		if len(mails.AllSeqNums()) == 0 {
			slog.Info("No emails found, waiting for emails")
			time.Sleep(5 * time.Second)
			continue
		}
		fetchOptions := &imap.FetchOptions{
			Flags:       true,
			Envelope:    true,
			BodySection: []*imap.FetchItemBodySection{{}},
		}
		msg, err := imapClient.Fetch(mails.All, fetchOptions).Collect()
		if err != nil {
			return nil, err
		}

		for _, m := range msg {
			if m.Envelope.Date.Before(validationStart) && m.Envelope.Date != validationStart {
				delta := validationStart.Sub(m.Envelope.Date)
				deltaSeconds := delta.Abs().Seconds()
				if deltaSeconds > float64(graceDelta) {
					slog.Info("Ignoring email", slog.Time("date", m.Envelope.Date), slog.Time("validationStart", validationStart), slog.Float64("deltaSeconds", deltaSeconds), slog.Int("graceDelta", graceDelta))
					continue
				}
			}
			for _, p := range m.BodySection {
				body, err := mail.CreateReader(bytes.NewReader(p.Bytes))
				if err != nil {
					return nil, err
				}
				for {
					part, err := body.NextPart()
					if err != nil {
						break
					}
					switch part.Header.(type) {
					case *mail.InlineHeader:
						b, _ := io.ReadAll(part.Body)
						body := string(b)
						// Extract the validation code from the email body
						for _, line := range strings.Split(body, "\n") {
							line = strings.TrimSpace(line)
							if strings.Contains(line, "IN TXT") {
								if len(validationRegex.FindStringSubmatch(line)) > 0 {
									matches := validationRegex.FindStringSubmatch(line)
									domain := strings.TrimSpace(matches[1])
									domain = strings.Trim(domain, ".")
									if !slices.Contains(domains, domain) && len(domains) != 0 {
										continue
									}
									if x, ok := validationCodes[domain]; !ok {
										validationCodes[domain] = ValidationCode{
											Code:     matches[2],
											mailDate: m.Envelope.Date,
										}
									} else if x.mailDate.Before(m.Envelope.Date) {
										validationCodes[domain] = ValidationCode{
											Code:     matches[2],
											mailDate: m.Envelope.Date,
										}
									}
								}
							}
						}
					}
				}
			}
		}
		if len(validationCodes) == len(domains) {
			break
		} else {
			time.Sleep(5 * time.Second)
		}
	}
	return validationCodes, nil
}
