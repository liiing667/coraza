// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"strings"

	"github.com/corazawaf/coraza/v3/testing/profile"
)

func mustGzip(data string) string {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte(data)); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

func mustZlib(data string) string {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write([]byte(data)); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

func mustRawDeflate(data string) string {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write([]byte(data)); err != nil {
		panic(err)
	}
	if err := w.Close(); err != nil {
		panic(err)
	}
	return buf.String()
}

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "coraza",
		Description: "request bodies with Content-Encoding are decompressed before inspection",
		Enabled:     true,
		Name:        "content_encoding.yaml",
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,pass,log"
SecRule ARGS_POST "@contains attack" "id:2,phase:2,deny,status:403,log"
`,
	Tests: []profile.Test{
		{
			Title: "gzip encoded body is decompressed before inspection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "gzip",
							},
							Data: mustGzip("test=attack"),
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 2,
								Action: "deny",
								Status: 403,
							},
						},
					},
				},
			},
		},
		{
			Title: "deflate encoded body is decompressed before inspection",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "deflate",
							},
							Data: mustZlib("test=attack"),
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 2,
								Action: "deny",
								Status: 403,
							},
						},
					},
				},
			},
		},
		{
			Title: "raw deflate body without zlib wrapper is decompressed",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "deflate",
							},
							Data: mustRawDeflate("test=attack"),
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 2,
								Action: "deny",
								Status: 403,
							},
						},
					},
				},
			},
		},
		{
			Title: "identity encoding keeps the body as is",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "identity",
							},
							Data: "test=attack",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 2,
								Action: "deny",
								Status: 403,
							},
						},
					},
				},
			},
		},
		{
			Title: "unsupported content encoding is rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "br",
							},
							Data: "test=attack",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 0,
								Action: "deny",
								Status: 415,
							},
						},
					},
				},
			},
		},
		{
			Title: "multipart body is inspected as received even with content encoding",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "multipart/form-data; boundary=boundary",
								"content-encoding": "gzip",
							},
							Data: mustGzip("--boundary\r\nContent-Disposition: form-data; name=\"test\"\r\n\r\nattack\r\n--boundary--\r\n"),
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
	},
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "coraza",
		Description: "encoded request bodies are bounded by SecRequestBodyLimit after decompression",
		Enabled:     true,
		Name:        "content_encoding_limit.yaml",
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 100
SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,pass,log"
`,
	Tests: []profile.Test{
		{
			Title: "decompressed body over the limit is rejected",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "gzip",
							},
							Data: mustGzip("test=" + strings.Repeat("attack", 50)),
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 0,
								Action: "deny",
								Status: 413,
							},
						},
					},
				},
			},
		},
		{
			Title: "corrupt gzip body is handled like a limit violation",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "gzip",
							},
							Data: "this is not a gzip stream",
						},
						Output: profile.ExpectedOutput{
							NonTriggeredRules: []int{1},
							Interruption: &profile.ExpectedInterruption{
								RuleID: 0,
								Action: "deny",
								Status: 413,
							},
						},
					},
				},
			},
		},
	},
})

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "coraza",
		Description: "encoded request bodies over SecRequestBodyLimit are partially processed with ProcessPartial",
		Enabled:     true,
		Name:        "content_encoding_process_partial.yaml",
	},
	Rules: `
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 100
SecRequestBodyLimitAction ProcessPartial
SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,pass,log"
SecRule INBOUND_DATA_ERROR "@eq 1" "id:2,phase:2,pass,log"
`,
	Tests: []profile.Test{
		{
			Title: "decompressed body over the limit is partially processed",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "gzip",
							},
							Data: mustGzip("test=" + strings.Repeat("attack", 50)),
						},
						Output: profile.ExpectedOutput{
							TriggeredRules: []int{1, 2},
						},
					},
				},
			},
		},
		{
			Title: "corrupt gzip body flags inbound data error",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/",
							Method: "POST",
							Headers: map[string]string{
								"content-type":     "application/x-www-form-urlencoded",
								"content-encoding": "gzip",
							},
							Data: "this is not a gzip stream",
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{2},
							NonTriggeredRules: []int{1},
						},
					},
				},
			},
		},
	},
})
