// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package corazawaf

import (
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"strings"

	"github.com/corazawaf/coraza/v3/types"
)

// requestContentEncoding returns the normalized Content-Encoding of the
// request, or the empty string when the header is not present.
func (tx *Transaction) requestContentEncoding() string {
	if m := tx.variables.requestHeaders.Get("content-encoding"); len(m) > 0 {
		return strings.ToLower(strings.TrimSpace(m[0]))
	}
	return ""
}

// isMultipartMimeType reports whether the content type belongs to the
// multipart family, whose bodies are inspected as received.
func isMultipartMimeType(mimeType string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(mimeType)), "multipart/")
}

// decompressRequestBody decompresses a gzip or deflate encoded request body
// into a new buffer bounded by the same limits as the raw request body buffer
// and returns a reader over the decompressed body. partial is true when the
// body could not be decompressed completely, either because the compressed
// data is corrupt or because the decompressed size reached
// SecRequestBodyLimit; the returned reader then yields what could be
// decompressed so that ProcessPartial can inspect it.
func (tx *Transaction) decompressRequestBody(reader io.Reader, encoding string) (io.Reader, bool, error) {
	var dec io.Reader
	switch encoding {
	case "gzip":
		d, err := gzip.NewReader(reader)
		if err != nil {
			// Corrupt gzip header, there is nothing to decompress.
			tx.debugLogger.Debug().Err(err).Msg("Failed to read gzip header of request body")
			return strings.NewReader(""), true, nil
		}
		dec = d
	case "deflate":
		d, err := zlib.NewReader(reader)
		if err != nil {
			// Some clients send raw DEFLATE data (RFC 1951) without the zlib
			// wrapper (RFC 1950) that the deflate Content-Encoding mandates.
			rawReader, rerr := tx.requestBodyBuffer.Reader()
			if rerr != nil {
				return nil, false, rerr
			}
			dec = flate.NewReader(rawReader)
		} else {
			dec = d
		}
	default:
		return nil, false, errors.New("unsupported content encoding: " + encoding)
	}

	decoded := NewBodyBuffer(types.BodyBufferOptions{
		TmpPath:     tx.requestBodyBuffer.options.TmpPath,
		MemoryLimit: tx.requestBodyBuffer.options.MemoryLimit,
		Limit:       tx.RequestBodyLimit,
	})
	// The decompressed output is capped at SecRequestBodyLimit so that a
	// compressed bomb cannot expand beyond it, and it spills to disk beyond
	// the in-memory limit like the raw body.
	_, copyErr := io.Copy(decoded, io.LimitReader(dec, tx.RequestBodyLimit))
	if copyErr != nil {
		tx.debugLogger.Debug().Err(copyErr).Msg("Failed to decompress request body")
	}
	partial := copyErr != nil || decoded.length >= tx.RequestBodyLimit

	tx.decodedRequestBodyBuffer = decoded
	r, err := decoded.Reader()
	if err != nil {
		return nil, false, err
	}
	return r, partial, nil
}
