package decompression

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

// CompressData compresses bytes using gzip
func CompressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	w.Close()
	return buf.Bytes(), nil
}

// DecompressData decompresses gzip data
func DecompressData(compressed []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func FuzzCompressionRoundtrip(f *testing.F) {
	f.Add([]byte("Hello, World!"))
	f.Add([]byte(""))
	f.Add([]byte("The quick brown fox jumps over the lazy dog"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD})

	f.Fuzz(func(t *testing.T, original []byte) {
		// Compress the data
		compressed, err := CompressData(original)
		if err != nil {
			t.Fatalf("Compression failed: %v", err)
		}

		// Decompress it
		decompressed, err := DecompressData(compressed)
		if err != nil {
			t.Fatalf("Decompression failed: %v", err)
		}

		// Verify we get the original back
		if !bytes.Equal(original, decompressed) {
			t.Errorf("Round-trip failed:\nOriginal:     %v\nDecompressed: %v",
				original, decompressed)
		}
	})
}

// Fuzz malformed gzip data
func FuzzMalformedGzip(f *testing.F) {
	f.Add([]byte{0x1F, 0x8B}) // Incomplete gzip header
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := DecompressData(data)
		// We don't care if it errors - just that it doesn't panic
		_ = err
	})
}
