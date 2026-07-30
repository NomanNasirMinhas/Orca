package graph

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"orca/internal/model"
)

// snapshot is the on-disk serialization form.
type snapshot struct {
	Nodes []model.Node `json:"nodes"`
	Facts []model.Fact `json:"facts"`
}

const (
	magic      = "ORCA1"
	saltLen    = 16
	pbkdf2Iter = 200_000
)

// Save writes the graph to path, encrypted with a key derived from passphrase
// (AES-256-GCM). The file layout is: magic | salt | nonce | ciphertext.
func (g *Graph) Save(path, passphrase string) error {
	g.mu.RLock()
	snap := snapshot{Nodes: g.Nodes(), Facts: g.Facts()}
	g.mu.RUnlock()

	plain, err := json.Marshal(snap)
	if err != nil {
		return err
	}

	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(magic))

	buf := make([]byte, 0, len(magic)+len(salt)+len(nonce)+len(ct))
	buf = append(buf, []byte(magic)...)
	buf = append(buf, salt...)
	buf = append(buf, nonce...)
	buf = append(buf, ct...)
	return os.WriteFile(path, buf, 0o600)
}

// Load decrypts and reads a graph from path.
func Load(path, passphrase string) (*Graph, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < len(magic)+saltLen || string(raw[:len(magic)]) != magic {
		return nil, errors.New("graph: not an Orca snapshot (bad magic)")
	}
	off := len(magic)
	salt := raw[off : off+saltLen]
	off += saltLen
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < off+ns {
		return nil, errors.New("graph: truncated snapshot")
	}
	nonce := raw[off : off+ns]
	ct := raw[off+ns:]
	plain, err := gcm.Open(nil, nonce, ct, []byte(magic))
	if err != nil {
		return nil, fmt.Errorf("graph: decrypt failed (wrong passphrase?): %w", err)
	}
	var snap snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return nil, err
	}
	g := New()
	for _, n := range snap.Nodes {
		g.AddNode(n)
	}
	for _, f := range snap.Facts {
		g.AddFact(f)
	}
	return g, nil
}

func newGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	key := pbkdf2SHA256([]byte(passphrase), salt, pbkdf2Iter, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2SHA256 is a stdlib-only PBKDF2-HMAC-SHA256 (RFC 2898) so the core has
// no external dependencies.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, numBlocks*hLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
