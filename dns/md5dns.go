package dns

import (
	"crypto/hmac"
	// Required due to the use in the MWN
	"crypto/md5" //#nosec
	"encoding/base64"
	"encoding/hex"

	"github.com/miekg/dns"
)

type Md5provider string

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func (key Md5provider) Generate(msg []byte, _ *dns.TSIG) ([]byte, error) {
	// If we barf here, the caller is to blame
	rawsecret, err := fromBase64([]byte(key))
	if err != nil {
		return nil, err
	}
	h := hmac.New(md5.New, rawsecret)

	h.Write(msg)
	return h.Sum(nil), nil
}

func (key Md5provider) Verify(msg []byte, t *dns.TSIG) error {
	b, err := key.Generate(msg, t)
	if err != nil {
		return err
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	if !hmac.Equal(b, mac) {
		return dns.ErrSig
	}
	return nil
}
