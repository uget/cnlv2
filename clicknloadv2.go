package cnlv2

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"github.com/robertkrimen/otto"
	"net/http"
	"regexp"
)

const CrossDomain = `<?xml version="1.0"?>
<!DOCTYPE cross-domain-policy SYSTEM "http://www.macromedia.com/xml/dtds/cross-domain-policy.dtd">
<cross-domain-policy>
<allow-access-from domain="*" />
</cross-domain-policy>
`

func HttpAction(success func([]string), failure func(string, error)) func(*http.Request) (int, string) {
	return func(r *http.Request) (int, string) {
		jk := r.FormValue("jk")
		pw := r.FormValue("pw")
		crypted := r.FormValue("crypted")
		links, text, err := Decrypt(jk, pw, crypted)
		if err != nil {
			if failure != nil {
				failure(text, err)
			}
			return http.StatusBadRequest, text
		}
		if success != nil {
			success(links)
		}
		return http.StatusOK, "success\r\n"
	}
}

// pw is not considered
// Returns:
// list of decrypted links, human readable error string, cause
func Decrypt(jk string, pw string, crypted string) ([]string, string, error) {
	vm := otto.New()
	value, err := vm.Run(jk)
	if err != nil {
		return []string{}, "Invalid Javascript in 'jk' (while loading)", err
	}
	value, err = vm.Run("f()")
	if err != nil {
		return []string{}, "Invalid Javascript in 'jk' (while calling f())", err
	}
	key, err := hex.DecodeString(value.String())
	if err != nil {
		return []string{}, "String returned from JS function was not valid HEX.", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return []string{}, "Invalid AES key.", err
	}
	data, err := base64.StdEncoding.DecodeString(crypted)
	if err != nil {
		return []string{}, "Invalid b64 encoded string in 'crypted'.", err
	}
	c := cipher.NewCBCDecrypter(block, key)
	c.CryptBlocks(data, data)
	result := regexp.MustCompile(`\s+`).Split(string(data), -1)
	return result, "", nil
}
