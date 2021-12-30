package hcl2

import (
	"encoding/json"
	"fmt"

	"github.com/tmccombs/hcl2json/convert"
)

func Unmarshal(b []byte, v interface{}) error {
	hclBytes, err := convert.Bytes(b, "", convert.Options{})
	if err != nil {
		return fmt.Errorf("convert hcl2 to bytes: %w", err)
	}

	if err = json.Unmarshal(hclBytes, v); err != nil {
		return fmt.Errorf("unmarshal hcl2: %w", err)
	}

	return nil
}
