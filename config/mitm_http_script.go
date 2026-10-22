package config

import (
	"reflect"

	"github.com/metacubex/mihomo/component/mitm/httphook"
	yaml "go.yaml.in/yaml/v3"
)

// RawHTTPScript keeps unknown-field checks scoped to the HTTP script subtree.
type RawHTTPScript httphook.Config

func (raw *RawHTTPScript) UnmarshalYAML(node *yaml.Node) error {
	if err := checkStrictFields(node, reflect.TypeOf(httphook.Config{}), make(map[rewriteFieldVisit]uint8), "mitm.http-script"); err != nil {
		return err
	}
	var config httphook.Config
	if err := node.Decode(&config); err != nil {
		return err
	}
	*raw = RawHTTPScript(config)
	return nil
}
