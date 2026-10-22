package config

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/metacubex/mihomo/component/mitm/rewrite"
	yaml "go.yaml.in/yaml/v3"
)

// RawRewrite keeps strict field checking scoped to the new rewrite subtree.
// Existing Mihomo configuration decoding retains its established behavior.
type RawRewrite rewrite.Config

func (raw *RawRewrite) UnmarshalYAML(node *yaml.Node) error {
	// Check the original node graph instead of re-serializing a subtree: aliases
	// may point to anchors elsewhere in the parent Mihomo configuration.
	if err := checkStrictFields(node, reflect.TypeOf(rewrite.Config{}), make(map[rewriteFieldVisit]uint8), "mitm.rewrite"); err != nil {
		return err
	}
	var config rewrite.Config
	if err := node.Decode(&config); err != nil {
		return err
	}
	*raw = RawRewrite(config)
	return nil
}

type rewriteFieldVisit struct {
	node *yaml.Node
	typ  reflect.Type
}

func checkStrictFields(node *yaml.Node, typ reflect.Type, visiting map[rewriteFieldVisit]uint8, prefix string) error {
	visit := rewriteFieldVisit{node, typ}
	if visiting[visit] == 2 {
		return nil
	}
	if visiting[visit] == 1 {
		return fmt.Errorf("%s: recursive YAML alias", prefix)
	}
	// Memoize node/type pairs so shared merge aliases cannot make validation
	// expand exponentially before the YAML decoder's alias checks run.
	visiting[visit] = 1
	defer func() { visiting[visit] = 2 }()
	if node.Kind == yaml.AliasNode {
		return checkStrictFields(node.Alias, typ, visiting, prefix)
	}
	for typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return nil
		} // Decode reports type errors.
		fields := make(map[string]reflect.Type, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			fields[strings.Split(field.Tag.Get("yaml"), ",")[0]] = field.Type
		}
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Tag == "!!merge" {
				if value.Kind == yaml.SequenceNode {
					for _, child := range value.Content {
						if err := checkStrictFields(child, typ, visiting, prefix); err != nil {
							return err
						}
					}
				} else if err := checkStrictFields(value, typ, visiting, prefix); err != nil {
					return err
				}
				continue
			}
			fieldType, ok := fields[key.Value]
			if !ok {
				return fmt.Errorf("%s: line %d: unknown field %q", prefix, key.Line, key.Value)
			}
			if err := checkStrictFields(value, fieldType, visiting, prefix); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if node.Kind == yaml.SequenceNode {
			for _, child := range node.Content {
				if err := checkStrictFields(child, typ.Elem(), visiting, prefix); err != nil {
					return err
				}
			}
		}
	case reflect.Map:
		if node.Kind == yaml.MappingNode {
			for i := 1; i < len(node.Content); i += 2 {
				if err := checkStrictFields(node.Content[i], typ.Elem(), visiting, prefix); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func parseMITMRewrite(raw RawRewrite) (*rewrite.Snapshot, error) {
	return rewrite.Compile(rewrite.Config(raw))
}
