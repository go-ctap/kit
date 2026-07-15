package logging

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode"
)

var jsonMarshalerType = reflect.TypeFor[json.Marshaler]()

type SafeJSONValue struct {
	Value          any
	RedactedFields []string
}

// SafeValue converts a typed domain or CTAP value to JSON-ready data. It keeps
// fields by default for diagnostic usefulness, but replaces the small set of
// known secret-bearing fields before the JSON serializer can observe them.
func SafeValue(value any) SafeJSONValue {
	redacted := make([]string, 0, 4)
	safe := sanitizeValue(reflect.ValueOf(value), nil, &redacted)

	return SafeJSONValue{Value: safe, RedactedFields: redacted}
}

func sanitizeValue(value reflect.Value, path []string, redacted *[]string) any {
	if !value.IsValid() {
		return nil
	}
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		value = value.Elem()
	}

	if value.CanAddr() && value.Addr().Type().Implements(jsonMarshalerType) {
		return value.Addr().Interface()
	}
	if value.CanInterface() && value.Type().Implements(jsonMarshalerType) {
		return value.Interface()
	}

	switch value.Kind() {
	case reflect.Struct:
		return sanitizeStruct(value, path, redacted)
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			if value.CanInterface() {
				return value.Interface()
			}
			return nil
		}
		items := make([]any, value.Len())
		for index := range value.Len() {
			items[index] = sanitizeValue(value.Index(index), appendPath(path, fmt.Sprint(index)), redacted)
		}
		return items
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		result := make(map[string]any, value.Len())
		iterator := value.MapRange()
		for iterator.Next() {
			key := fmt.Sprint(iterator.Key().Interface())
			fieldPath := appendPath(path, key)
			mapValue := iterator.Value()
			if sensitiveLogField(fieldPath) && !isZero(mapValue) {
				result[key] = Redacted
				*redacted = append(*redacted, strings.Join(fieldPath, "."))
				continue
			}
			result[key] = sanitizeValue(mapValue, fieldPath, redacted)
		}
		return result
	default:
		if value.CanInterface() {
			return value.Interface()
		}
		return nil
	}
}

func sanitizeStruct(value reflect.Value, path []string, redacted *[]string) any {
	typeInfo := value.Type()
	result := make(map[string]any, value.NumField())
	for index := range value.NumField() {
		fieldInfo := typeInfo.Field(index)
		if fieldInfo.PkgPath != "" {
			continue
		}

		name, omitEmpty, ignored := logFieldName(fieldInfo)
		fieldValue := value.Field(index)
		fieldPath := appendPath(path, name)
		if sensitiveLogField(fieldPath) {
			if !isZero(fieldValue) {
				result[name] = Redacted
				*redacted = append(*redacted, strings.Join(fieldPath, "."))
			}
			continue
		}
		if ignored || omitEmpty && isZero(fieldValue) {
			continue
		}
		if fieldInfo.Anonymous && fieldInfo.Tag.Get("json") == "" {
			inline, ok := sanitizeValue(fieldValue, path, redacted).(map[string]any)
			if ok {
				for key, item := range inline {
					result[key] = item
				}
			}
			continue
		}
		result[name] = sanitizeValue(fieldValue, fieldPath, redacted)
	}

	return result
}

func sensitiveLogField(path []string) bool {
	if len(path) == 0 {
		return false
	}
	name := canonicalLogName(path[len(path)-1])
	switch name {
	case "pin", "currentpin", "newpin", "confirmed",
		"pinuvauthtoken", "pinuvauthparam", "newpinenc", "pinhashenc",
		"confirmationmessage", "largeblobkey", "payload", "set", "config",
		"rawbytes", "rawhex", "decodedtext", "decodedvalue",
		"authdataraw", "authenticatordatahex", "attestationobjectcborhex",
		"unsignedextensionoutputs", "extensionoutputs",
		"credentialblob", "credblob", "hmacsecret", "hmacsecretmc", "hmacgetsecret", "prf",
		"saltenc", "saltauth", "output1hex", "output2hex", "firstoutputhex", "secondoutputhex":
		return true
	case "valuehex":
		for _, parent := range path[:len(path)-1] {
			normalized := canonicalLogName(parent)
			if normalized == "credentialblob" || normalized == "getcredblob" || normalized == "credblob" {
				return true
			}
		}
	}

	return false
}

func canonicalLogName(value string) string {
	return strings.Map(func(character rune) rune {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			return unicode.ToLower(character)
		}
		return -1
	}, value)
}

func logFieldName(field reflect.StructField) (name string, omitEmpty bool, ignored bool) {
	tag := field.Tag.Get("json")
	parts := strings.Split(tag, ",")
	if parts[0] == "-" {
		return lowerFirst(field.Name), false, true
	}
	name = parts[0]
	if name == "" {
		name = lowerFirst(field.Name)
	}
	for _, option := range parts[1:] {
		if option == "omitempty" || option == "omitzero" {
			omitEmpty = true
		}
	}

	return name, omitEmpty, false
}

func lowerFirst(value string) string {
	if value == "" {
		return value
	}
	runes := []rune(value)
	runes[0] = unicode.ToLower(runes[0])

	return string(runes)
}

func appendPath(path []string, value string) []string {
	result := make([]string, len(path), len(path)+1)
	copy(result, path)

	return append(result, value)
}

func isZero(value reflect.Value) bool {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return true
		}
		value = value.Elem()
	}

	return !value.IsValid() || value.IsZero()
}
