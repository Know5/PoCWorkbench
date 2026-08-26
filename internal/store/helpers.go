package store

import "encoding/json"

func jsonMarshal(v any) ([]byte, error) {
	if v == nil {
		return []byte("[]"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("[]"), err
	}
	return b, nil
}

func unjsonStrings(s string) []string {
	var out []string
	if s == "" {
		return out
	}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
