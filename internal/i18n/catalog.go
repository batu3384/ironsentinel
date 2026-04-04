package i18n

import (
	"fmt"
	"strings"
)

type Language string

const (
	EN Language = "en"
	TR Language = "tr"
)

type Catalog struct {
	lang Language
}

var messages = map[Language]map[string]string{
	EN: buildENMessages(),
	TR: buildTRMessages(),
}

func Parse(input string) Language {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case "tr":
		return TR
	default:
		return EN
	}
}

func New(language Language) Catalog {
	return Catalog{lang: language}
}

func (c Catalog) Language() Language {
	return c.lang
}

func (c Catalog) T(key string, args ...any) string {
	catalog, ok := messages[c.lang]
	if !ok {
		catalog = messages[EN]
	}
	text, ok := catalog[key]
	if !ok {
		text = messages[EN][key]
	}
	if len(args) == 0 {
		return text
	}
	return fmt.Sprintf(text, args...)
}
