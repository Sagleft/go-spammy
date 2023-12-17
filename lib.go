package gospammy

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/securisec/go-keywords"
)

type Analyzer interface {
	GetTextKeywords(text string, max int) ([]string, error)
	CheckTextSpamLevel(text string) (float64, error)
}

func New() Analyzer {
	return &defaultAnalyzer{}
}

type defaultAnalyzer struct{}

type KeyValue struct {
	key   string
	value int
}

// returns keywords usage, keywords, error
func getKeywords(text string, max int) (int, []string, error) {
	if text == "" {
		return 0, nil, nil
	}

	text, _ = strings.CutSuffix(text, ".")
	text = " " + text + " "

	keywords, err := keywords.Extract(text, keywords.ExtractOptions{
		RemoveDigits:     true,
		RemoveDuplicates: true,
		Lowercase:        true,
		IgnoreLength:     6,
	})
	if err != nil {
		return 0, nil, fmt.Errorf("extract keywords from text: %w", err)
	}

	var keywordsUsage int
	var sortedData []KeyValue
	for _, keyword := range keywords {
		usedCount := strings.Count(text, " "+keyword+" ")
		keywordsUsage += usedCount

		sortedData = append(sortedData, KeyValue{
			key:   keyword,
			value: usedCount,
		})
	}

	if max <= 0 {
		return keywordsUsage, keywords, nil
	}

	// take top entrys
	sort.Slice(sortedData, func(i, j int) bool {
		a := sortedData[i]
		b := sortedData[j]

		if a.value == b.value {
			c := strings.Compare(a.key, b.key)
			if c < 0 {
				return true
			} else if c > 0 {
				return false
			} else {
				return len(a.key) > len(b.key)
			}
		}

		return a.value > b.value
	})

	var result []string
	keywordsUsage = 0
	for i := 1; i <= max; i++ {
		keywordsUsage += sortedData[i].value
		result = append(result, sortedData[i].key)
	}
	return keywordsUsage, result, nil
}

func (a *defaultAnalyzer) GetTextKeywords(text string, max int) ([]string, error) {
	_, keywords, err := getKeywords(text, max)
	return keywords, err
}

func (a *defaultAnalyzer) CheckTextSpamLevel(text string) (float64, error) {
	keywordsUsage, _, err := getKeywords(text, 10)
	if err != nil {
		return 0, fmt.Errorf("get top keywords: %w", err)
	}

	allUsage, _, err := getKeywords(text, -1)
	if err != nil {
		return 0, fmt.Errorf("get all keywords: %w", err)
	}

	spammyLevel := 100 * float64(keywordsUsage) / float64(allUsage)
	spammyLevel = math.Round(spammyLevel*math.Pow10(2)) / math.Pow10(2)
	return spammyLevel, nil
}
