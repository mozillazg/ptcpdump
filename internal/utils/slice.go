package utils

import "strings"

func GetUniqInts(items []int) []int {
	var uniqItems []int
	uniqMap := map[int]bool{}
	for _, item := range items {
		if _, ok := uniqMap[item]; !ok {
			uniqItems = append(uniqItems, item)
			uniqMap[item] = true
		}
	}
	return uniqItems
}

func TidyCliMultipleVals(arr []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, str := range arr {
		parts := strings.Split(str, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if !seen[part] && part != "" {
				seen[part] = true
				result = append(result, part)
			}
		}
	}

	return result
}
