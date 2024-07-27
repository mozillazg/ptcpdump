package utils

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
