package cmd

func getSubProgArgs(rawArgs []string) []string {
	haveFlag := false
	flagI := 0
	for i, v := range rawArgs {
		if v == "--" {
			haveFlag = true
			flagI = i
			break
		}
	}
	if !haveFlag {
		return nil
	}
	return rawArgs[flagI+1:]
}
