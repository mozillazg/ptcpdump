package cmd

type Options struct {
	ifaces         []string
	pid            uint
	comm           string
	followForks    bool
	writeFilePath  string
	pcapFilter     string
	listInterfaces bool
}

func (o Options) WritePath() string {
	if o.writeFilePath == "" || o.writeFilePath == "-" {
		return ""
	}
	return o.writeFilePath
}
