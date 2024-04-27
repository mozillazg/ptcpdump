package cmd

type Options struct {
	ifaces         []string
	pid            uint
	comm           string
	followForks    bool
	writeFilePath  string
	pcapFilter     string
	listInterfaces bool
	version        bool
	print          bool
}

func (o Options) WritePath() string {
	return o.writeFilePath
}
