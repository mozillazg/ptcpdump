package types

type EnhancedContext uint32

const (
	EnhancedContextProcess EnhancedContext = 1 << iota
	EnhancedContextParentProc
	EnhancedContextContainer
	EnhancedContextPod
)

func (c EnhancedContext) ProcessContext() bool {
	return c == 0 || c&EnhancedContextProcess != 0
}

func (c EnhancedContext) ParentProcContext() bool {
	return c == 0 || c&EnhancedContextParentProc != 0
}

func (c EnhancedContext) ContainerContext() bool {
	return c == 0 || c&EnhancedContextContainer != 0
}

func (c EnhancedContext) PodContext() bool {
	return c == 0 || c&EnhancedContextPod != 0
}
