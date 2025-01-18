package types

type EnhancedContext uint32

const (
	EnhancedContextProcess EnhancedContext = 1 << iota
	EnhancedContextParentProc
	EnhancedContextContainer
	EnhancedContextPod
	EnhancedContextThread
	EnhancedContextUser
)

func (c EnhancedContext) ProcessContext() bool {
	return c == 0 || c&EnhancedContextProcess != 0
}

func (c EnhancedContext) UserContext() bool {
	return c == 0 || c&EnhancedContextUser != 0
}

func (c EnhancedContext) ThreadContext() bool {
	return c == 0 || c&EnhancedContextThread != 0
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
