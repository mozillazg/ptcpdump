package utils

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/mozillazg/ptcpdump/internal/log"
)

const EnvIsSubProgramLoader = "PTCPDUMP-IS-SUB-PROGRAM-LOADER"

func StartSubProcessLoader(ctx context.Context, program string, subProgramArgs []string) (int, <-chan struct{}, error) {
	os.Setenv(EnvIsSubProgramLoader, "true")
	defer os.Unsetenv(EnvIsSubProgramLoader)

	chFinished := make(chan struct{})

	args := []string{"--"}
	args = append(args, subProgramArgs...)
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	log.Debugf("start to run subprocess loader %s", cmd.String())
	if err := cmd.Start(); err != nil {
		return 0, chFinished, err
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Errorf("subprocess failed: %s", err)
		}
		close(chFinished)
	}()

	return cmd.Process.Pid, chFinished, nil
}

func StartSubProcess(ctx context.Context, Args []string) error {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)

	<-ch

	log.Infof("start to run %q", strings.Join(Args, " "))
	os.Unsetenv(EnvIsSubProgramLoader)
	cmd := exec.CommandContext(ctx, Args[0], Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}
