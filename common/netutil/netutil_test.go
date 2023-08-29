package netutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecCmdRecoder(t *testing.T) {
	// test with args
	ec := ExecCmdRecorder{}
	ec.ExecCmd("echo", "1", "2")
	ec.ExecCmd("echo", "3", "4")
	ec.ExecCmd("echo", "5", "6")
	out := ec.String()
	assert.Equal(t, "echo 1 2\necho 3 4\necho 5 6", out)

	t.Log(out)
	// output:
	// echo 1 2
	// echo 3 4
	// echo 5 6

	// test without args
	ec = ExecCmdRecorder{}
	ec.ExecCmd("echo")
	ec.ExecCmd("echo")
	ec.ExecCmd("echo")
	out = ec.String()
	assert.Equal(t, "echo \necho \necho ", out)

	t.Log(out)
	// output:
	// echo
	// echo
	// echo
}
