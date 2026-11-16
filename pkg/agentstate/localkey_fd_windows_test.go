//go:build windows

package agentstate

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsLocalKeyNodePipe(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("native wrapping-key contract test requires Node.js")
	}
	const script = `const {spawn} = require('node:child_process');
 const descriptor=process.argv[2]==='file'?require('node:fs').openSync(process.argv[1],'r'):'pipe';
 const child=spawn(process.argv[1], ['-test.run=^TestWindowsLocalKeyChild$'], {
   env:{...process.env,QURL_TEST_WINDOWS_KEY:process.argv[2],LAYERV_LOCAL_KEY_FD:'3'},
   stdio:['ignore','inherit','inherit',descriptor]
 });
 const watchdog=setTimeout(()=>child.kill(),10000);
 if(child.stdio[3]) child.stdio[3].on('error',()=>{});
 const length=process.argv[2]==='hold'?32:Number(process.argv[2]);
 if(child.stdio[3]) child.stdio[3].write(Buffer.alloc(length,42));
 if(child.stdio[3] && process.argv[2]!=='hold') child.stdio[3].end();
 child.on('exit',code=>{clearTimeout(watchdog);process.exit(code??1)});`
	for _, length := range []string{"0", "31", "32", "33", "hold", "file"} {
		t.Run(length, func(t *testing.T) {
			command := exec.Command(node, "-e", script, "--", os.Args[0], length)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("Node pipe contract: %v\n%s", err, output)
			}
		})
	}
}

func TestWindowsLocalKeyChild(t *testing.T) {
	scenario := os.Getenv("QURL_TEST_WINDOWS_KEY")
	if scenario == "" {
		return
	}
	key, err := readLocalWrappingKey("3")
	if scenario == "32" {
		if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{42}, 32)) {
			t.Fatalf("read inherited pipe: %v", err)
		}
	} else if err == nil {
		t.Fatal("accepted invalid wrapping-key pipe")
	}

	scrubBytes(key)
	if _, err := readLocalWrappingKey("3"); err == nil || !strings.Contains(err.Error(), "already consumed") {
		t.Fatalf("retried an immutable inherited handle: %v", err)
	}
}

func TestWindowsLocalKeyTokenOwnerRejectsForeignSID(t *testing.T) {
	foreign, err := windows.StringToSid("S-1-5-21-111-222-333-444")
	if err != nil {
		t.Fatal(err)
	}
	if isLocalKeyTokenOwner(foreign) {
		t.Fatal("accepted foreign token owner")
	}
}
