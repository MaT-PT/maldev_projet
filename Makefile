INJECT_EXE = inject.exe
PAYLOAD_EXE = payload.exe
READPE_EXE = readpe.exe
HELLO_EXE = hello.exe
CFLAGS = $(CFLAGS) /W4 /O2 /Os
LFLAGS = $(LFLAGS) /NOFUNCTIONPADSECTION:injected
TARGET_SRC = $(HELLO_EXE)
TARGET_DST = dummy.exe

all: "$(INJECT_EXE)"

"$(INJECT_EXE)": payload_begin.obj libproc.obj payload.obj payload_end.obj utils.obj inject.obj
	link $(LFLAGS) /OUT:"$@" $**

libproc_dbg.obj: libproc.cpp
	$(CC) $(CFLAGS) /DDEBUG /c $** /Fo"$@"

"$(PAYLOAD_EXE)": libproc_dbg.obj payload.obj payload_main.obj
	link $(LFLAGS) /OUT:"$@" $**

clean:
	del /Q *.obj *.pdb *.ilk *.exe

run_payload: "$(PAYLOAD_EXE)"
	"$(PAYLOAD_EXE)"

run: "$(INJECT_EXE)" "$(TARGET_SRC)"
	copy /Y "$(TARGET_SRC)" "$(TARGET_DST)"
	"$(INJECT_EXE)" "$(TARGET_DST)"

check: run
	"$(TARGET_DST)"
