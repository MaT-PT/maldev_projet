INJECT_EXE = inject.exe
PAYLOAD_EXE = payload.exe
READPE_EXE = readpe.exe
HELLO_EXE = hello.exe
CFLAGS = $(CFLAGS) /W4 /O2 /std:c++20
LFLAGS = $(LFLAGS) /NOFUNCTIONPADSECTION:injected
AFLAGS = $(AFLAGS) /W3 /Cx
CF_DBG = /DDEBUG		# Debug mode
CF_OPT = /Os /Oi /Zl	# Optimize for size
TARGET_SRC = $(HELLO_EXE)
TARGET_DST = dummy.exe

all: inject


payload.obj: payload.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) /c $** /Fo"$@"

libproc.obj: libproc.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) /c $** /Fo"$@"

libproc_dbg.obj: libproc.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) $(CF_DBG) /c $** /Fo"$@"


"$(INJECT_EXE)": payload_begin.obj libproc.obj payload.obj payload_end.obj utils.obj inject.obj
	link $(LFLAGS) /OUT:$@ $**

"$(PAYLOAD_EXE)": libproc_dbg.obj payload.obj payload_main.obj
	link $(LFLAGS) /OUT:$@ $**

"$(READPE_EXE)": utils.obj readpe.obj
	link $(LFLAGS) /OUT:$@ $**

clean:
	del /Q *.obj *.pdb *.ilk *.exe


inject: "$(INJECT_EXE)"

payload: "$(PAYLOAD_EXE)"

readpe: "$(READPE_EXE)"

hello: "$(HELLO_EXE)"

dummy: hello
	copy /Y "$(TARGET_SRC)" "$(TARGET_DST)"

run: inject dummy
	"$(INJECT_EXE)" "$(TARGET_DST)"

run_payload: payload
	"$(PAYLOAD_EXE)"

run_readpe: run readpe
	"$(READPE_EXE)" "$(TARGET_DST)"

check: run
	"$(TARGET_DST)"
