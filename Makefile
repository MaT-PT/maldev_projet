INJECT_EXE = inject.exe
PAYLOAD_EXE = payload.exe
READPE_EXE = readpe.exe
HELLO_EXE = hello.exe
CFLAGS = $(CFLAGS) /W4 /O2 /GS- /std:c++20 /DWIN32_LEAN_AND_MEAN
LFLAGS = $(LFLAGS) /NOFUNCTIONPADSECTION:injected
AFLAGS = $(AFLAGS) /W3 /Cx
CF_DBG = /DDEBUG  # General debug mode
CF_OPT = /Os /Oi /Zl /D_CRT_SECURE_NO_WARNINGS  # Optimize for size
TARGET_SRC = $(HELLO_EXE)
TARGET_DST = dummy.exe

!IF DEFINED(PL_DEBUG) & "$(PL_DEBUG)" != "0"
CF_PLDBG = /DPL_DEBUG  # Payload debug mode (MsgBox)
!ENDIF
!IF DEFINED(NEED_BANG) & "$(NEED_BANG)" != "0"
CF_NEEDBANG = /DNEED_BANG  # Make payload require '!' as first char in filename
!ENDIF

all: inject


payload.obj: payload.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) $(CF_PLDBG) $(CF_NEEDBANG) /c $** /Fo"$@"

payload_dbg.obj: payload.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) $(CF_PLDBG) $(CF_NEEDBANG) $(CF_DBG) /c $** /Fo"$@"

libproc.obj: libproc.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) /c $** /Fo"$@"

libproc_dbg.obj: libproc.cpp
	$(CPP) $(CFLAGS) $(CF_OPT) $(CF_DBG) /c $** /Fo"$@"


"$(INJECT_EXE)": payload_begin.obj libproc.obj payload.obj payload_end.obj utils.obj inject.obj
	link $(LFLAGS) /OUT:$@ $**

"$(PAYLOAD_EXE)": payload_begin.obj libproc_dbg.obj payload_dbg.obj payload_end.obj payload_main.obj
	link $(LFLAGS) /OUT:$@ $** /DEBUG

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
	copy /Y "$(TARGET_SRC)" "!$(TARGET_DST)"
	copy /Y "$(TARGET_SRC)" "!1$(TARGET_DST)"
	copy /Y "$(TARGET_SRC)" "!2$(TARGET_DST)"

run: inject dummy
	"$(INJECT_EXE)" "$(TARGET_DST)"

run_payload: payload dummy
	"$(PAYLOAD_EXE)"

run_readpe: run readpe
	"$(READPE_EXE)" "$(TARGET_DST)"

check: run
	"$(TARGET_DST)"
