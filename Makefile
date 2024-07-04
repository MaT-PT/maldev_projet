INJECT_EXE = inject.exe
PAYLOAD_EXE = payload.exe
READPE_EXE = readpe.exe
HELLO_EXE = hello.exe
TEST_AES_EXE = test_aes.exe
_FLAGS = /W4 /O2 /Ob3 /GS- /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS
CFLAGS = $(CFLAGS) $(_FLAGS) /std:clatest
CPPFLAGS = $(CPPFLAGS) $(_FLAGS) /std:c++20
CXXFLAGS = $(CXXFLAGS) $(_FLAGS) /std:c++20
LFLAGS = $(LFLAGS) /NOFUNCTIONPADSECTION:injected
AFLAGS = $(AFLAGS) /W3 /Cx
CF_DBG = /DDEBUG /DNO_ENCRYPT  # General debug mode
CF_OPT = /Os /Oi /Zl  # Optimize for size
TARGET_SRC = $(HELLO_EXE)
TARGET_DST = dummy.exe

!IF DEFINED(PL_DEBUG) && "$(PL_DEBUG)" != "0"
CF_PLDEBUG = /DPL_DEBUG  # Payload debug mode (MsgBox)
!ENDIF
!IF DEFINED(NEED_BANG) && "$(NEED_BANG)" != "0"
CF_NEEDBANG = /DNEED_BANG  # Make payload require '!' as first char in filename
!ENDIF
!IF DEFINED(SKIP_SIGN) && "$(SKIP_SIGN)" != "0"
CF_SKIPSIGN = /DSKIP_SIGN  # Skip signature verification (allow multiple injections)
!ENDIF
!IF DEFINED(NO_ANTIDBG) && "$(NO_ANTIDBG)" != "0"
CF_NOANTIDBG = /DNO_ANTIDBG  # Disable anti-debugging
!ENDIF
!IF DEFINED(NO_ENCRYPT) && "$(NO_ENCRYPT)" != "0"
CF_NOENCRYPT = /DNO_ENCRYPT  # Disable payload encryption
!ENDIF

CF_EXTRA = $(CF_PLDEBUG) $(CF_NEEDBANG) $(CF_SKIPSIGN) $(CF_NOANTIDBG) $(CF_NOENCRYPT)

all: inject

# Inference rules
.c.obj::
	$(CC) $(CFLAGS) $(CF_EXTRA) /c $<

.cpp.obj::
	$(CPP) $(CPPFLAGS) $(CF_EXTRA) /c $<

# Executable entry points: do not apply /Zl (omit default library names)
inject.obj: inject.cpp encrypt.hpp payload.h utils.h
	$(CPP) $(CPPFLAGS) $(CF_EXTRA) /c inject.cpp /Fo"$@"

readpe.obj: readpe.c utils.h
	$(CC) $(CFLAGS) $(CF_EXTRA) /c readpe.c /Fo"$@"

test_aes.obj: test_aes.c libaes.h utils.h
	$(CC) $(CFLAGS) $(CF_EXTRA) /c test_aes.c /Fo"$@"

# Library objects: apply /Zl (omit default library names) and other aggressive size optimizations
!IFNDEF CF_NOENCRYPT
payload_bootstrap.obj: payload_bootstrap.cpp payload.h encrypt.hpp injected.h libproc.hpp utils.h
!ELSE
payload_bootstrap.obj: payload_bootstrap.cpp payload.h injected.h libproc.hpp utils.h
!ENDIF
	$(CPP) $(CPPFLAGS) $(CF_OPT) $(CF_EXTRA) /c payload_bootstrap.cpp /Fo"$@"

payload.obj: payload.cpp payload.h injected.h libproc.hpp utils.h
	$(CPP) $(CPPFLAGS) $(CF_OPT) $(CF_EXTRA) /c payload.cpp /Fo"$@"

libproc.obj: libproc.cpp libproc.hpp injected.h utils.h
	$(CPP) $(CPPFLAGS) $(CF_OPT) $(CF_EXTRA) /c libproc.cpp /Fo"$@"

utils.obj: utils.c utils.h injected.h
	$(CC) $(CFLAGS) $(CF_OPT) $(CF_EXTRA) /c utils.c /Fo"$@"

libaes.obj: libaes.c libaes.h injected.h utils.h
	$(CC) $(CFLAGS) $(CF_OPT) $(CF_EXTRA) /c libaes.c /Fo"$@"

# Library objects for debug builds
payload_bootstrap_dbg.obj: payload_bootstrap.cpp payload.h injected.h libproc.hpp utils.h
	$(CPP) $(CPPFLAGS) $(CF_OPT) $(CF_EXTRA) $(CF_DBG) /c payload_bootstrap.cpp /Fo"$@"

payload_dbg.obj: payload.cpp payload.h injected.h libproc.hpp utils.h
	$(CPP) $(CPPFLAGS) $(CF_OPT) $(CF_EXTRA) $(CF_DBG) /c payload.cpp /Fo"$@"

libproc_dbg.obj: libproc.cpp libproc.hpp injected.h utils.h
	$(CPP) $(CPPFLAGS) $(CF_OPT) $(CF_EXTRA) $(CF_DBG) /c libproc.cpp /Fo"$@"


# Executables
!IFNDEF CF_NOENCRYPT
"$(INJECT_EXE)": payload_begin.obj libproc.obj libaes.obj payload_bootstrap.obj payload_enc_begin.obj payload.obj payload_end.obj utils.obj inject.obj
!ELSE
"$(INJECT_EXE)": payload_begin.obj libproc.obj payload_bootstrap.obj payload.obj payload_end.obj utils.obj inject.obj
!ENDIF
	link $(LFLAGS) /OUT:$@ $**

"$(PAYLOAD_EXE)": payload_begin.obj libproc_dbg.obj payload_bootstrap_dbg.obj payload_dbg.obj payload_end.obj payload_main.obj
	link $(LFLAGS) /OUT:$@ $** /DEBUG

"$(READPE_EXE)": utils.obj readpe.obj
	link $(LFLAGS) /OUT:$@ $**

"$(TEST_AES_EXE)": utils.obj libaes.obj test_aes.obj
	link $(LFLAGS) /OUT:$@ $**


# Phony targets
.PHONY:  # Pseudotarget for phony targets (will always be out-of-date)

clean: .PHONY
	del /Q *.obj *.pdb *.ilk

fclean: clean .PHONY
	del /Q *.exe

inject: "$(INJECT_EXE)"

payload: "$(PAYLOAD_EXE)"

readpe: "$(READPE_EXE)"

hello: "$(HELLO_EXE)"

test_aes: "$(TEST_AES_EXE)"

dummy: hello .PHONY
	copy /Y "$(TARGET_SRC)" "$(TARGET_DST)"
	copy /Y "$(TARGET_SRC)" "!$(TARGET_DST)"
	copy /Y "$(TARGET_SRC)" "!1$(TARGET_DST)"
	copy /Y "$(TARGET_SRC)" "!2$(TARGET_DST)"

run: inject dummy .PHONY
	"$(INJECT_EXE)" "$(TARGET_DST)"

run_payload: payload dummy .PHONY
	"$(PAYLOAD_EXE)"

run_readpe: run readpe .PHONY
	"$(READPE_EXE)" "$(TARGET_DST)"

check: run .PHONY
	"$(TARGET_DST)"
