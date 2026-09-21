LIBSGXSTEP_DIR       = ../..
LIBSGXSTEP           = $(LIBSGXSTEP_DIR)/libsgxstep
-include $(LIBSGXSTEP)/Makefile.config

ifeq ($(SGX_SDK),)
    SGX_SDK          = /opt/intel/sgxsdk
endif
export SGX_SDK

# Link against the ALREADY-BUILT enclave of app/foreshadow (via the Enclave
# symlink); do not regenerate it here (that would need sgx_edger8r/sgx_sign on
# PATH and re-sign the image). Only libsgxstep is (re)built as a subdir.
ENCLAVE              = Enclave
SUBDIRS              = $(LIBSGXSTEP)

CC                   = gcc
AS                   = gcc
LD                   = gcc

LIB_SUFX             = 64

CFLAGS              += -fPIC -fno-stack-protector -fno-builtin -fno-jump-tables \
                       -fno-common -Wno-attributes -g -D_GNU_SOURCE -O0
INCLUDE              = -I$(SGX_SDK)/include/ -I$(LIBSGXSTEP_DIR)
# PSW runtime dir (libsgx_enclave_common.so.1 etc.) for link-time rpath-link;
# override with PSW_LIB=... if the unpacked PSW tree lives elsewhere.
PSW_LIB             ?= $(HOME)/sgxsdk/psw227/extract/usr/lib/x86_64-linux-gnu
LDFLAGS             += -lsgx-step -pthread $(SUBDIRS:%=-L %) \
                       -L$(ENCLAVE) -lencl_proxy \
                       -L$(SGX_SDK)/lib$(LIB_SUFX)/ -lsgx_urts -lsgx_uae_service \
                       -L$(LIBSGXSTEP_DIR)/linux-sgx/psw/urts/linux \
                       -Wl,-rpath-link,$(SGX_SDK)/lib$(LIB_SUFX) \
                       -Wl,-rpath-link,$(PSW_LIB)

SOURCES              = main.c aep_stub.c
OBJECTS              = $(SOURCES:.c=.o)
OUTPUT               = app

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)

MAKEFLAGS           += --silent

all: $(OUTPUT)

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT)
	$(LD) $(OBJECTS) $(LDFLAGS) -o $(OUTPUT)

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)

$(BUILDDIRS):
	echo "$(INDENT)[===] $(@:build-%=%) [===]"
	$(MAKE) -C $(@:build-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)

$(CLEANDIRS):
	echo "$(INDENT)[===] $(@:clean-%=%) [===]"
	$(MAKE) clean -C $(@:clean-%=%) INDENT+="$(INDENT_STEP)" curr-dir=$(curr-dir)/$(@:build-%=%)
