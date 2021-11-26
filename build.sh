#!/bin/bash

ROOT_DIR=`cd $(dirname $0) && pwd`
BUILD_DIR=$ROOT_DIR/build

# default values
BUILDTYPE=release
TARCH=x86
JVM_TYPE=alhambra
JOBS=$(cat /proc/cpuinfo | grep 'model name' | sed -e 's/.*: //' | wc -l)
UPLOAD=
SCP_DST_DEFINED=
BOOT_JDK=
NOCONF=false
LTINFO_LIB=


# parse parameters
make_args_counter=0
configure_args_counter=0

for arg; do
  [ "${arg:0:10}" == "-boot_jdk=" ] && BOOT_JDK="${arg:10}" && continue
  [ "${arg:0:9}" == "BOOT_JDK=" ] && BOOT_JDK="${arg:9}" && continue
  [ "${arg:0:14}" == "-make-threads=" ] && JOBS="${arg:14}" && continue
  [ "${arg:0:6}" == "-JOBS=" ] && JOBS="${arg:6}" && continue
  [ "$arg" == "-zeroshark" ] && JVM_TYPE=zeroshark && continue
  [ "$arg" == "-server" ] && JVM_TYPE=server && continue
  [ "$arg" == "-alhambra" ] && JVM_TYPE=alhambra && continue
  [ "$arg" == "-release" -o "$arg" == "-debug=off" ] && BUILDTYPE=release && continue
  [ "$arg" == "-debug" -o "$arg" == "-debug=slow" -o "$arg" == "-slowdebug" ] && BUILDTYPE=slowdebug && continue
  [ "$arg" == "-fastdebug" -o "$arg" == "-debug=fast" ] && BUILDTYPE=fastdebug && continue
  [ "$arg" == "upload-jvm" -o  "$arg" == "upload-dist" ] && UPLOAD=true
  [ "$arg" == "-verbose" ] && VERBOSE="VERBOSE=" && continue
  [ "$arg" == "-noconfigure" ] && NOCONF="true" && continue
  [ "${arg:0:8}" == "SCP_DST=" ] && SCP_DST_DEFINED=true

  if [ "${arg:0:2}" == "--" ]; then
    configure_args[configure_args_counter++]=$arg
  else
    make_args[make_args_counter++]=$arg
  fi
done;

[ "x$UPLOAD" == "xtrue" -a "x$SCP_DST_DEFINED" != "xtrue" ] && {
    echo "Need to define SCP_DST variable"
    exit 1
}

LIBTINFO=$(ldconfig -p | grep -o "libtinfo.so ")
if [ "x$LIBTINFO" == "xlibtinfo.so " ]; then
    LTINFO_LIB="-ltinfo"
fi

CONF_PREFIX=linux-x86_64-normal
CONF_NAME=$CONF_PREFIX-$JVM_TYPE-$BUILDTYPE
echo Configuration $CONF_NAME

if [ "x$JVM_TYPE" = "xzeroshark" ] || [ "x$JVM_TYPE" = "xalhambra" ]; then
    if [ ! -d llvm-project ]; then
        echo Downloading llvm-project repository
        bash get_llvm_sources.sh
    fi

    export LLVM_ARCH=$TARCH
    LLVM_BUILD_DIR=$BUILD_DIR/llvm-$LLVM_ARCH
    LLVM_CFLAGS="-I${ROOT_DIR}/llvm-project/llvm/include -I${LLVM_BUILD_DIR}/include -DNDEBUG -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -O3 -fomit-frame-pointer -fvisibility-inlines-hidden -fno-exceptions -fno-rtti -fPIC -Woverloaded-virtual -Wcast-qual"

    LLVM_LIBS="-lLLVMWindowsManifest -lLLVMXRay -lLLVMLibDriver -lLLVMDlltoolDriver -lLLVMCoverage -lLLVMLineEditor  -lLLVMX86Disassembler -lLLVMX86AsmParser -lLLVMX86CodeGen -lLLVMX86Desc -lLLVMX86Info -lLLVMOrcJIT -lLLVMMCJIT -lLLVMJITLink -lLLVMOrcTargetProcess -lLLVMOrcShared -lLLVMInterpreter -lLLVMExecutionEngine -lLLVMRuntimeDyld -lLLVMSymbolize -lLLVMDebugInfoPDB -lLLVMDebugInfoGSYM -lLLVMOption -lLLVMObjectYAML -lLLVMMCA -lLLVMMCDisassembler -lLLVMLTO -lLLVMPasses -lLLVMCFGuard -lLLVMCoroutines -lLLVMObjCARCOpts -lLLVMHelloNew -lLLVMipo -lLLVMVectorize -lLLVMLinker -lLLVMInstrumentation -lLLVMFrontendOpenMP -lLLVMFrontendOpenACC -lLLVMExtensions -lLLVMDWARFLinker -lLLVMGlobalISel -lLLVMMIRParser -lLLVMAsmPrinter -lLLVMDebugInfoDWARF -lLLVMSelectionDAG -lLLVMCodeGen -lLLVMIRReader -lLLVMAsmParser -lLLVMInterfaceStub -lLLVMFileCheck -lLLVMFuzzMutate -lLLVMTarget -lLLVMScalarOpts -lLLVMInstCombine -lLLVMAggressiveInstCombine -lLLVMTransformUtils -lLLVMBitWriter -lLLVMAnalysis -lLLVMProfileData -lLLVMObject -lLLVMTextAPI -lLLVMMCParser -lLLVMMC -lLLVMDebugInfoCodeView -lLLVMDebugInfoMSF -lLLVMBitReader -lLLVMCore -lLLVMRemarks -lLLVMBitstreamReader -lLLVMBinaryFormat -lLLVMTableGen -lLLVMSupport -lLLVMDemangle";
    LLVM_LDFLAGS=""

    mkdir -p $LLVM_BUILD_DIR/bin

    cat > $LLVM_BUILD_DIR/bin/llvm-config << EOF
#!/bin/bash
case \$1 in
  --version) echo "12.0.1-alhambra" ;;
  --cxxflags) echo "$LLVM_CFLAGS" ;;
  --ldflags) echo "-L$LLVM_BUILD_DIR/lib -lpthread -ldl -lm $LLVM_LDFLAGS" ;;
  --libs) echo "$LLVM_LIBS -lLLVMExecutionEngine -lLLVMRuntimeDyld -lLLVMObject -lLLVMAsmPrinter -lLLVMMCParser -lLLVMMCJIT -lLLVMSelectionDAG -lLLVMScalarOpts -lLLVMTransformUtils -lLLVMAnalysis -lLLVMCore -lLLVMSupport -lLLVMCodeGen -lLLVMMC -lLLVMTarget -ltinfo -lz";
esac
EOF

    chmod +x $LLVM_BUILD_DIR/bin/llvm-config
    export PATH=$LLVM_BUILD_DIR/bin:$PATH
fi

export BUILD_CC=`which gcc`
export BUILD_CXX=`which g++`
export BUILD_LD="$BUILD_CC"

if [ "x$BUILDTYPE" = xfastdebug ]; then
    export OPT_CFLAGS_DEFAULT=SLOW
    export OPT_EXTRAS=-O1
fi

CONF_COMMON_FLAGS="--prefix=$ROOT_DIR/dist --disable-precompiled-headers"

if [ "x$BOOT_JDK" != x ]; then
  CONF_COMMON_FLAGS+=" --with-boot-jdk=$BOOT_JDK"
fi

if [ "x$BUILDTYPE" = xfastdebug ]; then
    CONF_FLAGS="$CONF_COMMON_FLAGS --disable-debug-symbols  --with-debug-level=fastdebug"
elif [ "x$BUILDTYPE" = xslowdebug ]; then
    CONF_FLAGS="$CONF_COMMON_FLAGS --disable-zip-debug-info --with-debug-level=slowdebug"
    export DEBUG_BINARIES=true
else
    CONF_FLAGS="$CONF_COMMON_FLAGS --disable-debug-symbols"
fi

# ./java -version output:
# openjdk version "1.8.0_112"
# OpenJDK Runtime Environment (build 1.8.0_152-b16)
# OpenJDK 64-Bit Client VM (RVM 3.2) (build 25.152-b16, mixed mode)
CONF_FLAGS="$CONF_FLAGS --with-milestone=fcs"
CONF_FLAGS="$CONF_FLAGS --with-update-version=152"
CONF_FLAGS="$CONF_FLAGS --with-user-release-suffix="
CONF_FLAGS="$CONF_FLAGS --with-build-number=b16"

CONF_JVM_FLAGS="--with-jvm-variants=$JVM_TYPE"

if [ "x$NOCONF" == xfalse ]; then
  sh ./configure $CONF_FLAGS $CONF_JVM_FLAGS ${configure_args[@]} 2>&1 | tee $BUILD_DIR/configure.log
fi
make $VERBOSE JOBS=$JOBS CONF=$CONF_NAME ${make_args[@]} 2>&1 | tee $BUILD_DIR/make.log
test ${PIPESTATUS[0]} -eq 0
