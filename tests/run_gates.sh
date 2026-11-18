#!/bin/bash
# tests/run_gates.sh - the checkpoint gate: the whole suite in every configuration, one command.
#
#   tests/run_gates.sh [gate ...]       gates: debug release asan tsan valgrind   (default: all five)
#
#   debug     -DCMAKE_BUILD_TYPE=Debug; then test_thread_pool once more with exited threads kept listed (tools/slow_reap.py)
#   release   -DCMAKE_BUILD_TYPE=Release; the build must also be free of compiler warnings
#   asan      Debug + -DCBAE_SANITIZE=address (ASan + UBSan, a finding aborts; LeakSanitizer on)
#   tsan      Debug + -DCBAE_SANITIZE=thread; and the same slow-teardown run
#   valgrind  the debug tree, every test under valgrind --leak-check=full (CBAE_TEST_QUICK=1: the tests
#             that sweep huge inputs skip their largest cases; every other configuration runs them all)
#
# Environment:
#   CBAE_GATES_DIR   where the build trees go (default: <repo>/../cbae-gates)
#   CBAE_JOBS        parallel jobs (default: number of processors)
#
# Exit status 0 only if every requested gate passed. A summary table is printed at the end.
set -u

ROOT=$(cd "$(dirname "$0")/.." && pwd)
GATES=${CBAE_GATES_DIR:-$ROOT/../cbae-gates}
JOBS=${CBAE_JOBS:-$(nproc 2>/dev/null || echo 2)}
mkdir -p "$GATES"
GATES=$(cd "$GATES" && pwd)

if [ $# -eq 0 ]; then set -- debug release asan tsan valgrind; fi

declare -a names results times
fail=0

configure_build() {   # <tree> <build type> [extra cmake args...]  -> build log in <tree>/build.log
    local tree=$1 type=$2; shift 2
    mkdir -p "$tree"
    cmake -S "$ROOT" -B "$tree" -DCMAKE_BUILD_TYPE="$type" "$@" >"$tree/configure.log" 2>&1 || { echo "  configure failed, see $tree/configure.log"; return 1; }
    cmake --build "$tree" -j"$JOBS" >"$tree/build.log" 2>&1 || { echo "  build failed, see $tree/build.log"; tail -n 20 "$tree/build.log"; return 1; }
}

# The thread pool test again, with every thread that exits kept listed in /proc for 25 ms (tools/slow_reap.py): a test that counts the
# threads of the process right after a join must survive the slowest teardown a loaded or virtual machine can show (A-057).
run_slow_teardown() { # <tree>
    command -v python3 >/dev/null || { echo "  slow teardown: python3 is not installed, skipped"; return 0; }
    ( cd "$1/tests" && ASAN_OPTIONS=detect_leaks=0 python3 -I "$ROOT/tools/slow_reap.py" 25 ../bin/test_thread_pool >"$1/slow_teardown.log" 2>&1 ); local rc=$?
    case $rc in
        0)  echo "  slow teardown: test_thread_pool passes with exited threads kept listed for 25 ms" ;;
        77) echo "  slow teardown: tracing is not allowed here, skipped" ;;
        *)  echo "  FAILED: test_thread_pool with exited threads kept listed for 25 ms (see $1/slow_teardown.log)"
            tail -n 8 "$1/slow_teardown.log" | sed 's/^/    /'; return 1 ;;
    esac
}

run_ctest() {         # <tree>
    ( cd "$1" && ctest -j"$JOBS" --output-on-failure >"$1/ctest.log" 2>&1 ); local rc=$?
    tail -n 4 "$1/ctest.log" | sed 's/^/  /'
    [ $rc -eq 0 ] || grep -E '^\s*[0-9]+/[0-9]+ Test +#[0-9]+: .*(Failed|Timeout|\*\*\*)' "$1/ctest.log" | sed 's/^/  /'
    return $rc
}

gate_debug()   { configure_build "$GATES/debug" Debug && run_ctest "$GATES/debug" && run_slow_teardown "$GATES/debug"; }
gate_release() {
    configure_build "$GATES/release" Release || return 1
    local w; w=$(grep -c 'warning:' "$GATES/release/build.log")
    if [ "$w" -ne 0 ]; then echo "  $w compiler warning(s) in the Release build:"; grep 'warning:' "$GATES/release/build.log" | head -n 20 | sed 's/^/    /'; return 1; fi
    run_ctest "$GATES/release"
}
gate_asan() {
    configure_build "$GATES/asan" Debug -DCBAE_SANITIZE=address || return 1
    ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=0 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 run_ctest "$GATES/asan"
}
gate_tsan() {
    configure_build "$GATES/tsan" Debug -DCBAE_SANITIZE=thread || return 1
    TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1 run_ctest "$GATES/tsan" && run_slow_teardown "$GATES/tsan"
}
gate_valgrind() {
    command -v valgrind >/dev/null || { echo "  valgrind is not installed"; return 1; }
    [ -d "$GATES/debug/bin" ] || configure_build "$GATES/debug" Debug || return 1
    cmake --build "$GATES/debug" -j"$JOBS" >"$GATES/debug/build.log" 2>&1 || { echo "  build failed"; return 1; }
    local bad=0 n=0 t
    # tests run from <tree>/tests, as under ctest, so relative data paths resolve
    for t in $(cd "$GATES/debug" && ctest -N | sed -n 's/^ *Test *#[0-9]*: //p'); do
        n=$((n + 1))
        ( cd "$GATES/debug/tests" && CBAE_TEST_QUICK=1 valgrind -q --error-exitcode=99 --leak-check=full \
              --errors-for-leak-kinds=definite,indirect,possible "../bin/$t" >"$GATES/debug/valgrind_$t.log" 2>&1 )
        if [ $? -ne 0 ]; then bad=$((bad + 1)); echo "  FAILED under valgrind: $t (see $GATES/debug/valgrind_$t.log)"; tail -n 12 "$GATES/debug/valgrind_$t.log" | sed 's/^/    /'; fi
    done
    echo "  valgrind: $((n - bad))/$n tests clean"
    [ $bad -eq 0 ]
}

for g in "$@"; do
    case $g in debug|release|asan|tsan|valgrind) ;; *) echo "unknown gate '$g' (debug release asan tsan valgrind)"; exit 2 ;; esac
    echo "== gate: $g"
    t0=$(date +%s)
    "gate_$g"; rc=$?
    t1=$(date +%s)
    names+=("$g"); times+=($((t1 - t0)))
    if [ $rc -eq 0 ]; then results+=("pass"); else results+=("FAIL"); fail=1; fi
done

echo
echo "== summary"
for i in "${!names[@]}"; do printf '  %-9s %-5s %5ss\n' "${names[$i]}" "${results[$i]}" "${times[$i]}"; done
exit $fail
