"""mutlib.py - one-change-at-a-time mutation testing of a source file against a set of test binaries.

For every mutant: replace one piece of text that occurs exactly once, rebuild the test binaries in the ASan+UBSan tree of
tests/run_gates.sh, run them (CBAE_TEST_QUICK=1 unless --full), and report whether one of them failed (the mutant is killed) or all
passed (it survived). A survivor is either an equivalent mutant (the change cannot be observed: write down why) or a missing
test. The source file is always restored, and its text is compared with the original at the end."""
import os, shutil, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TREE = os.environ.get('CBAE_GATES_DIR', ROOT + '/../cbae-gates') + '/asan'
TIMEOUT = int(os.environ.get('MUT_TIMEOUT', '240'))


def run(src_rel, tests, mutants, which, full):
    src = os.path.join(ROOT, src_rel)
    orig = os.path.join(tempfile.mkdtemp(prefix='cbae-mut-'), os.path.basename(src) + '.orig')
    shutil.copy(src, orig)
    s0 = open(orig).read()
    tags = [m[0].split()[0] for m in mutants]
    assert len(tags) == len(set(tags)), 'duplicate mutant tags'
    results = {}
    try:
        for name, old, new in mutants:
            tag = name.split()[0]
            if which and tag not in which:
                continue
            assert s0.count(old) == 1, (name, s0.count(old))
            open(src, 'w').write(s0.replace(old, new, 1))
            t0 = time.time()
            b = subprocess.run(['cmake', '--build', TREE, '-j2', '--target'] + tests, capture_output=True, text=True)
            if b.returncode != 0:
                print(name, ': BUILD FAILED', (b.stdout + b.stderr)[-400:], flush=True)
                results[tag] = 'BUILD'
                continue
            killed = None
            env = dict(os.environ)
            if not full:
                env['CBAE_TEST_QUICK'] = '1'
            for t in tests:
                try:
                    r = subprocess.run([TREE + '/bin/' + t], cwd=TREE + '/tests', capture_output=True, text=True, env=env, timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    killed = t + ': timeout'
                    break
                if r.returncode != 0:
                    why = r.stderr.strip().splitlines() or ['?']
                    line = [l for l in why if 'Assertion' in l or 'ERROR' in l or 'runtime error' in l]
                    killed = t + ': ' + (line[0][:140] if line else why[0][:140])
                    break
            results[tag] = killed or 'SURVIVED'
            print(('KILLED   ' if killed else 'SURVIVED ') + name + ('  <- ' + killed if killed else '') + '  (%.0fs)' % (time.time() - t0), flush=True)
    finally:
        shutil.copy(orig, src)
    assert open(src).read() == s0, 'the source was not restored'
    return results
