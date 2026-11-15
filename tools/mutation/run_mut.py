#!/usr/bin/env python3
"""Mutation campaign for one source file: break one thing at a time, rebuild under ASan+UBSan, run the tests of that file.
usage: tools/mutation/run_mut.py NAME [--full] [TAG ...]
  NAME             the mutants_NAME.py next to this script: elf, pe, logging, vector, hashmap, thread_pool ...
  --full           no CBAE_TEST_QUICK (the tests run in full); MUT_TIMEOUT=seconds per test binary (default 240)
  TAG ...          only these mutants (E01, R07, P12 ...)
Needs the ASan tree of tests/run_gates.sh (CBAE_GATES_DIR/asan, configured). The source is restored whatever happens."""
import glob, importlib, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mutlib

if __name__ == '__main__':
    args = sys.argv[1:]
    known = sorted(os.path.basename(p)[len('mutants_'):-len('.py')]
                   for p in glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mutants_*.py')))
    if not args or args[0] not in known:
        sys.exit(__doc__ + '\nknown: ' + ' '.join(known))
    mod = importlib.import_module('mutants_' + args[0])
    full = '--full' in args
    which = [a for a in args[1:] if a != '--full']
    res = mutlib.run(mod.SRC, mod.TESTS, mod.MUTANTS, which, full)
    surv = [k for k, v in res.items() if v in ('SURVIVED', 'BUILD')]
    print('\nkilled %d, survived/failed %d: %s' % (len(res) - len(surv), len(surv), ' '.join(surv)), flush=True)
