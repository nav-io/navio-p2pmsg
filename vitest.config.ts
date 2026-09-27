import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 60000,
    hookTimeout: 120000,
    /**
     * Cap the workers well below the core count.
     *
     * Almost every test here is CPU-bound on BLS12-381, so vitest's default of
     * one worker per core does not overlap I/O with compute — it just divides
     * the same cores more ways and adds scheduling. On a machine that is also
     * compiling a node, eleven such workers thrash: a run has been seen
     * spending 105 seconds merely COLLECTING 33 files, and vitest's own
     * worker RPC timing out mid-run, which then fails whichever tests happened
     * to be waiting. Raising per-test deadlines does not fix that; it only
     * moves which test loses.
     *
     * Four keeps the suite roughly as quick on an idle machine and stops it
     * being the thing that overloads a busy one.
     */
    maxWorkers: 4,
    minWorkers: 1,
  },
});
