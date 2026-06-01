1. Copy [template.ts](./template.ts) to wherever you store your code for your vite project (defaults to `/src`). Rename it to `test.ts` or something similar to reflect its purpose.
2. Within the file from step 1, update `<path>` to point to the location of `sweater-vest-suede` and update `<folder` in the glob pattern to be wherever your tests are stored (likely where you copied `template.ts` in step 1, e.g. `src`).
3. Copy [template.html](./template.html) to the root of your vite project. Rename it to `test.html` or something similar to reflect its purpose (as the entry point for your tests).
4. Within the file from step 3, update `file` to point to file from step 1 (e.g. `src/test.ts`).
5. `npm run dev` and navigate to `http://localhost:<port>/test` to see the test gallery. Click on a test file to run the tests within it.
