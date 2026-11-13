import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Testing Library only auto-cleans when test globals are on; we import from vitest explicitly instead.
afterEach(cleanup);
