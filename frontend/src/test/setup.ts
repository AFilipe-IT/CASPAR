import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// RTL doesn't auto-clean under globals:true unless the framework hooks it up.
afterEach(cleanup);
