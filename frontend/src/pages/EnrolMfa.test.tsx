import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { authState, calls, mockApi, renderAt } from "../test-utils";
import EnrolMfa from "./EnrolMfa";

afterEach(() => vi.unstubAllGlobals());

describe("EnrolMfa", () => {
  it("blocks the app behind a forced enrolment form", () => {
    renderAt(<EnrolMfa />, { auth: authState({ mfa_enrolment_required: true }) });
    expect(screen.getByRole("heading", { name: /LanWarden/ })).toBeTruthy();
    expect(screen.getByText(/requires two-step verification/)).toBeTruthy();
  });

  it("lets the user sign out instead", async () => {
    const api = mockApi({ "POST /auth/logout": undefined });
    const refresh = vi.fn().mockResolvedValue(undefined);
    renderAt(<EnrolMfa />, { auth: authState({ mfa_enrolment_required: true }), refresh });
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    await waitFor(() => expect(refresh).toHaveBeenCalled());
    expect(calls(api)).toEqual(["POST /auth/logout"]);
  });
});
