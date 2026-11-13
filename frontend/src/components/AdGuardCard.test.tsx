import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { mockApi, renderAt } from "../test-utils";
import AdGuardCard from "./AdGuardCard";

afterEach(() => vi.unstubAllGlobals());

const status = (over: object) => mockApi({ "/integrations/adguard/status": over });

describe("AdGuardCard", () => {
  it("is checking until the status arrives", () => {
    status({ configured: false });
    renderAt(<AdGuardCard />);
    expect(screen.getByText("Checking…")).toBeTruthy();
  });

  it("invites setup when not configured", async () => {
    status({ configured: false });
    renderAt(<AdGuardCard />);
    expect(await screen.findByText("Not configured")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Set up" }).getAttribute("href")).toBe("/adguard");
  });

  it("shows version and protection when reachable", async () => {
    status({ configured: true, reachable: true, server: { version: "v0.107.52", protection_enabled: true } });
    renderAt(<AdGuardCard />);
    expect(await screen.findByText("Reachable")).toBeTruthy();
    expect(screen.getByText("v0.107.52 · protection on")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Manage" })).toBeTruthy();
  });

  it("normalises a version without a leading v and reports protection off", async () => {
    status({ configured: true, reachable: true, server: { version: "0.107.1", protection_enabled: false } });
    renderAt(<AdGuardCard />);
    expect(await screen.findByText("v0.107.1 · protection off")).toBeTruthy();
  });

  it("shows the reason when unreachable", async () => {
    status({ configured: true, reachable: false, error: { message: "connection refused" } });
    renderAt(<AdGuardCard />);
    expect(await screen.findByText("Unreachable")).toBeTruthy();
    expect(screen.getByText("connection refused")).toBeTruthy();
  });
});
