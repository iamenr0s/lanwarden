import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { calls, fail, makeDevice, mockApi, renderAt } from "../test-utils";
import Devices from "./Devices";

afterEach(() => vi.unstubAllGlobals());

const lastQuery = (api: ReturnType<typeof mockApi>) => new URLSearchParams(calls(api).at(-1)!.split("?")[1]);

const items = [
  makeDevice({ id: 1, display_name: "NAS", is_favorite: true, effective_type: "storage", device_type: "storage" }),
  makeDevice({ id: 2, display_name: "Phone", is_known: false, status: "UNKNOWN", is_randomized_mac: true, is_online: false, current_ip: null, hostname: null, mac_address: null }),
  makeDevice({ id: 3, display_name: "Camera", is_known: false, status: "NEW", effective_type: "camera", type_guess: "camera" }),
];

describe("Devices", () => {
  it("renders a row per device with markers for favourite, private MAC and review state", async () => {
    mockApi({ "/devices*": { total: 3, items } });
    renderAt(<Devices />);
    const nas = await screen.findByRole("link", { name: /NAS/ });
    expect(nas.getAttribute("href")).toBe("/devices/1");
    expect(within(nas).getByLabelText("Favorite")).toBeTruthy();
    const phoneRow = screen.getByRole("link", { name: "Phone" }).closest("tr")!;
    expect(within(phoneRow).getByText("private MAC")).toBeTruthy();
    expect(within(phoneRow).getByText("Unknown")).toBeTruthy();
    const cameraRow = screen.getByRole("link", { name: "Camera" }).closest("tr")!;
    expect(within(cameraRow).getByText("New")).toBeTruthy();
    expect(within(cameraRow).getByText("(auto)")).toBeTruthy(); // type came from a guess, not the user
    expect(screen.getByText("3 devices")).toBeTruthy();
  });

  it("explains an empty list differently with and without filters", async () => {
    mockApi({ "/devices*": { total: 0, items: [] } });
    const { unmount } = renderAt(<Devices />);
    expect(await screen.findByText(/No devices yet/)).toBeTruthy();
    unmount();
    renderAt(<Devices />, { route: "/devices?online=true" });
    expect(await screen.findByText("No devices match these filters.")).toBeTruthy();
  });

  it("shows an error", async () => {
    mockApi({ "/devices*": fail(500, "boom") });
    renderAt(<Devices />);
    expect((await screen.findByRole("alert")).textContent).toBe("boom");
  });

  it("filter chips toggle a URL parameter on and off", async () => {
    const api = mockApi({ "/devices*": { total: 3, items } });
    renderAt(<Devices />);
    await screen.findByText("3 devices");
    const online = screen.getByRole("button", { name: "Online" });
    expect(online.getAttribute("aria-pressed")).toBe("false");
    fireEvent.click(online);
    await waitFor(() => expect(lastQuery(api).get("online")).toBe("true"));
    expect(screen.getByRole("button", { name: "Online" }).getAttribute("aria-pressed")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Online" }));
    await waitFor(() => expect(lastQuery(api).get("online")).toBeNull());
  });

  it("group and type filters from the URL can be cleared", async () => {
    const api = mockApi({ "/devices*": { total: 3, items } });
    renderAt(<Devices />, { route: "/devices?group=lab&type=camera" });
    await screen.findByText("3 devices");
    expect(lastQuery(api).get("group")).toBe("lab");
    fireEvent.click(screen.getByRole("button", { name: /Group: lab/ }));
    await waitFor(() => expect(lastQuery(api).get("group")).toBeNull());
    fireEvent.click(screen.getByRole("button", { name: /Type: camera/ }));
    await waitFor(() => expect(lastQuery(api).get("type")).toBeNull());
  });

  it("sorts by a column and flips the direction on a second click", async () => {
    const api = mockApi({ "/devices*": { total: 3, items } });
    renderAt(<Devices />);
    await screen.findByText("3 devices");
    expect(lastQuery(api).get("sort")).toBe("last_seen");
    fireEvent.click(screen.getByRole("button", { name: /^Device/ }));
    await waitFor(() => expect(lastQuery(api).get("sort")).toBe("name"));
    expect(lastQuery(api).get("order")).toBe("asc");
    fireEvent.click(screen.getByRole("button", { name: /^Device/ }));
    await waitFor(() => expect(lastQuery(api).get("order")).toBe("desc"));
    expect(screen.getByRole("columnheader", { name: /Device/ }).getAttribute("aria-sort")).toBe("descending");
  });

  it("searches after a pause and returns to the first page", async () => {
    const api = mockApi({ "/devices*": { total: 200, items } });
    renderAt(<Devices />, { route: "/devices?page=2" });
    await screen.findByText("200 devices");
    fireEvent.change(screen.getByLabelText("Search devices"), { target: { value: "nas" } });
    await waitFor(() => expect(lastQuery(api).get("q")).toBe("nas"));
    expect(lastQuery(api).get("offset")).toBe("0");
  });

  it("pages through results", async () => {
    const api = mockApi({ "/devices*": { total: 120, items } });
    renderAt(<Devices />);
    await screen.findByText("120 devices");
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(lastQuery(api).get("offset")).toBe("50"));
    fireEvent.click(screen.getByRole("button", { name: "Previous" }));
    await waitFor(() => expect(lastQuery(api).get("offset")).toBe("0"));
  });
});
