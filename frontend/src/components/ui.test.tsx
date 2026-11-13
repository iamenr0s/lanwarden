import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import InsecureNotice from "./InsecureNotice";
import QrCode from "./QrCode";
import { Card, ErrorBox, Field, Loading, Toggle } from "./ui";

describe("ui primitives", () => {
  it("Card shows an optional title", () => {
    const { rerender } = render(<Card title="Devices">body</Card>);
    expect(screen.getByRole("heading", { name: "Devices" })).toBeTruthy();
    rerender(<Card>body</Card>);
    expect(screen.queryByRole("heading")).toBeNull();
  });

  it("ErrorBox is announced as an alert; Loading says so", () => {
    render(
      <>
        <ErrorBox message="nope" />
        <Loading />
      </>,
    );
    expect(screen.getByRole("alert").textContent).toBe("nope");
    expect(screen.getByText("Loading…")).toBeTruthy();
  });

  it("Field labels its input and shows a hint", () => {
    render(
      <Field label="Name" hint="Shown in the list">
        <input />
      </Field>,
    );
    expect(screen.getByLabelText(/Name/)).toBeTruthy();
    expect(screen.getByText("Shown in the list")).toBeTruthy();
  });

  it("Toggle reports the new checked state", () => {
    const onChange = vi.fn();
    render(<Toggle label="Always connected" checked={false} onChange={onChange} />);
    fireEvent.click(screen.getByLabelText("Always connected"));
    expect(onChange).toHaveBeenCalledWith(true);
  });
});

describe("QrCode", () => {
  it("draws an accessible SVG whose size depends on the data", () => {
    const { container, rerender } = render(<QrCode value="otpauth://totp/a" label="Scan me" />);
    expect(screen.getByRole("img").getAttribute("aria-label")).toBe("Scan me");
    const small = container.querySelector("svg")!.getAttribute("viewBox");
    rerender(<QrCode value={"otpauth://totp/" + "a".repeat(120)} label="Scan me" />);
    expect(container.querySelector("svg")!.getAttribute("viewBox")).not.toBe(small);
  });
});

describe("InsecureNotice", () => {
  it("warns, and offers dismissal only when asked", () => {
    const onDismiss = vi.fn();
    const { rerender } = render(<InsecureNotice />);
    expect(screen.getByRole("alert").textContent).toContain("not encrypted");
    expect(screen.queryByLabelText("Dismiss warning")).toBeNull();
    rerender(<InsecureNotice onDismiss={onDismiss} />);
    fireEvent.click(screen.getByLabelText("Dismiss warning"));
    expect(onDismiss).toHaveBeenCalled();
  });
});
