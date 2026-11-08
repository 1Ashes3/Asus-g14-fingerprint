"""Light/dark colour themes for the Tk app, and the 100-template easter-egg watermark
(a procedurally drawn, generic fingerprint - not anyone's real print)."""
import math
import tkinter as tk
from tkinter import ttk

import numpy as np

THEMES = {
    "light": {"bg": "#efefef", "fg": "#1c1c1c", "muted": "#555555", "field": "#ffffff", "field_fg": "#1c1c1c",
              "button": "#e2e2e2", "button_active": "#d0d0d0", "border": "#b8b8b8", "select": "#3b6fb6",
              "watermark": "#1a4b8c", "watermark_alpha": 0.16},
    "dark": {"bg": "#202124", "fg": "#e8eaed", "muted": "#a0a4aa", "field": "#141517", "field_fg": "#e8eaed",
             "button": "#33363b", "button_active": "#44484e", "border": "#4a4d52", "select": "#5b8def",
             "watermark": "#7fd8ff", "watermark_alpha": 0.30},
}


def apply(root, mode):
    """Restyle every ttk widget class and the root window; returns the palette used."""
    t = THEMES[mode]
    s = ttk.Style(root)
    try:
        s.theme_use("clam")
    except tk.TclError:
        pass
    s.configure(".", background=t["bg"], foreground=t["fg"], fieldbackground=t["field"], bordercolor=t["border"],
                lightcolor=t["bg"], darkcolor=t["bg"], troughcolor=t["field"], selectbackground=t["select"])
    s.configure("TFrame", background=t["bg"])
    s.configure("TLabel", background=t["bg"], foreground=t["fg"])
    s.configure("Muted.TLabel", background=t["bg"], foreground=t["muted"])
    s.configure("TButton", background=t["button"], foreground=t["fg"], bordercolor=t["border"], focusthickness=1)
    s.map("TButton", background=[("active", t["button_active"]), ("disabled", t["bg"])],
          foreground=[("disabled", t["muted"])])
    s.configure("TCheckbutton", background=t["bg"], foreground=t["fg"])
    s.map("TCheckbutton", background=[("active", t["bg"])], indicatorcolor=[("selected", t["select"]), ("!selected", t["field"])])
    s.configure("TCombobox", fieldbackground=t["field"], background=t["button"], foreground=t["field_fg"],
                arrowcolor=t["fg"])
    s.map("TCombobox", fieldbackground=[("readonly", t["field"])], foreground=[("readonly", t["field_fg"])])
    s.configure("TSeparator", background=t["border"])
    root.configure(bg=t["bg"])
    root.option_add("*TCombobox*Listbox.background", t["field"])
    root.option_add("*TCombobox*Listbox.foreground", t["field_fg"])
    return t


def _hex(c):
    c = c.lstrip("#")
    return np.array([int(c[i:i + 2], 16) for i in (0, 2, 4)], np.float32)


def fingerprint_watermark(width, height, bg, color, alpha):
    """RGB uint8 image (height, width, 3): a generic whorl fingerprint blended onto bg at `alpha`."""
    width, height = max(width, 10), max(height, 10)
    size = int(min(width, height) * 0.82)
    y, x = np.mgrid[0:size, 0:size].astype(np.float32)
    x = (x - size / 2) / (size / 2)
    y = (y - size * 0.47) / (size / 2)
    ex, ey = x / 0.72, y / 0.92                                   # finger-shaped ellipse
    r = np.sqrt(ex ** 2 + ey ** 2)
    theta = np.arctan2(ey, ex)
    # whorl core slightly above centre, ridges that open into loops towards the bottom
    core = np.sqrt((ex - 0.05) ** 2 + (ey + 0.12) ** 2)
    phase = 13.0 * core + 0.9 * np.sin(theta * 2 + 0.6) * np.exp(-core * 1.4) + 1.6 * np.clip(ey, 0, None) ** 2
    ridges = 0.5 + 0.5 * np.cos(2 * math.pi * phase)
    ridges = np.clip((ridges - 0.55) / 0.3, 0, 1)                 # crisp ridge lines
    edge = np.clip((1.0 - r) / 0.08, 0, 1)                        # soft finger outline
    ridges *= edge
    a = (ridges * alpha)[..., None]
    out = np.tile(_hex(bg), (height, width, 1))
    oy, ox = (height - size) // 2, (width - size) // 2
    patch = out[oy:oy + size, ox:ox + size]
    out[oy:oy + size, ox:ox + size] = patch * (1 - a) + _hex(color) * a
    return np.clip(out, 0, 255).astype(np.uint8)
