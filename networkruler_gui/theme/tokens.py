from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ThemeName(str, Enum):
    SYSTEM = "System"
    CLEAN_MINIMAL_LIGHT = "Clean Minimal Light"
    CLEAN_MINIMAL_DARK = "Clean Minimal Dark"
    CYBER = "Cyber"
    GAMING_TECH_NEON = "Gaming / Tech Neon"
    PROFESSIONAL_ENTERPRISE = "Professional Enterprise"
    DARK_ENTERPRISE = "Dark Enterprise"


@dataclass(frozen=True)
class ThemeTokens:
    name: ThemeName
    background: str
    surface: str
    elevated_surface: str
    card: str
    card_hover: str
    border: str
    border_strong: str
    text_primary: str
    text_secondary: str
    text_muted: str
    accent: str
    accent_hover: str
    accent_soft: str
    on_accent: str
    danger: str
    danger_soft: str
    warning: str
    warning_soft: str
    success: str
    success_soft: str
    shadow: str
    chart: str
    radius: int
    radius_small: int
    spacing: int
    spacing_large: int

    @property
    def window(self) -> str:
        return self.background

    @property
    def elevated(self) -> str:
        return self.elevated_surface

    @property
    def text(self) -> str:
        return self.text_primary

    @property
    def muted(self) -> str:
        return self.text_secondary

    @property
    def subtle(self) -> str:
        return self.text_muted

    @property
    def surface_alt(self) -> str:
        return self.card_hover


THEMES: dict[ThemeName, ThemeTokens] = {
    ThemeName.CLEAN_MINIMAL_LIGHT: ThemeTokens(
        name=ThemeName.CLEAN_MINIMAL_LIGHT,
        background="#f5f5f7",
        surface="#fbfbfd",
        elevated_surface="#ffffff",
        card="#ffffff",
        card_hover="#f1f3f7",
        border="#e1e4ea",
        border_strong="#cfd5df",
        text_primary="#17181c",
        text_secondary="#626a78",
        text_muted="#8d96a5",
        accent="#0a84ff",
        accent_hover="#006edb",
        accent_soft="#e8f2ff",
        on_accent="#ffffff",
        danger="#d92d20",
        danger_soft="#ffeceb",
        warning="#b7791f",
        warning_soft="#fff4da",
        success="#248a4b",
        success_soft="#e9f7ef",
        shadow="rgba(18, 25, 38, 36)",
        chart="#4f8cff",
        radius=18,
        radius_small=11,
        spacing=14,
        spacing_large=24,
    ),
    ThemeName.CLEAN_MINIMAL_DARK: ThemeTokens(
        name=ThemeName.CLEAN_MINIMAL_DARK,
        background="#101114",
        surface="#15171c",
        elevated_surface="#1c1f27",
        card="#181b22",
        card_hover="#222631",
        border="#2d323d",
        border_strong="#3c4452",
        text_primary="#f6f7fb",
        text_secondary="#b7beca",
        text_muted="#7e8796",
        accent="#6aa9ff",
        accent_hover="#8cbdff",
        accent_soft="#1c3554",
        on_accent="#ffffff",
        danger="#ff6b68",
        danger_soft="#3a1f24",
        warning="#e3b760",
        warning_soft="#332818",
        success="#62d58a",
        success_soft="#193424",
        shadow="rgba(0, 0, 0, 82)",
        chart="#7fb7ff",
        radius=18,
        radius_small=11,
        spacing=14,
        spacing_large=24,
    ),
    ThemeName.CYBER: ThemeTokens(
        name=ThemeName.CYBER,
        background="#070a10",
        surface="#0d121c",
        elevated_surface="#121b2b",
        card="#0f1724",
        card_hover="#152238",
        border="#223a5a",
        border_strong="#2f5c8a",
        text_primary="#ecfbff",
        text_secondary="#9bb0c6",
        text_muted="#5d7187",
        accent="#00d4ff",
        accent_hover="#4fe4ff",
        accent_soft="#082d3c",
        on_accent="#001018",
        danger="#ff3d81",
        danger_soft="#351426",
        warning="#f7d154",
        warning_soft="#30270d",
        success="#37f59b",
        success_soft="#0e3426",
        shadow="rgba(0, 212, 255, 44)",
        chart="#00d4ff",
        radius=16,
        radius_small=10,
        spacing=14,
        spacing_large=24,
    ),
    ThemeName.GAMING_TECH_NEON: ThemeTokens(
        name=ThemeName.GAMING_TECH_NEON,
        background="#0b0b12",
        surface="#131320",
        elevated_surface="#1a1730",
        card="#171627",
        card_hover="#211d39",
        border="#3c315f",
        border_strong="#5d4b96",
        text_primary="#fff7ff",
        text_secondary="#c9bfde",
        text_muted="#817797",
        accent="#ff2bd6",
        accent_hover="#ff70e5",
        accent_soft="#341444",
        on_accent="#ffffff",
        danger="#ff4d6d",
        danger_soft="#371721",
        warning="#ffd166",
        warning_soft="#332811",
        success="#2dff9f",
        success_soft="#123525",
        shadow="rgba(255, 43, 214, 50)",
        chart="#8c5cff",
        radius=16,
        radius_small=10,
        spacing=14,
        spacing_large=24,
    ),
    ThemeName.PROFESSIONAL_ENTERPRISE: ThemeTokens(
        name=ThemeName.PROFESSIONAL_ENTERPRISE,
        background="#eef2f6",
        surface="#f8fafc",
        elevated_surface="#ffffff",
        card="#ffffff",
        card_hover="#edf3fa",
        border="#cfd7e3",
        border_strong="#b6c1d0",
        text_primary="#172033",
        text_secondary="#5a6576",
        text_muted="#8792a3",
        accent="#2557a7",
        accent_hover="#1b4384",
        accent_soft="#d9e6fb",
        on_accent="#ffffff",
        danger="#b42318",
        danger_soft="#fee4e2",
        warning="#9a6700",
        warning_soft="#fff1c2",
        success="#247a4d",
        success_soft="#dcfce7",
        shadow="rgba(23, 32, 51, 34)",
        chart="#2557a7",
        radius=13,
        radius_small=8,
        spacing=13,
        spacing_large=22,
    ),
    ThemeName.DARK_ENTERPRISE: ThemeTokens(
        name=ThemeName.DARK_ENTERPRISE,
        background="#0D1117",
        surface="#0D1117",
        elevated_surface="#161B22",
        card="#161B22",
        card_hover="#1F242C",
        border="#30363D",
        border_strong="#484F58",
        text_primary="#C9D1D9",
        text_secondary="#8B949E",
        text_muted="#6E7681",
        accent="#2F81F7",
        accent_hover="#388BFD",
        accent_soft="rgba(47, 129, 247, 0.15)",
        on_accent="#FFFFFF",
        danger="#F85149",
        danger_soft="rgba(248, 81, 73, 0.15)",
        warning="#D29922",
        warning_soft="rgba(210, 153, 34, 0.15)",
        success="#238636",
        success_soft="rgba(35, 134, 54, 0.15)",
        shadow="rgba(0, 0, 0, 80)",
        chart="#2F81F7",
        radius=8,
        radius_small=6,
        spacing=14,
        spacing_large=24,
    ),
}


def theme_names() -> list[str]:
    return [theme.value for theme in ThemeName]
