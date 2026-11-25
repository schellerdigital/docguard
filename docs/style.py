#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Layout-Bausteine der docguard-Papiere.

Rekonstruiert aus dem gesetzten PDF. Die Schriftsuche ist bewusst
plattformunabhängig, damit das Skript auch auf dem Mac läuft."""

import os, glob
from reportlab.lib.colors import HexColor, white
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Paragraph, Spacer, Table, TableStyle, Flowable,
                                KeepTogether)

# ---------------------------------------------------------------- Schriften
FONT_DIRS = [
    "/usr/share/fonts/truetype/dejavu/",
    "/usr/share/fonts/dejavu/",
    "/Library/Fonts/", os.path.expanduser("~/Library/Fonts/"),
    "/usr/local/share/fonts/",
]


def _find(name):
    for d in FONT_DIRS:
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    hits = glob.glob(f"/usr/share/fonts/**/{name}", recursive=True)
    return hits[0] if hits else None


_FACES = (("DJ", "DejaVuSans.ttf"), ("DJ-B", "DejaVuSans-Bold.ttf"),
          ("DJ-I", "DejaVuSans-Oblique.ttf"), ("DJ-BI", "DejaVuSans-BoldOblique.ttf"))
for _name, _file in _FACES:
    _path = _find(_file)
    if _path is None:
        raise SystemExit(f"Schrift {_file} nicht gefunden. Gesucht in: {FONT_DIRS}")
    pdfmetrics.registerFont(TTFont(_name, _path))
# Ohne diese Zuordnung bleiben <b> und <i> in Paragraphen wirkungslos.
pdfmetrics.registerFontFamily("DJ", normal="DJ", bold="DJ-B",
                              italic="DJ-I", boldItalic="DJ-BI")

# ---------------------------------------------------------------- Palette
TEAL = HexColor("#0B5F52")
INK = HexColor("#111827")
MUTED = HexColor("#4B5563")
RULE = HexColor("#DDE2E7")
CALL_BG = HexColor("#FDF3E7")
CALL_BD = HexColor("#C07A1F")
CALL_TX = HexColor("#8A5111")

BOX = {
    "grau":   (HexColor("#F3F2EE"), HexColor("#D8D5CC"), INK),
    "orange": (HexColor("#FDF1EA"), HexColor("#E3A77F"), HexColor("#B4541B")),
    "gruen":  (HexColor("#E9F5F1"), HexColor("#8FC9B8"), TEAL),
    "lila":   (HexColor("#EFEFFA"), HexColor("#A9A9DC"), HexColor("#3B3B8F")),
}

MARGIN = 60
WIDTH = 475          # Satzbreite in Punkt

# ---------------------------------------------------------------- Absätze
S = {}
S["eyebrow"] = ParagraphStyle("eyebrow", fontName="DJ-B", fontSize=7.5, leading=10,
                              textColor=TEAL, spaceAfter=10)
S["title"] = ParagraphStyle("title", fontName="DJ-B", fontSize=19, leading=25,
                            textColor=INK, spaceAfter=6)
S["subtitle"] = ParagraphStyle("subtitle", fontName="DJ-I", fontSize=9.5, leading=14,
                               textColor=MUTED, spaceAfter=4)
S["h1"] = ParagraphStyle("h1", fontName="DJ-B", fontSize=13, leading=17,
                         textColor=TEAL, spaceBefore=16, spaceAfter=7)
S["h2"] = ParagraphStyle("h2", fontName="DJ-B", fontSize=10.5, leading=14,
                         textColor=INK, spaceBefore=12, spaceAfter=5)
S["body"] = ParagraphStyle("body", fontName="DJ", fontSize=9.3, leading=14,
                           textColor=INK, alignment=TA_LEFT, spaceAfter=7)
S["bullet"] = ParagraphStyle("bullet", parent=S["body"], fontSize=8.6, leading=12.6,
                             leftIndent=12, bulletIndent=2, spaceAfter=6)
S["cell"] = ParagraphStyle("cell", fontName="DJ", fontSize=8.6, leading=12.6,
                           textColor=INK)
S["cellkey"] = ParagraphStyle("cellkey", parent=S["cell"], textColor=INK)
S["cellhead"] = ParagraphStyle("cellhead", fontName="DJ-B", fontSize=8.6, leading=12.6,
                               textColor=INK)
S["caption"] = ParagraphStyle("caption", fontName="DJ-I", fontSize=8, leading=11,
                              textColor=MUTED, spaceBefore=4, spaceAfter=10)
S["calltitle"] = ParagraphStyle("calltitle", fontName="DJ-B", fontSize=8.8, leading=12,
                                textColor=CALL_TX, spaceAfter=3)
S["calltext"] = ParagraphStyle("calltext", fontName="DJ", fontSize=8.4, leading=12.4,
                               textColor=CALL_TX)
S["footer"] = ParagraphStyle("footer", fontName="DJ", fontSize=7.6, leading=11,
                             textColor=MUTED)
S["boxhead"] = ParagraphStyle("boxhead", fontName="DJ-B", fontSize=8.8, leading=11.5,
                              alignment=1)
S["boxsub"] = ParagraphStyle("boxsub", fontName="DJ", fontSize=7.3, leading=9.5,
                             alignment=1, textColor=MUTED)


def h1(text):
    return Paragraph(text, S["h1"])


def h2(text):
    return Paragraph(text, S["h2"])


def para(text):
    return Paragraph(text, S["body"])


def bullets(items):
    return [Paragraph(t, S["bullet"], bulletText="•") for t in items]


class Rule(Flowable):
    """Dünne waagerechte Linie über die Satzbreite."""

    def __init__(self, width=WIDTH, color=RULE, thickness=0.6, space=6):
        Flowable.__init__(self)
        self.width, self.color, self.thickness, self.space = width, color, thickness, space
        self.height = space

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        self.canv.setStrokeColor(self.color)
        self.canv.setLineWidth(self.thickness)
        self.canv.line(0, self.space / 2, self.width, self.space / 2)


class Flow(Flowable):
    """Senkrechte Kette aus Kästen mit Pfeilen dazwischen."""

    BW, BH, GAP = 310, 26, 13

    def __init__(self, steps):
        Flowable.__init__(self)
        self.steps = steps
        self.width = WIDTH
        self.height = len(steps) * self.BH + (len(steps) - 1) * self.GAP

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        x = (WIDTH - self.BW) / 2
        y = self.height - self.BH
        for i, (head, sub, tone) in enumerate(self.steps):
            bg, bd, tx = BOX[tone]
            c.setFillColor(bg)
            c.setStrokeColor(bd)
            c.setLineWidth(0.7)
            c.roundRect(x, y, self.BW, self.BH, 3, stroke=1, fill=1)
            c.setFillColor(tx)
            c.setFont("DJ-B", 8.2)
            c.drawCentredString(WIDTH / 2, y + self.BH - 11, head)
            c.setFillColor(MUTED)
            c.setFont("DJ", 6.8)
            c.drawCentredString(WIDTH / 2, y + 6, sub)
            if i < len(self.steps) - 1:
                c.setStrokeColor(HexColor("#9AA3AE"))
                c.setLineWidth(0.7)
                top = y
                c.line(WIDTH / 2, top, WIDTH / 2, top - self.GAP + 4)
                c.line(WIDTH / 2 - 2.5, top - self.GAP + 7, WIDTH / 2, top - self.GAP + 4)
                c.line(WIDTH / 2 + 2.5, top - self.GAP + 7, WIDTH / 2, top - self.GAP + 4)
            y -= self.BH + self.GAP


class Decision(Flowable):
    """Verzweigung: eine Frage, zwei Ausgänge."""

    def __init__(self, question, left, right):
        Flowable.__init__(self)
        self.q, self.left, self.right = question, left, right
        self.width, self.height = WIDTH, 120

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        c = self.canv
        qw, qh = 230, 24
        qx = (WIDTH - qw) / 2
        qy = self.height - qh
        bg, bd, tx = BOX["grau"]
        c.setFillColor(bg); c.setStrokeColor(bd); c.setLineWidth(0.7)
        c.roundRect(qx, qy, qw, qh, 3, stroke=1, fill=1)
        c.setFillColor(INK); c.setFont("DJ-B", 8.2)
        c.drawCentredString(WIDTH / 2, qy + 8.5, self.q)

        bw, bh = 200, 34
        ly, lx, rx = 0, 10, WIDTH - bw - 10
        for (head, sub, tone), bx, label in ((self.left, lx, "nein"),
                                             (self.right, rx, "ja")):
            bg, bd, tx = BOX[tone]
            c.setFillColor(bg); c.setStrokeColor(bd); c.setLineWidth(0.7)
            c.roundRect(bx, ly, bw, bh, 3, stroke=1, fill=1)
            c.setFillColor(tx); c.setFont("DJ-B", 8.2)
            c.drawCentredString(bx + bw / 2, ly + bh - 13, head)
            c.setFillColor(MUTED); c.setFont("DJ", 6.8)
            c.drawCentredString(bx + bw / 2, ly + 8, sub)

            c.setStrokeColor(HexColor("#9AA3AE")); c.setLineWidth(0.7)
            c.line(WIDTH / 2, qy, WIDTH / 2, qy - 16)
            c.line(WIDTH / 2, qy - 16, bx + bw / 2, qy - 16)
            c.line(bx + bw / 2, qy - 16, bx + bw / 2, ly + bh)
            c.setFillColor(MUTED); c.setFont("DJ", 7)
            c.drawCentredString(bx + bw / 2, qy - 30, label)


def callout(title, text):
    inner = [Paragraph(title, S["calltitle"]), Paragraph(text, S["calltext"])]
    t = Table([[inner]], colWidths=[WIDTH])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CALL_BG),
        ("LINEBEFORE", (0, 0), (0, -1), 2.2, CALL_BD),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    return t


def deftable(rows, keyw=150):
    data = [[Paragraph(k, S["cellkey"]), Paragraph(v, S["cell"])] for k, v in rows]
    t = Table(data, colWidths=[keyw, WIDTH - keyw])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEABOVE", (0, 0), (-1, -1), 0.6, RULE),
        ("LINEBELOW", (0, -1), (-1, -1), 0.6, RULE),
        ("LEFTPADDING", (0, 0), (0, -1), 8),
        ("LEFTPADDING", (1, 0), (1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def comptable(heads, rows, keyw=150):
    cols = len(heads) + 1
    colw = [keyw] + [(WIDTH - keyw) / len(heads)] * len(heads)
    data = [[Paragraph("", S["cellhead"])] +
            [Paragraph(h, S["cellhead"]) for h in heads]]
    for row in rows:
        data.append([Paragraph(row[0], S["cellkey"])] +
                    [Paragraph(c, S["cell"]) for c in row[1:]])
    t = Table(data, colWidths=colw)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, HexColor("#9AA3AE")),
        ("LINEBELOW", (0, 1), (-1, -1), 0.6, RULE),
        ("LEFTPADDING", (0, 0), (0, -1), 8),
        ("LEFTPADDING", (1, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    return t
