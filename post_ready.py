#!/usr/bin/env python3
#
# PostReady v3.0 - System Preparation Tool
# Author: Julian Loontjens
# Copyright © 2026 Julian Loontjens. All rights reserved.
#

import curses
import npyscreen
import subprocess
import re
import os
import json
import logging
import shutil
import sys
import time
import ipaddress
from pathlib import Path

# --- CONFIGURATIE ---
LOG_FILE      = "/var/log/postready.log"
PRESET_DIR    = "/etc/postready/presets"
MOTD_REPO     = "https://github.com/JulienLoon/julianloontjens-motd.git"
MOTD_TARGET   = "/etc/essentials/julianloontjens-motd"
MOTD_INSTALL  = os.path.join(MOTD_TARGET, "install.sh")
MOTD_UNINSTALL= os.path.join(MOTD_TARGET, "uninstall.sh")

logging.basicConfig(
    filename=LOG_FILE, level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

LOGO = [
    r" ____           _   ____                _       ",
    r"|  _ \ ___  ___| |_|  _ \ ___  __ _  __| |_   _ ",
    r"| |_) / _ \/ __| __| |_) / _ \/ _` |/ _` | | | |",
    r"|  __/ (_) \__ \ |_|  _ <  __/ (_| | (_| | |_| |",
    r"|_|   \___/|___/\__|_| \_\___|\__,_|\__,_|\__, |",
    r"                                          |___/ ",
]

PAGE_NAMES = ["Cleanup", "Network", "Security", "Settings", "Advanced"]

# Row where page content starts (after title/logo/subtitle/sep/nav/sep)
CS = 11


# ============================================================
# LOG VIEWER
# ============================================================

class LogViewerForm(npyscreen.FormBaseNew):
    def create(self):
        self.add(npyscreen.FixedText,
                 value="PostReady v3.0 — Log Viewer   Q / ESC = back",
                 rely=0, relx=2, color="WARNING")
        self.add(npyscreen.FixedText, value="─" * 60, rely=1, relx=0, color="LABEL")
        self.log_box = self.add(
            npyscreen.MultiLineEdit,
            value=self._read_log(),
            relx=2, rely=2, max_height=-2, editable=False,
        )
        self.add_handlers({"q": self._back, "Q": self._back, "^[": self._back})

    def _read_log(self):
        try:
            lines = Path(LOG_FILE).read_text().splitlines()
            return "\n".join(lines[-300:]) if lines else "(empty)"
        except Exception as e:
            return f"Cannot read log: {e}"

    def _back(self, _=None):
        self.parentApp.switchForm("MAIN")


# ============================================================
# NAV BUTTON — left/right switches pages, down jumps to content
# ============================================================

class NavButton(npyscreen.ButtonPress):
    nav_index      = 0
    how_exited     = False   # always-present default so form never hits AttributeError
    _go_to_content = False   # flagged True only on real DOWN press

    def h_exit_left(self, _input):
        if self.nav_index > 0:
            self.parent._switch(self.nav_index - 1)
        self.h_exit_up(_input)                           # move to previous nav button

    def h_exit_right(self, _input):
        if self.nav_index < len(PAGE_NAMES) - 1:
            self.parent._switch(self.nav_index + 1)
        npyscreen.ButtonPress.h_exit_down(self, _input)  # move to next nav button

    def h_exit_down(self, _input):
        self._go_to_content = True                       # form intercepts this in handle_exiting_widgets
        npyscreen.ButtonPress.h_exit_down(self, _input)


# ============================================================
# MAIN FORM — single form, page switching
# ============================================================

class PostReadyForm(npyscreen.FormBaseNew):

    def __init__(self, *args, **kwargs):
        try:
            lines = max(35, curses.LINES) if curses.LINES else 35
            cols  = max(80, curses.COLS)  if curses.COLS  else 80
        except Exception:
            lines, cols = 35, 80
        kwargs.setdefault('lines',   lines)
        kwargs.setdefault('columns', cols)
        super().__init__(*args, **kwargs)

    def draw_form(self):
        try:
            cols = self.columns
        except Exception:
            try:   cols = curses.COLS or 80
            except Exception: cols = 80
        try:
            rows = self.lines
        except Exception:
            rows = 35

        H  = "─";  V  = "│"
        TL = "┌";  TR = "┐"
        BL = "└";  BR = "┘"
        LT = "├";  RT = "┤"

        # Row 0: top border with centred title
        title  = " PostReady v3.0 "
        inner  = max(0, cols - 2)
        side   = max(0, (inner - len(title)) // 2)
        fill_r = max(0, inner - side - len(title))
        top    = TL + H * side + title + H * fill_r + TR
        try: self.curses_pad.addstr(0, 0, top[:cols])
        except Exception: pass

        # Left / right borders
        for r in range(1, rows - 1):
            try: self.curses_pad.addstr(r, 0, V)
            except Exception: pass
            try: self.curses_pad.addstr(r, cols - 1, V)
            except Exception: pass

        # Bottom border with copyright
        copy_label = "  © 2026 Julian Loontjens  "
        copy_side  = max(0, (inner - len(copy_label)) // 2)
        copy_fill  = max(0, inner - copy_side - len(copy_label))
        bottom     = BL + H * copy_side + copy_label + H * copy_fill + BR
        try: self.curses_pad.addstr(rows - 1, 0, bottom[:cols])
        except Exception: pass

        # Rows 1-6: ASCII logo
        logo_w = max(len(l) for l in LOGO)
        logo_x = max(0, (cols - logo_w) // 2)
        for i, line in enumerate(LOGO):
            try: self.curses_pad.addstr(1 + i, logo_x, line)
            except Exception: pass

        # Row 7: subtitle
        subtitle = "Linux System Preparation Tool"
        sub_x = max(0, (cols - len(subtitle)) // 2)
        try: self.curses_pad.addstr(7, sub_x, subtitle)
        except Exception: pass

        # Row 8: ├──── Navigation ────┤
        nav_label = "  Navigation  "
        nav_side  = max(0, (inner - len(nav_label)) // 2)
        nav_fill  = max(0, inner - nav_side - len(nav_label))
        nav_sep   = LT + H * nav_side + nav_label + H * nav_fill + RT
        try: self.curses_pad.addstr(8, 0, nav_sep[:cols])
        except Exception: pass

        # Row 10: active page name (drawn by _draw_section_sep, placeholder here)
        try: self.curses_pad.addstr(10, 0, (LT + H * inner + RT)[:cols])
        except Exception: pass

        # Actions separator (dynamic row)
        r_act = getattr(self, '_row_actions_sep', 28)
        act_label = "  Actions  "
        act_side  = max(0, (inner - len(act_label)) // 2)
        act_fill  = max(0, inner - act_side - len(act_label))
        act_sep   = LT + H * act_side + act_label + H * act_fill + RT
        try: self.curses_pad.addstr(r_act, 0, act_sep[:cols])
        except Exception: pass

        # Status text (dynamic row)
        r_sts = getattr(self, '_row_status', 29)
        status = getattr(self, '_status_msg', '◆  Ready for next command.')
        try: self.curses_pad.addstr(r_sts, 3, status[:cols - 4])
        except Exception: pass

        # Output separator (dynamic row)
        r_out = getattr(self, '_row_output_sep', 31)
        out_label = "  Output  "
        out_side  = max(0, (inner - len(out_label)) // 2)
        out_fill  = max(0, inner - out_side - len(out_label))
        out_sep   = LT + H * out_side + out_label + H * out_fill + RT
        try: self.curses_pad.addstr(r_out, 0, out_sep[:cols])
        except Exception: pass

    def handle_exiting_widgets(self, condition):
        w = self._widgets__[self.editw]

        # DOWN from NavButton → jump to first visible content widget of current page
        if isinstance(w, NavButton) and w._go_to_content:
            w._go_to_content = False
            for i in range(len(PAGE_NAMES), len(self._widgets__)):
                c = self._widgets__[i]
                if c.editable and not c.hidden:
                    self.editw = i
                    return

        super().handle_exiting_widgets(condition)

        # UP from content → super may have landed on the wrong NavButton (e.g. Advanced).
        # Redirect to the nav button that matches the current page.
        if isinstance(self._widgets__[self.editw], NavButton):
            self.editw = self._current_page

    def display(self, *args, **kwargs):
        self.show_aty = 0  # always pin to top; layout fits the terminal
        super().display(*args, **kwargs)

    def _calc_layout(self):
        """Calculate row positions dynamically based on terminal height."""
        try:
            avail = curses.LINES
            if not avail or avail < 20:
                avail = 35
        except Exception:
            avail = 35
        # Fixed overhead: 11 header + 3 actions + 1 output sep + 1 bottom = 16
        remaining    = max(4, avail - 16)
        content_rows = min(17, max(2, remaining - 2))
        output_rows  = max(2, remaining - content_rows)
        self._row_actions_sep  = CS + content_rows
        self._row_status       = self._row_actions_sep + 1
        self._row_buttons      = self._row_status + 1
        self._row_output_sep   = self._row_buttons + 1
        self._row_output_start = self._row_output_sep + 1
        self._row_bottom       = avail - 1
        self._output_max_lines = output_rows

    def create(self):
        self._calc_layout()
        self._page_widgets = [[], [], [], [], []]
        self._current_page = 0

        self._draw_header()
        self._draw_nav()
        self._create_cleanup()
        self._create_network()
        self._create_security()
        self._create_settings()
        self._create_advanced()

        self._output_lines = []
        self._status_msg = "^T:tab   ^A:apply   ^L:log   ^Q:quit"
        self.add(npyscreen.ButtonPress, name="[ APPLY ]",
                 rely=self._row_buttons, relx=4,  when_pressed_function=self._do_apply)
        self.add(npyscreen.ButtonPress, name="[ LOG ]",
                 rely=self._row_buttons, relx=22, when_pressed_function=self._view_log)
        self.add(npyscreen.ButtonPress, name="[ QUIT ]",
                 rely=self._row_buttons, relx=38, when_pressed_function=self._quit)

        # Ctrl+T=20  Ctrl+A=1  Ctrl+L=12  Ctrl+Q=17
        self.add_handlers({
            20: lambda _: self._next_tab(),   # ^T
             1: lambda _: self._do_apply(),   # ^A
            12: lambda _: self._view_log(),   # ^L
            17: lambda _: self._quit(),       # ^Q
        })

        self._switch(0)

    def _next_tab(self):
        nxt = (self._current_page + 1) % len(PAGE_NAMES)
        self._switch(nxt)
        self.editw = nxt  # focus the nav button for the new page

    # ---- header ----

    def _draw_header(self):
        pass  # drawn via draw_form()

    def _draw_nav(self):
        self._nav_buttons = []
        x = 2
        for i, name in enumerate(PAGE_NAMES):
            lbl = f"[ {name} ]"
            btn = self.add(NavButton, name=lbl,
                           rely=9, relx=x,
                           when_pressed_function=lambda p=i: self._switch(p))
            btn.nav_index = i
            self._nav_buttons.append(btn)
            x += len(lbl) + 2

    # ---- page registration helper ----

    def _pw(self, page, widget):
        self._page_widgets[page].append(widget)
        return widget

    # ---- page 0: Cleanup ----

    def _create_cleanup(self):
        p = 0
        self._pw(p, self.add(npyscreen.FixedText, value="[ FEATURES ]",
                              rely=CS, relx=2, color="LABEL"))
        self.chk_motd = self._pw(p, self.add(
            npyscreen.Checkbox, name="Install/Update Custom MOTD",
            value=True, rely=CS+1, relx=4))
        self.chk_motd_uninstall = self._pw(p, self.add(
            npyscreen.Checkbox, name="Uninstall Custom MOTD",
            value=False, rely=CS+2, relx=4))

        self._pw(p, self.add(npyscreen.FixedText, value="[ CLEANUP / SYSPREP ]",
                              rely=CS+4, relx=2, color="LABEL"))
        self.chk_history   = self._pw(p, self.add(npyscreen.Checkbox, name="Clear Bash History",             value=True,  rely=CS+5,  relx=4))
        self.chk_logs      = self._pw(p, self.add(npyscreen.Checkbox, name="Truncate /var/log/*",             value=True,  rely=CS+6,  relx=4))
        self.chk_apt       = self._pw(p, self.add(npyscreen.Checkbox, name="APT Clean & Autoremove",          value=True,  rely=CS+7,  relx=4))
        self.chk_update    = self._pw(p, self.add(npyscreen.Checkbox, name="APT Update & Upgrade",            value=False, rely=CS+8,  relx=4))
        self.chk_snap      = self._pw(p, self.add(npyscreen.Checkbox, name="Snap / Flatpak Cleanup",          value=False, rely=CS+9,  relx=4))
        self.chk_crontab   = self._pw(p, self.add(npyscreen.Checkbox, name="Clear All Crontabs",              value=False, rely=CS+10, relx=4))
        self.chk_docker    = self._pw(p, self.add(npyscreen.Checkbox, name="Docker System Prune",             value=False, rely=CS+11, relx=4))
        self.chk_ssh_regen = self._pw(p, self.add(npyscreen.Checkbox, name="Regen SSH Host Keys",             value=False, rely=CS+12, relx=4))
        self.chk_machineid = self._pw(p, self.add(npyscreen.Checkbox, name="Reset Machine-ID",                value=False, rely=CS+13, relx=4))
        self.chk_cloudinit = self._pw(p, self.add(npyscreen.Checkbox, name="Clean Cloud-init (VM Template)",  value=False, rely=CS+14, relx=4))
        self.chk_shutdown  = self._pw(p, self.add(npyscreen.Checkbox, name="Shutdown when complete",          value=False, rely=CS+15, relx=4))
        self.chk_reboot    = self._pw(p, self.add(npyscreen.Checkbox, name="Reboot when complete",            value=False, rely=CS+16, relx=4))

        self.chk_shutdown.when_value_edited = lambda: (
            setattr(self.chk_reboot, 'value', False), self.display()
        ) if self.chk_shutdown.value else None
        self.chk_reboot.when_value_edited = lambda: (
            setattr(self.chk_shutdown, 'value', False), self.display()
        ) if self.chk_reboot.value else None

    # ---- page 1: Network ----

    def _create_network(self):
        p = 1
        self._pw(p, self.add(npyscreen.FixedText, value="[ NETWORK ]",
                              rely=CS, relx=2, color="LABEL"))
        ifaces = self._detect_ifaces()
        self.field_iface = self._pw(p, self.add(
            npyscreen.TitleText, name="Interface:",
            rely=CS+1, relx=4, begin_entry_at=14,
            value=ifaces[0] if ifaces else "eth0"))
        self.chk_dhcp = self._pw(p, self.add(
            npyscreen.Checkbox, name="Enable DHCP",
            value=True, rely=CS+2, relx=4))
        self.chk_dhcp.when_value_edited = self._toggle_dhcp
        self.chk_ipv6_off = self._pw(p, self.add(
            npyscreen.Checkbox, name="Disable IPv6",
            value=False, rely=CS+3, relx=4))
        self.chk_dns_override = self._pw(p, self.add(
            npyscreen.Checkbox, name="Override DNS (in DHCP mode)",
            value=False, rely=CS+4, relx=4))
        self.chk_dns_override.when_value_edited = self._toggle_dns
        self.field_ip  = self._pw(p, self.add(
            npyscreen.TitleText, name="IP/CIDR:",
            rely=CS+5, relx=4, begin_entry_at=12))
        self.field_gw  = self._pw(p, self.add(
            npyscreen.TitleText, name="Gateway:",
            rely=CS+6, relx=4, begin_entry_at=12))
        self.field_dns = self._pw(p, self.add(
            npyscreen.TitleText, name="DNS:",
            rely=CS+7, relx=4, begin_entry_at=12))

    def _detect_ifaces(self):
        try:
            out = subprocess.check_output(
                "ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'",
                shell=True, stderr=subprocess.DEVNULL).decode().strip().split('\n')
            return [i.strip() for i in out if i.strip()] or ["eth0"]
        except Exception:
            return ["eth0"]

    def _selected_iface(self):
        return (self.field_iface.value or "").strip() or "eth0"

    def _toggle_dhcp(self):
        static = not self.chk_dhcp.value
        for w in [self.field_ip, self.field_gw]:
            w.hidden = not static
            w.editable = static
        self.chk_dns_override.hidden = static
        self._toggle_dns()

    def _toggle_dns(self):
        show = (not self.chk_dhcp.value) or self.chk_dns_override.value
        self.field_dns.hidden   = not show
        self.field_dns.editable = show
        self.display()

    # ---- page 2: Security ----

    def _create_security(self):
        p = 2
        self._pw(p, self.add(npyscreen.FixedText, value="[ SECURITY ]",
                              rely=CS, relx=2, color="LABEL"))
        self.chk_ssh_harden = self._pw(p, self.add(
            npyscreen.Checkbox, name="SSH Hardening",
            value=False, rely=CS+1, relx=4))
        self.chk_ssh_harden.when_value_edited = self._toggle_ssh
        self.field_ssh_port = self._pw(p, self.add(
            npyscreen.TitleText, name="SSH Port:", value="22",
            rely=CS+2, relx=6, begin_entry_at=14))
        self.chk_ssh_no_pass = self._pw(p, self.add(
            npyscreen.Checkbox, name="Disable Password Auth",
            value=True, rely=CS+3, relx=6))
        self.chk_ssh_no_root = self._pw(p, self.add(
            npyscreen.Checkbox, name="Disable Root Login",
            value=True, rely=CS+4, relx=6))
        self.chk_ufw = self._pw(p, self.add(
            npyscreen.Checkbox, name="Configure UFW Firewall",
            value=False, rely=CS+6, relx=4))
        self.chk_ufw.when_value_edited = self._toggle_ufw
        self.field_ufw_ports = self._pw(p, self.add(
            npyscreen.TitleText, name="Allow Ports:", value="22,80,443",
            rely=CS+7, relx=6, begin_entry_at=14))
        self.chk_fail2ban = self._pw(p, self.add(
            npyscreen.Checkbox, name="Install & Enable Fail2ban",
            value=False, rely=CS+9, relx=4))
        self.chk_unattended = self._pw(p, self.add(
            npyscreen.Checkbox, name="Enable Unattended Upgrades",
            value=False, rely=CS+10, relx=4))

    def _toggle_ssh(self):
        show = self.chk_ssh_harden.value
        for w in [self.field_ssh_port, self.chk_ssh_no_pass, self.chk_ssh_no_root]:
            w.hidden   = not show
            w.editable = show
        self.display()

    def _toggle_ufw(self):
        self.field_ufw_ports.hidden   = not self.chk_ufw.value
        self.field_ufw_ports.editable = self.chk_ufw.value
        self.display()

    # ---- page 3: Settings ----

    def _create_settings(self):
        p = 3
        self._pw(p, self.add(npyscreen.FixedText, value="[ SETTINGS ]",
                              rely=CS, relx=2, color="LABEL"))
        self.field_hostname   = self._pw(p, self.add(
            npyscreen.TitleText,     name="Hostname:",    rely=CS+1, relx=4, begin_entry_at=16))
        self.field_user       = self._pw(p, self.add(
            npyscreen.TitleText,     name="New User:",    rely=CS+2, relx=4, begin_entry_at=16))
        self.field_password   = self._pw(p, self.add(
            npyscreen.TitlePassword, name="Password:",    rely=CS+3, relx=4, begin_entry_at=16))
        self.field_ssh_pubkey = self._pw(p, self.add(
            npyscreen.TitleText,     name="SSH Pub Key:", rely=CS+4, relx=4, begin_entry_at=16))
        self.field_timezone   = self._pw(p, self.add(
            npyscreen.TitleText,     name="Timezone:",    rely=CS+5, relx=4, begin_entry_at=16,
            value="Europe/Amsterdam"))
        self.field_locale     = self._pw(p, self.add(
            npyscreen.TitleText,     name="Locale:",      rely=CS+6, relx=4, begin_entry_at=16,
            value="en_US.UTF-8"))
        self.field_ntp        = self._pw(p, self.add(
            npyscreen.TitleText,     name="NTP Server:",  rely=CS+7, relx=4, begin_entry_at=16))
        self.field_swap       = self._pw(p, self.add(
            npyscreen.TitleText,     name="Swap (MB):",   rely=CS+8, relx=4, begin_entry_at=16,
            value="0"))

    # ---- page 4: Advanced ----

    def _create_advanced(self):
        p = 4
        self._pw(p, self.add(npyscreen.FixedText, value="[ ADVANCED ]",
                              rely=CS, relx=2, color="LABEL"))
        self.field_custom_script = self._pw(p, self.add(
            npyscreen.TitleText, name="Custom Script:",
            rely=CS+1, relx=4, begin_entry_at=16))
        self.chk_dryrun = self._pw(p, self.add(
            npyscreen.Checkbox, name="Dry-run (preview only, no changes)",
            value=False, rely=CS+2, relx=4))
        self._pw(p, self.add(npyscreen.FixedText, value="[ PRESETS ]",
                              rely=CS+4, relx=2, color="LABEL"))
        self._pw(p, self.add(npyscreen.ButtonPress, name="[ SAVE PRESET ]",
                              rely=CS+5, relx=4,
                              when_pressed_function=self._save_preset))
        self._pw(p, self.add(npyscreen.ButtonPress, name="[ LOAD PRESET ]",
                              rely=CS+5, relx=22,
                              when_pressed_function=self._load_preset))

    # ---- page switching ----

    def _draw_section_sep(self, page):
        try:
            cols = self.columns
        except Exception:
            cols = 80
        H = "─"; LT = "├"; RT = "┤"
        inner = max(0, cols - 2)
        label = f"  {PAGE_NAMES[page]}  "
        side  = max(0, (inner - len(label)) // 2)
        fill  = max(0, inner - side - len(label))
        sep   = LT + H * side + label + H * fill + RT
        try: self.curses_pad.addstr(10, 0, sep[:cols])
        except Exception: pass

    def _switch(self, page):
        for p_idx, widgets in enumerate(self._page_widgets):
            visible = (p_idx == page)
            for w in widgets:
                w.hidden = not visible
                if not isinstance(w, npyscreen.FixedText):
                    w.editable = visible
        self._current_page = page
        # Mark active tab with ▸, inactive tabs with plain brackets
        for i, btn in enumerate(getattr(self, '_nav_buttons', [])):
            name = PAGE_NAMES[i]
            btn.name = f"[▸{name} ]" if i == page else f"[ {name} ]"
        self._draw_section_sep(page)
        if page == 1:
            self._toggle_dhcp()
        elif page == 2:
            self._toggle_ssh()
            self._toggle_ufw()
        self.show_aty = 0
        self.display()

    # ---- shared helpers ----

    def set_status(self, text):
        self._status_msg = text
        try:
            cols = self.columns
        except Exception:
            cols = 80
        r = getattr(self, '_row_status', 29)
        try:
            blank = " " * max(0, cols - 4)
            self.curses_pad.addstr(r, 3, blank)
            self.curses_pad.addstr(r, 3, text[:cols - 4])
            self.curses_pad.refresh(0, 0, 0, 0, curses.LINES - 1, curses.COLS - 1)
        except Exception:
            pass

    def _clear_output(self):
        self._output_lines = []
        self._redraw_output_area()

    def _restore_output(self):
        pass  # output area is always visible; no widget swapping needed

    def _redraw_output_area(self):
        try:
            cols = self.columns
        except Exception:
            cols = 80
        row_start = getattr(self, '_row_output_start', 32)
        max_lines = getattr(self, '_output_max_lines', 3)
        blank = " " * max(0, cols - 4)
        for i in range(max_lines):
            try:
                self.curses_pad.addstr(row_start + i, 2, blank)
            except Exception:
                pass
        visible = self._output_lines[-max_lines:]
        for i, text in enumerate(visible):
            try:
                self.curses_pad.addstr(row_start + i, 2, text[:cols - 4])
            except Exception:
                pass
        try:
            self.curses_pad.refresh(0, 0, 0, 0, curses.LINES - 1, curses.COLS - 1)
        except Exception:
            pass

    def _append_output(self, line):
        try:
            self._output_lines.append(str(line))
            self._redraw_output_area()
        except Exception:
            pass

    def _view_log(self):
        self.parentApp.switchForm("LOG")

    def _quit(self):
        if npyscreen.notify_yes_no("Are you sure you want to quit?",
                                   title="Confirm", editw=1):
            logging.info("User exited.")
            self.parentApp.switchForm(None)

    def run_cmd(self, cmd, shell=True):
        if getattr(self.parentApp, "_dryrun", False):
            logging.info(f"[DRY-RUN] {cmd}")
            self._append_output(f"[DRY-RUN] {cmd[:80]}")
            return True
        logging.info(f"CMD_EXEC: {cmd}")
        short = cmd[:80] + ("…" if len(cmd) > 80 else "")
        self._append_output(f"$ {short}")
        try:
            # stdbuf forces line-buffered stdout/stderr so we get real-time output
            if shell and shutil.which("stdbuf"):
                actual_cmd = ["stdbuf", "-oL", "-eL", "sh", "-c", cmd]
                use_shell = False
            else:
                actual_cmd = cmd
                use_shell = shell
            proc = subprocess.Popen(
                actual_cmd, shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for raw in iter(proc.stdout.readline, ""):
                line = raw.rstrip()
                if line:
                    logging.info(f"  {line}")
                    self._append_output(line)
            proc.stdout.close()
            rc = proc.wait()
            if rc != 0:
                logging.error(f"CMD_FAIL: {cmd} | RC={rc}")
                self._append_output(f"[rc={rc}]")
                return False
            return True
        except Exception as e:
            logging.error(f"CMD_ERROR: {cmd} | {e}")
            self._append_output(f"[ERROR] {e}")
            return False

    def wait_for_network(self, timeout=20):
        for _ in range(timeout):
            if subprocess.run("getent hosts github.com", shell=True,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                return True
            time.sleep(1)
        return False

    def _valid_ip(self, s):
        try:
            parts = s.split('/')
            ipaddress.ip_address(parts[0])
            if len(parts) == 2 and not (0 <= int(parts[1]) <= 32):
                return False
            return True
        except ValueError:
            return False

    # ============================================================
    # APPLY
    # ============================================================

    def _do_apply(self):
        self.parentApp._dryrun = self.chk_dryrun.value

        if self.chk_motd.value and self.chk_motd_uninstall.value:
            npyscreen.notify_confirm("Cannot install and uninstall MOTD at the same time.", title="Error")
            return
        if not self.chk_dhcp.value:
            if not all([self.field_ip.value, self.field_gw.value, self.field_dns.value]):
                npyscreen.notify_confirm("Static IP requires: IP, Gateway and DNS.", title="Error")
                self._switch(1); return
            if not self._valid_ip((self.field_ip.value or "").strip()):
                npyscreen.notify_confirm("Invalid IP format.", title="Error")
                self._switch(1); return
        if self.chk_ssh_harden.value:
            try:
                port = int((self.field_ssh_port.value or "").strip())
                if not (1 <= port <= 65535): raise ValueError
            except ValueError:
                npyscreen.notify_confirm("Invalid SSH port.", title="Error")
                self._switch(2); return

        if self.chk_history.value:
            if not npyscreen.notify_yes_no(
                "WARNING: clearing history will close all bash sessions!\n"
                "SSH connection will be dropped. Script keeps running.\nContinue?",
                title="Warning", editw=1): return

        dry = " [DRY-RUN]" if self.parentApp._dryrun else ""
        if not npyscreen.notify_yes_no(f"Apply changes?{dry}",
                                       title="Confirm", editw=1):
            return

        self._clear_output()
        logging.info(f"--- START (dryrun={self.parentApp._dryrun}) ---")
        steps = [
            ("Cleanup…",  self.exec_cleanup),
            ("Network…",  self.exec_network),
            ("Security…", self.exec_security),
            ("System…",   self.exec_system),
        ]
        for i, (lbl, fn) in enumerate(steps, 1):
            self.set_status(f"▶  Step {i}/{len(steps)}: {lbl}")
            fn()

        if self.chk_motd.value or self.chk_motd_uninstall.value:
            self.set_status("▶  MOTD…")
            if self.wait_for_network():
                if self.chk_motd_uninstall.value: self.exec_motd_uninstall()
                elif self.chk_motd.value:         self.exec_motd()
            else:
                npyscreen.notify_confirm("Network unreachable. MOTD skipped.", title="Warning")

        script = (self.field_custom_script.value or "").strip()
        if script:
            self.set_status("▶  Custom script…")
            self.exec_custom_script(script)

        self.set_status("^T:tab   ^A:apply   ^L:log   ^Q:quit")
        self._restore_output()
        logging.info("--- COMPLETED ---")

        # Flush buffered keypresses so a leftover Enter from "Apply changes?"
        # doesn't auto-dismiss the next popup
        try: curses.flushinp()
        except Exception: pass

        if self.chk_shutdown.value:
            npyscreen.notify_confirm("Done. System will shut down.", title="Success")
            self.run_cmd("shutdown -h now")
        elif self.chk_reboot.value:
            npyscreen.notify_confirm("Done. System will reboot.", title="Success")
            self.run_cmd("shutdown -r now")
        else:
            if npyscreen.notify_yes_no("Configuration applied. Quit PostReady?", title="Done", editw=1):
                self.parentApp.switchForm(None)
            return

        self.parentApp.switchForm(None)

    # ============================================================
    # EXEC — cleanup
    # ============================================================

    def exec_cleanup(self):
        if self.chk_logs.value:
            for lf in Path("/var/log").rglob("*.log"):
                try: lf.write_text("")
                except Exception: pass
            self.run_cmd("find /var/log -type f \\( -name '*.log.*' -o -name '*.[0-9]' -o -name '*.gz' \\) -delete")
            if Path("/var/log/journal").exists():
                self.run_cmd("journalctl --vacuum-time=1s")
            self.run_cmd("rm -rf /tmp/* /var/tmp/* 2>/dev/null || true")

        if self.chk_apt.value:
            self.run_cmd("apt-get clean")
            self.run_cmd("apt-get autoremove -y --purge")
            self.run_cmd("rm -rf /var/lib/apt/lists/*")
            self.run_cmd("apt-get update")

        if self.chk_update.value:
            self.run_cmd("apt-get update")
            self.run_cmd("DEBIAN_FRONTEND=noninteractive apt-get upgrade -y "
                         "-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'")
            self.run_cmd("DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y "
                         "-o Dpkg::Options::='--force-confdef' -o Dpkg::Options::='--force-confold'")

        if self.chk_snap.value:
            if shutil.which("snap"):
                try:
                    pkgs = subprocess.check_output(
                        "snap list --all | awk 'NR>1 {print $1}' | sort -u",
                        shell=True, text=True, stderr=subprocess.DEVNULL).strip().split('\n')
                    for pkg in pkgs:
                        if pkg.strip():
                            self.run_cmd(f"snap remove --purge {pkg.strip()} 2>/dev/null || true")
                except Exception: pass
            if shutil.which("flatpak"):
                self.run_cmd("flatpak uninstall --all --noninteractive 2>/dev/null || true")

        if self.chk_crontab.value:
            self.run_cmd("crontab -r 2>/dev/null || true")
            self.run_cmd('for u in $(cut -f1 -d: /etc/passwd); do crontab -r -u "$u" 2>/dev/null; done || true')
            for d in ["/etc/cron.d","/etc/cron.daily","/etc/cron.hourly","/etc/cron.monthly","/etc/cron.weekly"]:
                self.run_cmd(f"find {d} -maxdepth 1 -type f -not -name '.*' -delete 2>/dev/null || true")

        if self.chk_docker.value and shutil.which("docker"):
            self.run_cmd("docker system prune -af --volumes 2>/dev/null || true")

        if self.chk_ssh_regen.value:
            self.run_cmd("rm -f /etc/ssh/ssh_host_*")
            for kt in ["rsa", "ecdsa", "ed25519"]:
                self.run_cmd(f"ssh-keygen -t {kt} -f /etc/ssh/ssh_host_{kt}_key -N '' -q")
            self.run_cmd("systemctl restart sshd || systemctl restart ssh")

        if self.chk_machineid.value:
            self.run_cmd("truncate -s 0 /etc/machine-id")
            dbus = "/var/lib/dbus/machine-id"
            if not os.path.islink(dbus) and os.path.exists(dbus):
                try: os.remove(dbus)
                except OSError: pass
            self.run_cmd("ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true")

        if self.chk_cloudinit.value:
            if shutil.which("cloud-init"):
                self.run_cmd("cloud-init clean --logs --seed")
            for path in ["/var/lib/cloud/",
                         "/etc/cloud/cloud.cfg.d/99-installer.cfg",
                         "/etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg",
                         "/var/log/cloud-init.log", "/var/log/cloud-init-output.log"]:
                if os.path.exists(path):
                    try: shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
                    except Exception: pass

        if self.chk_history.value:
            self.run_cmd("find /root /home -name '.bash_history' -type f -exec truncate -s 0 {} \\; 2>/dev/null || true")
            self.run_cmd("sleep 1 && pkill -9 bash 2>/dev/null || true")

    # ============================================================
    # EXEC — network
    # ============================================================

    def exec_network(self):
        iface   = self._selected_iface()
        netplan = "/etc/netplan/99-postready.yaml"

        if self.chk_dhcp.value:
            content = (
                f"network:\n  version: 2\n  ethernets:\n"
                f"    {iface}:\n      dhcp4: true\n"
            )
        else:
            ip  = (self.field_ip.value or "").strip()
            ip  = ip if "/" in ip else f"{ip}/24"
            gw  = (self.field_gw.value or "").strip()
            dns = (self.field_dns.value or "").strip()
            content = (
                f"network:\n  version: 2\n  ethernets:\n    {iface}:\n"
                f"      dhcp4: false\n      addresses: [{ip}]\n"
                f"      routes:\n        - to: default\n          via: {gw}\n"
                f"      nameservers:\n        addresses: [{dns}]\n"
            )
        try:
            bk = Path("/etc/netplan/backup"); bk.mkdir(exist_ok=True)
            for f in Path("/etc/netplan").glob("*.yaml"):
                if f.name != "99-postready.yaml":
                    shutil.move(str(f), str(bk / f.name))
            Path(netplan).write_text(content)
            os.chmod(netplan, 0o600)
            self.run_cmd("netplan apply")
        except Exception as e:
            logging.error(f"Netplan error: {e}")

        if self.chk_dhcp.value and self.chk_dns_override.value and (self.field_dns.value or "").strip():
            try:
                Path("/etc/systemd/resolved.conf").write_text(
                    f"[Resolve]\nDNS={(self.field_dns.value or '').strip()}\n")
                self.run_cmd("systemctl restart systemd-resolved")
            except Exception as e:
                logging.error(f"DNS override: {e}")

        if self.chk_ipv6_off.value:
            try:
                Path("/etc/sysctl.d/99-disable-ipv6.conf").write_text(
                    "net.ipv6.conf.all.disable_ipv6 = 1\n"
                    "net.ipv6.conf.default.disable_ipv6 = 1\n"
                    "net.ipv6.conf.lo.disable_ipv6 = 1\n")
                self.run_cmd("sysctl -p /etc/sysctl.d/99-disable-ipv6.conf")
            except Exception as e:
                logging.error(f"IPv6 disable: {e}")

    # ============================================================
    # EXEC — security
    # ============================================================

    def exec_security(self):
        if self.chk_ssh_harden.value:
            try:
                cfg = Path("/etc/ssh/sshd_config").read_text()
                port = (self.field_ssh_port.value or "").strip()
                cfg = re.sub(r'^#?Port\s+\d+', f'Port {port}', cfg, flags=re.MULTILINE)
                if not re.search(r'^Port\s+', cfg, re.MULTILINE):
                    cfg += f'\nPort {port}\n'
                if self.chk_ssh_no_pass.value:
                    cfg = re.sub(r'^#?PasswordAuthentication\s+\w+',
                                 'PasswordAuthentication no', cfg, flags=re.MULTILINE)
                    if not re.search(r'^PasswordAuthentication\s+', cfg, re.MULTILINE):
                        cfg += '\nPasswordAuthentication no\n'
                if self.chk_ssh_no_root.value:
                    cfg = re.sub(r'^#?PermitRootLogin\s+\w+',
                                 'PermitRootLogin no', cfg, flags=re.MULTILINE)
                    if not re.search(r'^PermitRootLogin\s+', cfg, re.MULTILINE):
                        cfg += '\nPermitRootLogin no\n'
                Path("/etc/ssh/sshd_config").write_text(cfg)
                self.run_cmd("systemctl restart sshd || systemctl restart ssh")
            except Exception as e:
                logging.error(f"SSH harden: {e}")

        if self.chk_ufw.value:
            self.run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y ufw 2>/dev/null || true")
            self.run_cmd("ufw --force reset")
            self.run_cmd("ufw default deny incoming")
            self.run_cmd("ufw default allow outgoing")
            for port in (self.field_ufw_ports.value or "").strip().split(','):
                if port.strip(): self.run_cmd(f"ufw allow {port.strip()}")
            self.run_cmd("ufw --force enable")

        if self.chk_fail2ban.value:
            self.run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban")
            self.run_cmd("systemctl enable --now fail2ban")

        if self.chk_unattended.value:
            self.run_cmd("DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades")
            self.run_cmd("DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -plow unattended-upgrades")

    # ============================================================
    # EXEC — system
    # ============================================================

    def exec_system(self):
        if (self.field_hostname.value or "").strip():
            h = (self.field_hostname.value or "").strip()
            self.run_cmd(f"hostnamectl set-hostname {h}")
            self.run_cmd(f"sed -i 's/127.0.1.1.*/127.0.1.1\\t{h}/' /etc/hosts")

        if (self.field_timezone.value or "").strip():
            self.run_cmd(f"timedatectl set-timezone {(self.field_timezone.value or '').strip()}")

        if (self.field_locale.value or "").strip():
            lc = (self.field_locale.value or "").strip()
            self.run_cmd(f"locale-gen {lc}")
            self.run_cmd(f"update-locale LANG={lc}")

        if (self.field_ntp.value or "").strip():
            try:
                Path("/etc/systemd/timesyncd.conf").write_text(
                    f"[Time]\nNTP={(self.field_ntp.value or '').strip()}\n")
                self.run_cmd("systemctl restart systemd-timesyncd")
            except Exception as e:
                logging.error(f"NTP: {e}")

        try:
            swap_mb = int((self.field_swap.value or "").strip())
            if swap_mb > 0: self._exec_swap(swap_mb)
        except (ValueError, AttributeError): pass

        user = (self.field_user.value or "").strip()
        if user:
            try:
                subprocess.run(f"id -u {user}", shell=True, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                self.run_cmd(f"useradd -m -s /bin/bash {user}")
                self.run_cmd(f"usermod -aG sudo {user}")

            if self.field_password.value:
                if not self.parentApp._dryrun:
                    try:
                        subprocess.run("chpasswd",
                                       input=f"{user}:{self.field_password.value}".encode(),
                                       shell=True, check=True, capture_output=True)
                        logging.info(f"Password set for {user}")
                    except Exception as e:
                        logging.error(f"chpasswd: {e}")
                else:
                    logging.info(f"[DRY-RUN] would set password for {user}")

            if (self.field_ssh_pubkey.value or "").strip():
                try:
                    home = subprocess.check_output(
                        f"getent passwd {user} | cut -d: -f6",
                        shell=True, text=True, stderr=subprocess.DEVNULL).strip()
                    ssh_dir = Path(home) / ".ssh"
                    ssh_dir.mkdir(mode=0o700, exist_ok=True)
                    auth = ssh_dir / "authorized_keys"
                    with open(auth, 'a') as f:
                        f.write(f"{(self.field_ssh_pubkey.value or '').strip()}\n")
                    os.chmod(auth, 0o600)
                    self.run_cmd(f"chown -R {user}:{user} {ssh_dir}")
                except Exception as e:
                    logging.error(f"SSH pubkey: {e}")

            if self.chk_motd.value and not self.chk_motd_uninstall.value:
                sf   = f"/etc/sudoers.d/{user}"
                rule = f"{user} ALL=(root) NOPASSWD: {MOTD_INSTALL}\n"
                try:
                    if not Path(sf).exists() or Path(sf).read_text() != rule:
                        Path(sf).write_text(rule)
                        os.chmod(sf, 0o440)
                except Exception as e:
                    logging.error(f"sudoers: {e}")

    def _exec_swap(self, mb):
        sw = "/swapfile"
        self.run_cmd(f"swapoff {sw} 2>/dev/null || true")
        self.run_cmd(f"rm -f {sw}")
        self.run_cmd(f"fallocate -l {mb}M {sw} || dd if=/dev/zero of={sw} bs=1M count={mb}")
        self.run_cmd(f"chmod 600 {sw} && mkswap {sw} && swapon {sw}")
        try:
            fstab = Path("/etc/fstab").read_text()
            if sw not in fstab:
                with open("/etc/fstab", 'a') as f:
                    f.write(f"\n{sw} none swap sw 0 0\n")
        except Exception as e:
            logging.error(f"fstab: {e}")

    # ============================================================
    # EXEC — MOTD
    # ============================================================

    def exec_motd(self):
        if not shutil.which("git"):
            self.run_cmd("apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates")
        Path(MOTD_TARGET).parent.mkdir(parents=True, exist_ok=True)
        try: os.chmod(Path(MOTD_TARGET).parent, 0o755)
        except Exception: pass

        if Path(MOTD_TARGET).exists():
            if Path(MOTD_TARGET, ".git").is_dir():
                cwd = os.getcwd()
                try:
                    os.chdir(MOTD_TARGET)
                    ok = self.run_cmd("git pull")
                finally:
                    os.chdir(cwd)
                if not ok:
                    shutil.rmtree(MOTD_TARGET)
                    self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET}")
            else:
                shutil.rmtree(MOTD_TARGET)
                self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET}")
        else:
            if not self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET}"):
                logging.error("MOTD clone failed"); return

        if Path(MOTD_INSTALL).exists():
            try:
                os.chmod(MOTD_INSTALL, 0o755)
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET)
                try: self.run_cmd("./install.sh")
                finally: os.chdir(cwd)
            except Exception as e:
                logging.error(f"install.sh: {e}")

    def exec_motd_uninstall(self):
        if Path(MOTD_UNINSTALL).exists():
            try:
                os.chmod(MOTD_UNINSTALL, 0o755)
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET)
                try: self.run_cmd("./uninstall.sh")
                finally: os.chdir(cwd)
            except Exception as e:
                logging.error(f"uninstall.sh: {e}")

        user = (self.field_user.value or "").strip()
        if user:
            sf = f"/etc/sudoers.d/{user}"
            if os.path.exists(sf):
                try: os.remove(sf)
                except Exception: pass

        if Path(MOTD_TARGET).exists():
            try: shutil.rmtree(MOTD_TARGET)
            except Exception: pass

    def exec_custom_script(self, script):
        if not os.path.exists(script):
            logging.error(f"Script not found: {script}")
            npyscreen.notify_confirm(f"Script not found:\n{script}", title="Error")
            return
        try:
            os.chmod(script, 0o755)
            self.run_cmd(f"bash {script}")
        except Exception as e:
            logging.error(f"Custom script: {e}")

    # ============================================================
    # PRESETS
    # ============================================================

    def _save_preset(self):
        name = npyscreen.notify_input("Name for this preset:", title="Save Preset")
        if not name or not name.strip(): return
        name = name.strip()
        try:
            Path(PRESET_DIR).mkdir(parents=True, exist_ok=True)
            data = self._gather_preset()
            data["name"] = name
            (Path(PRESET_DIR) / f"{name}.json").write_text(json.dumps(data, indent=2))
            npyscreen.notify_confirm(f"Preset '{name}' saved.", title="Saved")
            logging.info(f"Preset saved: {name}")
        except Exception as e:
            npyscreen.notify_confirm(f"Error: {e}", title="Error")

    def _load_preset(self):
        presets = sorted(Path(PRESET_DIR).glob("*.json")) if Path(PRESET_DIR).exists() else []
        if not presets:
            npyscreen.notify_confirm("No presets found in " + PRESET_DIR, title="Info")
            return
        listing = "\n".join(f"{i+1}. {p.stem}" for i, p in enumerate(presets))
        choice = npyscreen.notify_input(f"Choose a number:\n{listing}", title="Load Preset")
        if not choice or not choice.strip(): return
        try:
            idx = int(choice.strip()) - 1
            if not (0 <= idx < len(presets)):
                npyscreen.notify_confirm("Invalid number.", title="Error"); return
            data = json.loads(presets[idx].read_text())
            self._apply_preset(data)
            npyscreen.notify_confirm(f"Preset '{presets[idx].stem}' loaded.", title="Loaded")
        except Exception as e:
            npyscreen.notify_confirm(f"Error: {e}", title="Error")

    def _gather_preset(self):
        return {
            "motd":            self.chk_motd.value,
            "motd_uninstall":  self.chk_motd_uninstall.value,
            "history":         self.chk_history.value,
            "logs":            self.chk_logs.value,
            "apt":             self.chk_apt.value,
            "update":          self.chk_update.value,
            "snap":            self.chk_snap.value,
            "crontab":         self.chk_crontab.value,
            "docker":          self.chk_docker.value,
            "ssh_regen":       self.chk_ssh_regen.value,
            "machineid":       self.chk_machineid.value,
            "cloudinit":       self.chk_cloudinit.value,
            "shutdown":        self.chk_shutdown.value,
            "reboot":          self.chk_reboot.value,
            "dhcp":            self.chk_dhcp.value,
            "ipv6_off":        self.chk_ipv6_off.value,
            "dns_override":    self.chk_dns_override.value,
            "ip":              self.field_ip.value,
            "gw":              self.field_gw.value,
            "dns":             self.field_dns.value,
            "ssh_harden":      self.chk_ssh_harden.value,
            "ssh_port":        self.field_ssh_port.value,
            "ssh_no_pass":     self.chk_ssh_no_pass.value,
            "ssh_no_root":     self.chk_ssh_no_root.value,
            "ufw":             self.chk_ufw.value,
            "ufw_ports":       self.field_ufw_ports.value,
            "fail2ban":        self.chk_fail2ban.value,
            "unattended":      self.chk_unattended.value,
            "hostname":        self.field_hostname.value,
            "user":            self.field_user.value,
            "timezone":        self.field_timezone.value,
            "locale":          self.field_locale.value,
            "ntp":             self.field_ntp.value,
            "swap":            self.field_swap.value,
            "custom_script":   self.field_custom_script.value,
            "dryrun":          self.chk_dryrun.value,
        }

    def _apply_preset(self, s):
        self.chk_motd.value            = s.get("motd", True)
        self.chk_motd_uninstall.value  = s.get("motd_uninstall", False)
        self.chk_history.value         = s.get("history", True)
        self.chk_logs.value            = s.get("logs", True)
        self.chk_apt.value             = s.get("apt", True)
        self.chk_update.value          = s.get("update", False)
        self.chk_snap.value            = s.get("snap", False)
        self.chk_crontab.value         = s.get("crontab", False)
        self.chk_docker.value          = s.get("docker", False)
        self.chk_ssh_regen.value       = s.get("ssh_regen", False)
        self.chk_machineid.value       = s.get("machineid", False)
        self.chk_cloudinit.value       = s.get("cloudinit", False)
        self.chk_shutdown.value        = s.get("shutdown", False)
        self.chk_reboot.value          = s.get("reboot", False)
        self.chk_dhcp.value            = s.get("dhcp", True)
        self.chk_ipv6_off.value        = s.get("ipv6_off", False)
        self.chk_dns_override.value    = s.get("dns_override", False)
        self.field_ip.value            = s.get("ip", "")
        self.field_gw.value            = s.get("gw", "")
        self.field_dns.value           = s.get("dns", "")
        self.chk_ssh_harden.value      = s.get("ssh_harden", False)
        self.field_ssh_port.value      = s.get("ssh_port", "22")
        self.chk_ssh_no_pass.value     = s.get("ssh_no_pass", True)
        self.chk_ssh_no_root.value     = s.get("ssh_no_root", True)
        self.chk_ufw.value             = s.get("ufw", False)
        self.field_ufw_ports.value     = s.get("ufw_ports", "22,80,443")
        self.chk_fail2ban.value        = s.get("fail2ban", False)
        self.chk_unattended.value      = s.get("unattended", False)
        self.field_hostname.value      = s.get("hostname", "")
        self.field_user.value          = s.get("user", "")
        self.field_timezone.value      = s.get("timezone", "Europe/Amsterdam")
        self.field_locale.value        = s.get("locale", "en_US.UTF-8")
        self.field_ntp.value           = s.get("ntp", "")
        self.field_swap.value          = s.get("swap", "0")
        self.field_custom_script.value = s.get("custom_script", "")
        self.chk_dryrun.value          = s.get("dryrun", False)
        self._toggle_dhcp()
        self._toggle_ssh()
        self._toggle_ufw()
        self.display()


# ============================================================
# APP
# ============================================================

class PostReadyApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self._dryrun = False
        self.addForm("MAIN", PostReadyForm)
        self.addForm("LOG",  LogViewerForm)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ERROR: Root privileges required. Run with sudo.")
        sys.exit(1)

    logging.info("=== PostReady Application Started ===")
    try:
        PostReadyApp().run()
        logging.info("=== PostReady Application Ended Normally ===")
        width = 50
        print(f"\n{' PostReady ':=^{width}}")
        print(f"|| {'Goodbye! See you next time.':<{width-6}} ||")
        print("=" * width + "\n")
    except KeyboardInterrupt:
        logging.warning("User interrupted (SIGINT)")
        print("\n[WARNING] Process terminated by user.")
        try: sys.exit(0)
        except Exception: os._exit(0)
    except Exception as e:
        logging.critical(f"FATAL EXCEPTION: {e}", exc_info=True)
        print(f"\n[ERROR] Fatal crash. See {LOG_FILE} for details.")
        sys.exit(1)
