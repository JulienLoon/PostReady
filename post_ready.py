#!/usr/bin/env python3
#
# PostReady v3.0 - System Preparation Tool
# Author: Julian Loontjens
# Date: 2026-06-09
#

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
LOG_FILE = "/var/log/postready.log"
PRESET_DIR = "/etc/postready/presets"
MOTD_REPO = "https://github.com/JulienLoon/julianloontjens-motd.git"
MOTD_TARGET_DIR = "/etc/essentials/julianloontjens-motd"
MOTD_SCRIPT_PATH = os.path.join(MOTD_TARGET_DIR, "install.sh")
MOTD_UNINSTALL_PATH = os.path.join(MOTD_TARGET_DIR, "uninstall.sh")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class LogViewerForm(npyscreen.FormBaseNew):
    def create(self):
        self.add(npyscreen.FixedText, value="[ LOG VIEWER ]  Press Q or ESC to close", relx=2, rely=0, color="WARNING")
        self.log_box = self.add(
            npyscreen.MultiLineEdit,
            value=self._read_log(),
            relx=2, rely=2,
            max_height=-2,
            editable=False,
        )
        self.add_handlers({"q": self._close, "Q": self._close, "^[": self._close})

    def _read_log(self):
        try:
            lines = Path(LOG_FILE).read_text().splitlines()
            return "\n".join(lines[-300:]) if lines else "(log is leeg)"
        except Exception as e:
            return f"Kan log niet lezen: {e}"

    def _close(self, _=None):
        self.parentApp.switchFormPrevious()


class PostReadyForm(npyscreen.FormScrolled):
    def create(self):
        title = "PostReady v3.0 - System Preparation Tool"
        self.add(npyscreen.FixedText, value=title, editable=False, rely=0,
                 relx=max(0, (self.columns - len(title)) // 2), color="STANDOUT")

        logo_lines = [
            r" ____           _   ____                _       ",
            r"|  _ \ ___  ___| |_|  _ \ ___  __ _  __| |_   _ ",
            r"| |_) / _ \/ __| __| |_) / _ \/ _` |/ _` | | | |",
            r"|  __/ (_) \__ \ |_|  _ <  __/ (_| | (_| | |_| |",
            r"|_|   \___/|___/\__|_| \_\___|\__,_|\__,_|\__, |",
            r"                                          |___/ ",
        ]
        subtitle = "by Julian Loontjens"
        row = 2
        for line in logo_lines:
            self.add(npyscreen.FixedText, value=line, editable=False, rely=row,
                     relx=max(0, (self.columns - len(line)) // 2), color="GOOD")
            row += 1
        self.add(npyscreen.FixedText, value=subtitle, editable=False, rely=row,
                 relx=max(0, (self.columns - len(subtitle)) // 2), color="CYAN")
        self.add(npyscreen.FixedText, value=f"Log: {LOG_FILE}", editable=False,
                 rely=row + 2, relx=2, color="WARNING")
        row += 4

        # --- FEATURES ---
        self.add(npyscreen.FixedText, value="[ FEATURES ]", rely=row, relx=2, color="LABEL"); row += 1
        self.chk_motd = self.add(npyscreen.Checkbox, name="Install/Update Custom MOTD", value=True, rely=row, relx=4); row += 1
        self.chk_motd_uninstall = self.add(npyscreen.Checkbox, name="Uninstall Custom MOTD", value=False, rely=row, relx=4); row += 2

        # --- CLEANUP ---
        self.add(npyscreen.FixedText, value="[ CLEANUP / SYSPREP ]", rely=row, relx=2, color="LABEL"); row += 1
        self.chk_history   = self.add(npyscreen.Checkbox, name="Clear Bash History",            value=True,  rely=row, relx=4); row += 1
        self.chk_logs      = self.add(npyscreen.Checkbox, name="Truncate /var/log/*",            value=True,  rely=row, relx=4); row += 1
        self.chk_apt       = self.add(npyscreen.Checkbox, name="APT Clean & Autoremove",         value=True,  rely=row, relx=4); row += 1
        self.chk_update    = self.add(npyscreen.Checkbox, name="APT Update & Upgrade",           value=False, rely=row, relx=4); row += 1
        self.chk_snap      = self.add(npyscreen.Checkbox, name="Snap / Flatpak Cleanup",         value=False, rely=row, relx=4); row += 1
        self.chk_crontab   = self.add(npyscreen.Checkbox, name="Clear All Crontabs",             value=False, rely=row, relx=4); row += 1
        self.chk_docker    = self.add(npyscreen.Checkbox, name="Docker System Prune",            value=False, rely=row, relx=4); row += 1
        self.chk_ssh_regen = self.add(npyscreen.Checkbox, name="Regen SSH Host Keys",            value=False, rely=row, relx=4); row += 1
        self.chk_machineid = self.add(npyscreen.Checkbox, name="Reset Machine-ID",               value=False, rely=row, relx=4); row += 1
        self.chk_cloudinit = self.add(npyscreen.Checkbox, name="Clean Cloud-init (VM Template)", value=False, rely=row, relx=4); row += 1
        self.chk_shutdown  = self.add(npyscreen.Checkbox, name="Shutdown when complete",         value=False, rely=row, relx=4)
        self.chk_shutdown.when_value_edited = self._toggle_shutdown; row += 1
        self.chk_reboot    = self.add(npyscreen.Checkbox, name="Reboot when complete",           value=False, rely=row, relx=4)
        self.chk_reboot.when_value_edited = self._toggle_reboot; row += 2

        # --- NETWORK ---
        self.add(npyscreen.FixedText, value="[ NETWORK ]", rely=row, relx=2, color="LABEL"); row += 1
        self.all_interfaces = self._get_all_interfaces()
        iface_height = min(4, len(self.all_interfaces) + 1)
        self.iface_select = self.add(
            npyscreen.TitleSelectOne, name="Interface:", values=self.all_interfaces,
            value=[0], rely=row, relx=4, max_height=iface_height, scroll_exit=True,
        )
        row += iface_height + 1
        self.chk_dhcp = self.add(npyscreen.Checkbox, name="Enable DHCP", value=True, rely=row, relx=4)
        self.chk_dhcp.when_value_edited = self._toggle_static; row += 1
        self.chk_ipv6_off = self.add(npyscreen.Checkbox, name="Disable IPv6", value=False, rely=row, relx=4); row += 1
        self.chk_dns_override = self.add(npyscreen.Checkbox, name="Override DNS (DHCP mode)", value=False, rely=row, relx=4)
        self.chk_dns_override.when_value_edited = self._toggle_dns_override; row += 1
        self.field_ip  = self.add(npyscreen.TitleText, name="IP/CIDR:",  rely=row,   relx=4, hidden=True,  begin_entry_at=14); row += 1
        self.field_gw  = self.add(npyscreen.TitleText, name="Gateway:",  rely=row,   relx=4, hidden=True,  begin_entry_at=14); row += 1
        self.field_dns = self.add(npyscreen.TitleText, name="DNS:",      rely=row,   relx=4, hidden=False, begin_entry_at=14); row += 2

        # --- SECURITY ---
        self.add(npyscreen.FixedText, value="[ SECURITY ]", rely=row, relx=2, color="LABEL"); row += 1
        self.chk_ssh_harden = self.add(npyscreen.Checkbox, name="SSH Hardening", value=False, rely=row, relx=4)
        self.chk_ssh_harden.when_value_edited = self._toggle_ssh_fields; row += 1
        self.field_ssh_port     = self.add(npyscreen.TitleText, name="SSH Port:",  rely=row, relx=6, hidden=True, begin_entry_at=14, value="22"); row += 1
        self.chk_ssh_no_pass    = self.add(npyscreen.Checkbox, name="Disable Password Authentication", value=True,  rely=row, relx=6, hidden=True); row += 1
        self.chk_ssh_no_root    = self.add(npyscreen.Checkbox, name="Disable Root Login",              value=True,  rely=row, relx=6, hidden=True); row += 2
        self.chk_ufw = self.add(npyscreen.Checkbox, name="Configure UFW Firewall", value=False, rely=row, relx=4)
        self.chk_ufw.when_value_edited = self._toggle_ufw_fields; row += 1
        self.field_ufw_ports = self.add(npyscreen.TitleText, name="Allow Ports:", rely=row, relx=6, hidden=True, begin_entry_at=14, value="22,80,443"); row += 2
        self.chk_fail2ban   = self.add(npyscreen.Checkbox, name="Install & Enable Fail2ban",      value=False, rely=row, relx=4); row += 1
        self.chk_unattended = self.add(npyscreen.Checkbox, name="Enable Unattended Upgrades",     value=False, rely=row, relx=4); row += 2

        # --- SETTINGS ---
        self.add(npyscreen.FixedText, value="[ SETTINGS ]", rely=row, relx=2, color="LABEL"); row += 1
        self.field_hostname  = self.add(npyscreen.TitleText,     name="Hostname:",    rely=row, relx=4, begin_entry_at=16); row += 1
        self.field_user      = self.add(npyscreen.TitleText,     name="New User:",    rely=row, relx=4, begin_entry_at=16); row += 1
        self.field_password  = self.add(npyscreen.TitlePassword, name="Password:",    rely=row, relx=4, begin_entry_at=16); row += 1
        self.field_ssh_pubkey= self.add(npyscreen.TitleText,     name="SSH Pub Key:", rely=row, relx=4, begin_entry_at=16); row += 1
        self.field_timezone  = self.add(npyscreen.TitleText,     name="Timezone:",    rely=row, relx=4, begin_entry_at=16, value="Europe/Amsterdam"); row += 1
        self.field_locale    = self.add(npyscreen.TitleText,     name="Locale:",      rely=row, relx=4, begin_entry_at=16, value="en_US.UTF-8"); row += 1
        self.field_ntp       = self.add(npyscreen.TitleText,     name="NTP Server:",  rely=row, relx=4, begin_entry_at=16, value=""); row += 1
        self.field_swap      = self.add(npyscreen.TitleText,     name="Swap (MB):",   rely=row, relx=4, begin_entry_at=16, value="0"); row += 2

        # --- ADVANCED ---
        self.add(npyscreen.FixedText, value="[ ADVANCED ]", rely=row, relx=2, color="LABEL"); row += 1
        self.field_custom_script = self.add(npyscreen.TitleText, name="Custom Script:", rely=row, relx=4, begin_entry_at=16, value=""); row += 1
        self.chk_dryrun = self.add(npyscreen.Checkbox, name="Dry-run (preview only, no changes)", value=False, rely=row, relx=4); row += 2

        # --- PRESETS ---
        self.add(npyscreen.FixedText, value="[ PRESETS ]", rely=row, relx=2, color="LABEL"); row += 1
        self.add(npyscreen.ButtonPress, name="[ SAVE PRESET ]", rely=row, relx=4,  when_pressed_function=self.save_preset)
        self.add(npyscreen.ButtonPress, name="[ LOAD PRESET ]", rely=row, relx=22, when_pressed_function=self.load_preset)
        row += 2

        # --- STATUS + CONTROLS ---
        self.add(npyscreen.FixedText, value="[ CONTROLS ]", rely=row, relx=2, color="LABEL"); row += 1
        self.status_text = self.add(npyscreen.FixedText, value="Klaar.", rely=row, relx=4, color="GOOD"); row += 1
        mid = max(4, self.columns // 2 - 20)
        self.add(npyscreen.ButtonPress, name="[ APPLY ]",    rely=row, relx=mid,      when_pressed_function=self.on_start)
        self.add(npyscreen.ButtonPress, name="[ VIEW LOG ]", rely=row, relx=mid + 12, when_pressed_function=self._view_log)
        self.add(npyscreen.ButtonPress, name="[ QUIT ]",     rely=row, relx=mid + 25, when_pressed_function=self.on_exit)

        self._toggle_static()
        self._toggle_dns_override()
        self._toggle_ssh_fields()
        self._toggle_ufw_fields()

    # --- TOGGLE HANDLERS ---

    def _toggle_shutdown(self):
        if self.chk_shutdown.value:
            self.chk_reboot.value = False
        self.display()

    def _toggle_reboot(self):
        if self.chk_reboot.value:
            self.chk_shutdown.value = False
        self.display()

    def _toggle_static(self):
        is_static = not self.chk_dhcp.value
        self.field_ip.hidden = not is_static
        self.field_gw.hidden = not is_static
        self.field_ip.editable = is_static
        self.field_gw.editable = is_static
        self.chk_dns_override.hidden = is_static
        self._toggle_dns_override()

    def _toggle_dns_override(self):
        is_static = not self.chk_dhcp.value
        show_dns = is_static or self.chk_dns_override.value
        self.field_dns.hidden = not show_dns
        self.field_dns.editable = show_dns
        self.display()

    def _toggle_ssh_fields(self):
        show = self.chk_ssh_harden.value
        for w in [self.field_ssh_port, self.chk_ssh_no_pass, self.chk_ssh_no_root]:
            w.hidden = not show
            w.editable = show
        self.display()

    def _toggle_ufw_fields(self):
        show = self.chk_ufw.value
        self.field_ufw_ports.hidden = not show
        self.field_ufw_ports.editable = show
        self.display()

    def _view_log(self):
        self.parentApp.switchForm("LOG")

    def on_exit(self):
        if not npyscreen.notify_yes_no("Weet je zeker dat je wilt afsluiten?", title="Bevestigen", editw=1):
            return
        logging.info("User exited via GUI.")
        self.parentApp.switchForm(None)

    # --- INTERFACE DETECTION ---

    def _get_all_interfaces(self):
        try:
            out = subprocess.check_output(
                "ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$'",
                shell=True
            ).decode().strip().split('\n')
            ifaces = [i.strip() for i in out if i.strip()]
            return ifaces or ["eth0"]
        except Exception:
            return ["eth0"]

    def _selected_interface(self):
        try:
            return self.all_interfaces[self.iface_select.value[0]]
        except (IndexError, TypeError):
            return self.all_interfaces[0]

    # --- UTILS ---

    def _validate_ip(self, ip_input):
        try:
            parts = ip_input.split('/')
            ipaddress.ip_address(parts[0])
            if len(parts) == 2 and not (0 <= int(parts[1]) <= 32):
                return False
            return True
        except ValueError:
            return False

    def run_cmd(self, command, shell=True):
        if self.chk_dryrun.value:
            logging.info(f"[DRY-RUN] {command}")
            return True
        logging.info(f"CMD_EXEC: {command}")
        try:
            subprocess.run(command, shell=shell, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"CMD_FAIL: {command} | RC={e.returncode}")
            return False

    def set_status(self, text):
        self.status_text.value = text
        self.status_text.display()

    def wait_for_network(self, timeout=20):
        logging.info("Waiting for network...")
        for _ in range(timeout):
            if subprocess.run("getent hosts github.com", shell=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                logging.info("Network ready.")
                return True
            time.sleep(1)
        logging.error("Network timeout.")
        return False

    # --- PRESET SYSTEM ---

    def _form_state(self):
        return {
            "motd": self.chk_motd.value,
            "motd_uninstall": self.chk_motd_uninstall.value,
            "history": self.chk_history.value,
            "logs": self.chk_logs.value,
            "apt": self.chk_apt.value,
            "update": self.chk_update.value,
            "snap": self.chk_snap.value,
            "crontab": self.chk_crontab.value,
            "docker": self.chk_docker.value,
            "ssh_regen": self.chk_ssh_regen.value,
            "machineid": self.chk_machineid.value,
            "cloudinit": self.chk_cloudinit.value,
            "shutdown": self.chk_shutdown.value,
            "reboot": self.chk_reboot.value,
            "dhcp": self.chk_dhcp.value,
            "ipv6_off": self.chk_ipv6_off.value,
            "dns_override": self.chk_dns_override.value,
            "ip": self.field_ip.value,
            "gw": self.field_gw.value,
            "dns": self.field_dns.value,
            "ssh_harden": self.chk_ssh_harden.value,
            "ssh_port": self.field_ssh_port.value,
            "ssh_no_pass": self.chk_ssh_no_pass.value,
            "ssh_no_root": self.chk_ssh_no_root.value,
            "ufw": self.chk_ufw.value,
            "ufw_ports": self.field_ufw_ports.value,
            "fail2ban": self.chk_fail2ban.value,
            "unattended": self.chk_unattended.value,
            "hostname": self.field_hostname.value,
            "user": self.field_user.value,
            "timezone": self.field_timezone.value,
            "locale": self.field_locale.value,
            "ntp": self.field_ntp.value,
            "swap": self.field_swap.value,
            "custom_script": self.field_custom_script.value,
            "dryrun": self.chk_dryrun.value,
        }

    def _apply_state(self, s):
        self.chk_motd.value           = s.get("motd", True)
        self.chk_motd_uninstall.value = s.get("motd_uninstall", False)
        self.chk_history.value        = s.get("history", True)
        self.chk_logs.value           = s.get("logs", True)
        self.chk_apt.value            = s.get("apt", True)
        self.chk_update.value         = s.get("update", False)
        self.chk_snap.value           = s.get("snap", False)
        self.chk_crontab.value        = s.get("crontab", False)
        self.chk_docker.value         = s.get("docker", False)
        self.chk_ssh_regen.value      = s.get("ssh_regen", False)
        self.chk_machineid.value      = s.get("machineid", False)
        self.chk_cloudinit.value      = s.get("cloudinit", False)
        self.chk_shutdown.value       = s.get("shutdown", False)
        self.chk_reboot.value         = s.get("reboot", False)
        self.chk_dhcp.value           = s.get("dhcp", True)
        self.chk_ipv6_off.value       = s.get("ipv6_off", False)
        self.chk_dns_override.value   = s.get("dns_override", False)
        self.field_ip.value           = s.get("ip", "")
        self.field_gw.value           = s.get("gw", "")
        self.field_dns.value          = s.get("dns", "")
        self.chk_ssh_harden.value     = s.get("ssh_harden", False)
        self.field_ssh_port.value     = s.get("ssh_port", "22")
        self.chk_ssh_no_pass.value    = s.get("ssh_no_pass", True)
        self.chk_ssh_no_root.value    = s.get("ssh_no_root", True)
        self.chk_ufw.value            = s.get("ufw", False)
        self.field_ufw_ports.value    = s.get("ufw_ports", "22,80,443")
        self.chk_fail2ban.value       = s.get("fail2ban", False)
        self.chk_unattended.value     = s.get("unattended", False)
        self.field_hostname.value     = s.get("hostname", "")
        self.field_user.value         = s.get("user", "")
        self.field_timezone.value     = s.get("timezone", "Europe/Amsterdam")
        self.field_locale.value       = s.get("locale", "en_US.UTF-8")
        self.field_ntp.value          = s.get("ntp", "")
        self.field_swap.value         = s.get("swap", "0")
        self.field_custom_script.value= s.get("custom_script", "")
        self.chk_dryrun.value         = s.get("dryrun", False)
        self._toggle_static()
        self._toggle_ssh_fields()
        self._toggle_ufw_fields()
        self.display()

    def save_preset(self):
        name = npyscreen.notify_input("Geef de preset een naam:", title="Preset opslaan")
        if not name or not name.strip():
            return
        name = name.strip()
        try:
            Path(PRESET_DIR).mkdir(parents=True, exist_ok=True)
            state = self._form_state()
            state["name"] = name
            with open(Path(PRESET_DIR) / f"{name}.json", 'w') as f:
                json.dump(state, f, indent=2)
            npyscreen.notify_confirm(f"Preset '{name}' opgeslagen.", title="Opgeslagen")
            logging.info(f"Preset saved: {name}")
        except Exception as e:
            npyscreen.notify_confirm(f"Fout: {e}", title="Error")
            logging.error(f"Preset save failed: {e}")

    def load_preset(self):
        presets = sorted(Path(PRESET_DIR).glob("*.json")) if Path(PRESET_DIR).exists() else []
        if not presets:
            npyscreen.notify_confirm("Geen presets gevonden in:\n" + PRESET_DIR, title="Info")
            return
        names = [p.stem for p in presets]
        listing = "\n".join(f"{i+1}. {n}" for i, n in enumerate(names))
        choice = npyscreen.notify_input(f"Kies nummer:\n{listing}", title="Preset laden")
        if not choice or not choice.strip():
            return
        try:
            idx = int(choice.strip()) - 1
            if not (0 <= idx < len(presets)):
                npyscreen.notify_confirm("Ongeldig nummer.", title="Fout")
                return
            with open(presets[idx]) as f:
                state = json.load(f)
            self._apply_state(state)
            npyscreen.notify_confirm(f"Preset '{presets[idx].stem}' geladen.", title="Geladen")
            logging.info(f"Preset loaded: {presets[idx].stem}")
        except (ValueError, json.JSONDecodeError) as e:
            npyscreen.notify_confirm(f"Fout bij laden: {e}", title="Error")

    # --- MAIN ---

    def on_start(self):
        if self.chk_motd.value and self.chk_motd_uninstall.value:
            npyscreen.notify_confirm("Kan MOTD niet tegelijk installeren en verwijderen.", title="Validatiefout")
            return

        if not self.chk_dhcp.value:
            if not all([self.field_ip.value, self.field_gw.value, self.field_dns.value]):
                npyscreen.notify_confirm("Statisch IP vereist: IP, Gateway en DNS.", title="Validatiefout")
                return
            if not self._validate_ip(self.field_ip.value.strip()):
                npyscreen.notify_confirm("Ongeldig IP-formaat.", title="Validatiefout")
                return

        if self.chk_ssh_harden.value:
            try:
                port = int(self.field_ssh_port.value.strip())
                if not (1 <= port <= 65535):
                    raise ValueError
            except ValueError:
                npyscreen.notify_confirm("Ongeldige SSH-poort (1-65535).", title="Validatiefout")
                return

        if self.chk_history.value:
            if not npyscreen.notify_yes_no(
                "WAARSCHUWING: Bash history wissen sluit alle bash sessies!\n\n"
                "Je SSH verbinding wordt verbroken.\n"
                "Het script blijft doorlopen.\n\nDoorgaan?",
                title="Waarschuwing", editw=1
            ):
                return

        dry_label = " [DRY-RUN]" if self.chk_dryrun.value else ""
        if not npyscreen.notify_yes_no(f"Wijzigingen toepassen?{dry_label}", title="Bevestigen", editw=1):
            return

        logging.info(f"--- STARTING BATCH OPERATIONS (dry_run={self.chk_dryrun.value}) ---")

        steps = [
            ("Cleanup...",                self.exec_cleanup),
            ("Netwerk configureren...",   self.exec_network),
            ("Beveiliging...",            self.exec_security),
            ("Systeem configureren...",   self.exec_system),
        ]
        for i, (label, fn) in enumerate(steps, 1):
            self.set_status(f"Stap {i}/{len(steps)}: {label}")
            fn()

        if self.chk_motd.value or self.chk_motd_uninstall.value:
            self.set_status("MOTD operaties...")
            if not self.wait_for_network():
                npyscreen.notify_confirm("Netwerk niet beschikbaar.\nMOTD overgeslagen.", title="Waarschuwing")
            else:
                if self.chk_motd_uninstall.value:
                    self.exec_motd_uninstall()
                elif self.chk_motd.value:
                    self.exec_motd()

        if self.field_custom_script.value and self.field_custom_script.value.strip():
            self.set_status("Custom script uitvoeren...")
            self.exec_custom_script()

        self.set_status("Klaar!")
        logging.info("--- BATCH OPERATIONS COMPLETED ---")

        if self.chk_shutdown.value:
            npyscreen.notify_confirm("Alle taken voltooid.\nSysteem wordt afgesloten.", title="Succes")
            logging.info("Initiating shutdown")
            self.run_cmd("shutdown -h now")
        elif self.chk_reboot.value:
            npyscreen.notify_confirm("Alle taken voltooid.\nSysteem wordt herstart.", title="Succes")
            logging.info("Initiating reboot")
            self.run_cmd("shutdown -r now")
        else:
            npyscreen.notify_confirm("Configuratie toegepast.\nHerstart aanbevolen.", title="Succes")

        self.parentApp.switchForm(None)

    # --- EXEC METHODS ---

    def exec_motd(self):
        if not shutil.which("git"):
            self.run_cmd("apt-get update && apt-get install -y git ca-certificates")
        logging.info("--- MOTD INSTALL ---")
        parent_dir = Path(MOTD_TARGET_DIR).parent
        parent_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(parent_dir, 0o755)
            shutil.chown(parent_dir, user="root", group="root")
        except Exception as e:
            logging.warning(f"Permissions on {parent_dir}: {e}")

        if Path(MOTD_TARGET_DIR).exists():
            if Path(MOTD_TARGET_DIR, ".git").is_dir():
                cwd = os.getcwd()
                try:
                    os.chdir(MOTD_TARGET_DIR)
                    pull_ok = self.run_cmd("git pull")
                finally:
                    os.chdir(cwd)
                if not pull_ok:
                    shutil.rmtree(MOTD_TARGET_DIR)
                    self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET_DIR}")
            else:
                shutil.rmtree(MOTD_TARGET_DIR)
                self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET_DIR}")
        else:
            if not self.run_cmd(f"git clone {MOTD_REPO} {MOTD_TARGET_DIR}"):
                logging.error("Failed to clone MOTD repo.")
                return

        if Path(MOTD_SCRIPT_PATH).exists():
            try:
                os.chmod(MOTD_SCRIPT_PATH, 0o755)
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET_DIR)
                try:
                    self.run_cmd("./install.sh")
                finally:
                    os.chdir(cwd)
            except Exception as e:
                logging.error(f"install.sh error: {e}")
        else:
            logging.error(f"install.sh not found at {MOTD_SCRIPT_PATH}")

    def exec_motd_uninstall(self):
        logging.info("--- MOTD UNINSTALL ---")
        if Path(MOTD_UNINSTALL_PATH).exists():
            try:
                os.chmod(MOTD_UNINSTALL_PATH, 0o755)
                cwd = os.getcwd()
                os.chdir(MOTD_TARGET_DIR)
                try:
                    self.run_cmd("./uninstall.sh")
                finally:
                    os.chdir(cwd)
            except Exception as e:
                logging.error(f"uninstall.sh error: {e}")
        else:
            npyscreen.notify_confirm(f"Niet gevonden:\n{MOTD_UNINSTALL_PATH}", title="Fout")

        if self.field_user.value:
            sudoers = f"/etc/sudoers.d/{self.field_user.value.strip()}"
            if os.path.exists(sudoers):
                try:
                    os.remove(sudoers)
                except Exception as e:
                    logging.error(f"Could not remove sudoers: {e}")

        if Path(MOTD_TARGET_DIR).exists():
            try:
                shutil.rmtree(MOTD_TARGET_DIR)
            except Exception as e:
                logging.warning(f"Could not remove repo dir: {e}")

    def exec_cleanup(self):
        if self.chk_logs.value:
            logging.info("Truncating /var/log")
            for lf in Path("/var/log").rglob("*.log"):
                try:
                    lf.write_text("")
                except (PermissionError, OSError) as e:
                    logging.warning(f"Could not truncate {lf}: {e}")
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
            logging.info("Snap/Flatpak cleanup")
            if shutil.which("snap"):
                try:
                    pkgs = subprocess.check_output(
                        "snap list --all | awk 'NR>1 {print $1}' | sort -u",
                        shell=True, text=True
                    ).strip().split('\n')
                    for pkg in pkgs:
                        if pkg.strip():
                            self.run_cmd(f"snap remove --purge {pkg.strip()} 2>/dev/null || true")
                except Exception as e:
                    logging.warning(f"Snap cleanup error: {e}")
            if shutil.which("flatpak"):
                self.run_cmd("flatpak uninstall --all --noninteractive 2>/dev/null || true")

        if self.chk_crontab.value:
            logging.info("Clearing crontabs")
            self.run_cmd("crontab -r 2>/dev/null || true")
            self.run_cmd("for u in $(cut -f1 -d: /etc/passwd); do crontab -r -u \"$u\" 2>/dev/null; done || true")
            for cron_dir in ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly"]:
                self.run_cmd(f"find {cron_dir} -maxdepth 1 -type f -not -name '.*' -delete 2>/dev/null || true")

        if self.chk_docker.value:
            if shutil.which("docker"):
                self.run_cmd("docker system prune -af --volumes 2>/dev/null || true")
            else:
                logging.info("Docker not found, skipping")

        if self.chk_ssh_regen.value:
            self.run_cmd("rm -f /etc/ssh/ssh_host_*")
            for kt in ["rsa", "ecdsa", "ed25519"]:
                self.run_cmd(f"ssh-keygen -t {kt} -f /etc/ssh/ssh_host_{kt}_key -N '' -q")
            self.run_cmd("systemctl restart sshd || systemctl restart ssh")

        if self.chk_machineid.value:
            self.run_cmd("truncate -s 0 /etc/machine-id")
            dbus = "/var/lib/dbus/machine-id"
            if not os.path.islink(dbus) and os.path.exists(dbus):
                try:
                    os.remove(dbus)
                except OSError:
                    pass
            self.run_cmd("ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true")

        if self.chk_cloudinit.value:
            if shutil.which("cloud-init"):
                self.run_cmd("cloud-init clean --logs --seed")
            for p in ["/var/lib/cloud/", "/etc/cloud/cloud.cfg.d/99-installer.cfg",
                      "/etc/cloud/cloud.cfg.d/subiquity-disable-cloudinit-networking.cfg",
                      "/var/log/cloud-init.log", "/var/log/cloud-init-output.log"]:
                if os.path.exists(p):
                    try:
                        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
                    except Exception as e:
                        logging.warning(f"Could not remove {p}: {e}")
            self.run_cmd("swapoff -a 2>/dev/null || true")
            self.run_cmd("swapon -a 2>/dev/null || true")

        # History last — kills bash sessions
        if self.chk_history.value:
            self.run_cmd("find /root /home -name '.bash_history' -type f -exec truncate -s 0 {} \\; 2>/dev/null || true")
            logging.info("Terminating bash sessions...")
            self.run_cmd("sleep 1 && pkill -9 bash 2>/dev/null || true")

    def exec_network(self):
        iface = self._selected_interface()
        logging.info(f"Configuring Netplan on {iface}")
        netplan_file = "/etc/netplan/99-postready.yaml"

        if self.chk_dhcp.value:
            content = f"network:\n  version: 2\n  ethernets:\n    {iface}:\n      dhcp4: true\n"
        else:
            raw_ip = self.field_ip.value.strip()
            ip  = raw_ip if "/" in raw_ip else f"{raw_ip}/24"
            gw  = self.field_gw.value.strip()
            dns = self.field_dns.value.strip()
            content = (
                f"network:\n  version: 2\n  ethernets:\n    {iface}:\n"
                f"      dhcp4: false\n      addresses: [{ip}]\n"
                f"      routes:\n        - to: default\n          via: {gw}\n"
                f"      nameservers:\n        addresses: [{dns}]\n"
            )

        try:
            backup = Path("/etc/netplan/backup")
            backup.mkdir(exist_ok=True)
            for f in Path("/etc/netplan").glob("*.yaml"):
                if f.name != "99-postready.yaml":
                    shutil.move(str(f), str(backup / f.name))
            Path(netplan_file).write_text(content)
            os.chmod(netplan_file, 0o600)
            self.run_cmd("netplan apply")
        except Exception as e:
            logging.error(f"Netplan error: {e}")

        if self.chk_dhcp.value and self.chk_dns_override.value and self.field_dns.value.strip():
            try:
                Path("/etc/systemd/resolved.conf").write_text(
                    f"[Resolve]\nDNS={self.field_dns.value.strip()}\n"
                )
                self.run_cmd("systemctl restart systemd-resolved")
            except Exception as e:
                logging.error(f"DNS override failed: {e}")

        if self.chk_ipv6_off.value:
            try:
                Path("/etc/sysctl.d/99-disable-ipv6.conf").write_text(
                    "net.ipv6.conf.all.disable_ipv6 = 1\n"
                    "net.ipv6.conf.default.disable_ipv6 = 1\n"
                    "net.ipv6.conf.lo.disable_ipv6 = 1\n"
                )
                self.run_cmd("sysctl -p /etc/sysctl.d/99-disable-ipv6.conf")
            except Exception as e:
                logging.error(f"IPv6 disable failed: {e}")

    def exec_security(self):
        if self.chk_ssh_harden.value:
            logging.info("SSH hardening")
            sshd = "/etc/ssh/sshd_config"
            try:
                cfg = Path(sshd).read_text()
                port = self.field_ssh_port.value.strip()
                cfg = re.sub(r'^#?Port\s+\d+', f'Port {port}', cfg, flags=re.MULTILINE)
                if not re.search(r'^Port\s+', cfg, re.MULTILINE):
                    cfg += f'\nPort {port}\n'
                if self.chk_ssh_no_pass.value:
                    cfg = re.sub(r'^#?PasswordAuthentication\s+\w+', 'PasswordAuthentication no', cfg, flags=re.MULTILINE)
                    if not re.search(r'^PasswordAuthentication\s+', cfg, re.MULTILINE):
                        cfg += '\nPasswordAuthentication no\n'
                if self.chk_ssh_no_root.value:
                    cfg = re.sub(r'^#?PermitRootLogin\s+\w+', 'PermitRootLogin no', cfg, flags=re.MULTILINE)
                    if not re.search(r'^PermitRootLogin\s+', cfg, re.MULTILINE):
                        cfg += '\nPermitRootLogin no\n'
                Path(sshd).write_text(cfg)
                self.run_cmd("systemctl restart sshd || systemctl restart ssh")
            except Exception as e:
                logging.error(f"SSH hardening failed: {e}")

        if self.chk_ufw.value:
            logging.info("Configuring UFW")
            self.run_cmd("apt-get install -y ufw 2>/dev/null || true")
            self.run_cmd("ufw --force reset")
            self.run_cmd("ufw default deny incoming")
            self.run_cmd("ufw default allow outgoing")
            for port in self.field_ufw_ports.value.strip().split(','):
                port = port.strip()
                if port:
                    self.run_cmd(f"ufw allow {port}")
            self.run_cmd("ufw --force enable")

        if self.chk_fail2ban.value:
            self.run_cmd("apt-get install -y fail2ban")
            self.run_cmd("systemctl enable --now fail2ban")

        if self.chk_unattended.value:
            self.run_cmd("apt-get install -y unattended-upgrades")
            self.run_cmd("dpkg-reconfigure -plow unattended-upgrades")

    def exec_system(self):
        if self.field_hostname.value.strip():
            hname = self.field_hostname.value.strip()
            self.run_cmd(f"hostnamectl set-hostname {hname}")
            self.run_cmd(f"sed -i 's/127.0.1.1.*/127.0.1.1\\t{hname}/' /etc/hosts")

        if self.field_timezone.value.strip():
            self.run_cmd(f"timedatectl set-timezone {self.field_timezone.value.strip()}")

        if self.field_locale.value.strip():
            locale = self.field_locale.value.strip()
            self.run_cmd(f"locale-gen {locale}")
            self.run_cmd(f"update-locale LANG={locale}")

        if self.field_ntp.value.strip():
            try:
                Path("/etc/systemd/timesyncd.conf").write_text(
                    f"[Time]\nNTP={self.field_ntp.value.strip()}\n"
                )
                self.run_cmd("systemctl restart systemd-timesyncd")
            except Exception as e:
                logging.error(f"NTP config failed: {e}")

        swap_str = self.field_swap.value.strip()
        if swap_str:
            try:
                swap_mb = int(swap_str)
                if swap_mb > 0:
                    self._exec_swap(swap_mb)
            except ValueError:
                logging.warning(f"Invalid swap size: {swap_str}")

        if self.field_user.value.strip():
            user = self.field_user.value.strip()
            try:
                subprocess.run(f"id -u {user}", shell=True, check=True, stdout=subprocess.DEVNULL)
                logging.info(f"User {user} already exists")
            except subprocess.CalledProcessError:
                self.run_cmd(f"useradd -m -s /bin/bash {user}")
                self.run_cmd(f"usermod -aG sudo {user}")

            if self.field_password.value and not self.chk_dryrun.value:
                try:
                    subprocess.run(
                        "chpasswd",
                        input=f"{user}:{self.field_password.value}".encode(),
                        shell=True, check=True, capture_output=True
                    )
                    logging.info(f"Password set for {user}")
                except Exception as e:
                    logging.error(f"chpasswd failed: {e}")
            elif self.field_password.value and self.chk_dryrun.value:
                logging.info(f"[DRY-RUN] would set password for {user}")

            if self.field_ssh_pubkey.value.strip():
                try:
                    home = subprocess.check_output(
                        f"getent passwd {user} | cut -d: -f6", shell=True, text=True
                    ).strip()
                    ssh_dir = Path(home) / ".ssh"
                    ssh_dir.mkdir(mode=0o700, exist_ok=True)
                    auth_keys = ssh_dir / "authorized_keys"
                    with open(auth_keys, 'a') as f:
                        f.write(f"{self.field_ssh_pubkey.value.strip()}\n")
                    os.chmod(auth_keys, 0o600)
                    self.run_cmd(f"chown -R {user}:{user} {ssh_dir}")
                    logging.info(f"SSH pubkey installed for {user}")
                except Exception as e:
                    logging.error(f"SSH pubkey install failed: {e}")

            if self.chk_motd.value and not self.chk_motd_uninstall.value:
                sudoers_file = f"/etc/sudoers.d/{user}"
                sudo_rule = f"{user} ALL=(root) NOPASSWD: {MOTD_SCRIPT_PATH}\n"
                try:
                    if not Path(sudoers_file).exists() or Path(sudoers_file).read_text() != sudo_rule:
                        Path(sudoers_file).write_text(sudo_rule)
                        os.chmod(sudoers_file, 0o440)
                except Exception as e:
                    logging.error(f"sudoers failed: {e}")

    def _exec_swap(self, swap_mb):
        logging.info(f"Configuring {swap_mb}MB swap")
        swapfile = "/swapfile"
        self.run_cmd(f"swapoff {swapfile} 2>/dev/null || true")
        self.run_cmd(f"rm -f {swapfile}")
        self.run_cmd(f"fallocate -l {swap_mb}M {swapfile} || dd if=/dev/zero of={swapfile} bs=1M count={swap_mb}")
        self.run_cmd(f"chmod 600 {swapfile}")
        self.run_cmd(f"mkswap {swapfile}")
        self.run_cmd(f"swapon {swapfile}")
        try:
            fstab = Path("/etc/fstab").read_text()
            if swapfile not in fstab:
                with open("/etc/fstab", 'a') as f:
                    f.write(f"\n{swapfile} none swap sw 0 0\n")
        except Exception as e:
            logging.error(f"fstab update failed: {e}")

    def exec_custom_script(self):
        script = self.field_custom_script.value.strip()
        if not os.path.exists(script):
            logging.error(f"Custom script not found: {script}")
            npyscreen.notify_confirm(f"Script niet gevonden:\n{script}", title="Fout")
            return
        logging.info(f"Running custom script: {script}")
        try:
            os.chmod(script, 0o755)
            self.run_cmd(f"bash {script}")
        except Exception as e:
            logging.error(f"Custom script failed: {e}")


class PostReadyApp(npyscreen.NPSAppManaged):
    def onStart(self):
        self.addForm("MAIN", PostReadyForm)
        self.addForm("LOG", LogViewerForm)


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
        logging.warning("User interrupted process (SIGINT/Ctrl+C)")
        print("\n[WARNING] Process terminated by user.")
        try:
            sys.exit(0)
        except Exception:
            os._exit(0)
    except Exception as e:
        logging.critical(f"FATAL EXCEPTION: {e}", exc_info=True)
        print(f"\n[ERROR] Fatal crash. See {LOG_FILE} for details.")
        sys.exit(1)
