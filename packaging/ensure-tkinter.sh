# Sourced by the launchers (AppRun and ./asus-fingerprint). Usage: ensure_tkinter <python>
# If <python> cannot import tkinter, offer to install the distribution's Tk package (password prompt via
# pkexec), then re-check. Returns 0 when tkinter is available, 1 otherwise.
_fp_dialog_yesno() {   # $1 = message
  if command -v kdialog >/dev/null 2>&1; then kdialog --title "ASUS Fingerprint" --yesno "$1"; return $?; fi
  if command -v zenity  >/dev/null 2>&1; then zenity --question --title="ASUS Fingerprint" --text="$1"; return $?; fi
  if [ -t 0 ]; then printf '%s [y/N] ' "$1"; read -r a; [ "$a" = y ] || [ "$a" = Y ]; return $?; fi
  return 1
}
_fp_dialog_error() {
  if command -v kdialog >/dev/null 2>&1; then kdialog --title "ASUS Fingerprint" --error "$1"
  elif command -v zenity >/dev/null 2>&1; then zenity --error --title="ASUS Fingerprint" --text="$1"
  else echo "$1" >&2; fi
}
ensure_tkinter() {
  _py="$1"
  "$_py" -I -c 'import tkinter' >/dev/null 2>&1 && return 0
  if   command -v pacman  >/dev/null 2>&1; then _pkg=tk;              _cmd="pacman -S --needed --noconfirm tk"
  elif command -v dnf     >/dev/null 2>&1; then _pkg=python3-tkinter; _cmd="dnf install -y python3-tkinter"
  elif command -v apt-get >/dev/null 2>&1; then _pkg=python3-tk;      _cmd="apt-get install -y python3-tk"
  elif command -v zypper  >/dev/null 2>&1; then _pkg=python3-tk;      _cmd="zypper --non-interactive install python3-tk"
  else
    _fp_dialog_error "ASUS Fingerprint needs Python's tkinter (the Tk GUI library), which is not installed. Please install your distribution's Tk package for Python and start the app again."
    return 1
  fi
  if ! _fp_dialog_yesno "ASUS Fingerprint needs Python's tkinter (the Tk GUI library), which is not installed.

Install the package '$_pkg' now? You will be asked for your password."; then
    return 1
  fi
  if ! command -v pkexec >/dev/null 2>&1; then
    _fp_dialog_error "pkexec is not available. Please run as root:  $_cmd"; return 1
  fi
  # shellcheck disable=SC2086
  if ! pkexec $_cmd; then
    _fp_dialog_error "Installing '$_pkg' failed or was cancelled. You can install it yourself with:  sudo $_cmd"; return 1
  fi
  "$_py" -I -c 'import tkinter' >/dev/null 2>&1 && return 0
  _fp_dialog_error "'$_pkg' was installed but tkinter still cannot be imported by $_py. Please install the Tk package that matches this Python version."
  return 1
}
