Output .github/demo.gif

Require ssh
Require ssh-keygen
Require unssh
Require echo

Set Shell "zsh"
Set LineHeight 1.4
Set FontSize 16
Set Padding 20
Set Width 960
Set Height 480

Type "ssh-keygen -q -N '' -t ed25519 -f .ssh/host_ed25519_key" Sleep 500ms  Enter

Sleep 2s

Type "unssh run --public-key .ssh/host_ed25519_key.pub --port 2223 >/dev/null &" Sleep 500ms Enter

Sleep 2s

Type "ssh 127.0.0.1 -p 2223" Sleep 500ms Enter

Sleep 2s

Type "yes" Sleep 500ms Enter

Sleep 3s

Type "echo 'Hello from ssh!'" Sleep 500ms Enter

Sleep 5s
