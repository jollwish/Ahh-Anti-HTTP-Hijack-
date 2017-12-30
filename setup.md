# Local Setup

```bash
mkdir cos561
cd cos561
vagrant init archlinux/archlinux
vagrant up
vagrant ssh
```



# VM Setup

```bash
sudo pacman -Syu
sudo pacman -S python python-pip gcc libnetfilter_queue git tcpdump
sudo pip install NetfilterQueue
git clone https://github.com/jollwish/Ahh-Anti-HTTP-Hijack-.git
sudo reboot
```

Reboot now. `vagrant ssh` into VM again. Open 2 ssh connections or use tmux (install it if you want, `sudo pacman -S tmux `). 

In Terminal A:

```bash
cd Ahh-Anti-HTTP-Hijack-/
```

In Terminal B:

```bash
curl http://www.cs.princeton.edu/\~yupingl/
```

Record its output.

Now go back to Terminal A:

```bash
sudo python isp.py
```

 Wait until you see `net.ipv4.ip_forward = 1`. It shouldn't take more than 2 seconds. 

Go to Terminal B, the same `curl` command will produce different output. 

To stop the *ISP monitoring*, `Ctrl-C` to kill the script. If you see things like

```
Exception ignored in: 'netfilterqueue.global_callback'
Traceback (most recent call last):
  File "isp.py", line 19, in callback
    pkt.accept()
KeyboardInterrupt
```

try it for many times. Anyway, you can use `Ctrl-\` to force-kill it, though in this way the script won't recover `iptables` rules. 
