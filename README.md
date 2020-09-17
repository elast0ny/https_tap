# https_tap

This is a toy project used to inspect HTTPS traffic.


In order to test it, you can simply change your `hosts` file to point to 127.0.0.1 and browse to the desired website while https_tap is running. It should forward the traffic to the real host while also sending the plaintext traffic to the loopback interface so you can inspect it in wireshark.