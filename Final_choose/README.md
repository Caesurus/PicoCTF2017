# PicoCTF2017_final_choose
Final challenge in the PicoCTF2017 competition

I chose to do this with a two stage payload. 
There was a nice piece of code in `readWrapper()` that calls `readInput()` with two pointers.

```
   0x08048eb7 <+28>:    push   DWORD PTR [ebp+0xc]
   0x08048eba <+31>:    push   DWORD PTR [ebp+0x8]
   0x08048ebd <+34>:    call   0x8048e3c <readInput>
```

Since we overwrite EBP and return, I pointed EBP to the input buffer which could then point to the parameters I wanted to pass to `readInput()`

At that point I uploaded shellcode to be executed and once `readInput` returned, the code jumps to the shellcode.

Final [exploit](exploit.py) is checked in. It was a fun challenge.
