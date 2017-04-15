# PicoCTF2017_final_choose
Final challenge in the PicoCTF2017 competition
```
Choose
Unhappy that you can't choose which enemies to fight? Choose your own adventure! Source. Connect on shell2017.picoctf.com:43651. ASLR is not enabled.

 HINTS
An assumption made in the code is wrong. Which assumption, and what does it allow you to do?
```
First we need to find a vulnerability. I found this by getting Wizards Sight and calculating the difference between enemys structures in memory. This led to a clear difference between the size of an orc and a unicorn. A closer look shows why:
```C
typedef struct _orc{
    char type;
    short damage;
    int health;
    char name[ENEMNAMELEN];
} orc;

typedef struct _unicorn{
    char type;
    int health;
    short damage;
    char name[ENEMNAMELEN];
} unicorn;
```

Both have members that add up to 19bytes, but due to the ordering of the members of the struct, the unicorn will take up 24 bytes and the orc will take up 20. Google memory alignment for more information on this.

So by choosing 11 unicorns or 11 centaurs to fight, we can overwrite EBP and RET pointers.

Even though ASLR is disabled on the version that is running on the server. Lets solve it as if it were enabled.

When I initially looked at this I figured I could try to load shellcode in each of the names of the enemies, and have the shellcode jump to the next section when needed. I didn't like the idea of having to do this, sounded too much like real work ¯¯\\_(ツ)_/¯¯

So I looked for other options.

There was a nice piece of code in `readWrapper()` that calls `readInput()` with two pointers.
```asm
   0x08048eb7 <+28>:    push   DWORD PTR [ebp+0xc]
   0x08048eba <+31>:    push   DWORD PTR [ebp+0x8]
   0x08048ebd <+34>:    call   0x8048e3c <readInput>
```
So I chose to do this with a two stage payload.

Since we overwrite EBP and return, I pointed EBP to the input buffer which could then hold the pointers to the parameters I wanted to pass to `readInput()`

So after exiting the fight with the dragon, EBP is updated, and the code return to the asm above. Since EBP points to our input buffer we have preloaded that with values we want to pass to `readInput` and readInput() is called and we can place our second stage payload in what is soon to be our stack.

When the `readWrapper()` runs to completion, it will cause the stack to be pivoted to BSS and which is preloaded with a return pointer to our shellcode.

Final [exploit](exploit.py) is checked in. 

It was a fun challenge. Hopefully this writeup presents an interesting solution to this problem. I think this was the intended solution, but it looks like others solved it differently.

