# Level 3 - Enter The Matrix
```
Enter The Matrix
The Matrix awaits you,. Take the red pill and begin your journey. Source. Jack in at shell2017.picoctf.com:57222.

 HINTS
Look carefully at how the matrix is indexed.
Study the heap memory layout to see what you can overwrite.
```

So first off, I'm not going to be able to do a better job of explaining this challenge than jordan @ [http://byte-off.com/golang/picoctf-enter-the-matrix-writeup/](http://byte-off.com/golang/picoctf-enter-the-matrix-writeup/)
For a very detailed writeup and exploit written in GO, please read his [page](http://byte-off.com/golang/picoctf-enter-the-matrix-writeup/).

My python [exploit](./L3_EnterTheMatrix/exploit.py) is checked in, and I've checked in the source, binary and libc version the server used.

My exploit has a function hex2float() that I implemented because I was interested in how the float was stored as a 32bit value in memory. 
This is absolutely unnecessary since there are other ways to convert this, but it seemed like something I should know, so I implemented it myself to get a better understanding of how it works.
