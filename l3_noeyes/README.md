# Level 3 - no eyes
```
No Eyes
The website isn't really me much, but you can still get the admin password, right?
http://shell2017.picoctf.com:16012/

HINTS
 Sometimes an error message can be just as useful.
```

I'm fairly new to web exploits, so this one seemed interesting to me. I started playing around with it.
One of the first things I tried got me an error:
```
There Was An Error With Your Request
select * from users where user = 'aoe;'';
```
mmm, what about input `aoeu' or '1'='1`

This got me a page that says:
```Login Functionality Not Complete. Flag is 63 characters```

So now what do I try... Ok lets try a different user, like admin:

Input: `admin' or '1'='1`

So far so good... still successful login.
How about some more fields, where I don't care what the value actually is, the flag is there somewhere:

Input: `aoeu' WHERE user LIKE '%`

MMM, that gets an error. How about password? No... pass?

```aoeu' WHERE pass LIKE '%```
No... but wait... I took out the `or 1=1`. So I need a real username... lets try:
```admin' WHERE pass LIKE '%```

DOHHH... the full SQL already has a WHERE clause. Dummy...
```aoeu' and user LIKE '%```

Ohhh, that gets me `User not Found.`
Ok, lets try admin again
```admin' and user LIKE '%```

Yes... Ok `Incorrect Password.`

So now lets see if we can get the flag:
```admin' and flag LIKE '%```

Nope, sql error again. flag must not be the right parameter.
Lets try: ```admin' and pass LIKE '%```

Ahhh, that gets an `incorrect password` so that must be the right field.
Ok, time to try a character:
```admin' and pass LIKE 'A%```

No... `User not Found.` again. Ok I see how this is going to be... 63 characters, 26 Uppercase, 26 Lowercase, 10 numbers and special characters. Time to get a beer ;)

Break out wireshark and look at the post request to get the fields..
Break out our trusty python requests library and set to work.

Here is the final [exploit code](exploit.py)

I tried to make it very 'movie' like, where you see the character it's trying and then it's replaced with the next character till it find the correct one and moves on. :)

Enjoy.
If you're wondering why I placed most of the flag already in the script. This is because that part shouldn't change between users. And I want to be as gentle as possible on the servers, lets all play nice right?

You may have to update the URL with the port that was given to you. That port is mine and the flag won't necessarily work for others.
