# MicroCrvice
This was intended to be the backend of an extension I wanted to make

Libevent http server
|
|___Router
    |
    |_ favicon.ico
    |
    |_ /Index
    |...

## Main problems/pitfalls
Using C for the backend is simpler than expected but it is still
a bit of a pain to work with. 

### Bad things

1. __Error handling__ isn't always clear. Mysql's library result fetching can break the program 
if the binded row doesn't have the expected type, one would expect for it to return an error instead, 
which execute/result_bind/prepare_statement/etc do do.

2. __Memory management__ could be a performance bottleneck:
    With GNUC's __attribute__((cleanup))__ you can forget about freeing stuff when early returning,
    specially useful if you wrap the macro, for example I use `__clean` for common malloced pointers.
    Freeing memory before serving the data to the user is kinda cringe, an implementation with a simple GC
    that wakes up each X seconds in another thread, can be useful for this.

3. __Libevent__ requires time to get used to, specially if you are used to
    async/await or similar which is knowledge you can transfer seamlessly between js and c# for example.

4. __String handling/lack of a template engine__ is a pain. Althought string handling can be eased by
'asprintf', at least for htmx a templating engine is __required__

5. __Getting used to common functions and structures__ such as `time_t`, `struct tm` can get you out of 
common bugs, in my case, token validation :).
 
6. __Lack of flexibility__ using `mysql`'s library is different to `sqlite`'s, which is not the case
in .net on which you just change a couple lines in `startup.cs`

7. __Don't yet know how to ship it__ probably it will be a docker, not skillfull enought to do this, yet.

### Good things

1. Libevent eases event driven programming, common in frameworks/languages such as `Node`/`C#`
2. I learned that Node uses a similar library to libevent, `libuv`, also, before I thought 
that there was no cost to enqueuing with async/await, but there is, because it pushes the work to the bottom 
of the event loop.
3. __Error handling__, forced me to handle errors ala GO, otherwise the backend would crash, which, I think,
is unwanted.
4. __Tons of control__ over the 

### Might be good to consider

1. Haven't tried mysql's async library
2. Haven't tried websockets
3. Haven't tried ssl __yet__

# Overall 8/10, would repeat
