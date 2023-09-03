# HINTS

## Where to start

How is the calculator storing solutions for operands that are not +, -, or *? In particular, what object is it storing the solutions in?

## So what if we're storing the solutions in global?

It's risky to write to global, especially if we can control what key we're writing to.

Stuff like functions are stored in global too. What would happen if we overwrote the functions?

## Why would I need to overwrite a function?

If you overwrite the functions protecting eval, you could maybe clobber your way through to code execution.

