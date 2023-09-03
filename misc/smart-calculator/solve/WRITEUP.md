Smart Calculator
============

The aim is to ouptut the variable "flag" using eval. We control the input to eval, however, it must be a number due to the functions, "isNaN" and "Number".

Within the "Calculator" function, there is the ability to write to the global object to any arbitrary key.

By writing to the keys "isNaN" and "Number", the functions are overwritten. When executing the "To Decimal" function in this state, the functions will throw errors, but "eval" still executes with your input due to the try catch.

Inputs to solve challenge:

```
1
isNaN
1
1
1
Number
1
1
1
2
flag

```

Shorter solve:

```
1
isNaN
x
x
x
2
flag
```

