
## How 2 solve:

The binary itself is a simple two functions.

I used binary ninja since its free and you can use it up on the cloud so no download needed but it should be possible in anything that can re-assemble.


Looking past all the runtime compile things that the odin language sticks inside a no optimised binary. there are two functions of interest, a fmt.printf and a _main.print_flag.

Should find an array that has been unfurled into individual declarations inside the print flag function.


```c
// _main.print_flag
int64_t var_218 = 0
while (true)
    int32_t x8_3
    if (var_218 s< 0x3b)
        x8_3 = 1
    else
        x8_3 = 0
    if ((x8_3 & 1) == 0)
        break
    int32_t x10_1 = ((&var_200)[var_218]).d ^ 0x11
    int64_t var_248_1
    __builtin_memset(var_248_1, 0, 0x30)
    int32_t var_24c = x10_1
    int32_t* var_238 = &var_24c
    int64_t var_230_1 = 0x4200000000000001
    _fmt.printf(&data_100031ecc, 2, &var_238, 1, arg1)
    var_218 = var_218 + 1
```

The important part to look at is that `... ^ 0x11` - an XOR command with the first variable in the 
start of the flattened array.

So the solve from here is rather simple: Take each part of the array and XOR it with 0x11 that'll give you some bytes that look a little something like this:

``44 55 43 54 46 7b 4f 64 31 6e 5f 31 53 2d 4e 30 74 5f 43 7d`` 

The challenge FLUF eludes to converting TEXT or HEX - Change the HEX to ASCII / TEXT and you get the flag:
  DUCTF{Od1n_1S-N0t_C}

Well done!
