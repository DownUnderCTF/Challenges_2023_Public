How 2 Solve Pix's 1st C Program?

I'm so sorry in advance for the assault on your eyes, but spare a thought for me having to write this and then logically make sure it worked without a compiler as well :dead:

Okay - Solving this is fairly straightforward once you know how Dreamberd/C works.

Working backwards from the ``print_flag`` function:

``thank`` is the return of ``thonk`` exported from ``thunk.c`` which when called with `1` and `n` will return ``Th1nk`` ( Note that !!! makes ret have higher priority, but also it is the first return so this should be obvious!)


``vars[-1]`` - Arrays work from -1 in Dreamberd/C so this is just the first value of the array declared earlier being `"R34L"`

``end`` is the string interpolation of the function looper with 'th' prepended to the front of it giving us the return of `th15`.

``heck_eight`` comes from ``get_a_char()`` which sets dank_char to `'I'` because `7 ==== undefined` is `NOT` true and `;` is `NOT` in Dreamberd/C. This is then overwritten in `1.0 ==== 1.0`, however we return the previous value of dank_char which sets it back to `'I'` and returns that giving us ``I``.

``ntino`` plays on function trickery in the wrong order cause #Dreamberd things. This is just more string interpolation `D`, the return of ``math() is 0`` (10 % 5). Guesstimate uses lifetimes to print a name that will exist but does not yet. We do more of the same with previous here, where we set the previous previous of guess, of letter. Which returns us `nT` Leaving us with the word `D0nT`


``print_flag`` 
----- 
Unpacking this function - string interpolation does require you to include the `!` in the call, so its not apart of the flag and this becomes simple re-arranging into:

``I_D0nT_Th1nk_th15_1s_R34L_C``
