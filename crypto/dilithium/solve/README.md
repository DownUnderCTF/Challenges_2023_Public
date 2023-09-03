# dilithium± mini writeup

Dilithium is a signature scheme based on the "Fiat-Shamir with Aborts" approach. The "aborts" part of the scheme is important to security as without it, some information about the secret key may be leaked in the signatures.

In Dilithium, a signature is the pair $(\mathbf{z}, c)$ with $\mathbf{z} = \mathbf{y} + c \mathbf{s_1}$ where $\mathbf{y}$ is taken from the uniform distribution over $[-(\gamma_1 - 1), \gamma_1]$ and $c$ is a vector of $\tau = 39$ $-1$ or $1$'s built from the message to be signed. $\mathbf{s_1}$ is the secret short vector which contains elements in the range $[-\eta, \eta]$ with $\eta = 2$.

In the challenge, the reference implementation is patched to _only_ produce signatures where the infinity norm of $\mathbf{z}$ satisfies $\gamma_1 - 2 \leq ||\mathbf{z}||_{\infty} \leq \gamma_1 + 2$ (instead of ensuring that $||\mathbf{z}||_{\infty} \leq \gamma_1 - \beta$)

This leaks information about the secret $\mathbf{s_1}$. To see why we can split it up in to two cases (one for when $z \geq 0$ and one for when $z < 0$).

### Case 1 ($\mathbf{z} \geq 0$)

Suppose some coefficient (call it $z$) of $\mathbf{z}_i$ is greater than $\gamma_1 - \beta$. Let the corresponding coefficient of $\mathbf{y}_i$ be $y$.
Let $v = z - (\gamma_1 - \beta) > 0$.
Now, note that

$$
\begin{aligned}
    z &= y + c \mathbf{s_1} \\
    \implies v + (\gamma_1 - \beta) &= y + c \mathbf{s_1} \\
\implies v - \beta + (\gamma_1 - y) &= c \mathbf{s_1}
\end{aligned}
$$

From the distribution of $y \in [-(\gamma_1 - 1), \gamma_1]$ we can tell that the value of $(\gamma_1 - y)$ is in the range $[0, 2\gamma_1 - 1]$. Or in other words, $(\gamma_1 - y) \geq 0$. This tells us that

$$
v - \beta \leq c \mathbf{s_1}
$$

So when $z = \gamma_1$ then $v = \beta$ and so we get the constraint $0 \leq c \mathbf{s_1}$. This is helpful because normally we would only know that $-\beta \leq c \mathbf{s_1}$.

When $z = \gamma_1 - 1$, we get the constraint $-1 \leq c \mathbf{s_1}$.

When $z = \gamma_1 - 2$, we get the constraint $-2 \leq c \mathbf{s_1}$.

### Case 2 ($\mathbf{z} < 0$)

Similar thing, but this time let $v = -(\gamma_1 - \beta) - z \geq 0$. Note that

$$
\begin{aligned}
    z &= y + c \mathbf{s_1} \\
\implies -v - (\gamma_1 - \beta) &= y + c \mathbf{s_1} \\
\implies \beta - v - (\gamma_1 + y) &= c \mathbf{s_1}
\end{aligned}
$$

From the distribution of $y \in [-(\gamma_1 - 1), \gamma_1]$ we can tell that the value of $(\gamma_1 + y)$ is in the range $[1, 2\gamma_1]$. Or in other words, $(\gamma_1 + y - 1) \geq 0$. This tells us that

$$
c \mathbf{s_1} \leq \beta - v - 1
$$

So when $z = -\gamma_1$ then $v = \beta$ and so we get the constraint $c \mathbf{s_1} \leq -1$. This is helpful because normally we would only know that $c \mathbf{s_1} \leq \beta$.

When $z = -\gamma_1+1$, we get the constraint $c \mathbf{s_1} \leq 0$.

When $z = -\gamma_1+2$, we get the constraint $c \mathbf{s_1} \leq 1$.

## Unpacking the signatures

To have enough information to recover $\mathbf{s_1}$ we need to make use of the signatures which satisfy $||\mathbf{z}||_{\infty} = \gamma_1$.
The patch changes the signing procedure to allow $||\mathbf{z}||_{\infty} = -\gamma_1$, however, when packing the signature into bytes, the reference implementation only allows
the $\mathbf{z}_i$ polynomials to have coefficients in the range $[-(\gamma_1 - 1), \gamma_1]$. This can be seen [here](https://github.com/pq-crystals/dilithium/blob/master/ref/poly.c#L766-L775).
What this means is that when one of the coefficients of $\mathbf{z}_i$ is $-\gamma_1$, it actually gets packed in a way such that it wraps and becomes unpacked as $\gamma_1$. This means that signatures
with a coefficient of absolute value $\gamma_1$ look the same (regardless of their sign). However, we can distinguish the two cases by checking whether or not it verifies under the public key;
if it doesn't verify, then we know we have the negative case, and if it does verify, then we know we have the positive case.

## Solving

Using both cases (when $||\mathbf{z}||_{\infty} \in \{ \gamma_1 - 1, \gamma_1 \}$ leading to approx ~9500 constraints) and throwing it into OR-Tools recovers $\mathbf{s_1}$ in a few seconds.
Once we have $\mathbf{s_1}$ it's more or less straightforward to forge a signature.
