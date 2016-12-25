# XRC4 - eXtended RC4

Many have discouraged the use of RC4 for its weaknesses.

But why not enhance it? Or create another algorithm based on it?

Here I propose some initial changes to the RC4 to make a strong and still fast algorithm, primarily named XRC4.

Note that we can continue enhancing it until it passes all major cryptanalisys tests. A collaborative approach is the answer.


## First implementation 

The goal is to make a modern cipher that handles a nounce/iv and a counter.

It must generate a different keystream for each nounce + counter combination.

I will consider the use of a 32 bit counter and a variable length nounce.

The counter is expected to be incremented on each message/block and the nounce is expected to be random and different on each message/block.


### The PRGA

This is the current RC4 PRGA

    i := 0
    j := 0
    while GeneratingOutput:
        i := (i + 1) mod 256
        j := (j + S[i]) mod 256
        SWAP(S[i], S[j])
        K := S[(S[i] + S[j]) mod 256]
        output K
    endwhile


## First proposal change

By just setting different initial values for `i` and `j` we end up with 2^16 (65535) different keystreams.

These initial values can come from the LSB bytes from the counter, like this (little endian here):


    i = counter & 0xff;
    j = (counter & 0xff00) >> 8;


By just flipping a single bit in the counter we end up with a completely different keystream:


| Counter | Keystream |
|---------|-----------|
| 0000    | ...       |
| 0001    | ... |


## Second proposal change

We still have 16 bits of the counter + the entire nounce to be used.

One approach is to use these values to swap bytes in the sbox.

For this we will need to make a copy of the original sbox:

    memcpy(s, sbox, 256);

Get initial values for i and j from the counter:

    i = (counter & 0xff0000) >> 16;
    j = (counter & 0xff000000) >> 24;

And swap the local sbox values using the nounce and an algorithm identical to the one used in the KSA:

    for (n = 0; n < NUM_SWAPS; n++) {
      i = (i + 1) & 255;
      j = (j + iv[j % ivlen] + s[i]) & 255;
      SWAP(s[i], s[j]);
    }

The number of swaps can be 256 to make sure all the bytes will be swapped at least once.

Note that this algorithm limits the used nounce length to the number of swaps. So the nounce can be up to 256 bytes long.

With this we end up with (theoretically) the maximum of 2^2080 unique keystreams (if my calculation is not wrong: 256 bytes * 8 bits + 32 bits from the counter)

Off course we can use a smaller length nounce.

For a 8 bytes nounce we have 2^96 unique keystreams.


## Third proposal change

The use of co-primes of 256, so after 256 iterations of the loop, the value `i` (incremented by co-prime on every iteration) has taken on all possible values from 0 to 255.

So instead of:

    i = (i + 1) & 255;

We will use:

    i = (i + increment) & 255;

And use a function to retrieve a co-prime of 256 based on some value.

    increment = xrc4_coprime(iv[0], 0);

In the case of number 256 all the odd numbers from 1 to 255 are co-primes of 256.

Now the final PRGA code looks like this:

    memcpy(s, sbox, 256);

    i = (counter & 0xff0000) >> 16;        // byte 3
    j = (counter & 0xff000000) >> 24;      // byte 4
    increment = xrc4_coprime(iv[0], 0);

    for (n = 0; n < NUM_SWAPS; n++) {
      i = (i + increment) & 255;
      j = (j + iv[j % ivlen] + s[i]) & 255;
      SWAP(s[i], s[j]);
    }

    i = counter & 0xff;                    // byte 1
    j = (counter & 0xff00) >> 8;           // byte 2
    increment = xrc4_coprime(i, increment);

    for (n = 0; n < len; n++) {
      i = (i + increment) & 255;
      j = (j + s[i]) & 255;
      SWAP(s[i], s[j]);

      *buf ^= s[(s[i] + s[j]) & 255];
      buf++;
    }


## Fourth proposal change

Enhance the KSA

Instead of start filling the sbox with sequential numbers from 0 to 255 we can use a co-prime of 256 to fill it in another order.

So instead of this:

    for (i = 0; i < 256; i++)
        sbox[i] = i;

We use this:

    for (n = 0; n < 256; n++) {
        i = (i + COPRIME) & 255;
        sbox[i] = n;
    }

It will fill every entry with a unique value.

We can even use a different co-prime for each supplied key:

    increment = xrc4_coprime(key[0], 0);

    for (n = 0; n < 256; n++) {
        i = (i + increment) & 255;
        sbox[i] = n;
    }

Then we can swap the values using a different co-prime (in this case based on the key second byte) and the key.

    increment = xrc4_coprime(key[1 % key_length], increment);

    i = 0;
    for (n = 0; n < 3 * 256; n++) {
        i = (i + increment) & 255;
        j = (j + key[i % key_length] + sbox[i]) & 255;
        SWAP(sbox[i], sbox[j]);
    }


## Performance

TODO!


## Cryptanalisys and other enhancements

The original RC4 algorithm is full of biases. These proposals on XRC4 may not solve all the problems.

We need cryptanalisys to check for biases in the keystream.

If we discover, we can then fix it and test again.

Feel free to fork, test, discuss and contribute with suggestions or code.
