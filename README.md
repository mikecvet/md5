# MD5
This is a toy implementation of the MD5 digest algorithm, implemented in Rust. This program was a fun Rust-learning adventure.

There are a few simple arugments to the program:

    ~/code/md5 ~>> cargo build --release
    Finished release [optimized] target(s) in 0.03s

    ~/code/md5 ~>> ./target/release/md5 --test
    tests completed successfully!

    ~/code/md5 ~>> ./target/release/md5 --string abcde
    ab56b4d92b40713acc5af89985d4b786

    ~/code/md5 ~>> echo -n abcde > input_file.txt
    ~/code/md5 ~>> ./target/release/md5 --path input_file.txt
    ab56b4d92b40713acc5af89985d4b786

I tested the performance of this code against the build-in `md5` tool in OSX using the [2006 English Wikipedia Corpus](http://mattmahoney.net/dc/textdata.html), which comes in around 954Mb.

    ~/code/md5 ~>> time ./target/release/md5 --path ~/Downloads/wiki/enwik9
    e206c3450ac99950df65bf70ef61a12d

    real	0m2.001s
    user	0m1.758s
    sys	0m0.243s

    ~/code/md5 ~>> time md5 ~/Downloads/wiki/enwik9 
    MD5 (/Users/mike/Downloads/wiki/enwik9) = e206c3450ac99950df65bf70ef61a12d

    real	0m1.776s
    user	0m1.741s
    sys	0m0.152s

This code comes in around 111% of the digest time of that tool.
