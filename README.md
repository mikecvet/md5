# MD5
This is a toy implementation of the MD5 digest algorithm, implemented in Rust.

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
