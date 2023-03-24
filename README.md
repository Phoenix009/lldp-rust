# HON LLDP Agent

This project implements a skeleton for a minimal LLDP agent in Rust.

The finished LLDP agent is able to announce information about itself as well as receive information from neightboring systems.

## Project Tasks

Before starting this project you should refamiliarize yourself with the LLDP protocol using the lecture slides.
The slides give you a basic description of the LLDP protocol and its message format.
Detailed information is given along with the class definitions in the agent skeleton.

If you are unsure about where functionality has to be implemented look for comments marking a "TODO:" or the `todo!()` macro.

We advise you to start by implementing the TLVs (in the files in the `src/tlv` directory) and work your way up from there.

To pass the project your code will have to **pass all the unit tests** provided.
You are not allowed to use any third-party rust crates, apart from those already included in `Cargo.toml` (`bytes` and `pnet`).

## Unit Tests

The skeleton comes with a set of unit tests.
These allow you to validate (parts of) your implementation early on, without having to implement all of the functionality in one go.
The tests for each module are included at the bottom of the respective file, marked by `#[cfg(test)]`.

To run the unit tests you can issue the following command in the project root:

    cargo test

To only run a subset of the unit tests you can specify the specific test case to run.
If you e.g. want to run only the tests for TTL TLVs (in `src/tlv/ttl_tlv.rs`), you can use the following command:

    cargo test tlv::ttl_tlv::tests

To find out more about testing your code in Rust, check out the respective chapters in [Rust By Example](https://doc.rust-lang.org/rust-by-example/testing.html) and [The Rust Programming Language](https://doc.rust-lang.org/book/ch11-00-testing.html), or run the command

    cargo help test

Unit tests may also be run from an IDE like VSCode.

Feel free to write some tests of your own.

## Running the Agent

Once you finished your implementation you can e.g. test the LLDP agent on your local network.

When running the LLDP agent, be aware that it needs to be able to send raw Ethernet frames to the network, which requires the agent to run with root priviliges.
The project is configured to automatically start the agent with `sudo` in `.cargo/config`.

From the project root directory you can use the following command:
 
    cargo run --release
    
To run the agent on a specific network interface simply append the interface name:

    cargo run --release eth1

## Documentation

Each struct and function you have to implement is annotated with [doc comments](https://doc.rust-lang.org/reference/comments.html#doc-comments).
To look at this documentation, you can run

    cargo doc --open
