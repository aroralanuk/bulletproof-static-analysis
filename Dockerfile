# Used for running integration tests on a simulated MPC network
# Builder stage 
FROM rust:1.63-slim-buster AS builder

WORKDIR /build
# Place a set of dummy sources in the path, build the dummy executable
# to cache built dependencies, then bulid the full executable
RUN mkdir src
RUN touch src/dummy-lib.rs
RUN mkdir integration
RUN echo 'fn main() { println!("dummy main!") }' >> integration/dummy-main.rs
COPY tests ./tests
COPY benches ./benches
COPY rust-toolchain .

COPY Cargo.toml .
COPY Cargo.lock .

# Modify the Cargo.toml to point to our dummy sources
RUN sed -i 's/lib.rs/dummy-lib.rs/g' Cargo.toml
RUN sed -i 's/main.rs/dummy-main.rs/g' Cargo.toml

RUN cargo build --test integration

# Edit the Cargo.toml back to the original, build the full executable
RUN sed -i 's/dummy-lib.rs/lib.rs/g' Cargo.toml
RUN sed -i 's/dummy-main.rs/main.rs/g' Cargo.toml

# Copy the docs in so that linter denials don't prevent compilation
COPY docs ./docs
COPY README.md .

COPY src ./src
COPY integration ./integration

ENV RUST_BACKTRACE=1

RUN cargo build --test integration \
    --features integration_test

CMD [ "cargo", "test" ]
