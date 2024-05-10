FROM nikolaik/python-nodejs:python3.8-nodejs16-bullseye
ADD . /workspace
WORKDIR /workspace
RUN bash

RUN yarn

# Run hardhat tests
RUN yarn run test:hh

# Setup foundry
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:$PATH"
RUN foundryup

ENV GIT_SUBMODULE_STRATEGY=recursive

# Run foundry tests
RUN forge install
RUN forge test -vvv --root . -C contracts/src --match-path \"contracts/test/*\" --out forge-artifacts