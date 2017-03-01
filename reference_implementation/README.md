# Reference Implementation

This is a python3 reference implementation of the *Puzzle Solver* and *Puzzle Promise* protocols.

### Dependencies

- LibreSSL
- pytest
- pycrypto
- python-bitcoinlib

You will need to install or build LibreSSL and you can install
the python dependencies by running `sudo pip3 install -r requirements.txt`

For ubuntu, you can install the dependencies by running:
```
./ubuntu_setup.sh
```

### Running Tests
Our python code only supports python3.

```
sudo pip install -e .
python3 -m pytest tests/
```

### TODO

- [ ] Create script tests
- [ ] Create a test that tests the protocols on testnet without timelocks.
