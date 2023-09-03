# Writeup

This challenge is a test of a players ability to read and parse Golang really. The app checks if the `X-Forwarded-For` header exists and if it does, it uses it to determine the client's IP. Therefore, the requestor can spoof a client IP by adding a `X-Forwarded-For` header.
