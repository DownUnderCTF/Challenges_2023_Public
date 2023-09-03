clang -o wrong-signal-pre wrong-signal.c -no-pie
python3 postprocess.py
rm wrong-signal-pre
# strip wrong-signal