f = open('../src/pyny.py', 'rb').read()
print(f.replace(b'#coding: punycode',b'').decode('punycode'))