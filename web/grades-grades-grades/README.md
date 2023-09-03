grades_grades_grades
============

**Category:** web

**Difficulty:** easy

**Author:** donfran

**Ports Open:** 5000

Sign up and see those grades :D! How well did you do this year's subject?

Author: donfran

---

## Solution

- Navigate to /signup
- Enter in your student_number, student_email and password
- Notice that JWT is created for your session and it follows the form parameters
- Observe in the JWT that there is a value called is_teacher
- Sign out and sign up for a new account
- Once submitted intercept the request and add in the extra parameter and value in the request body of: is_teacher=whatever
- Notice you now have "Grading_Tool" in the navbar
- Click on it and get the flag :D
