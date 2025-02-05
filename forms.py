from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Email, Optional

#------------>Register START<--------------
class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    hometown = StringField('Hometown (Optional)', validators=[Optional()])
    email_address = StringField('Email Address', validators=[DataRequired(), Email()])
    mobile = StringField('Mobile (Optional)', validators=[Optional()])
    origin = SelectField('Origin', choices=[('Facebook', 'Facebook'), ('Instagram', 'Instagram'), ('LinkedIn', 'LinkedIn'), ('Direct', 'Direct'), ('Other', 'Other')])
    origin_details = StringField('Origin Details (Optional)', validators=[Optional()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'), ('helper', 'Helper'), ('manager', 'Manager')], default='user')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    captcha_answer = StringField('CAPTCHA Answer', validators=[DataRequired()])
    submit = SubmitField('Login')