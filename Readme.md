backend
|
|-- routes
|       |--auth.py
|--models.py
|--server.py
|--utils.py"# Chrome-Extension" 


Create ECR Repository

Create IAM User : extension-users : AKIAVY2PGZMEZGZHPSWQ >  uVaEmo6A5Tl3+J49cnt6KRIEN9iUtSj8J1gt1u8M

Create EC2 Instance and Install Docker 

Create Runner on Github portal - and run the commans mentioend in the Github on your EC2 Instance

Add all Secret Environement variables declared in main.yaml file 

AWS_ACCESS_KEY_ID : AKIAVY2PGZMEZGZHPSWQ > AWS_SECRET_ACCESS_KEY: uVaEmo6A5Tl3+J49cnt6KRIEN9iUtSj8J1gt1u8M ( IAM User  )

AWS_REGION : ap-southeast-2

AWS_ECR_LOGIN_URI : 396913724169.dkr.ecr.ap-southeast-2.amazonaws.com/thinkinfo/extension

ECR_REPOSITORY_NAME : extension-rep
